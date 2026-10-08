package org.clipbridge.android.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.system.Os
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.security.KeyStore
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class SafeIdentityMetadata(val deviceId: String, val publicKey: ByteArray) {
    val shortFingerprint: String get() = deviceId.take(12)
}

/** Android Keystore protects a versioned Rust CBID record; no plaintext file fallback exists. */
class AndroidIdentityStore(context: Context) {
    private val appContext = context.applicationContext
    private val identityFile = File(appContext.noBackupFilesDir, IDENTITY_FILE)
    private val temporaryFile = File(appContext.noBackupFilesDir, "$IDENTITY_FILE.tmp")

    fun loadOrCreate(): SafeIdentityMetadata = synchronized(CREATION_LOCK) {
        NativeCore.requireAvailable()
        if (identityFile.exists()) {
            require(identityFile.isFile && identityFile.length() == ENVELOPE_SIZE.toLong()) {
                "identity_envelope_malformed"
            }
            val encoded = identityFile.readBytes()
            val record = decrypt(encoded)
            val expectedPublicKey = encoded.copyOfRange(18, 50)
            return try {
                validateRecord(record, expectedPublicKey).also { installInRust(record, it) }
            } finally {
                Arrays.fill(record, 0)
                Arrays.fill(encoded, 0)
                Arrays.fill(expectedPublicKey, 0)
            }
        }
        if (hasWrappingKey()) {
            error("identity_material_missing")
        }

        val record = NativeCore.nativeGenerateIdentityRecord()
        try {
            require(record.size == IDENTITY_RECORD_SIZE) { "identity_record_malformed" }
            val publicKey = record.copyOfRange(PUBLIC_KEY_OFFSET, PUBLIC_KEY_OFFSET + PUBLIC_KEY_SIZE)
            val metadata = validateRecord(record, publicKey)
            val key = createWrappingKey()
            val encoded = encrypt(record, publicKey, key)
            try {
                writeAtomically(encoded)
            } finally {
                Arrays.fill(encoded, 0)
                Arrays.fill(publicKey, 0)
            }
            installInRust(record, metadata)
            return metadata
        } finally {
            Arrays.fill(record, 0)
        }
    }

    private fun validateRecord(record: ByteArray, expectedPublicKey: ByteArray): SafeIdentityMetadata {
        require(record.size == IDENTITY_RECORD_SIZE) { "identity_record_malformed" }
        require(record.copyOfRange(0, 4).contentEquals(RECORD_MAGIC)) { "identity_record_malformed" }
        require(record[4] == 0.toByte() && record[5] == 1.toByte()) { "identity_record_version" }
        val metadata = NativeCore.nativeIdentityMetadata(record)
        try {
            require(metadata.size == 64) { "identity_record_malformed" }
            val publicKey = metadata.copyOfRange(32, 64)
            require(publicKey.contentEquals(expectedPublicKey)) { "identity_key_mismatch" }
            return SafeIdentityMetadata(metadata.copyOfRange(0, 32).toHex(), publicKey)
        } finally {
            Arrays.fill(metadata, 0)
        }
    }

    private fun installInRust(record: ByteArray, expected: SafeIdentityMetadata) {
        val installed = NativeCore.nativeInstallIdentityRecord(record)
        try {
            require(installed.size == 64) { "identity_install_failed" }
            require(installed.copyOfRange(0, 32).contentEquals(expected.deviceId.hexToBytes())) {
                "identity_install_mismatch"
            }
            require(installed.copyOfRange(32, 64).contentEquals(expected.publicKey)) {
                "identity_install_mismatch"
            }
        } finally {
            Arrays.fill(installed, 0)
        }
    }

    private fun decrypt(encoded: ByteArray): ByteArray {
        require(encoded.size == ENVELOPE_SIZE) { "identity_envelope_malformed" }
        require(encoded.copyOfRange(0, 4).contentEquals(ENVELOPE_MAGIC)) { "identity_envelope_malformed" }
        require(encoded[4] == 0.toByte() && encoded[5] == 1.toByte()) { "identity_envelope_version" }
        val nonce = encoded.copyOfRange(6, 18)
        val publicKey = encoded.copyOfRange(18, 50)
        val key = existingWrappingKey() ?: error("identity_wrapping_key_missing")
        val cipher = Cipher.getInstance(TRANSFORMATION, ANDROID_KEY_STORE)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, nonce))
        cipher.updateAAD(aad(publicKey))
        return try {
            cipher.doFinal(encoded, 50, encoded.size - 50)
        } finally {
            Arrays.fill(nonce, 0)
            Arrays.fill(publicKey, 0)
        }
    }

    private fun encrypt(record: ByteArray, publicKey: ByteArray, key: SecretKey): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION, ANDROID_KEY_STORE)
        // Let Android Keystore choose the IV; randomized-encryption authorization can reject
        // caller-supplied IVs even when the caller claims they are random.
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val nonce = cipher.iv ?: error("identity_iv_unavailable")
        require(nonce.size == NONCE_SIZE) { "identity_iv_unavailable" }
        cipher.updateAAD(aad(publicKey))
        val ciphertext = cipher.doFinal(record)
        require(ciphertext.size == CIPHERTEXT_SIZE) { "identity_envelope_malformed" }
        return ByteBuffer.allocate(ENVELOPE_SIZE).order(ByteOrder.BIG_ENDIAN)
            .put(ENVELOPE_MAGIC).putShort(ENVELOPE_VERSION).put(nonce).put(publicKey).put(ciphertext).array()
            .also {
                Arrays.fill(nonce, 0)
                Arrays.fill(ciphertext, 0)
            }
    }

    private fun aad(publicKey: ByteArray): ByteArray =
        APP_ID.toByteArray(Charsets.UTF_8) + byteArrayOf(0) +
            ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort(ENVELOPE_VERSION).array() +
            KEY_ALIAS.toByteArray(Charsets.US_ASCII) + byteArrayOf(0) + publicKey

    private fun writeAtomically(encoded: ByteArray) {
        identityFile.parentFile?.let { check(it.isDirectory || it.mkdirs()) { "identity_store_unavailable" } }
        FileOutputStream(temporaryFile, false).use { stream ->
            stream.write(encoded)
            stream.fd.sync()
        }
        try {
            // Both files live in the same app-private directory, so POSIX rename is atomic.
            Os.rename(temporaryFile.absolutePath, identityFile.absolutePath)
        } catch (error: Exception) {
            throw IllegalStateException("identity_atomic_commit_unavailable", error)
        } finally {
            temporaryFile.delete()
        }
    }

    private fun hasWrappingKey(): Boolean = try {
        val store = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        store.containsAlias(KEY_ALIAS)
    } catch (error: Exception) {
        throw IllegalStateException("secure_store_unavailable", error)
    }

    private fun existingWrappingKey(): SecretKey? = try {
        val store = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        store.getKey(KEY_ALIAS, null) as? SecretKey
    } catch (error: Exception) {
        throw IllegalStateException("secure_store_unavailable", error)
    }

    private fun createWrappingKey(): SecretKey = try {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        generator.generateKey()
    } catch (error: Exception) {
        throw IllegalStateException("secure_store_unavailable", error)
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private companion object {
        val CREATION_LOCK = Any()
        const val APP_ID = "org.clipbridge.android"
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val KEY_ALIAS = "clipbridge.identity.wrap.v1"
        const val IDENTITY_FILE = "identity.v1.ciphertext"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val TAG_BITS = 128
        const val NONCE_SIZE = 12
        const val PUBLIC_KEY_SIZE = 32
        const val IDENTITY_RECORD_SIZE = 70
        const val PUBLIC_KEY_OFFSET = 38
        const val CIPHERTEXT_SIZE = IDENTITY_RECORD_SIZE + 16
        const val ENVELOPE_SIZE = 4 + 2 + NONCE_SIZE + PUBLIC_KEY_SIZE + CIPHERTEXT_SIZE
        const val ENVELOPE_VERSION: Short = 1
        val ENVELOPE_MAGIC = byteArrayOf('C'.code.toByte(), 'B'.code.toByte(), 'A'.code.toByte(), 'E'.code.toByte())
        val RECORD_MAGIC = byteArrayOf('C'.code.toByte(), 'B'.code.toByte(), 'I'.code.toByte(), 'D'.code.toByte())
    }
}
