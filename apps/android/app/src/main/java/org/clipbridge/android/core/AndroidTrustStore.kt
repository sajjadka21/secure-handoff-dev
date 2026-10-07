package org.clipbridge.android.core

import android.content.Context
import java.nio.ByteBuffer
import java.nio.ByteOrder

data class TrustedDeviceMetadata(
    val deviceId: ByteArray,
    val publicKey: ByteArray,
    val label: String,
    val minimumProtocol: Int,
    val trustedAt: Long,
    val needsRepair: Boolean,
)

/** Trust decisions and SQLite access remain in clipcore; Kotlin receives public metadata only. */
class AndroidTrustStore(context: Context) {
    private val database = context.applicationContext.noBackupFilesDir.resolve("trust.sqlite")

    fun open(): Boolean = NativeCore.nativeOpenTrustDb(database.absolutePath)

    fun list(): List<TrustedDeviceMetadata> {
        val encoded = NativeCore.nativeListTrustedDevices()
        try {
            require(encoded.size >= 4) { "trust_records_malformed" }
            val input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
            val count = input.int
            require(count in 0..256) { "trust_records_malformed" }
            val records = ArrayList<TrustedDeviceMetadata>(count)
            repeat(count) {
                require(input.remaining() >= 77) { "trust_records_malformed" }
                val id = ByteArray(32).also { input.get(it) }
                val key = ByteArray(32).also { input.get(it) }
                val labelSize = input.short.toInt() and 0xffff
                require(labelSize <= 64 && input.remaining() >= labelSize + 11) { "trust_records_malformed" }
                val label = ByteArray(labelSize).also { input.get(it) }.toString(Charsets.UTF_8)
                require(!label.any { it.isISOControl() }) { "trust_records_malformed" }
                val protocol = input.short.toInt() and 0xffff
                val trustedAt = input.long
                val status = input.get().toInt()
                require(status == 1 || status == 2) { "trust_records_malformed" }
                records += TrustedDeviceMetadata(id, key, label, protocol, trustedAt, status == 2)
            }
            require(!input.hasRemaining()) { "trust_records_malformed" }
            return records
        } finally {
            encoded.fill(0)
        }
    }

    fun revoke(device: TrustedDeviceMetadata): Boolean =
        NativeCore.nativeRevokeDevice(device.deviceId, device.publicKey)
}
