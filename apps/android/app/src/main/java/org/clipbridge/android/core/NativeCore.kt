package org.clipbridge.android.core

/** JNI surface returns only public identity metadata. Private identity bytes stay in Rust except
 * during the short AES-GCM wrap/unwrap call described in SECURITY.md. */
class NativeCore private constructor() {
    companion object {
        private val loadFailure: Throwable? = runCatching { System.loadLibrary("clipbridge_android") }.exceptionOrNull()

        fun requireAvailable() {
            loadFailure?.let { throw IllegalStateException("rust_core_unavailable", it) }
        }

        @JvmStatic external fun nativeGenerateIdentityRecord(): ByteArray
        @JvmStatic external fun nativeIdentityMetadata(record: ByteArray): ByteArray
        @JvmStatic external fun nativeInstallIdentityRecord(record: ByteArray): ByteArray
    }
}
