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
        @JvmStatic external fun nativeOpenTrustDb(path: String): Boolean
        @JvmStatic external fun nativeListTrustedDevices(): ByteArray
        @JvmStatic external fun nativeSetPrivacyPaused(paused: Boolean)
        @JvmStatic external fun nativeJoinPairing(payload: ByteArray, label: String): String?
        @JvmStatic external fun nativeConfirmPairing(accepted: Boolean): String?
        @JvmStatic external fun nativeRevokeDevice(deviceId: ByteArray, publicKey: ByteArray): Boolean
        @JvmStatic external fun nativeSendText(endpoint: String, deviceId: ByteArray, text: String): String?
        @JvmStatic external fun nativeStartReceiver(bindAddress: String): String?
        @JvmStatic external fun nativeStopReceiver()
        @JvmStatic external fun nativeReceiveText(): ByteArray?
    }
}
