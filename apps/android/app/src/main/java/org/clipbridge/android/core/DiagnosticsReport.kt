package org.clipbridge.android.core

/** Allowlisted diagnostics serializer. It intentionally accepts no content, paths, keys, or IPs. */
data class SafeDiagnostics(
    val appVersion: String,
    val androidApi: Int,
    val identityState: String,
    val trustStoreState: String,
    val listenerState: String,
    val privacyPaused: Boolean,
    val lastErrorCode: String,
)

private val ALLOWED_ERROR_CODES = setOf(
    "none",
    "secure_store_unavailable",
    "trust_store_unavailable",
    "identity_unavailable",
    "invalid_endpoint",
    "endpoint_not_lan",
    "invalid_device",
    "invalid_text",
    "payload_too_large",
    "privacy_paused",
    "connection_failed",
    "peer_untrusted",
    "peer_revoked",
    "protocol_incompatible",
    "auth_failed",
    "send_failed",
    "pairing_state_error",
    "pairing_not_ready",
    "pairing_incomplete",
    "pairing_needs_repair",
)

fun serializeDiagnostics(value: SafeDiagnostics): String {
    val version = value.appVersion.takeIf { it.matches(Regex("[A-Za-z0-9._+-]{1,32}")) } ?: "unknown"
    val identity = value.identityState.takeIf { it in setOf("ready", "unavailable", "loading") } ?: "unavailable"
    val trust = value.trustStoreState.takeIf { it in setOf("ready", "unavailable") } ?: "unavailable"
    val listener = value.listenerState.takeIf { it in setOf("active", "inactive") } ?: "inactive"
    val error = value.lastErrorCode.takeIf { it in ALLOWED_ERROR_CODES } ?: "none"
    return listOf(
        "app_version=$version",
        "os=Android",
        "android_api=${value.androidApi.coerceIn(1, 999)}",
        "protocol_version=1",
        "identity=$identity",
        "trust_store=$trust",
        "route=LAN_manual_endpoint",
        "listener=$listener",
        "session=per_transfer_authenticated_encryption",
        "privacy_paused=${value.privacyPaused}",
        "last_error=$error",
    ).joinToString("\n")
}

