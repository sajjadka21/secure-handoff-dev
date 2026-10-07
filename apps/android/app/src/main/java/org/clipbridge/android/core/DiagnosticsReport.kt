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

fun serializeDiagnostics(value: SafeDiagnostics): String {
    val version = value.appVersion.takeIf { it.matches(Regex("[A-Za-z0-9._+-]{1,32}")) } ?: "unknown"
    val identity = value.identityState.takeIf { it in setOf("ready", "unavailable", "loading") } ?: "unavailable"
    val trust = value.trustStoreState.takeIf { it in setOf("ready", "unavailable") } ?: "unavailable"
    val listener = value.listenerState.takeIf { it in setOf("active", "inactive") } ?: "inactive"
    val error = value.lastErrorCode.takeIf { it.matches(Regex("[a-z0-9_]{1,48}")) } ?: "none"
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
