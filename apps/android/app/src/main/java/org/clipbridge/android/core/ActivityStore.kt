package org.clipbridge.android.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

enum class ActivityKind(val label: String) {
    TEXT_SENT("Text sent"),
    TEXT_RECEIVED("Text received"),
    PAIRING_COMPLETED("Pairing completed"),
    PAIRING_FAILED("Pairing failed"),
    DEVICE_REVOKED("Device revoked"),
    CONNECTION_FAILED("Connection failed"),
}

enum class ActivityResult(val value: String) { SUCCESS("success"), FAILED("failed") }

data class ActivityEvent(
    val kind: ActivityKind,
    val deviceLabel: String,
    val timestampMillis: Long,
    val route: String,
    val result: ActivityResult,
)

/** Bounded metadata-only local activity. Its typed API cannot accept message or clipboard content. */
class ActivityStore(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    @Synchronized
    fun record(kind: ActivityKind, deviceLabel: String, route: String, result: ActivityResult) {
        val safeLabel = deviceLabel.filterNot(Char::isISOControl).take(MAX_LABEL_CHARS)
        val safeRoute = route.takeIf { it in ALLOWED_ROUTES } ?: "unknown"
        val events = read().toMutableList()
        events.add(0, ActivityEvent(kind, safeLabel, System.currentTimeMillis(), safeRoute, result))
        val encoded = JSONArray().apply {
            events.take(MAX_EVENTS).forEach { event ->
                put(JSONObject().put("kind", event.kind.name).put("device", event.deviceLabel)
                    .put("time", event.timestampMillis).put("route", event.route).put("result", event.result.value))
            }
        }
        check(preferences.edit().putString(KEY_EVENTS, encoded.toString()).commit()) { "activity_store_unavailable" }
    }

    @Synchronized
    fun list(): List<ActivityEvent> {
        val result = read()
        return result
    }

    private fun read(): List<ActivityEvent> = try {
        val encoded = preferences.getString(KEY_EVENTS, null) ?: return emptyList()
        val array = JSONArray(encoded)
        buildList {
            for (index in 0 until minOf(array.length(), MAX_EVENTS)) {
                val item = array.optJSONObject(index) ?: continue
                val kind = runCatching { ActivityKind.valueOf(item.optString("kind")) }.getOrNull() ?: continue
                val outcome = runCatching { ActivityResult.valueOf(item.optString("result").uppercase()) }.getOrNull() ?: continue
                val route = item.optString("route").takeIf { it in ALLOWED_ROUTES } ?: "unknown"
                val label = item.optString("device").filterNot(Char::isISOControl).take(MAX_LABEL_CHARS)
                val timestamp = item.optLong("time", -1L).takeIf { it > 0 } ?: continue
                add(ActivityEvent(kind, label, timestamp, route, outcome))
            }
        }
    } catch (_: Exception) {
        emptyList()
    }

    private companion object {
        const val PREFERENCES = "activity_metadata"
        const val KEY_EVENTS = "events_v1"
        const val MAX_EVENTS = 100
        const val MAX_LABEL_CHARS = 64
        val ALLOWED_ROUTES = setOf("LAN Direct", "unknown")
    }
}
