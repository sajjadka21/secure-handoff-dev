package org.clipbridge.android

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.clipbridge.android.core.ActivityKind
import org.clipbridge.android.core.ActivityResult
import org.clipbridge.android.core.ActivityStore
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidClientSmokeInstrumentedTest {
    @get:Rule
    val composeRule = createAndroidComposeRule<MainActivity>()

    @Test
    fun appLaunchesAndNavigatesToTrustedDevices() {
        composeRule.onNodeWithText("ClipBridge").assertIsDisplayed()
        composeRule.onNodeWithText("Clipboard").assertIsDisplayed()
        composeRule.onAllNodesWithText("Devices")[0].performClick()
        composeRule.onNodeWithText("Trusted devices").assertIsDisplayed()
    }

    @Test
    fun activityPersistenceContainsOnlyMetadataFields() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val store = ActivityStore(context)
        store.record(ActivityKind.TEXT_SENT, "Windows test device", "LAN Direct", ActivityResult.SUCCESS)

        val encoded = context.getSharedPreferences("activity_metadata", 0)
            .getString("events_v1", "[]")
            .orEmpty()
        val first = JSONArray(encoded).getJSONObject(0)
        val keys = first.keys().asSequence().toSet()
        assertEquals(setOf("kind", "device", "time", "route", "result"), keys)
        assertFalse(keys.any { it.contains("content", ignoreCase = true) || it.contains("payload", ignoreCase = true) })
    }
}

