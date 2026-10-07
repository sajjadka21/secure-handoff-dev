package org.clipbridge.android

import org.clipbridge.android.core.SafeDiagnostics
import org.clipbridge.android.core.serializeDiagnostics
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SafeMetadataTest {
    @Test fun diagnosticsContainsOnlyAllowlistedRuntimeFacts() {
        val report = serializeDiagnostics(SafeDiagnostics("0.1.0", 36, "ready", "ready", "active", false, "none"))
        assertTrue(report.contains("trust_store=ready"))
        assertTrue(report.contains("listener=active"))
        assertFalse(report.contains("192.168."))
        assertFalse(report.contains("private"))
    }

    @Test fun diagnosticsRejectsUntrustedFields() {
        val report = serializeDiagnostics(SafeDiagnostics("/private/path", 36, "private-key", "raw-db", "192.168.0.1", false, "clipboard_contents"))
        assertFalse(report.contains("/private/path"))
        assertFalse(report.contains("private-key"))
        assertFalse(report.contains("192.168.0.1"))
        assertFalse(report.contains("clipboard_contents"))
        assertTrue(report.contains("last_error=none"))
    }
}

