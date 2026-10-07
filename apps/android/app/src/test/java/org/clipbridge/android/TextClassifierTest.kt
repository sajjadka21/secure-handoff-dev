package org.clipbridge.android

import org.junit.Assert.assertEquals
import org.junit.Test

class TextClassifierTest {
    @Test fun detectsUrlWithoutChangingContent() {
        assertEquals(TextKind.URL, TextClassifier.classify("https://example.test/path?q=1"))
    }

    @Test fun conservativelyDetectsCode() {
        assertEquals(TextKind.CODE, TextClassifier.classify("fun main() { println(1); }"))
        assertEquals(TextKind.TEXT, TextClassifier.classify("A short sentence; still text"))
    }

    @Test fun emptyInputIsText() {
        assertEquals(TextKind.TEXT, TextClassifier.classify(" \n "))
    }
}
