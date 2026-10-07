package org.clipbridge.android

enum class TextKind { TEXT, URL, CODE }

object TextClassifier {
    private val urlPattern = Regex("^https?://[^\\s]+$", RegexOption.IGNORE_CASE)
    private val codeSignals = listOf("{", "}", ";", "=>", "fun ", "def ", "#include", "import ")

    fun classify(value: String): TextKind {
        val trimmed = value.trim()
        if (trimmed.isEmpty()) return TextKind.TEXT
        if (urlPattern.matches(trimmed)) return TextKind.URL
        return if (codeSignals.count { signal -> trimmed.contains(signal) } >= 2 || trimmed.contains("```") ) TextKind.CODE else TextKind.TEXT
    }
}
