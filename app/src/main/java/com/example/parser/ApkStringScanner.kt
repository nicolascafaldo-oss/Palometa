package com.example.parser

import com.example.model.ApkPrintableString
import com.example.model.DexSummary
import com.example.model.ManifestAnalysis
import com.example.model.StringFindingCategory

object ApkStringScanner {

    private val urlRegex = Regex("""(?:https?|wss?|ftp)://[^\s"'<>\\]{4,}""", RegexOption.IGNORE_CASE)
    private val ipv4Regex = Regex("""\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b""")
    private val emailRegex = Regex("""[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,12}""")
    private val keyTokenRegex = Regex(
        """(AIza[0-9A-Za-z\-_]{20,}|AKIA[0-9A-Z]{16}|sk_live_[0-9A-Za-z]{16,}|pk_live_[0-9A-Za-z]{16,}|ghp_[0-9A-Za-z]{20,}|-----BEGIN [A-Z ]+ KEY-----|Bearer\s+[A-Za-z0-9\-._~+/]+=*)"""
    )
    private val secretHintRegex = Regex(
        """(?i)(api[_-]?key|client[_-]?secret|auth[_-]?token|private[_-]?key|password|passwd|SecretKeySpec|aws_secret|firebase_url)\s*[:=]?"""
    )
    private val pathRegex = Regex("""^(/data/data/|/sdcard/|/storage/emulated/|/system/bin/|/proc/self/|/vendor/lib)""")

    fun scanAll(
        dexFiles: List<DexSummary>,
        manifest: ManifestAnalysis?,
        nativeBuffers: List<Pair<String, ByteArray>>,
        assetTextBuffers: List<Pair<String, ByteArray>>,
        maxTotalStrings: Int = 8000
    ): List<ApkPrintableString> {
        val seen = HashSet<String>(4096)
        val findings = ArrayList<ApkPrintableString>(2048)
        var nextId = 1

        fun record(raw: String, source: String) {
            if (findings.size >= maxTotalStrings) return
            val s = raw.trim()
            if (s.length < 4 || s.length > 400) return
            if (!seen.add(s)) return
            val category = classify(s)
            findings.add(
                ApkPrintableString(
                    id = nextId++,
                    value = s,
                    sourceFile = source,
                    category = category
                )
            )
        }

        // 1. Scan Manifest URLs / metadata
        manifest?.decodedXml?.lineSequence()?.forEach { line ->
            urlRegex.findAll(line).forEach { m -> record(m.value, "AndroidManifest.xml") }
            emailRegex.findAll(line).forEach { m -> record(m.value, "AndroidManifest.xml") }
        }

        // 2. Scan Native .so binaries for printable ASCII strings
        nativeBuffers.forEach { (path, bytes) ->
            extractAsciiStrings(bytes, minLen = 5, maxPerBinary = 1200).forEach { str ->
                record(str, path)
            }
        }

        // 3. Scan text/config/json assets
        assetTextBuffers.forEach { (path, bytes) ->
            val text = runCatching { String(bytes, Charsets.UTF_8) }.getOrNull() ?: return@forEach
            text.lineSequence().take(400).forEach { line ->
                val trimmed = line.trim()
                if (trimmed.length in 5..300 && trimmed.all { !it.isISOControl() || it == '\t' }) {
                    record(trimmed, path)
                }
            }
        }

        // 4. Scan DEX string pools (prioritize leaks/notable first, then general printable strings)
        dexFiles.forEach { dex ->
            dex.notableStrings.forEach { record(it.value, dex.entryName) }
            dex.sampleStrings.forEach { record(it, dex.entryName) }
        }

        // Sort with potential leaks first so analysts immediately spot high-signal data
        return findings.sortedWith(
            compareByDescending<ApkPrintableString> { it.category.isPotentialLeak }
                .thenBy { it.category.ordinal }
                .thenBy { it.id }
        )
    }

    private fun extractAsciiStrings(
        bytes: ByteArray,
        minLen: Int = 5,
        maxPerBinary: Int = 1200
    ): List<String> {
        val out = ArrayList<String>(minOf(maxPerBinary, 512))
        val sb = StringBuilder(64)
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            if (c in 0x20..0x7E) {
                sb.append(c.toChar())
            } else {
                if (sb.length >= minLen) {
                    out.add(sb.toString())
                    if (out.size >= maxPerBinary) break
                }
                sb.setLength(0)
            }
        }
        if (sb.length >= minLen && out.size < maxPerBinary) {
            out.add(sb.toString())
        }
        return out
    }

    private fun classify(s: String): StringFindingCategory {
        return when {
            keyTokenRegex.containsMatchIn(s) -> StringFindingCategory.API_KEY_TOKEN
            urlRegex.containsMatchIn(s) -> StringFindingCategory.URL_ENDPOINT
            emailRegex.containsMatchIn(s) -> StringFindingCategory.EMAIL
            isLikelyIpv4(s) -> StringFindingCategory.IP_ADDRESS
            secretHintRegex.containsMatchIn(s) -> StringFindingCategory.SECRET_HINT
            pathRegex.containsMatchIn(s) -> StringFindingCategory.FILE_PATH
            s.startsWith("Java_") || s == "JNI_OnLoad" || s.contains("javax/crypto") || s.contains("Cipher") ->
                StringFindingCategory.CRYPTO_JNI
            else -> StringFindingCategory.PRINTABLE
        }
    }

    private fun isLikelyIpv4(s: String): Boolean {
        val match = ipv4Regex.find(s) ?: return false
        val ip = match.value
        if (ip == "0.0.0.0" || ip == "127.0.0.1" && s.length > 30) return false
        // Avoid matching version-like strings like 1.2.3.4 in resource labels unless standalone or in URL/host
        return !ip.startsWith("0.") && s.length <= 64
    }
}
