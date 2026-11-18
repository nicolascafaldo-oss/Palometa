package com.example.parser

import com.example.model.ManifestAnalysis
import com.example.model.ManifestComponent
import java.util.Locale

object AxmlDecoder {
    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val RES_XML_TYPE = 0x0003
    private const val RES_XML_START_NAMESPACE = 0x0100
    private const val RES_XML_END_NAMESPACE = 0x0101
    private const val RES_XML_START_ELEMENT = 0x0102
    private const val RES_XML_END_ELEMENT = 0x0103
    private const val RES_XML_CDATA = 0x0104
    private const val RES_XML_RESOURCE_MAP = 0x0180
    private const val UTF8_FLAG = 1 shl 8

    fun decode(bytes: ByteArray): ManifestAnalysis {
        if (bytes.size < 8) {
            return ManifestAnalysis(
                decodedXml = "<!-- Empty or invalid AndroidManifest.xml -->",
                packageName = "unknown",
                versionCode = "?",
                versionName = "?",
                minSdk = "?",
                targetSdk = "?",
                debuggable = false,
                allowBackup = null,
                usesCleartextTraffic = null,
                permissions = emptyList(),
                components = emptyList()
            )
        }

        // Handle already-plaintext XML gracefully if ever encountered
        if (bytes[0] == '<'.code.toByte()) {
            val plain = String(bytes, Charsets.UTF_8)
            return ManifestAnalysis(
                decodedXml = plain,
                packageName = "plaintext.xml",
                versionCode = "?",
                versionName = "?",
                minSdk = "?",
                targetSdk = "?",
                debuggable = plain.contains("debuggable=\"true\""),
                allowBackup = null,
                usesCleartextTraffic = null,
                permissions = emptyList(),
                components = emptyList()
            )
        }

        val cursor = BinaryCursor(bytes, littleEndian = true)
        val rootType = cursor.u16At(0)
        if (rootType != RES_XML_TYPE) {
            return ManifestAnalysis(
                decodedXml = "<!-- Unsupported AXML chunk header: 0x${rootType.toString(16)} -->",
                packageName = "unknown",
                versionCode = "?",
                versionName = "?",
                minSdk = "?",
                targetSdk = "?",
                debuggable = false,
                allowBackup = null,
                usesCleartextTraffic = null,
                permissions = emptyList(),
                components = emptyList()
            )
        }

        val rootHeaderSize = cursor.u16At(2)
        val rootChunkSize = cursor.i32At(4).coerceAtMost(bytes.size)
        var pos = rootHeaderSize

        var strings: List<String> = emptyList()
        val namespaces = mutableMapOf<String, String>()
        val pendingNamespaces = mutableListOf<Pair<String, String>>()

        val xml = StringBuilder(4096)
        xml.append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")

        var indent = 0
        var packageName = "unknown"
        var versionCode = "?"
        var versionName = "?"
        var minSdk = "?"
        var targetSdk = "?"
        var debuggable = false
        var allowBackup: Boolean? = null
        var usesCleartextTraffic: Boolean? = null
        val permissions = mutableListOf<String>()
        val components = mutableListOf<ManifestComponent>()

        while (pos + 8 <= rootChunkSize) {
            val chunkType = cursor.u16At(pos)
            val headerSize = cursor.u16At(pos + 2)
            val chunkSize = cursor.i32At(pos + 4)
            if (chunkSize < 8 || pos + chunkSize > bytes.size) break

            when (chunkType) {
                RES_STRING_POOL_TYPE -> {
                    strings = parseStringPool(bytes, pos, chunkSize)
                }
                RES_XML_RESOURCE_MAP -> {
                    // Resource ID mapping table; skipped for textual reconstruction
                }
                RES_XML_START_NAMESPACE -> {
                    val prefixIdx = cursor.i32At(pos + 16)
                    val uriIdx = cursor.i32At(pos + 20)
                    val prefix = strings.getOrNull(prefixIdx) ?: "ns"
                    val uri = strings.getOrNull(uriIdx) ?: ""
                    if (uri.isNotEmpty()) {
                        namespaces[uri] = prefix
                        pendingNamespaces.add(prefix to uri)
                    }
                }
                RES_XML_END_NAMESPACE -> {
                    // No-op
                }
                RES_XML_START_ELEMENT -> {
                    val nsIdx = cursor.i32At(pos + 16)
                    val nameIdx = cursor.i32At(pos + 20)
                    val attrStart = cursor.u16At(pos + 24)
                    val attrSize = cursor.u16At(pos + 26)
                    val attrCount = cursor.u16At(pos + 28)

                    val tagNs = if (nsIdx >= 0) strings.getOrNull(nsIdx) else null
                    val tagName = strings.getOrNull(nameIdx) ?: "element"
                    val fullTag = buildQualifiedName(tagNs, tagName, namespaces)

                    appendIndent(xml, indent)
                    xml.append('<').append(fullTag)

                    if (pendingNamespaces.isNotEmpty()) {
                        for ((p, u) in pendingNamespaces) {
                            xml.append(" xmlns:").append(p).append("=\"").append(escapeXml(u)).append('"')
                        }
                        pendingNamespaces.clear()
                    }

                    val attrsBase = pos + 16 + attrStart
                    val attrMap = mutableMapOf<String, String>()
                    for (i in 0 until attrCount) {
                        val attrOff = attrsBase + i * attrSize
                        if (attrOff + 20 > pos + chunkSize) break
                        val aNsIdx = cursor.i32At(attrOff)
                        val aNameIdx = cursor.i32At(attrOff + 4)
                        val aRawIdx = cursor.i32At(attrOff + 8)
                        val aDataType = (cursor.u16At(attrOff + 14) shr 8) and 0xFF
                        val aData = cursor.i32At(attrOff + 16)

                        val aNs = if (aNsIdx >= 0) strings.getOrNull(aNsIdx) else null
                        val aName = strings.getOrNull(aNameIdx) ?: "attr_$i"
                        val qName = buildQualifiedName(aNs, aName, namespaces)

                        val valueStr = if (aRawIdx >= 0 && aDataType == 0x03) {
                            strings.getOrNull(aRawIdx) ?: ""
                        } else {
                            formatTypedValue(aDataType, aData, strings, aRawIdx)
                        }

                        attrMap[aName] = valueStr
                        xml.append('\n')
                        appendIndent(xml, indent + 1)
                        xml.append(qName).append("=\"").append(escapeXml(valueStr)).append('"')
                    }
                    xml.append(">\n")
                    indent++

                    when (tagName) {
                        "manifest" -> {
                            attrMap["package"]?.let { packageName = it }
                            attrMap["versionCode"]?.let { versionCode = it }
                            attrMap["versionName"]?.let { versionName = it }
                        }
                        "uses-sdk" -> {
                            attrMap["minSdkVersion"]?.let { minSdk = it }
                            attrMap["targetSdkVersion"]?.let { targetSdk = it }
                        }
                        "uses-permission", "uses-permission-sdk-23" -> {
                            attrMap["name"]?.let { permissions.add(it) }
                        }
                        "application" -> {
                            attrMap["debuggable"]?.let { debuggable = it == "true" }
                            attrMap["allowBackup"]?.let { allowBackup = it == "true" }
                            attrMap["usesCleartextTraffic"]?.let { usesCleartextTraffic = it == "true" }
                        }
                        "activity", "activity-alias", "service", "receiver", "provider" -> {
                            val compName = attrMap["name"]
                            if (compName != null) {
                                val exported = attrMap["exported"]?.let { it == "true" }
                                components.add(
                                    ManifestComponent(
                                        type = tagName,
                                        name = compName,
                                        exported = exported
                                    )
                                )
                            }
                        }
                    }
                }
                RES_XML_END_ELEMENT -> {
                    indent = (indent - 1).coerceAtLeast(0)
                    val nsIdx = cursor.i32At(pos + 16)
                    val nameIdx = cursor.i32At(pos + 20)
                    val tagNs = if (nsIdx >= 0) strings.getOrNull(nsIdx) else null
                    val tagName = strings.getOrNull(nameIdx) ?: "element"
                    val fullTag = buildQualifiedName(tagNs, tagName, namespaces)
                    appendIndent(xml, indent)
                    xml.append("</").append(fullTag).append(">\n")
                }
                RES_XML_CDATA -> {
                    val dataIdx = cursor.i32At(pos + 16)
                    val text = strings.getOrNull(dataIdx)
                    if (!text.isNullOrBlank()) {
                        appendIndent(xml, indent)
                        xml.append(escapeXml(text)).append('\n')
                    }
                }
            }

            pos += chunkSize
        }

        return ManifestAnalysis(
            decodedXml = xml.toString(),
            packageName = packageName,
            versionCode = versionCode,
            versionName = versionName,
            minSdk = minSdk,
            targetSdk = targetSdk,
            debuggable = debuggable,
            allowBackup = allowBackup,
            usesCleartextTraffic = usesCleartextTraffic,
            permissions = permissions.distinct(),
            components = components
        )
    }

    private fun parseStringPool(bytes: ByteArray, chunkPos: Int, chunkSize: Int): List<String> {
        val cursor = BinaryCursor(bytes, littleEndian = true)
        val stringCount = cursor.i32At(chunkPos + 8).coerceIn(0, 200_000)
        val flags = cursor.i32At(chunkPos + 16)
        val stringsStart = cursor.i32At(chunkPos + 20)
        val isUtf8 = (flags and UTF8_FLAG) != 0

        val offsetsBase = chunkPos + 28
        val dataBase = chunkPos + stringsStart
        val result = ArrayList<String>(stringCount)

        for (i in 0 until stringCount) {
            val offTablePos = offsetsBase + i * 4
            if (offTablePos + 4 > chunkPos + chunkSize) break
            val strRelOffset = cursor.i32At(offTablePos)
            val absOffset = dataBase + strRelOffset
            if (absOffset < 0 || absOffset >= chunkPos + chunkSize) {
                result.add("")
                continue
            }
            if (isUtf8) {
                var p = absOffset
                // UTF-16 char len (1 or 2 bytes)
                val b0 = bytes[p++].toInt() and 0xFF
                if ((b0 and 0x80) != 0 && p < bytes.size) p++
                // UTF-8 byte len (1 or 2 bytes)
                var byteLen = if (p < bytes.size) bytes[p++].toInt() and 0xFF else 0
                if ((byteLen and 0x80) != 0 && p < bytes.size) {
                    val bLow = bytes[p++].toInt() and 0xFF
                    byteLen = ((byteLen and 0x7F) shl 8) or bLow
                }
                val safeLen = byteLen.coerceIn(0, (bytes.size - p).coerceAtLeast(0))
                result.add(String(bytes, p, safeLen, Charsets.UTF_8))
            } else {
                var p = absOffset
                if (p + 2 > bytes.size) {
                    result.add("")
                    continue
                }
                var charLen = cursor.u16At(p)
                p += 2
                if ((charLen and 0x8000) != 0 && p + 2 <= bytes.size) {
                    charLen = ((charLen and 0x7FFF) shl 16) or cursor.u16At(p)
                    p += 2
                }
                val byteLen = (charLen * 2).coerceIn(0, (bytes.size - p).coerceAtLeast(0))
                result.add(String(bytes, p, byteLen, Charsets.UTF_16LE))
            }
        }
        return result
    }

    private fun buildQualifiedName(ns: String?, name: String, namespaces: Map<String, String>): String {
        if (ns.isNullOrEmpty()) return name
        val prefix = namespaces[ns]
        return if (!prefix.isNullOrEmpty()) "$prefix:$name" else name
    }

    private fun formatTypedValue(
        type: Int,
        data: Int,
        strings: List<String>,
        rawIdx: Int
    ): String {
        return when (type) {
            0x01 -> String.format(Locale.US, "@0x%08X", data) // TYPE_REFERENCE
            0x02 -> String.format(Locale.US, "?0x%08X", data) // TYPE_ATTRIBUTE
            0x03 -> strings.getOrNull(data) ?: strings.getOrNull(rawIdx) ?: ""
            0x04 -> java.lang.Float.intBitsToFloat(data).toString()
            0x10 -> data.toString() // TYPE_INT_DEC
            0x11 -> String.format(Locale.US, "0x%08X", data) // TYPE_INT_HEX
            0x12 -> (data != 0).toString() // TYPE_INT_BOOLEAN
            0x1C, 0x1D, 0x1E, 0x1F -> String.format(Locale.US, "#%08X", data)
            else -> if (rawIdx >= 0) strings.getOrNull(rawIdx) ?: data.toString() else "0x${data.toString(16)}"
        }
    }

    private fun appendIndent(sb: StringBuilder, indent: Int) {
        repeat(indent) { sb.append("  ") }
    }

    private fun escapeXml(input: String): String =
        input
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
}
