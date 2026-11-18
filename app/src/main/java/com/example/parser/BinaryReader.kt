package com.example.parser

import com.example.model.HexDumpLine
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.Locale

class BinaryCursor(
    private val data: ByteArray,
    var position: Int = 0,
    var littleEndian: Boolean = true
) {
    val size: Int get() = data.size
    val remaining: Int get() = (data.size - position).coerceAtLeast(0)

    fun hasBytes(count: Int): Boolean = position >= 0 && position + count <= data.size

    fun u8(): Int {
        if (!hasBytes(1)) return 0
        return data[position++].toInt() and 0xFF
    }

    fun u16(): Int {
        if (!hasBytes(2)) return 0
        val b0 = data[position++].toInt() and 0xFF
        val b1 = data[position++].toInt() and 0xFF
        return if (littleEndian) (b1 shl 8) or b0 else (b0 shl 8) or b1
    }

    fun u16At(offset: Int): Int {
        if (offset < 0 || offset + 2 > data.size) return 0
        val b0 = data[offset].toInt() and 0xFF
        val b1 = data[offset + 1].toInt() and 0xFF
        return if (littleEndian) (b1 shl 8) or b0 else (b0 shl 8) or b1
    }

    fun u32(): Long {
        if (!hasBytes(4)) return 0L
        val b0 = (data[position++].toLong() and 0xFFL)
        val b1 = (data[position++].toLong() and 0xFFL)
        val b2 = (data[position++].toLong() and 0xFFL)
        val b3 = (data[position++].toLong() and 0xFFL)
        return if (littleEndian) {
            (b3 shl 24) or (b2 shl 16) or (b1 shl 8) or b0
        } else {
            (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
        }
    }

    fun i32(): Int = u32().toInt()

    fun u32At(offset: Int): Long {
        if (offset < 0 || offset + 4 > data.size) return 0L
        val b0 = (data[offset].toLong() and 0xFFL)
        val b1 = (data[offset + 1].toLong() and 0xFFL)
        val b2 = (data[offset + 2].toLong() and 0xFFL)
        val b3 = (data[offset + 3].toLong() and 0xFFL)
        return if (littleEndian) {
            (b3 shl 24) or (b2 shl 16) or (b1 shl 8) or b0
        } else {
            (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
        }
    }

    fun i32At(offset: Int): Int = u32At(offset).toInt()

    fun u64At(offset: Int): Long {
        if (offset < 0 || offset + 8 > data.size) return 0L
        val lo = u32At(offset)
        val hi = u32At(offset + 4)
        return if (littleEndian) (hi shl 32) or lo else (lo shl 32) or hi
    }

    fun readUleb128(): Int {
        var result = 0
        var shift = 0
        while (position < data.size && shift < 35) {
            val b = data[position++].toInt() and 0xFF
            result = result or ((b and 0x7F) shl shift)
            if ((b and 0x80) == 0) break
            shift += 7
        }
        return result
    }

    fun readUleb128p1(): Int = readUleb128() - 1

    fun readSleb128(): Int {
        var result = 0
        var shift = 0
        var b = 0
        while (position < data.size && shift < 35) {
            b = data[position++].toInt() and 0xFF
            result = result or ((b and 0x7F) shl shift)
            shift += 7
            if ((b and 0x80) == 0) break
        }
        if ((shift < 32) && ((b and 0x40) != 0)) {
            result = result or (-1 shl shift)
        }
        return result
    }

    fun readMutf8String(): String {
        // Skip ULEB128 char length prefix
        readUleb128()
        val start = position
        while (position < data.size && data[position].toInt() != 0) {
            position++
        }
        val len = position - start
        if (position < data.size) position++ // consume null terminator
        return decodeMutf8(data, start, len)
    }

    fun readCStringAt(offset: Int, maxLen: Int = 512): String {
        if (offset < 0 || offset >= data.size) return ""
        var end = offset
        val limit = minOf(data.size, offset + maxLen)
        while (end < limit && data[end].toInt() != 0) {
            end++
        }
        return String(data, offset, end - offset, Charsets.UTF_8)
    }

    companion object {
        fun decodeMutf8(bytes: ByteArray, offset: Int, byteLen: Int): String {
            if (byteLen <= 0) return ""
            val sb = StringBuilder(byteLen)
            var i = offset
            val end = minOf(bytes.size, offset + byteLen)
            while (i < end) {
                val a = bytes[i++].toInt() and 0xFF
                when {
                    a < 0x80 -> sb.append(a.toChar())
                    (a and 0xE0) == 0xC0 && i < end -> {
                        val b = bytes[i++].toInt() and 0xFF
                        sb.append((((a and 0x1F) shl 6) or (b and 0x3F)).toChar())
                    }
                    (a and 0xF0) == 0xE0 && i + 1 < end -> {
                        val b = bytes[i++].toInt() and 0xFF
                        val c = bytes[i++].toInt() and 0xFF
                        sb.append((((a and 0x0F) shl 12) or ((b and 0x3F) shl 6) or (c and 0x3F)).toChar())
                    }
                    else -> sb.append('?')
                }
            }
            return sb.toString()
        }
    }
}

object BinaryFormatters {
    fun formatBytes(bytes: Long): String {
        if (bytes < 1024L) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024.0) return String.format(Locale.US, "%.1f KB", kb)
        val mb = kb / 1024.0
        if (mb < 1024.0) return String.format(Locale.US, "%.2f MB", mb)
        val gb = mb / 1024.0
        return String.format(Locale.US, "%.2f GB", gb)
    }

    fun toHexString(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    fun digestFile(file: File, algorithm: String): String {
        val md = MessageDigest.getInstance(algorithm)
        val buffer = ByteArray(16 * 1024)
        file.inputStream().use { input ->
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                md.update(buffer, 0, read)
            }
        }
        return toHexString(md.digest())
    }

    fun digestBytes(bytes: ByteArray, algorithm: String): String =
        toHexString(MessageDigest.getInstance(algorithm).digest(bytes))

    fun readStreamBounded(input: InputStream, maxBytes: Int = 32 * 1024 * 1024): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(16 * 1024)
        var total = 0
        while (total < maxBytes) {
            val toRead = minOf(buf.size, maxBytes - total)
            val n = input.read(buf, 0, toRead)
            if (n <= 0) break
            out.write(buf, 0, n)
            total += n
        }
        return out.toByteArray()
    }

    fun buildHexDump(bytes: ByteArray, maxBytes: Int = 16 * 512): List<HexDumpLine> {
        val limit = minOf(bytes.size, maxBytes)
        val lines = ArrayList<HexDumpLine>((limit + 15) / 16)
        var offset = 0
        while (offset < limit) {
            val lineLen = minOf(16, limit - offset)
            val hexBuilder = StringBuilder(48)
            val asciiBuilder = StringBuilder(16)
            for (i in 0 until 16) {
                if (i == 8) hexBuilder.append(' ')
                if (i < lineLen) {
                    val b = bytes[offset + i].toInt() and 0xFF
                    hexBuilder.append(String.format(Locale.US, "%02X ", b))
                    asciiBuilder.append(if (b in 0x20..0x7E) b.toChar() else '.')
                } else {
                    hexBuilder.append("   ")
                    asciiBuilder.append(' ')
                }
            }
            lines.add(
                HexDumpLine(
                    offsetHex = String.format(Locale.US, "%08X", offset),
                    hexBytes = hexBuilder.toString().trimEnd(),
                    asciiText = asciiBuilder.toString()
                )
            )
            offset += 16
        }
        return lines
    }
}
