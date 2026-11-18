package com.example.parser

import com.example.model.ElfAnalysis
import com.example.model.ElfSectionInfo
import com.example.model.ElfSymbolInfo
import java.util.Locale

object ElfParser {

    fun parse(entryPath: String, bytes: ByteArray): ElfAnalysis? {
        if (bytes.size < 52) return null
        if (bytes[0] != 0x7F.toByte() ||
            bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() ||
            bytes[3] != 'F'.code.toByte()
        ) {
            return null
        }

        val eiClass = bytes[4].toInt() and 0xFF
        val eiData = bytes[5].toInt() and 0xFF
        val is64 = eiClass == 2
        val littleEndian = eiData != 2
        val cursor = BinaryCursor(bytes, littleEndian = littleEndian)

        val elfClassLabel = if (is64) "ELF64" else "ELF32"
        val endianLabel = if (littleEndian) "LSB (Little Endian)" else "MSB (Big Endian)"

        val eType = cursor.u16At(16)
        val eMachine = cursor.u16At(18)

        val entryPoint: Long
        val shOff: Long
        val phNum: Int
        val shEntSize: Int
        val shNum: Int
        val shStrNdx: Int

        if (is64) {
            if (bytes.size < 64) return null
            entryPoint = cursor.u64At(24)
            shOff = cursor.u64At(40)
            phNum = cursor.u16At(56)
            shEntSize = cursor.u16At(58)
            shNum = cursor.u16At(60)
            shStrNdx = cursor.u16At(62)
        } else {
            entryPoint = cursor.u32At(24)
            shOff = cursor.u32At(32)
            phNum = cursor.u16At(44)
            shEntSize = cursor.u16At(46)
            shNum = cursor.u16At(48)
            shStrNdx = cursor.u16At(50)
        }

        val sections = parseSections(
            bytes = bytes,
            cursor = cursor,
            is64 = is64,
            shOff = shOff,
            shEntSize = shEntSize,
            shNum = shNum,
            shStrNdx = shStrNdx
        )

        val symbols = parseDynamicSymbols(
            bytes = bytes,
            cursor = cursor,
            is64 = is64,
            shOff = shOff,
            shEntSize = shEntSize,
            shNum = shNum,
            sections = sections
        )

        val jniExports = symbols.filter { it.isJni }.map { it.name }
        val hasJniOnLoad = symbols.any { it.name == "JNI_OnLoad" }
        val abi = extractAbiFromPath(entryPath)
        val fileName = entryPath.substringAfterLast('/')
        val (machineName, ghidraLang, ghidraCompiler) = mapMachineToGhidra(eMachine, is64, littleEndian)

        return ElfAnalysis(
            entryPath = entryPath,
            fileName = fileName,
            abi = abi,
            fileSize = bytes.size.toLong(),
            elfClass = elfClassLabel,
            endianness = endianLabel,
            machineName = machineName,
            ghidraLanguageId = ghidraLang,
            ghidraCompilerSpec = ghidraCompiler,
            elfType = mapElfType(eType),
            entryPointHex = String.format(Locale.US, "0x%X", entryPoint),
            programHeadersCount = phNum,
            sections = sections,
            dynamicSymbols = symbols,
            jniExports = jniExports,
            hasJniOnLoad = hasJniOnLoad
        )
    }

    private data class RawSection(
        val nameIdx: Int,
        val type: Int,
        val flags: Long,
        val addr: Long,
        val offset: Long,
        val size: Long,
        val link: Int,
        val entSize: Long
    )

    private fun parseSections(
        bytes: ByteArray,
        cursor: BinaryCursor,
        is64: Boolean,
        shOff: Long,
        shEntSize: Int,
        shNum: Int,
        shStrNdx: Int
    ): List<ElfSectionInfo> {
        if (shOff <= 0 || shNum <= 0 || shEntSize <= 0 || shNum > 512) return emptyList()
        val rawSections = ArrayList<RawSection>(shNum)
        for (i in 0 until shNum) {
            val base = (shOff + i.toLong() * shEntSize).toInt()
            if (base < 0 || base + shEntSize > bytes.size) break
            val sec = if (is64) {
                RawSection(
                    nameIdx = cursor.i32At(base),
                    type = cursor.i32At(base + 4),
                    flags = cursor.u64At(base + 8),
                    addr = cursor.u64At(base + 16),
                    offset = cursor.u64At(base + 24),
                    size = cursor.u64At(base + 32),
                    link = cursor.i32At(base + 40),
                    entSize = cursor.u64At(base + 56)
                )
            } else {
                RawSection(
                    nameIdx = cursor.i32At(base),
                    type = cursor.i32At(base + 4),
                    flags = cursor.u32At(base + 8),
                    addr = cursor.u32At(base + 12),
                    offset = cursor.u32At(base + 16),
                    size = cursor.u32At(base + 20),
                    link = cursor.i32At(base + 24),
                    entSize = cursor.u32At(base + 36)
                )
            }
            rawSections.add(sec)
        }

        val shStrTabOffset = rawSections.getOrNull(shStrNdx)?.offset?.toInt() ?: -1
        return rawSections.mapIndexed { idx, raw ->
            val name = if (shStrTabOffset >= 0 && raw.nameIdx >= 0) {
                cursor.readCStringAt(shStrTabOffset + raw.nameIdx)
            } else {
                ""
            }.ifEmpty { if (idx == 0) "<NULL>" else ".sec_$idx" }

            ElfSectionInfo(
                index = idx,
                name = name,
                typeName = mapSectionType(raw.type),
                flags = buildSectionFlags(raw.flags),
                addrHex = String.format(Locale.US, "0x%08X", raw.addr),
                offsetHex = String.format(Locale.US, "0x%08X", raw.offset),
                sizeBytes = raw.size
            )
        }
    }

    private fun parseDynamicSymbols(
        bytes: ByteArray,
        cursor: BinaryCursor,
        is64: Boolean,
        shOff: Long,
        shEntSize: Int,
        shNum: Int,
        sections: List<ElfSectionInfo>
    ): List<ElfSymbolInfo> {
        val dynSymSecIdx = sections.indexOfFirst { it.name == ".dynsym" || it.typeName == "DYNSYM" }
        if (dynSymSecIdx < 0) return emptyList()

        val base = (shOff + dynSymSecIdx.toLong() * shEntSize).toInt()
        if (base < 0 || base + shEntSize > bytes.size) return emptyList()

        val symOffset: Long
        val symSize: Long
        val linkIdx: Int
        val symEntSize: Long

        if (is64) {
            symOffset = cursor.u64At(base + 24)
            symSize = cursor.u64At(base + 32)
            linkIdx = cursor.i32At(base + 40)
            symEntSize = cursor.u64At(base + 56).let { if (it > 0) it else 24L }
        } else {
            symOffset = cursor.u32At(base + 16)
            symSize = cursor.u32At(base + 20)
            linkIdx = cursor.i32At(base + 24)
            symEntSize = cursor.u32At(base + 36).let { if (it > 0) it else 16L }
        }

        if (linkIdx < 0 || linkIdx >= shNum) return emptyList()
        val strSecBase = (shOff + linkIdx.toLong() * shEntSize).toInt()
        if (strSecBase < 0 || strSecBase + shEntSize > bytes.size) return emptyList()
        val dynStrOffset = if (is64) cursor.u64At(strSecBase + 24).toInt() else cursor.u32At(strSecBase + 16).toInt()

        val count = (symSize / symEntSize).toInt().coerceIn(0, 4000)
        val result = ArrayList<ElfSymbolInfo>()

        for (i in 0 until count) {
            val pos = (symOffset + i * symEntSize).toInt()
            if (pos < 0 || pos + symEntSize > bytes.size) break
            val stName: Int
            val stInfo: Int
            val stShndx: Int
            val stValue: Long
            if (is64) {
                stName = cursor.i32At(pos)
                stInfo = bytes[pos + 4].toInt() and 0xFF
                stShndx = cursor.u16At(pos + 6)
                stValue = cursor.u64At(pos + 8)
            } else {
                stName = cursor.i32At(pos)
                stValue = cursor.u32At(pos + 4)
                stInfo = bytes[pos + 12].toInt() and 0xFF
                stShndx = cursor.u16At(pos + 14)
            }

            if (stName <= 0) continue
            val name = cursor.readCStringAt(dynStrOffset + stName)
            if (name.isEmpty()) continue

            val bind = (stInfo shr 4) and 0xF
            val type = stInfo and 0xF
            val isExported = stShndx != 0 && (bind == 1 || bind == 2)
            val isJni = name.startsWith("Java_") || name == "JNI_OnLoad" || name == "JNI_OnUnload"

            result.add(
                ElfSymbolInfo(
                    name = name,
                    binding = when (bind) {
                        0 -> "LOCAL"
                        1 -> "GLOBAL"
                        2 -> "WEAK"
                        else -> "OTHER($bind)"
                    },
                    type = when (type) {
                        0 -> "NOTYPE"
                        1 -> "OBJECT"
                        2 -> "FUNC"
                        3 -> "SECTION"
                        else -> "TYPE($type)"
                    },
                    isExported = isExported,
                    isJni = isJni,
                    valueHex = String.format(Locale.US, "0x%X", stValue)
                )
            )
        }

        // Put JNI and exported functions near the top
        return result.sortedWith(
            compareByDescending<ElfSymbolInfo> { it.isJni }
                .thenByDescending { it.isExported }
                .thenBy { it.name }
        )
    }

    private fun extractAbiFromPath(path: String): String {
        val parts = path.split('/')
        return if (parts.size >= 3 && parts[0] == "lib") parts[1] else "unknown"
    }

    private fun mapElfType(eType: Int): String = when (eType) {
        1 -> "ET_REL (Relocatable)"
        2 -> "ET_EXEC (Executable)"
        3 -> "ET_DYN (Shared Object)"
        4 -> "ET_CORE (Core)"
        else -> "ET_$eType"
    }

    private fun mapSectionType(type: Int): String = when (type) {
        0 -> "NULL"
        1 -> "PROGBITS"
        2 -> "SYMTAB"
        3 -> "STRTAB"
        4 -> "RELA"
        5 -> "HASH"
        6 -> "DYNAMIC"
        7 -> "NOTE"
        8 -> "NOBITS"
        9 -> "REL"
        11 -> "DYNSYM"
        14 -> "INIT_ARRAY"
        15 -> "FINI_ARRAY"
        0x6ffffff6 -> "GNU_HASH"
        0x6ffffffe -> "VERNEED"
        0x6fffffff -> "VERSYM"
        else -> "0x${type.toString(16)}"
    }

    private fun buildSectionFlags(flags: Long): String {
        val sb = StringBuilder()
        if ((flags and 0x1L) != 0L) sb.append('W')
        if ((flags and 0x2L) != 0L) sb.append('A')
        if ((flags and 0x4L) != 0L) sb.append('X')
        return if (sb.isEmpty()) "-" else sb.toString()
    }

    private fun mapMachineToGhidra(
        eMachine: Int,
        is64: Boolean,
        littleEndian: Boolean
    ): Triple<String, String, String> {
        val endian = if (littleEndian) "LE" else "BE"
        return when (eMachine) {
            40 -> Triple("ARM (32-bit)", "ARM:$endian:32:v7", "default")
            183 -> Triple("AArch64 (ARM64)", "AARCH64:$endian:64:v8A", "default")
            3 -> Triple("x86 (IA-32)", "x86:$endian:32:default", "gcc")
            62 -> Triple("x86-64 (AMD64)", "x86:$endian:64:default", "gcc")
            8 -> Triple("MIPS", "MIPS:$endian:${if (is64) 64 else 32}:default", "default")
            243 -> Triple("RISC-V", "RISCV:$endian:${if (is64) 64 else 32}:RV${if (is64) 64 else 32}GC", "default")
            else -> Triple("Machine($eMachine)", "UNKNOWN:$endian:${if (is64) 64 else 32}:default", "default")
        }
    }
}
