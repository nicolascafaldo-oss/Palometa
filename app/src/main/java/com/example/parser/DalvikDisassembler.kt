package com.example.parser

import com.example.model.DalvikInstruction
import java.util.Locale

interface DexSymbolResolver {
    fun resolveString(index: Int): String
    fun resolveType(index: Int): String
    fun resolveField(index: Int): String
    fun resolveMethod(index: Int): String
    fun resolveSmaliType(index: Int): String
    fun resolveSmaliField(index: Int): String
    fun resolveSmaliMethod(index: Int): String
}

object DalvikDisassembler {

    private enum class Fmt {
        F10X, F12X, F11N, F11X, F10T,
        F20T, F22X, F21T, F21S, F21H, F21C, F23X, F22B, F22T, F22S, F22C,
        F30T, F32X, F31I, F31T, F31C, F35C, F3RC, F51L
    }

    private enum class RefKind { NONE, STRING, TYPE, FIELD, METHOD }

    private data class OpDef(
        val mnemonic: String,
        val fmt: Fmt,
        val refKind: RefKind = RefKind.NONE
    )

    private val opcodeTable: Array<OpDef?> = arrayOfNulls<OpDef>(256).apply {
        fun reg(op: Int, name: String, fmt: Fmt, ref: RefKind = RefKind.NONE) {
            this[op] = OpDef(name, fmt, ref)
        }
        reg(0x00, "nop", Fmt.F10X)
        reg(0x01, "move", Fmt.F12X)
        reg(0x02, "move/from16", Fmt.F22X)
        reg(0x03, "move/16", Fmt.F32X)
        reg(0x04, "move-wide", Fmt.F12X)
        reg(0x05, "move-wide/from16", Fmt.F22X)
        reg(0x06, "move-wide/16", Fmt.F32X)
        reg(0x07, "move-object", Fmt.F12X)
        reg(0x08, "move-object/from16", Fmt.F22X)
        reg(0x09, "move-object/16", Fmt.F32X)
        reg(0x0A, "move-result", Fmt.F11X)
        reg(0x0B, "move-result-wide", Fmt.F11X)
        reg(0x0C, "move-result-object", Fmt.F11X)
        reg(0x0D, "move-exception", Fmt.F11X)
        reg(0x0E, "return-void", Fmt.F10X)
        reg(0x0F, "return", Fmt.F11X)
        reg(0x10, "return-wide", Fmt.F11X)
        reg(0x11, "return-object", Fmt.F11X)
        reg(0x12, "const/4", Fmt.F11N)
        reg(0x13, "const/16", Fmt.F21S)
        reg(0x14, "const", Fmt.F31I)
        reg(0x15, "const/high16", Fmt.F21H)
        reg(0x16, "const-wide/16", Fmt.F21S)
        reg(0x17, "const-wide/32", Fmt.F31I)
        reg(0x18, "const-wide", Fmt.F51L)
        reg(0x19, "const-wide/high16", Fmt.F21H)
        reg(0x1A, "const-string", Fmt.F21C, RefKind.STRING)
        reg(0x1B, "const-string/jumbo", Fmt.F31C, RefKind.STRING)
        reg(0x1C, "const-class", Fmt.F21C, RefKind.TYPE)
        reg(0x1D, "monitor-enter", Fmt.F11X)
        reg(0x1E, "monitor-exit", Fmt.F11X)
        reg(0x1F, "check-cast", Fmt.F21C, RefKind.TYPE)
        reg(0x20, "instance-of", Fmt.F22C, RefKind.TYPE)
        reg(0x21, "array-length", Fmt.F12X)
        reg(0x22, "new-instance", Fmt.F21C, RefKind.TYPE)
        reg(0x23, "new-array", Fmt.F22C, RefKind.TYPE)
        reg(0x24, "filled-new-array", Fmt.F35C, RefKind.TYPE)
        reg(0x25, "filled-new-array/range", Fmt.F3RC, RefKind.TYPE)
        reg(0x26, "fill-array-data", Fmt.F31T)
        reg(0x27, "throw", Fmt.F11X)
        reg(0x28, "goto", Fmt.F10T)
        reg(0x29, "goto/16", Fmt.F20T)
        reg(0x2A, "goto/32", Fmt.F30T)
        reg(0x2B, "packed-switch", Fmt.F31T)
        reg(0x2C, "sparse-switch", Fmt.F31T)

        val cmps = listOf("cmpl-float", "cmpg-float", "cmpl-double", "cmpg-double", "cmp-long")
        cmps.forEachIndexed { idx, name -> reg(0x2D + idx, name, Fmt.F23X) }

        val ifTests = listOf("if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le")
        ifTests.forEachIndexed { idx, name -> reg(0x32 + idx, name, Fmt.F22T) }

        val ifZTests = listOf("if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez")
        ifZTests.forEachIndexed { idx, name -> reg(0x38 + idx, name, Fmt.F21T) }

        val agetOps = listOf("aget", "aget-wide", "aget-object", "aget-boolean", "aget-byte", "aget-char", "aget-short")
        agetOps.forEachIndexed { idx, name -> reg(0x44 + idx, name, Fmt.F23X) }
        val aputOps = listOf("aput", "aput-wide", "aput-object", "aput-boolean", "aput-byte", "aput-char", "aput-short")
        aputOps.forEachIndexed { idx, name -> reg(0x4B + idx, name, Fmt.F23X) }

        val igetOps = listOf("iget", "iget-wide", "iget-object", "iget-boolean", "iget-byte", "iget-char", "iget-short")
        igetOps.forEachIndexed { idx, name -> reg(0x52 + idx, name, Fmt.F22C, RefKind.FIELD) }
        val iputOps = listOf("iput", "iput-wide", "iput-object", "iput-boolean", "iput-byte", "iput-char", "iput-short")
        iputOps.forEachIndexed { idx, name -> reg(0x59 + idx, name, Fmt.F22C, RefKind.FIELD) }

        val sgetOps = listOf("sget", "sget-wide", "sget-object", "sget-boolean", "sget-byte", "sget-char", "sget-short")
        sgetOps.forEachIndexed { idx, name -> reg(0x60 + idx, name, Fmt.F21C, RefKind.FIELD) }
        val sputOps = listOf("sput", "sput-wide", "sput-object", "sput-boolean", "sput-byte", "sput-char", "sput-short")
        sputOps.forEachIndexed { idx, name -> reg(0x67 + idx, name, Fmt.F21C, RefKind.FIELD) }

        reg(0x6E, "invoke-virtual", Fmt.F35C, RefKind.METHOD)
        reg(0x6F, "invoke-super", Fmt.F35C, RefKind.METHOD)
        reg(0x70, "invoke-direct", Fmt.F35C, RefKind.METHOD)
        reg(0x71, "invoke-static", Fmt.F35C, RefKind.METHOD)
        reg(0x72, "invoke-interface", Fmt.F35C, RefKind.METHOD)

        reg(0x74, "invoke-virtual/range", Fmt.F3RC, RefKind.METHOD)
        reg(0x75, "invoke-super/range", Fmt.F3RC, RefKind.METHOD)
        reg(0x76, "invoke-direct/range", Fmt.F3RC, RefKind.METHOD)
        reg(0x77, "invoke-static/range", Fmt.F3RC, RefKind.METHOD)
        reg(0x78, "invoke-interface/range", Fmt.F3RC, RefKind.METHOD)

        val unOps = listOf(
            "neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double",
            "int-to-long", "int-to-float", "int-to-double", "long-to-int", "long-to-float", "long-to-double",
            "float-to-int", "float-to-long", "float-to-double", "double-to-int", "double-to-long", "double-to-float",
            "int-to-byte", "int-to-char", "int-to-short"
        )
        unOps.forEachIndexed { idx, name -> reg(0x7B + idx, name, Fmt.F12X) }

        val binOps = listOf(
            "add-int", "sub-int", "mul-int", "div-int", "rem-int", "and-int", "or-int", "xor-int", "shl-int", "shr-int", "ushr-int",
            "add-long", "sub-long", "mul-long", "div-long", "rem-long", "and-long", "or-long", "xor-long", "shl-long", "shr-long", "ushr-long",
            "add-float", "sub-float", "mul-float", "div-float", "rem-float",
            "add-double", "sub-double", "mul-double", "div-double", "rem-double"
        )
        binOps.forEachIndexed { idx, name -> reg(0x90 + idx, name, Fmt.F23X) }
        binOps.forEachIndexed { idx, name -> reg(0xB0 + idx, "$name/2addr", Fmt.F12X) }

        val lit16Ops = listOf("add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16", "rem-int/lit16", "and-int/lit16", "or-int/lit16", "xor-int/lit16")
        lit16Ops.forEachIndexed { idx, name -> reg(0xD0 + idx, name, Fmt.F22S) }

        val lit8Ops = listOf("add-int/lit8", "rsub-int/lit8", "mul-int/lit8", "div-int/lit8", "rem-int/lit8", "and-int/lit8", "or-int/lit8", "xor-int/lit8", "shl-int/lit8", "shr-int/lit8", "ushr-int/lit8")
        lit8Ops.forEachIndexed { idx, name -> reg(0xD8 + idx, name, Fmt.F22B) }
    }

    fun disassemble(
        dexBytes: ByteArray,
        insnsOffset: Int,
        insnsWordCount: Int,
        resolver: DexSymbolResolver,
        maxInstructions: Int = 600
    ): List<DalvikInstruction> {
        if (insnsOffset < 0 || insnsWordCount <= 0 || insnsOffset + insnsWordCount * 2 > dexBytes.size) {
            return emptyList()
        }
        val cursor = BinaryCursor(dexBytes, littleEndian = true)
        val result = ArrayList<DalvikInstruction>()
        var wordIdx = 0

        while (wordIdx < insnsWordCount && result.size < maxInstructions) {
            val bytePos = insnsOffset + wordIdx * 2
            val unit0 = cursor.u16At(bytePos)
            val opcode = unit0 and 0xFF
            val def = opcodeTable[opcode]

            if (def == null) {
                result.add(
                    DalvikInstruction(
                        offsetBytes = wordIdx * 2,
                        offsetHex = String.format(Locale.US, "%04X", wordIdx * 2),
                        rawHex = String.format(Locale.US, "%04X", unit0),
                        opcode = String.format(Locale.US, ".dw 0x%04X", unit0),
                        operands = "",
                        comment = "unknown opcode 0x${opcode.toString(16)}",
                        smaliOperand = ""
                    )
                )
                wordIdx += 1
                continue
            }

            val wordLen = when (def.fmt) {
                Fmt.F10X, Fmt.F12X, Fmt.F11N, Fmt.F11X, Fmt.F10T -> 1
                Fmt.F20T, Fmt.F22X, Fmt.F21T, Fmt.F21S, Fmt.F21H, Fmt.F21C, Fmt.F23X, Fmt.F22B, Fmt.F22T, Fmt.F22S, Fmt.F22C -> 2
                Fmt.F30T, Fmt.F32X, Fmt.F31I, Fmt.F31T, Fmt.F31C, Fmt.F35C, Fmt.F3RC -> 3
                Fmt.F51L -> 5
            }

            if (wordIdx + wordLen > insnsWordCount) break

            val units = IntArray(wordLen) { i -> cursor.u16At(bytePos + i * 2) }
            val rawHex = units.joinToString(" ") { String.format(Locale.US, "%04X", it) }

            val decoded = decodeOperands(def, units, wordIdx, resolver)
            result.add(
                DalvikInstruction(
                    offsetBytes = wordIdx * 2,
                    offsetHex = String.format(Locale.US, "%04X", wordIdx * 2),
                    rawHex = rawHex,
                    opcode = def.mnemonic,
                    operands = decoded.operands,
                    comment = decoded.comment,
                    smaliOperand = decoded.smaliOperand
                )
            )
            wordIdx += wordLen
        }

        return result
    }

    private data class DecodedOps(
        val operands: String,
        val comment: String,
        val smaliOperand: String
    )

    private fun decodeOperands(
        def: OpDef,
        u: IntArray,
        currentWordIdx: Int,
        resolver: DexSymbolResolver
    ): DecodedOps {
        val hi0 = (u[0] shr 8) and 0xFF
        return when (def.fmt) {
            Fmt.F10X -> DecodedOps("", "", "")
            Fmt.F12X -> {
                val vA = hi0 and 0xF
                val vB = (hi0 shr 4) and 0xF
                val op = "v$vA, v$vB"
                DecodedOps(op, "", op)
            }
            Fmt.F11N -> {
                val vA = hi0 and 0xF
                val lit = signExtend4((hi0 shr 4) and 0xF)
                DecodedOps("v$vA, #$lit", "", "v$vA, 0x${(lit and 0xF).toString(16)}")
            }
            Fmt.F11X -> DecodedOps("v$hi0", "", "v$hi0")
            Fmt.F10T -> {
                val off = hi0.toByte().toInt()
                val targetBytes = (currentWordIdx + off) * 2
                val lbl = String.format(Locale.US, ":goto_%04x", targetBytes.coerceAtLeast(0))
                DecodedOps(String.format(Locale.US, "0x%04X", targetBytes.coerceAtLeast(0)), "", lbl)
            }
            Fmt.F20T -> {
                val off = u[1].toShort().toInt()
                val targetBytes = (currentWordIdx + off) * 2
                val lbl = String.format(Locale.US, ":goto_%04x", targetBytes.coerceAtLeast(0))
                DecodedOps(String.format(Locale.US, "0x%04X", targetBytes.coerceAtLeast(0)), "", lbl)
            }
            Fmt.F22X -> {
                val op = "v$hi0, v${u[1]}"
                DecodedOps(op, "", op)
            }
            Fmt.F21T -> {
                val off = u[1].toShort().toInt()
                val targetBytes = (currentWordIdx + off) * 2
                val cond = String.format(Locale.US, ":cond_%04x", targetBytes.coerceAtLeast(0))
                DecodedOps(String.format(Locale.US, "v%d, 0x%04X", hi0, targetBytes.coerceAtLeast(0)), "", "v$hi0, $cond")
            }
            Fmt.F21S -> {
                val lit = u[1].toShort().toInt()
                DecodedOps("v$hi0, #$lit", String.format(Locale.US, "0x%X", lit), "v$hi0, 0x${lit.toString(16)}")
            }
            Fmt.F21H -> {
                val op = "v$hi0, 0x${u[1].toString(16)}0000"
                DecodedOps("v$hi0, #0x${u[1].toString(16)}", "", op)
            }
            Fmt.F21C -> {
                val idx = u[1]
                val resolved = resolveRef(def.refKind, idx, resolver)
                val smaliRef = resolveSmaliRef(def.refKind, idx, resolver)
                DecodedOps("v$hi0, ${refPrefix(def.refKind)}@$idx", resolved, "v$hi0, $smaliRef")
            }
            Fmt.F23X -> {
                val vB = u[1] and 0xFF
                val vC = (u[1] shr 8) and 0xFF
                val op = "v$hi0, v$vB, v$vC"
                DecodedOps(op, "", op)
            }
            Fmt.F22B -> {
                val vA = hi0
                val vB = u[1] and 0xFF
                val lit = ((u[1] shr 8) and 0xFF).toByte().toInt()
                DecodedOps("v$vA, v$vB, #$lit", "", "v$vA, v$vB, 0x${lit.toString(16)}")
            }
            Fmt.F22T -> {
                val vA = hi0 and 0xF
                val vB = (hi0 shr 4) and 0xF
                val off = u[1].toShort().toInt()
                val targetBytes = (currentWordIdx + off) * 2
                val cond = String.format(Locale.US, ":cond_%04x", targetBytes.coerceAtLeast(0))
                DecodedOps(String.format(Locale.US, "v%d, v%d, 0x%04X", vA, vB, targetBytes.coerceAtLeast(0)), "", "v$vA, v$vB, $cond")
            }
            Fmt.F22S -> {
                val vA = hi0 and 0xF
                val vB = (hi0 shr 4) and 0xF
                val lit = u[1].toShort().toInt()
                DecodedOps("v$vA, v$vB, #$lit", "", "v$vA, v$vB, 0x${lit.toString(16)}")
            }
            Fmt.F22C -> {
                val vA = hi0 and 0xF
                val vB = (hi0 shr 4) and 0xF
                val idx = u[1]
                val resolved = resolveRef(def.refKind, idx, resolver)
                val smaliRef = resolveSmaliRef(def.refKind, idx, resolver)
                DecodedOps("v$vA, v$vB, ${refPrefix(def.refKind)}@$idx", resolved, "v$vA, v$vB, $smaliRef")
            }
            Fmt.F30T -> {
                val off = (u[2] shl 16) or u[1]
                val targetBytes = (currentWordIdx + off) * 2
                val lbl = String.format(Locale.US, ":goto_%04x", targetBytes.coerceAtLeast(0))
                DecodedOps(String.format(Locale.US, "0x%04X", targetBytes.coerceAtLeast(0)), "", lbl)
            }
            Fmt.F32X -> {
                val op = "v${u[1]}, v${u[2]}"
                DecodedOps(op, "", op)
            }
            Fmt.F31I -> {
                val lit = (u[2] shl 16) or u[1]
                DecodedOps("v$hi0, #$lit", String.format(Locale.US, "0x%08X", lit), "v$hi0, 0x${lit.toString(16)}")
            }
            Fmt.F31T -> {
                val off = (u[2] shl 16) or u[1]
                val targetBytes = (currentWordIdx + off) * 2
                val lbl = String.format(Locale.US, ":data_%04x", targetBytes.coerceAtLeast(0))
                DecodedOps(String.format(Locale.US, "v%d, 0x%04X", hi0, targetBytes.coerceAtLeast(0)), "", "v$hi0, $lbl")
            }
            Fmt.F31C -> {
                val idx = (u[2] shl 16) or u[1]
                val resolved = resolveRef(def.refKind, idx, resolver)
                val smaliRef = resolveSmaliRef(def.refKind, idx, resolver)
                DecodedOps("v$hi0, ${refPrefix(def.refKind)}@$idx", resolved, "v$hi0, $smaliRef")
            }
            Fmt.F35C -> {
                val count = (hi0 shr 4) and 0xF
                val g = hi0 and 0xF
                val idx = u[1]
                val argsWord = u[2]
                val regs = IntArray(5)
                regs[0] = argsWord and 0xF
                regs[1] = (argsWord shr 4) and 0xF
                regs[2] = (argsWord shr 8) and 0xF
                regs[3] = (argsWord shr 12) and 0xF
                regs[4] = g
                val regList = (0 until count.coerceAtMost(5)).joinToString(", ") { "v${regs[it]}" }
                val resolved = resolveRef(def.refKind, idx, resolver)
                val smaliRef = resolveSmaliRef(def.refKind, idx, resolver)
                DecodedOps("{$regList}, ${refPrefix(def.refKind)}@$idx", resolved, "{$regList}, $smaliRef")
            }
            Fmt.F3RC -> {
                val count = hi0
                val idx = u[1]
                val startReg = u[2]
                val endReg = (startReg + count - 1).coerceAtLeast(startReg)
                val rangeStr = if (count == 0) "{}" else "{v$startReg .. v$endReg}"
                val resolved = resolveRef(def.refKind, idx, resolver)
                val smaliRef = resolveSmaliRef(def.refKind, idx, resolver)
                DecodedOps("$rangeStr, ${refPrefix(def.refKind)}@$idx", resolved, "$rangeStr, $smaliRef")
            }
            Fmt.F51L -> {
                val lit = u[1].toLong() or
                    (u[2].toLong() shl 16) or
                    (u[3].toLong() shl 32) or
                    (u[4].toLong() shl 48)
                DecodedOps("v$hi0, #0x${lit.toString(16)}", "", "v$hi0, 0x${lit.toString(16)}L")
            }
        }
    }

    private fun signExtend4(v: Int): Int = if ((v and 0x8) != 0) v or -16 else v

    private fun refPrefix(kind: RefKind): String = when (kind) {
        RefKind.STRING -> "str"
        RefKind.TYPE -> "type"
        RefKind.FIELD -> "field"
        RefKind.METHOD -> "method"
        RefKind.NONE -> "ref"
    }

    private fun resolveRef(kind: RefKind, idx: Int, resolver: DexSymbolResolver): String = when (kind) {
        RefKind.STRING -> "\"${resolver.resolveString(idx).take(80)}\""
        RefKind.TYPE -> resolver.resolveType(idx)
        RefKind.FIELD -> resolver.resolveField(idx)
        RefKind.METHOD -> resolver.resolveMethod(idx)
        RefKind.NONE -> ""
    }

    private fun resolveSmaliRef(kind: RefKind, idx: Int, resolver: DexSymbolResolver): String = when (kind) {
        RefKind.STRING -> {
            val escaped = resolver.resolveString(idx)
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
            "\"$escaped\""
        }
        RefKind.TYPE -> resolver.resolveSmaliType(idx)
        RefKind.FIELD -> resolver.resolveSmaliField(idx)
        RefKind.METHOD -> resolver.resolveSmaliMethod(idx)
        RefKind.NONE -> ""
    }
}
