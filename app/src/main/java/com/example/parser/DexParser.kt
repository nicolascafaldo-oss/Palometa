package com.example.parser

import com.example.model.DalvikInstruction
import com.example.model.DexClassInfo
import com.example.model.DexFieldInfo
import com.example.model.DexMethodInfo
import com.example.model.DexSummary
import com.example.model.NotableString
import java.util.Locale

class ParsedDexHandle(
    val summary: DexSummary,
    private val bytes: ByteArray,
    private val resolver: DexSymbolResolver
) {
    fun disassemble(method: DexMethodInfo, maxInstructions: Int = 600): List<DalvikInstruction> {
        if (method.codeOffset <= 0 || method.insnsSizeWords <= 0) return emptyList()
        return DalvikDisassembler.disassemble(
            dexBytes = bytes,
            insnsOffset = method.codeOffset + 16,
            insnsWordCount = method.insnsSizeWords,
            resolver = resolver,
            maxInstructions = maxInstructions
        )
    }
}

object DexParser {

    fun parse(entryName: String, bytes: ByteArray): ParsedDexHandle? {
        if (bytes.size < 112) return null
        if (bytes[0] != 'd'.code.toByte() ||
            bytes[1] != 'e'.code.toByte() ||
            bytes[2] != 'x'.code.toByte() ||
            bytes[3] != '\n'.code.toByte()
        ) {
            return null
        }

        val version = String(bytes, 4, 3, Charsets.US_ASCII)
        val cursor = BinaryCursor(bytes, littleEndian = true)
        val checksum = cursor.u32At(8)
        val sha1Hex = BinaryFormatters.toHexString(bytes.copyOfRange(12, 32))
        val fileSize = cursor.i32At(32)

        val stringIdsSize = cursor.i32At(56).coerceIn(0, 500_000)
        val stringIdsOff = cursor.i32At(60)
        val typeIdsSize = cursor.i32At(64).coerceIn(0, 200_000)
        val typeIdsOff = cursor.i32At(68)
        val protoIdsSize = cursor.i32At(72).coerceIn(0, 200_000)
        val protoIdsOff = cursor.i32At(76)
        val fieldIdsSize = cursor.i32At(80).coerceIn(0, 300_000)
        val fieldIdsOff = cursor.i32At(84)
        val methodIdsSize = cursor.i32At(88).coerceIn(0, 300_000)
        val methodIdsOff = cursor.i32At(92)
        val classDefsSize = cursor.i32At(96).coerceIn(0, 200_000)
        val classDefsOff = cursor.i32At(100)

        val stringDataOffsets = IntArray(stringIdsSize)
        for (i in 0 until stringIdsSize) {
            val pos = stringIdsOff + i * 4
            if (pos + 4 > bytes.size) break
            stringDataOffsets[i] = cursor.i32At(pos)
        }

        val stringCache = HashMap<Int, String>(minOf(stringIdsSize, 8192))
        fun getString(idx: Int): String {
            if (idx < 0 || idx >= stringDataOffsets.size) return "<str#$idx>"
            return stringCache.getOrPut(idx) {
                val off = stringDataOffsets[idx]
                if (off <= 0 || off >= bytes.size) "" else {
                    val c = BinaryCursor(bytes, position = off)
                    c.readMutf8String()
                }
            }
        }

        fun getType(typeIdx: Int): String {
            if (typeIdx < 0 || typeIdx >= typeIdsSize) return "Ljava/lang/Object;"
            val pos = typeIdsOff + typeIdx * 4
            if (pos + 4 > bytes.size) return "Ljava/lang/Object;"
            val strIdx = cursor.i32At(pos)
            return getString(strIdx)
        }

        fun getRawProto(protoIdx: Int): String {
            if (protoIdx < 0 || protoIdx >= protoIdsSize) return "()V"
            val pos = protoIdsOff + protoIdx * 12
            if (pos + 12 > bytes.size) return "()V"
            val returnTypeIdx = cursor.i32At(pos + 4)
            val paramsOff = cursor.i32At(pos + 8)
            val params = if (paramsOff > 0 && paramsOff + 4 <= bytes.size) {
                val size = cursor.i32At(paramsOff).coerceIn(0, 64)
                buildString {
                    append('(')
                    for (p in 0 until size) {
                        val tPos = paramsOff + 4 + p * 2
                        if (tPos + 2 > bytes.size) break
                        val tIdx = cursor.u16At(tPos)
                        append(getType(tIdx))
                    }
                    append(')')
                }
            } else {
                "()"
            }
            return "$params${getType(returnTypeIdx)}"
        }

        fun getProto(protoIdx: Int): String {
            if (protoIdx < 0 || protoIdx >= protoIdsSize) return "()"
            val pos = protoIdsOff + protoIdx * 12
            if (pos + 12 > bytes.size) return "()"
            val returnTypeIdx = cursor.i32At(pos + 4)
            val paramsOff = cursor.i32At(pos + 8)
            val params = if (paramsOff > 0 && paramsOff + 4 <= bytes.size) {
                val size = cursor.i32At(paramsOff).coerceIn(0, 64)
                buildString {
                    append('(')
                    for (p in 0 until size) {
                        val tPos = paramsOff + 4 + p * 2
                        if (tPos + 2 > bytes.size) break
                        val tIdx = cursor.u16At(tPos)
                        append(shortenDescriptor(getType(tIdx)))
                        if (p < size - 1) append(", ")
                    }
                    append(')')
                }
            } else {
                "()"
            }
            return "$params -> ${shortenDescriptor(getType(returnTypeIdx))}"
        }

        fun getFieldParts(fieldIdx: Int): Triple<String, String, String> {
            if (fieldIdx < 0 || fieldIdx >= fieldIdsSize) return Triple("Lunknown;", "field", "Ljava/lang/Object;")
            val pos = fieldIdsOff + fieldIdx * 8
            if (pos + 8 > bytes.size) return Triple("Lunknown;", "field", "Ljava/lang/Object;")
            val classIdx = cursor.u16At(pos)
            val typeIdx = cursor.u16At(pos + 2)
            val nameIdx = cursor.i32At(pos + 4)
            return Triple(getType(classIdx), getString(nameIdx), getType(typeIdx))
        }

        fun getMethodSignature(methodIdx: Int): List<String> {
            if (methodIdx < 0 || methodIdx >= methodIdsSize) return listOf("Lunknown;", "<method>", "()", "()V")
            val pos = methodIdsOff + methodIdx * 8
            if (pos + 8 > bytes.size) return listOf("Lunknown;", "<method>", "()", "()V")
            val classIdx = cursor.u16At(pos)
            val protoIdx = cursor.u16At(pos + 2)
            val nameIdx = cursor.i32At(pos + 4)
            return listOf(
                getType(classIdx),
                getString(nameIdx),
                getProto(protoIdx),
                getRawProto(protoIdx)
            )
        }

        val resolver = object : DexSymbolResolver {
            override fun resolveString(index: Int): String = getString(index)
            override fun resolveType(index: Int): String = shortenDescriptor(getType(index))
            override fun resolveField(index: Int): String {
                val (cls, name, typeDesc) = getFieldParts(index)
                return "${shortenDescriptor(cls)}.$name: ${shortenDescriptor(typeDesc)}"
            }
            override fun resolveMethod(index: Int): String {
                val sig = getMethodSignature(index)
                return "${shortenDescriptor(sig[0])}.${sig[1]}${sig[2]}"
            }
            override fun resolveSmaliType(index: Int): String = getType(index)
            override fun resolveSmaliField(index: Int): String {
                val (cls, name, typeDesc) = getFieldParts(index)
                return "$cls->$name:$typeDesc"
            }
            override fun resolveSmaliMethod(index: Int): String {
                val sig = getMethodSignature(index)
                return "${sig[0]}->${sig[1]}${sig[3]}"
            }
        }

        val classes = ArrayList<DexClassInfo>(minOf(classDefsSize, 4000))
        val maxClassesToParse = minOf(classDefsSize, 4000)
        for (i in 0 until maxClassesToParse) {
            val pos = classDefsOff + i * 32
            if (pos + 32 > bytes.size) break
            val classIdx = cursor.i32At(pos)
            val accessFlags = cursor.i32At(pos + 4)
            val superclassIdx = cursor.i32At(pos + 8)
            val sourceFileIdx = cursor.i32At(pos + 16)
            val classDataOff = cursor.i32At(pos + 24)

            val descriptor = getType(classIdx)
            val displayName = descriptorToJavaName(descriptor)
            val pkg = displayName.substringBeforeLast('.', "<default>")
            val superDesc = if (superclassIdx >= 0) getType(superclassIdx) else "Ljava/lang/Object;"
            val superName = if (superclassIdx >= 0) descriptorToJavaName(superDesc) else "None"
            val sourceFile = if (sourceFileIdx >= 0) getString(sourceFileIdx) else null

            var staticFieldsCount = 0
            var instanceFieldsCount = 0
            val fields = mutableListOf<DexFieldInfo>()
            val directMethods = mutableListOf<DexMethodInfo>()
            val virtualMethods = mutableListOf<DexMethodInfo>()

            if (classDataOff > 0 && classDataOff < bytes.size) {
                val cd = BinaryCursor(bytes, position = classDataOff)
                staticFieldsCount = cd.readUleb128().coerceIn(0, 10_000)
                instanceFieldsCount = cd.readUleb128().coerceIn(0, 10_000)
                val directMethodsSize = cd.readUleb128().coerceIn(0, 5_000)
                val virtualMethodsSize = cd.readUleb128().coerceIn(0, 5_000)

                var fieldIdxAcc = 0
                repeat(staticFieldsCount) {
                    fieldIdxAcc += cd.readUleb128()
                    val fFlags = cd.readUleb128()
                    val (_, fName, fType) = getFieldParts(fieldIdxAcc)
                    fields.add(
                        DexFieldInfo(
                            name = fName,
                            typeDescriptor = fType,
                            accessFlags = formatAccessFlags(fFlags, isMethod = false),
                            isStatic = true
                        )
                    )
                }

                fieldIdxAcc = 0
                repeat(instanceFieldsCount) {
                    fieldIdxAcc += cd.readUleb128()
                    val fFlags = cd.readUleb128()
                    val (_, fName, fType) = getFieldParts(fieldIdxAcc)
                    fields.add(
                        DexFieldInfo(
                            name = fName,
                            typeDescriptor = fType,
                            accessFlags = formatAccessFlags(fFlags, isMethod = false),
                            isStatic = false
                        )
                    )
                }

                var methodIdxAcc = 0
                repeat(directMethodsSize) {
                    methodIdxAcc += cd.readUleb128()
                    val mFlags = cd.readUleb128()
                    val codeOff = cd.readUleb128()
                    directMethods.add(
                        buildMethodInfo(
                            methodIdx = methodIdxAcc,
                            flags = mFlags,
                            codeOff = codeOff,
                            isDirect = true,
                            bytes = bytes,
                            cursor = cursor,
                            getMethodSignature = ::getMethodSignature
                        )
                    )
                }

                methodIdxAcc = 0
                repeat(virtualMethodsSize) {
                    methodIdxAcc += cd.readUleb128()
                    val mFlags = cd.readUleb128()
                    val codeOff = cd.readUleb128()
                    virtualMethods.add(
                        buildMethodInfo(
                            methodIdx = methodIdxAcc,
                            flags = mFlags,
                            codeOff = codeOff,
                            isDirect = false,
                            bytes = bytes,
                            cursor = cursor,
                            getMethodSignature = ::getMethodSignature
                        )
                    )
                }
            }

            classes.add(
                DexClassInfo(
                    index = i,
                    descriptor = descriptor,
                    displayName = displayName,
                    packageName = pkg,
                    superClass = superName,
                    superDescriptor = superDesc,
                    accessFlags = formatAccessFlags(accessFlags, isMethod = false),
                    sourceFile = sourceFile,
                    staticFieldsCount = staticFieldsCount,
                    instanceFieldsCount = instanceFieldsCount,
                    fields = fields,
                    directMethods = directMethods,
                    virtualMethods = virtualMethods
                )
            )
        }

        val notable = mutableListOf<NotableString>()
        val sampleStrings = mutableListOf<String>()
        val scanLimit = minOf(stringIdsSize, 40_000)
        for (i in 0 until scanLimit) {
            val s = getString(i)
            if (s.length in 3..512 && s.all { ch -> ch == '\t' || ch == '\n' || !ch.isISOControl() }) {
                sampleStrings.add(s)
            }
            if (notable.size < 300) {
                val category = classifyNotableString(s)
                if (category != null) {
                    notable.add(NotableString(index = i, category = category, value = s))
                }
            }
        }

        val summary = DexSummary(
            entryName = entryName,
            version = version,
            fileSize = fileSize,
            adler32Hex = String.format(Locale.US, "0x%08X", checksum),
            sha1Hex = sha1Hex,
            stringCount = stringIdsSize,
            typeCount = typeIdsSize,
            protoCount = protoIdsSize,
            fieldCount = fieldIdsSize,
            methodCount = methodIdsSize,
            classDefCount = classDefsSize,
            classes = classes,
            notableStrings = notable,
            sampleStrings = sampleStrings
        )

        return ParsedDexHandle(summary = summary, bytes = bytes, resolver = resolver)
    }

    private fun buildMethodInfo(
        methodIdx: Int,
        flags: Int,
        codeOff: Int,
        isDirect: Boolean,
        bytes: ByteArray,
        cursor: BinaryCursor,
        getMethodSignature: (Int) -> List<String>
    ): DexMethodInfo {
        val sig = getMethodSignature(methodIdx)
        var regs = 0
        var ins = 0
        var outs = 0
        var insnsWords = 0
        if (codeOff > 0 && codeOff + 16 <= bytes.size) {
            regs = cursor.u16At(codeOff)
            ins = cursor.u16At(codeOff + 2)
            outs = cursor.u16At(codeOff + 4)
            insnsWords = cursor.i32At(codeOff + 12).coerceAtLeast(0)
        }
        return DexMethodInfo(
            methodIndex = methodIdx,
            name = sig[1],
            prototype = sig[2],
            rawPrototype = sig[3],
            accessFlags = formatAccessFlags(flags, isMethod = true),
            isDirect = isDirect,
            codeOffset = codeOff,
            registersSize = regs,
            insSize = ins,
            outsSize = outs,
            insnsSizeWords = insnsWords
        )
    }

    private fun classifyNotableString(s: String): String? {
        if (s.length < 5 || s.length > 260) return null
        return when {
            s.startsWith("http://") || s.startsWith("https://") -> "URL Endpoint"
            s.startsWith("Java_") || s == "JNI_OnLoad" -> "JNI Bridge"
            s.contains("javax/crypto") || s.contains("Cipher") || s.contains("MessageDigest") -> "Crypto API"
            s.contains("DexClassLoader") || s.contains("PathClassLoader") || s.contains("java/lang/reflect") -> "Dynamic / Reflect"
            s.contains("Runtime;->exec") || s.contains("ProcessBuilder") -> "Process Exec"
            s.startsWith("android.permission.") -> "Permission Ref"
            else -> null
        }
    }

    private fun descriptorToJavaName(desc: String): String {
        if (desc.startsWith("L") && desc.endsWith(";") && desc.length >= 2) {
            return desc.substring(1, desc.length - 1).replace('/', '.')
        }
        return shortenDescriptor(desc)
    }

    private fun shortenDescriptor(desc: String): String {
        return when (desc) {
            "V" -> "void"
            "Z" -> "boolean"
            "B" -> "byte"
            "S" -> "short"
            "C" -> "char"
            "I" -> "int"
            "J" -> "long"
            "F" -> "float"
            "D" -> "double"
            else -> {
                if (desc.startsWith("[")) "${shortenDescriptor(desc.substring(1))}[]"
                else if (desc.startsWith("L") && desc.endsWith(";")) {
                    desc.substring(1, desc.length - 1).substringAfterLast('/')
                } else {
                    desc
                }
            }
        }
    }

    private fun formatAccessFlags(flags: Int, isMethod: Boolean): String {
        val parts = mutableListOf<String>()
        if ((flags and 0x0001) != 0) parts.add("public")
        if ((flags and 0x0002) != 0) parts.add("private")
        if ((flags and 0x0004) != 0) parts.add("protected")
        if ((flags and 0x0008) != 0) parts.add("static")
        if ((flags and 0x0010) != 0) parts.add("final")
        if (isMethod && (flags and 0x0020) != 0) parts.add("synchronized")
        if (isMethod && (flags and 0x0100) != 0) parts.add("native")
        if ((flags and 0x0200) != 0) parts.add("interface")
        if ((flags and 0x0400) != 0) parts.add("abstract")
        if ((flags and 0x1000) != 0) parts.add("synthetic")
        if (isMethod && (flags and 0x10000) != 0) parts.add("constructor")
        return parts.joinToString(" ")
    }
}
