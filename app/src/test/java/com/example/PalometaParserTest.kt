package com.example

import com.example.model.DexClassInfo
import com.example.model.DexFieldInfo
import com.example.model.DexMethodInfo
import com.example.model.DexSummary
import com.example.model.NotableString
import com.example.model.StringFindingCategory
import com.example.parser.ApkStringScanner
import com.example.parser.DalvikDisassembler
import com.example.parser.DexSymbolResolver
import com.example.parser.ElfParser
import com.example.parser.SmaliGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class PalometaParserTest {

    @Test
    fun elfParser_parsesElf64Aarch64HeaderAndSections() {
        // Minimal ELF64 LE AArch64 binary with 3 sections: NULL, .shstrtab, .text
        val shstrtab = "\u0000.shstrtab\u0000.text\u0000".toByteArray(Charsets.US_ASCII)
        val shstrtabOffset = 64
        val shoff = 128
        val totalSize = shoff + 3 * 64
        val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)

        // e_ident
        buf.put(0x7F.toByte())
        buf.put('E'.code.toByte())
        buf.put('L'.code.toByte())
        buf.put('F'.code.toByte())
        buf.put(2.toByte()) // EI_CLASS = ELFCLASS64
        buf.put(1.toByte()) // EI_DATA = ELFDATA2LSB
        buf.put(1.toByte()) // EI_VERSION
        buf.position(16)
        buf.putShort(3.toShort()) // ET_DYN
        buf.putShort(183.toShort()) // EM_AARCH64
        buf.putInt(1) // e_version
        buf.putLong(0x1000L) // e_entry
        buf.putLong(0L) // e_phoff
        buf.putLong(shoff.toLong()) // e_shoff
        buf.putInt(0) // e_flags
        buf.putShort(64.toShort()) // e_ehsize
        buf.putShort(56.toShort()) // e_phentsize
        buf.putShort(0.toShort()) // e_phnum
        buf.putShort(64.toShort()) // e_shentsize
        buf.putShort(3.toShort()) // e_shnum
        buf.putShort(1.toShort()) // e_shstrndx

        buf.position(shstrtabOffset)
        buf.put(shstrtab)

        // Section 0: NULL (all zeros)
        // Section 1: .shstrtab (nameIdx = 1, type = 3 STRTAB)
        buf.position(shoff + 64)
        buf.putInt(1)
        buf.putInt(3)
        buf.putLong(0L)
        buf.putLong(0L)
        buf.putLong(shstrtabOffset.toLong())
        buf.putLong(shstrtab.size.toLong())

        // Section 2: .text (nameIdx = 11, type = 1 PROGBITS, flags = 6 AX)
        buf.position(shoff + 128)
        buf.putInt(11)
        buf.putInt(1)
        buf.putLong(6L)
        buf.putLong(0x2000L)
        buf.putLong(0x2000L)
        buf.putLong(256L)

        val parsed = ElfParser.parse("lib/arm64-v8a/libnative.so", buf.array())
        assertNotNull(parsed)
        assertEquals("ELF64", parsed!!.elfClass)
        assertEquals("arm64-v8a", parsed.abi)
        assertEquals("AARCH64:LE:64:v8A", parsed.ghidraLanguageId)
        assertEquals(3, parsed.sections.size)
        assertEquals(".text", parsed.sections[2].name)
        assertEquals("AX", parsed.sections[2].flags)
    }

    @Test
    fun dalvikDisassembler_decodesOpcodesAndResolvesSymbols() {
        // 0x12 0x10 -> const/4 v0, #1
        // 0x1A 0x00, 0x0002 -> const-string v0, str@2
        // 0x0E 0x00 -> return-void
        val dexBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(0x1012.toShort())
            putShort(0x001A.toShort())
            putShort(0x0002.toShort())
            putShort(0x000E.toShort())
        }.array()

        val resolver = object : DexSymbolResolver {
            override fun resolveString(index: Int) = if (index == 2) "https://api.example.com" else ""
            override fun resolveType(index: Int) = "String"
            override fun resolveField(index: Int) = "f"
            override fun resolveMethod(index: Int) = "m"
            override fun resolveSmaliType(index: Int) = "Ljava/lang/String;"
            override fun resolveSmaliField(index: Int) = "Lf;->a:I"
            override fun resolveSmaliMethod(index: Int) = "Lm;->x()V"
        }

        val insns = DalvikDisassembler.disassemble(dexBytes, 0, 4, resolver)
        assertEquals(3, insns.size)
        assertEquals("const/4", insns[0].opcode)
        assertEquals("v0, #1", insns[0].operands)
        assertEquals("const-string", insns[1].opcode)
        assertTrue(insns[1].comment.contains("https://api.example.com"))
        assertEquals("return-void", insns[2].opcode)
    }

    @Test
    fun smaliGenerator_outputsValidSmaliClassStructure() {
        val cls = DexClassInfo(
            index = 0,
            descriptor = "Lcom/palometa/Sample;",
            displayName = "com.palometa.Sample",
            packageName = "com.palometa",
            superClass = "java.lang.Object",
            superDescriptor = "Ljava/lang/Object;",
            accessFlags = "public final",
            sourceFile = "Sample.kt",
            staticFieldsCount = 1,
            instanceFieldsCount = 0,
            fields = listOf(DexFieldInfo("TAG", "Ljava/lang/String;", "private static final", true)),
            directMethods = listOf(
                DexMethodInfo(
                    methodIndex = 0,
                    name = "<init>",
                    prototype = "() -> void",
                    rawPrototype = "()V",
                    accessFlags = "public constructor",
                    isDirect = true,
                    codeOffset = 0,
                    registersSize = 1,
                    insSize = 1,
                    outsSize = 0,
                    insnsSizeWords = 0
                )
            ),
            virtualMethods = emptyList()
        )

        val smali = SmaliGenerator.generateClassSmali(cls, null)
        assertTrue(smali.contains(".class public final Lcom/palometa/Sample;"))
        assertTrue(smali.contains(".super Ljava/lang/Object;"))
        assertTrue(smali.contains(".source \"Sample.kt\""))
        assertTrue(smali.contains(".field private static final TAG:Ljava/lang/String;"))
        assertTrue(smali.contains(".method public constructor <init>()V"))
        assertTrue(smali.contains(".end method"))
    }

    @Test
    fun apkStringScanner_flagsUrlsTokensAndIpsAsPotentialLeaks() {
        val dex = DexSummary(
            entryName = "classes.dex",
            version = "035",
            fileSize = 1024,
            adler32Hex = "0x1",
            sha1Hex = "abc",
            stringCount = 4,
            typeCount = 1,
            protoCount = 1,
            fieldCount = 0,
            methodCount = 1,
            classDefCount = 1,
            classes = emptyList(),
            notableStrings = listOf(NotableString(0, "URL", "https://internal.example.org/v1")),
            sampleStrings = listOf(
                "AIzaSyDummyExampleKey1234567890abcdef",
                "192.168.10.42",
                "Regular UI label"
            )
        )

        val results = ApkStringScanner.scanAll(
            dexFiles = listOf(dex),
            manifest = null,
            nativeBuffers = emptyList(),
            assetTextBuffers = emptyList()
        )

        val categories = results.associate { it.value to it.category }
        assertEquals(StringFindingCategory.URL_ENDPOINT, categories["https://internal.example.org/v1"])
        assertEquals(StringFindingCategory.API_KEY_TOKEN, categories["AIzaSyDummyExampleKey1234567890abcdef"])
        assertEquals(StringFindingCategory.IP_ADDRESS, categories["192.168.10.42"])
        assertEquals(StringFindingCategory.PRINTABLE, categories["Regular UI label"])
    }
}
