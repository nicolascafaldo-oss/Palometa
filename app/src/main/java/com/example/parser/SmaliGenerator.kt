package com.example.parser

import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import com.example.model.DexClassInfo
import com.example.model.DexMethodInfo
import com.example.ui.theme.DexScopeSyntaxColors

object SmaliGenerator {

    fun generateClassSmali(
        cls: DexClassInfo,
        dexHandle: ParsedDexHandle?
    ): String {
        val sb = StringBuilder(2048)
        val access = if (cls.accessFlags.isNotBlank()) "${cls.accessFlags} " else ""
        sb.appendLine(".class ${access}${cls.descriptor}")
        sb.appendLine(".super ${cls.superDescriptor}")
        cls.sourceFile?.let { src ->
            sb.appendLine(".source \"$src\"")
        }
        sb.appendLine()

        val staticFields = cls.fields.filter { it.isStatic }
        if (staticFields.isNotEmpty()) {
            sb.appendLine("# static fields")
            staticFields.forEach { f ->
                val fAccess = if (f.accessFlags.isNotBlank()) "${f.accessFlags} " else ""
                sb.appendLine(".field $fAccess${f.name}:${f.typeDescriptor}")
            }
            sb.appendLine()
        }

        val instanceFields = cls.fields.filter { !it.isStatic }
        if (instanceFields.isNotEmpty()) {
            sb.appendLine("# instance fields")
            instanceFields.forEach { f ->
                val fAccess = if (f.accessFlags.isNotBlank()) "${f.accessFlags} " else ""
                sb.appendLine(".field $fAccess${f.name}:${f.typeDescriptor}")
            }
            sb.appendLine()
        }

        if (cls.directMethods.isNotEmpty()) {
            sb.appendLine("# direct methods")
            cls.directMethods.forEach { method ->
                appendMethodSmali(sb, method, dexHandle)
            }
        }

        if (cls.virtualMethods.isNotEmpty()) {
            sb.appendLine("# virtual methods")
            cls.virtualMethods.forEach { method ->
                appendMethodSmali(sb, method, dexHandle)
            }
        }

        return sb.toString()
    }

    private fun appendMethodSmali(
        sb: StringBuilder,
        method: DexMethodInfo,
        dexHandle: ParsedDexHandle?
    ) {
        val mAccess = if (method.accessFlags.isNotBlank()) "${method.accessFlags} " else ""
        sb.appendLine(".method $mAccess${method.name}${method.rawPrototype}")

        if (method.codeOffset > 0 && method.insnsSizeWords > 0 && dexHandle != null) {
            sb.appendLine("    .registers ${method.registersSize}")
            sb.appendLine("    # ins=${method.insSize}, outs=${method.outsSize}, code_off=0x${method.codeOffset.toString(16)}")
            val insns = dexHandle.disassemble(method, maxInstructions = 400)
            insns.forEach { insn ->
                val opText = if (insn.smaliOperand.isNotEmpty()) {
                    "${insn.opcode} ${insn.smaliOperand}"
                } else {
                    insn.opcode
                }
                sb.append("    ").append(opText)
                if (insn.offsetBytes % 16 == 0) {
                    sb.append("  # +0x").append(insn.offsetHex)
                }
                sb.appendLine()
            }
        } else {
            sb.appendLine("    # abstract or native method (no Dalvik code_item)")
        }

        sb.appendLine(".end method")
        sb.appendLine()
    }
}

object SmaliSyntaxHighlighter {
    private val directiveRegex = Regex("""^\s*(\.(?:class|super|source|field|method|end method|registers|locals|implements|annotation|end annotation|param|line|prologue))\b""")
    private val accessKeywordRegex = Regex("""\b(public|private|protected|static|final|synchronized|native|interface|abstract|synthetic|constructor|bridge|varargs|declared-synchronized)\b""")
    private val registerRegex = Regex("""\b([vp]\d{1,3})\b""")
    private val stringRegex = Regex(""""(?:\\.|[^"\\])*"""")
    private val typeDescRegex = Regex("""L[a-zA-Z0-9_$/-]+;""")

    fun highlight(smali: String, syntax: DexScopeSyntaxColors): AnnotatedString {
        return buildAnnotatedString {
            val lines = smali.split('\n')
            lines.forEachIndexed { idx, line ->
                appendHighlightedLine(this, line, syntax)
                if (idx < lines.lastIndex) append('\n')
            }
        }
    }

    private fun appendHighlightedLine(
        builder: AnnotatedString.Builder,
        line: String,
        syntax: DexScopeSyntaxColors
    ) {
        val trimmed = line.trimStart()
        if (trimmed.startsWith("#")) {
            builder.withStyle(SpanStyle(color = syntax.addressOffset)) {
                append(line)
            }
            return
        }

        // Split trailing comment outside string quotes
        var commentIdx = -1
        var inQuote = false
        var escaped = false
        for (i in line.indices) {
            val ch = line[i]
            if (escaped) {
                escaped = false
                continue
            }
            if (ch == '\\') {
                escaped = true
            } else if (ch == '"') {
                inQuote = !inQuote
            } else if (ch == '#' && !inQuote) {
                commentIdx = i
                break
            }
        }

        val codePart = if (commentIdx >= 0) line.substring(0, commentIdx) else line
        val commentPart = if (commentIdx >= 0) line.substring(commentIdx) else ""

        val dirMatch = directiveRegex.find(codePart)
        if (dirMatch != null) {
            val g = dirMatch.groups[1]!!
            builder.append(codePart.substring(0, g.range.first))
            builder.withStyle(SpanStyle(color = syntax.otherSegment, fontWeight = FontWeight.Bold)) {
                append(g.value)
            }
            highlightInlineTokens(builder, codePart.substring(g.range.last + 1), syntax, isInstructionLine = false)
        } else {
            // Indented opcode line
            val leadingSpaces = codePart.takeWhile { it == ' ' || it == '\t' }
            val body = codePart.substring(leadingSpaces.length)
            builder.append(leadingSpaces)
            val spaceIdx = body.indexOf(' ')
            if (spaceIdx > 0) {
                val opcode = body.substring(0, spaceIdx)
                val rest = body.substring(spaceIdx)
                builder.withStyle(SpanStyle(color = syntax.opcode, fontWeight = FontWeight.Bold)) {
                    append(opcode)
                }
                highlightInlineTokens(builder, rest, syntax, isInstructionLine = true)
            } else if (body.isNotEmpty()) {
                builder.withStyle(SpanStyle(color = syntax.opcode, fontWeight = FontWeight.Bold)) {
                    append(body)
                }
            }
        }

        if (commentPart.isNotEmpty()) {
            builder.withStyle(SpanStyle(color = syntax.addressOffset)) {
                append(commentPart)
            }
        }
    }

    private fun highlightInlineTokens(
        builder: AnnotatedString.Builder,
        text: String,
        syntax: DexScopeSyntaxColors,
        isInstructionLine: Boolean
    ) {
        if (text.isEmpty()) return
        val spans = Array<SpanStyle?>(text.length) { null }

        typeDescRegex.findAll(text).forEach { m ->
            for (i in m.range) spans[i] = SpanStyle(color = syntax.register)
        }
        if (!isInstructionLine) {
            accessKeywordRegex.findAll(text).forEach { m ->
                for (i in m.range) spans[i] = SpanStyle(color = syntax.nativeTag, fontWeight = FontWeight.SemiBold)
            }
        }
        registerRegex.findAll(text).forEach { m ->
            for (i in m.range) spans[i] = SpanStyle(color = syntax.register, fontWeight = FontWeight.Medium)
        }
        stringRegex.findAll(text).forEach { m ->
            for (i in m.range) spans[i] = SpanStyle(color = syntax.stringLiteral)
        }

        var i = 0
        while (i < text.length) {
            val style = spans[i]
            var j = i + 1
            while (j < text.length && spans[j] == style) j++
            val chunk = text.substring(i, j)
            if (style != null) {
                builder.withStyle(style) { append(chunk) }
            } else {
                builder.append(chunk)
            }
            i = j
        }
    }
}
