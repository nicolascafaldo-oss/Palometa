package com.example.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.model.ApkAnalysis
import com.example.model.DalvikInstruction
import com.example.model.DexClassInfo
import com.example.model.DexMethodInfo
import com.example.model.DexSummary
import com.example.parser.BinaryFormatters
import com.example.parser.SmaliSyntaxHighlighter
import com.example.ui.components.StatusPill
import com.example.ui.components.TerminalCard
import com.example.ui.theme.LocalDexScopeSyntax
import com.example.ui.theme.MonoCodeStyle
import com.example.ui.theme.MonoLabelStyle

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DexExplorerScreen(
    analysis: ApkAnalysis,
    selectedDexIndex: Int,
    searchQuery: String,
    selectedClass: DexClassInfo?,
    classSmaliSource: String,
    selectedMethod: DexMethodInfo?,
    disassembledMethod: List<DalvikInstruction>,
    onSelectDex: (Int) -> Unit,
    onSearchChange: (String) -> Unit,
    onSelectClass: (String, DexClassInfo?) -> Unit,
    onSelectMethod: (String, DexMethodInfo) -> Unit,
    onCloseMethod: () -> Unit,
    onCopiedNotice: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    if (analysis.dexFiles.isEmpty()) {
        Column(
            modifier = modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "No classes*.dex entries found in this APK.",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        return
    }

    val activeDex = analysis.dexFiles.getOrElse(selectedDexIndex) { analysis.dexFiles.first() }

    if (selectedClass != null && selectedMethod != null) {
        BackHandler { onCloseMethod() }
        DalvikMethodDisassemblyView(
            dexName = activeDex.entryName,
            cls = selectedClass,
            method = selectedMethod,
            instructions = disassembledMethod,
            onBack = onCloseMethod,
            onCopiedNotice = onCopiedNotice,
            modifier = modifier
        )
        return
    }

    if (selectedClass != null) {
        BackHandler { onSelectClass(activeDex.entryName, null) }
        DexClassDetailView(
            dexName = activeDex.entryName,
            cls = selectedClass,
            smaliSource = classSmaliSource,
            onBack = { onSelectClass(activeDex.entryName, null) },
            onMethodClick = { method -> onSelectMethod(activeDex.entryName, method) },
            onCopiedNotice = onCopiedNotice,
            modifier = modifier
        )
        return
    }

    var subTab by rememberSaveable { mutableIntStateOf(0) }
    val filteredClasses = remember(activeDex, searchQuery) {
        if (searchQuery.isBlank()) activeDex.classes
        else activeDex.classes.filter {
            it.displayName.contains(searchQuery, ignoreCase = true) ||
                it.descriptor.contains(searchQuery, ignoreCase = true)
        }
    }
    val filteredNotable = remember(activeDex, searchQuery) {
        if (searchQuery.isBlank()) activeDex.notableStrings
        else activeDex.notableStrings.filter {
            it.value.contains(searchQuery, ignoreCase = true) ||
                it.category.contains(searchQuery, ignoreCase = true)
        }
    }

    Column(modifier = modifier.fillMaxSize()) {
        if (analysis.dexFiles.size > 1) {
            LazyRow(
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                itemsIndexed(analysis.dexFiles) { idx, dex ->
                    FilterChip(
                        selected = idx == selectedDexIndex,
                        onClick = { onSelectDex(idx) },
                        label = { Text(dex.entryName, style = MonoLabelStyle) }
                    )
                }
            }
        }

        DexHeaderStrip(dex = activeDex, modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp))

        OutlinedTextField(
            value = searchQuery,
            onValueChange = onSearchChange,
            placeholder = { Text("Filter classes or descriptors for Smali…") },
            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
            trailingIcon = {
                if (searchQuery.isNotEmpty()) {
                    IconButton(
                        onClick = { onSearchChange("") },
                        modifier = Modifier.minimumInteractiveComponentSize()
                    ) {
                        Icon(Icons.Filled.Clear, contentDescription = "Clear search")
                    }
                }
            },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 4.dp)
                .testTag("dex_search_input")
        )

        PrimaryTabRow(selectedTabIndex = subTab) {
            Tab(
                selected = subTab == 0,
                onClick = { subTab = 0 },
                text = { Text("Classes & Smali (${filteredClasses.size})") }
            )
            Tab(
                selected = subTab == 1,
                onClick = { subTab = 1 },
                text = { Text("DEX Artifacts (${filteredNotable.size})") }
            )
        }

        if (subTab == 0) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                items(filteredClasses.take(350), key = { it.index }) { cls ->
                    TerminalCard(
                        modifier = Modifier
                            .widthIn(max = 760.dp)
                            .testTag("dex_class_card_${cls.index}"),
                        onClick = { onSelectClass(activeDex.entryName, cls) }
                    ) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                text = cls.displayName,
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "extends ${cls.superClass.substringAfterLast('.')}",
                                    style = MonoLabelStyle,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    modifier = Modifier.weight(1f)
                                )
                                StatusPill(
                                    text = "Smali · ${cls.totalMethods} mtd",
                                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                                    contentColor = MaterialTheme.colorScheme.onPrimaryContainer
                                )
                            }
                        }
                    }
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                if (filteredNotable.isEmpty()) {
                    item {
                        Text(
                            text = "No matching high-signal DEX references.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                items(filteredNotable, key = { it.index }) { item ->
                    TerminalCard(modifier = Modifier.widthIn(max = 760.dp)) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            StatusPill(
                                text = item.category,
                                containerColor = MaterialTheme.colorScheme.secondaryContainer,
                                contentColor = MaterialTheme.colorScheme.onSecondaryContainer
                            )
                            Text(
                                text = item.value,
                                style = MonoCodeStyle,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DexHeaderStrip(dex: DexSummary, modifier: Modifier = Modifier) {
    TerminalCard(modifier = modifier) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "${dex.entryName} · DEX v${dex.version}",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = "${BinaryFormatters.formatBytes(dex.fileSize.toLong())} · Adler32 ${dex.adler32Hex}",
                    style = MonoLabelStyle,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    text = "${dex.classDefCount} cls · ${dex.methodCount} mtd",
                    style = MonoLabelStyle,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = "${dex.stringCount} strings",
                    style = MonoLabelStyle,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DexClassDetailView(
    dexName: String,
    cls: DexClassInfo,
    smaliSource: String,
    onBack: () -> Unit,
    onMethodClick: (DexMethodInfo) -> Unit,
    onCopiedNotice: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val syntax = LocalDexScopeSyntax.current
    val clipboard = LocalClipboardManager.current
    var classTab by rememberSaveable { mutableIntStateOf(0) }
    val allMethods = remember(cls) { cls.directMethods + cls.virtualMethods }
    val highlightedSmali = remember(smaliSource, syntax) {
        SmaliSyntaxHighlighter.highlight(smaliSource, syntax)
    }

    Column(modifier = modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(
                onClick = onBack,
                modifier = Modifier
                    .minimumInteractiveComponentSize()
                    .testTag("dex_class_back_button")
            ) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back to classes")
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = cls.displayName.substringAfterLast('.'),
                    style = MaterialTheme.typography.titleLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "$dexName · ${cls.descriptor}",
                    style = MonoLabelStyle,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            if (classTab == 0 && smaliSource.isNotEmpty()) {
                IconButton(
                    onClick = {
                        clipboard.setText(AnnotatedString(smaliSource))
                        onCopiedNotice("Smali source")
                    },
                    modifier = Modifier
                        .minimumInteractiveComponentSize()
                        .testTag("copy_smali_button")
                ) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = "Copy Smali source")
                }
            }
        }

        PrimaryTabRow(selectedTabIndex = classTab) {
            Tab(
                selected = classTab == 0,
                onClick = { classTab = 0 },
                text = { Text("Smali Source") }
            )
            Tab(
                selected = classTab == 1,
                onClick = { classTab = 1 },
                text = { Text("Methods (${allMethods.size})") }
            )
        }

        if (classTab == 0) {
            SelectionContainer {
                Text(
                    text = highlightedSmali,
                    style = MonoCodeStyle,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .horizontalScroll(rememberScrollState())
                        .padding(16.dp)
                        .testTag("smali_code_viewer")
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                item {
                    TerminalCard(modifier = Modifier.widthIn(max = 760.dp)) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                text = "Class Metadata",
                                style = MaterialTheme.typography.labelLarge,
                                color = MaterialTheme.colorScheme.primary
                            )
                            Text("Package: ${cls.packageName}", style = MonoLabelStyle)
                            Text("Superclass: ${cls.superClass}", style = MonoLabelStyle)
                            Text("Access: ${cls.accessFlags.ifBlank { "package-private" }}", style = MonoLabelStyle)
                            cls.sourceFile?.let {
                                Text("Source File: $it", style = MonoLabelStyle)
                            }
                            Text(
                                "Fields: ${cls.staticFieldsCount} static, ${cls.instanceFieldsCount} instance",
                                style = MonoLabelStyle
                            )
                        }
                    }
                }

                if (allMethods.isEmpty()) {
                    item {
                        Text(
                            text = "No methods defined in class_data_item.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                items(allMethods, key = { "${it.isDirect}_${it.methodIndex}" }) { method ->
                    val hasBytecode = method.codeOffset > 0 && method.insnsSizeWords > 0
                    TerminalCard(
                        modifier = Modifier
                            .widthIn(max = 760.dp)
                            .testTag("dex_method_${method.methodIndex}"),
                        onClick = if (hasBytecode) ({ onMethodClick(method) }) else null
                    ) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = method.name,
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.SemiBold,
                                    color = MaterialTheme.colorScheme.onSurface,
                                    modifier = Modifier.weight(1f),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                StatusPill(
                                    text = if (hasBytecode) "${method.insnsSizeWords} words" else "abstract/native",
                                    containerColor = if (hasBytecode) {
                                        MaterialTheme.colorScheme.primaryContainer
                                    } else {
                                        MaterialTheme.colorScheme.surfaceVariant
                                    },
                                    contentColor = if (hasBytecode) {
                                        MaterialTheme.colorScheme.onPrimaryContainer
                                    } else {
                                        MaterialTheme.colorScheme.onSurfaceVariant
                                    }
                                )
                            }
                            Text(
                                text = "${method.accessFlags} ${method.prototype}".trim(),
                                style = MonoCodeStyle,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            if (hasBytecode) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Filled.Code,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.secondary,
                                        modifier = Modifier.size(14.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = "Tap for raw hex + Dalvik opcodes (regs=${method.registersSize}, ins=${method.insSize})",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.secondary
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DalvikMethodDisassemblyView(
    dexName: String,
    cls: DexClassInfo,
    method: DexMethodInfo,
    instructions: List<DalvikInstruction>,
    onBack: () -> Unit,
    onCopiedNotice: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val syntax = LocalDexScopeSyntax.current
    val clipboard = LocalClipboardManager.current

    Column(modifier = modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(
                onClick = onBack,
                modifier = Modifier
                    .minimumInteractiveComponentSize()
                    .testTag("dalvik_disasm_back")
            ) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back to class")
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "${cls.displayName.substringAfterLast('.')}.${method.name}",
                    style = MaterialTheme.typography.titleLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "$dexName · regs=${method.registersSize} ins=${method.insSize} outs=${method.outsSize} · ${instructions.size} ops",
                    style = MonoLabelStyle,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            IconButton(
                onClick = {
                    val dump = buildString {
                        appendLine("# ${cls.descriptor}->${method.name}${method.rawPrototype}")
                        instructions.forEach { insn ->
                            val cmt = if (insn.comment.isNotEmpty()) " ; ${insn.comment}" else ""
                            appendLine("${insn.offsetHex}: ${insn.opcode} ${insn.operands}$cmt")
                        }
                    }
                    clipboard.setText(AnnotatedString(dump))
                    onCopiedNotice("Dalvik disassembly")
                },
                modifier = Modifier
                    .minimumInteractiveComponentSize()
                    .testTag("copy_disassembly_button")
            ) {
                Icon(Icons.Filled.ContentCopy, contentDescription = "Copy Dalvik disassembly")
            }
        }

        HorizontalDivider(color = syntax.borderSubtle)

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .horizontalScroll(rememberScrollState()),
            contentPadding = PaddingValues(14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            items(instructions, key = { it.offsetBytes }) { insn ->
                Row(
                    modifier = Modifier.padding(vertical = 2.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = insn.offsetHex,
                        style = MonoCodeStyle,
                        color = syntax.addressOffset,
                        modifier = Modifier.width(48.dp)
                    )
                    Text(
                        text = insn.rawHex,
                        style = MonoLabelStyle,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.width(126.dp),
                        maxLines = 1
                    )
                    Text(
                        text = insn.opcode,
                        style = MonoCodeStyle,
                        fontWeight = FontWeight.Bold,
                        color = syntax.opcode,
                        modifier = Modifier.width(156.dp)
                    )
                    if (insn.operands.isNotEmpty()) {
                        Text(
                            text = insn.operands,
                            style = MonoCodeStyle,
                            color = syntax.register
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                    }
                    if (insn.comment.isNotEmpty()) {
                        Text(
                            text = "; ${insn.comment}",
                            style = MonoCodeStyle,
                            color = syntax.stringLiteral
                        )
                    }
                }
            }
            item { Spacer(modifier = Modifier.height(16.dp)) }
        }
    }
}
