package com.example.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.model.ApkAnalysis
import com.example.model.ElfAnalysis
import com.example.parser.BinaryFormatters
import com.example.ui.components.SectionLabel
import com.example.ui.components.StatusPill
import com.example.ui.components.TerminalCard
import com.example.ui.theme.LocalDexScopeSyntax
import com.example.ui.theme.MonoCodeStyle
import com.example.ui.theme.MonoLabelStyle

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ElfInspectorScreen(
    analysis: ApkAnalysis,
    selectedElf: ElfAnalysis?,
    onSelectElf: (ElfAnalysis?) -> Unit,
    modifier: Modifier = Modifier
) {
    if (selectedElf != null) {
        BackHandler { onSelectElf(null) }
        ElfDetailView(
            elf = selectedElf,
            onBack = { onSelectElf(null) },
            modifier = modifier
        )
        return
    }

    if (analysis.elfFiles.isEmpty()) {
        Column(
            modifier = modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                imageVector = Icons.Filled.Memory,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(40.dp)
            )
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = "No Native ELF (.so) Libraries",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onBackground
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = "This APK contains pure Dalvik/ART bytecode without lib/<abi>/*.so shared objects.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        return
    }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        item {
            SectionLabel(
                title = "Native Shared Libraries (${analysis.elfFiles.size})",
                subtitle = "ABIs: ${analysis.availableAbis.joinToString(", ")}",
                modifier = Modifier.widthIn(max = 760.dp)
            )
        }

        items(analysis.elfFiles, key = { it.entryPath }) { elf ->
            TerminalCard(
                modifier = Modifier
                    .widthIn(max = 760.dp)
                    .testTag("elf_card_${elf.abi}_${elf.fileName}"),
                onClick = { onSelectElf(elf) }
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = elf.fileName,
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = "${elf.abi} · ${BinaryFormatters.formatBytes(elf.fileSize)} · ${elf.machineName}",
                                style = MonoLabelStyle,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        StatusPill(
                            text = elf.elfClass,
                            containerColor = MaterialTheme.colorScheme.primaryContainer,
                            contentColor = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                    }

                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        StatusPill(
                            text = elf.ghidraLanguageId,
                            containerColor = MaterialTheme.colorScheme.secondaryContainer,
                            contentColor = MaterialTheme.colorScheme.onSecondaryContainer
                        )
                        StatusPill(
                            text = "${elf.sections.size} sections",
                            containerColor = MaterialTheme.colorScheme.surfaceVariant,
                            contentColor = MaterialTheme.colorScheme.onSurface
                        )
                        if (elf.hasJniOnLoad || elf.jniExports.isNotEmpty()) {
                            StatusPill(
                                text = "JNI (${elf.jniExports.size} exports)",
                                containerColor = MaterialTheme.colorScheme.tertiaryContainer,
                                contentColor = MaterialTheme.colorScheme.onTertiaryContainer
                            )
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ElfDetailView(
    elf: ElfAnalysis,
    onBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    val syntax = LocalDexScopeSyntax.current
    var activeTab by rememberSaveable { mutableIntStateOf(0) }

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
                    .testTag("elf_detail_back")
            ) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back to ELF list")
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = elf.fileName,
                    style = MaterialTheme.typography.titleLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "${elf.entryPath} · ${elf.ghidraLanguageId}",
                    style = MonoLabelStyle,
                    color = MaterialTheme.colorScheme.primary
                )
            }
        }

        TerminalCard(
            modifier = Modifier
                .padding(horizontal = 16.dp, vertical = 6.dp)
                .widthIn(max = 760.dp)
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = "${elf.elfClass} · ${elf.endianness} · ${elf.elfType}",
                    style = MonoLabelStyle,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = "Machine: ${elf.machineName} · Entry: ${elf.entryPointHex} · PHDRs: ${elf.programHeadersCount}",
                    style = MonoLabelStyle,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "Ghidra Spec: ${elf.ghidraLanguageId} / ${elf.ghidraCompilerSpec}",
                    style = MonoLabelStyle,
                    color = syntax.stringLiteral
                )
            }
        }

        PrimaryTabRow(selectedTabIndex = activeTab) {
            Tab(
                selected = activeTab == 0,
                onClick = { activeTab = 0 },
                text = { Text("Sections (${elf.sections.size})") }
            )
            Tab(
                selected = activeTab == 1,
                onClick = { activeTab = 1 },
                text = { Text("Symbols (${elf.dynamicSymbols.size})") }
            )
        }

        if (activeTab == 0) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                items(elf.sections, key = { it.index }) { sec ->
                    TerminalCard(modifier = Modifier.widthIn(max = 760.dp)) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = sec.name,
                                    style = MonoCodeStyle,
                                    fontWeight = FontWeight.Bold,
                                    color = syntax.opcode
                                )
                                Text(
                                    text = "${sec.typeName} · vaddr ${sec.addrHex} · off ${sec.offsetHex}",
                                    style = MonoLabelStyle,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Column(horizontalAlignment = Alignment.End) {
                                StatusPill(
                                    text = sec.flags,
                                    containerColor = MaterialTheme.colorScheme.surfaceVariant,
                                    contentColor = MaterialTheme.colorScheme.onSurface
                                )
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = BinaryFormatters.formatBytes(sec.sizeBytes),
                                    style = MonoLabelStyle,
                                    color = MaterialTheme.colorScheme.primary
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
                verticalArrangement = Arrangement.spacedBy(6.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                if (elf.dynamicSymbols.isEmpty()) {
                    item {
                        Text(
                            text = "No .dynsym symbols found (library may be stripped).",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                items(elf.dynamicSymbols) { sym ->
                    TerminalCard(modifier = Modifier.widthIn(max = 760.dp)) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = sym.name,
                                    style = MonoCodeStyle,
                                    color = if (sym.isJni) syntax.nativeTag else MaterialTheme.colorScheme.onSurface,
                                    modifier = Modifier.weight(1f),
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis
                                )
                                if (sym.isJni) {
                                    StatusPill(
                                        text = "JNI",
                                        containerColor = MaterialTheme.colorScheme.errorContainer,
                                        contentColor = MaterialTheme.colorScheme.onErrorContainer
                                    )
                                }
                            }
                            HorizontalDivider(color = syntax.borderSubtle)
                            Text(
                                text = "${sym.binding} · ${sym.type} · ${if (sym.isExported) "EXPORTED" else "IMPORT"} · ${sym.valueHex}",
                                style = MonoLabelStyle,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
}
