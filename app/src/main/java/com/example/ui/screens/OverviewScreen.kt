package com.example.ui.screens

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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Archive
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.model.ApkAnalysis
import com.example.parser.BinaryFormatters
import com.example.ui.components.BinaryCompositionBar
import com.example.ui.components.CopyableKeyValueRow
import com.example.ui.components.SectionLabel
import com.example.ui.components.StatusPill
import com.example.ui.components.TerminalCard
import com.example.ui.theme.LocalDexScopeSyntax

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun OverviewScreen(
    analysis: ApkAnalysis,
    onNavigateDex: () -> Unit,
    onNavigateElf: () -> Unit,
    onNavigateInspect: () -> Unit,
    onNavigateExport: () -> Unit,
    onOpenAnotherApk: () -> Unit,
    onCopiedNotice: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val syntax = LocalDexScopeSyntax.current
    val manifest = analysis.manifest

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        item {
            TerminalCard(modifier = Modifier.widthIn(max = 760.dp)) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.Top
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = manifest?.packageName ?: analysis.fileName,
                                style = MaterialTheme.typography.headlineSmall,
                                color = MaterialTheme.colorScheme.onSurface,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                text = "${analysis.fileName} · ${BinaryFormatters.formatBytes(analysis.fileSizeBytes)} · parsed in ${analysis.analysisDurationMs} ms",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        StatusPill(
                            text = "${analysis.entries.size} entries",
                            containerColor = MaterialTheme.colorScheme.primaryContainer,
                            contentColor = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                    }

                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        if (manifest != null) {
                            StatusPill(
                                text = "v${manifest.versionName} (${manifest.versionCode})",
                                containerColor = MaterialTheme.colorScheme.surfaceVariant,
                                contentColor = MaterialTheme.colorScheme.onSurface
                            )
                            StatusPill(
                                text = "minSdk ${manifest.minSdk} · targetSdk ${manifest.targetSdk}",
                                containerColor = MaterialTheme.colorScheme.surfaceVariant,
                                contentColor = MaterialTheme.colorScheme.onSurface
                            )
                        }
                        analysis.signingSchemes.forEach { scheme ->
                            StatusPill(
                                text = "Sig $scheme",
                                containerColor = MaterialTheme.colorScheme.tertiaryContainer,
                                contentColor = MaterialTheme.colorScheme.onTertiaryContainer
                            )
                        }
                    }

                    HorizontalDivider(color = syntax.borderSubtle)

                    CopyableKeyValueRow(
                        label = "SHA-256",
                        value = analysis.sha256,
                        onCopied = onCopiedNotice
                    )
                    CopyableKeyValueRow(
                        label = "MD5",
                        value = analysis.md5,
                        onCopied = onCopiedNotice
                    )
                }
            }
        }

        item {
            TerminalCard(modifier = Modifier.widthIn(max = 760.dp)) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    SectionLabel(
                        title = "Binary Composition",
                        subtitle = "Uncompressed footprint across Dalvik DEX, native ELF, and resources"
                    )
                    BinaryCompositionBar(
                        dexBytes = analysis.totalDexBytes,
                        nativeBytes = analysis.totalNativeBytes,
                        resourceBytes = analysis.totalResourceBytes,
                        otherBytes = analysis.totalOtherBytes
                    )
                }
            }
        }

        if (manifest != null) {
            item {
                TerminalCard(modifier = Modifier.widthIn(max = 760.dp)) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Filled.Security,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.secondary,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            SectionLabel(
                                title = "Manifest Posture & Attack Surface",
                                subtitle = "${manifest.permissions.size} permissions · ${manifest.components.size} components"
                            )
                        }
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            StatusPill(
                                text = "debuggable=${manifest.debuggable}",
                                containerColor = if (manifest.debuggable) {
                                    MaterialTheme.colorScheme.errorContainer
                                } else {
                                    MaterialTheme.colorScheme.tertiaryContainer
                                },
                                contentColor = if (manifest.debuggable) {
                                    MaterialTheme.colorScheme.onErrorContainer
                                } else {
                                    MaterialTheme.colorScheme.onTertiaryContainer
                                }
                            )
                            manifest.allowBackup?.let { backup ->
                                StatusPill(
                                    text = "allowBackup=$backup",
                                    containerColor = MaterialTheme.colorScheme.secondaryContainer,
                                    contentColor = MaterialTheme.colorScheme.onSecondaryContainer
                                )
                            }
                            manifest.usesCleartextTraffic?.let { clear ->
                                StatusPill(
                                    text = "cleartext=$clear",
                                    containerColor = if (clear) {
                                        MaterialTheme.colorScheme.errorContainer
                                    } else {
                                        MaterialTheme.colorScheme.surfaceVariant
                                    },
                                    contentColor = if (clear) {
                                        MaterialTheme.colorScheme.onErrorContainer
                                    } else {
                                        MaterialTheme.colorScheme.onSurface
                                    }
                                )
                            }
                            val exportedCount = manifest.components.count { it.exported == true }
                            StatusPill(
                                text = "$exportedCount exported components",
                                containerColor = MaterialTheme.colorScheme.primaryContainer,
                                contentColor = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                        }
                    }
                }
            }
        }

        item {
            Column(
                modifier = Modifier.widthIn(max = 760.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                SectionLabel(title = "Workbench Modules")
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    ModuleQuickCard(
                        icon = Icons.Filled.Code,
                        title = "Smali & DEX",
                        detail = "${analysis.dexFiles.size} DEX · ${analysis.dexFiles.sumOf { it.classDefCount }} classes",
                        onClick = onNavigateDex,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("overview_goto_dex")
                    )
                    ModuleQuickCard(
                        icon = Icons.Filled.Memory,
                        title = "Native ELF",
                        detail = "${analysis.elfFiles.size} .so · ${analysis.availableAbis.size} ABIs",
                        onClick = onNavigateElf,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("overview_goto_elf")
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    ModuleQuickCard(
                        icon = Icons.Filled.Description,
                        title = "Strings & Leaks",
                        detail = "${analysis.printableStrings.size} strings · ${analysis.leakFindingsCount} flagged",
                        onClick = onNavigateInspect,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("overview_goto_inspect")
                    )
                    ModuleQuickCard(
                        icon = Icons.Filled.Archive,
                        title = "Ghidra Bundle",
                        detail = "Ready for desktop",
                        onClick = onNavigateExport,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("overview_goto_export")
                    )
                }
            }
        }

        item {
            Row(
                modifier = Modifier
                    .widthIn(max = 760.dp)
                    .fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Button(
                    onClick = onNavigateExport,
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 48.dp)
                        .testTag("overview_primary_export")
                ) {
                    Icon(
                        imageVector = Icons.Filled.VerifiedUser,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Prepare Ghidra Export")
                }
                OutlinedButton(
                    onClick = onOpenAnotherApk,
                    modifier = Modifier
                        .heightIn(min = 48.dp)
                        .testTag("overview_open_another")
                ) {
                    Text("Open APK")
                }
            }
            Spacer(modifier = Modifier.height(12.dp))
        }
    }
}

@Composable
private fun ModuleQuickCard(
    icon: ImageVector,
    title: String,
    detail: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    TerminalCard(
        modifier = modifier,
        onClick = onClick
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = title,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(16.dp)
                )
            }
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = detail,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}
