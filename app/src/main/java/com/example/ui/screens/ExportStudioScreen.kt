package com.example.ui.screens

import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Switch
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.model.ApkAnalysis
import com.example.model.ExportBundlePreview
import com.example.model.ExportConfig
import com.example.parser.BinaryFormatters
import com.example.ui.components.SectionLabel
import com.example.ui.components.StatusPill
import com.example.ui.components.TerminalCard
import com.example.ui.theme.LocalDexScopeSyntax
import com.example.ui.theme.MonoCodeStyle
import com.example.ui.theme.MonoLabelStyle
import com.example.viewmodel.ExportStatus

@OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)
@Composable
fun ExportStudioScreen(
    analysis: ApkAnalysis,
    config: ExportConfig,
    preview: ExportBundlePreview?,
    exportStatus: ExportStatus,
    onProjectNameChange: (String) -> Unit,
    onToggleDex: (Boolean) -> Unit,
    onToggleNative: (Boolean) -> Unit,
    onToggleManifest: (Boolean) -> Unit,
    onToggleSigning: (Boolean) -> Unit,
    onToggleScripts: (Boolean) -> Unit,
    onToggleAbi: (String) -> Unit,
    onSaveBundleClick: () -> Unit,
    onShareBundleClick: () -> Unit,
    onCopiedNotice: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val syntax = LocalDexScopeSyntax.current
    val clipboard = LocalClipboardManager.current
    var previewTab by rememberSaveable { mutableIntStateOf(0) }
    val isExporting = exportStatus is ExportStatus.Exporting

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
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    SectionLabel(
                        title = "Ghidra Workstation Bundle",
                        subtitle = "Package extracted DEX, native .so libraries, decoded XML, and headless import scripts"
                    )

                    OutlinedTextField(
                        value = config.projectName,
                        onValueChange = onProjectNameChange,
                        label = { Text("Workstation Project Name") },
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("export_project_name_input")
                    )

                    ExportToggleRow(
                        title = "Dalvik DEX Bytecode",
                        subtitle = "${analysis.dexFiles.size} DEX files · ${BinaryFormatters.formatBytes(analysis.totalDexBytes)}",
                        checked = config.includeDex,
                        enabled = analysis.dexFiles.isNotEmpty(),
                        onCheckedChange = onToggleDex
                    )
                    ExportToggleRow(
                        title = "Native ELF Shared Libraries (.so)",
                        subtitle = "${analysis.elfFiles.size} libraries · ${BinaryFormatters.formatBytes(analysis.totalNativeBytes)}",
                        checked = config.includeNativeLibs,
                        enabled = analysis.elfFiles.isNotEmpty(),
                        onCheckedChange = onToggleNative
                    )

                    if (config.includeNativeLibs && analysis.availableAbis.isNotEmpty()) {
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            analysis.availableAbis.forEach { abi ->
                                FilterChip(
                                    selected = abi in config.selectedAbis,
                                    onClick = { onToggleAbi(abi) },
                                    label = { Text(abi, style = MonoLabelStyle) }
                                )
                            }
                        }
                    }

                    ExportToggleRow(
                        title = "Decoded AndroidManifest.xml",
                        subtitle = "Plaintext UTF-8 manifest XML",
                        checked = config.includeDecodedManifest,
                        enabled = analysis.manifest != null,
                        onCheckedChange = onToggleManifest
                    )
                    ExportToggleRow(
                        title = "Signing & META-INF Artifacts",
                        subtitle = analysis.signingSchemes.joinToString(", "),
                        checked = config.includeSigningMeta,
                        enabled = true,
                        onCheckedChange = onToggleSigning
                    )
                    ExportToggleRow(
                        title = "Ghidra Helper Script & JSON Manifest",
                        subtitle = "import_manifest.json + ghidra_import_helper.py + README",
                        checked = config.includeGhidraScripts,
                        enabled = true,
                        onCheckedChange = onToggleScripts
                    )
                }
            }
        }

        if (preview != null) {
            item {
                TerminalCard(modifier = Modifier.widthIn(max = 760.dp)) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "Bundle Staging Preview",
                                style = MaterialTheme.typography.titleMedium
                            )
                            StatusPill(
                                text = "${preview.includedPaths.size} files · ~${BinaryFormatters.formatBytes(preview.estimatedUncompressedBytes)}",
                                containerColor = MaterialTheme.colorScheme.primaryContainer,
                                contentColor = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                        }

                        PrimaryTabRow(selectedTabIndex = previewTab) {
                            Tab(selected = previewTab == 0, onClick = { previewTab = 0 }, text = { Text("CLI & Tree") })
                            Tab(selected = previewTab == 1, onClick = { previewTab = 1 }, text = { Text("Manifest JSON") })
                            Tab(selected = previewTab == 2, onClick = { previewTab = 2 }, text = { Text("Ghidra .py") })
                        }

                        val previewText = when (previewTab) {
                            0 -> buildString {
                                appendLine("# Desktop analyzeHeadless command:")
                                appendLine(preview.headlessCommand)
                                appendLine()
                                appendLine("# Staged archive entries (${preview.includedPaths.size}):")
                                preview.includedPaths.take(40).forEach { appendLine("  $it") }
                                if (preview.includedPaths.size > 40) {
                                    appendLine("  ... +${preview.includedPaths.size - 40} more")
                                }
                            }
                            1 -> preview.importManifestJson
                            else -> preview.ghidraPythonScript
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.End
                        ) {
                            IconButton(
                                onClick = {
                                    val copyPayload = if (previewTab == 0) preview.headlessCommand else previewText
                                    clipboard.setText(AnnotatedString(copyPayload))
                                    onCopiedNotice("Workstation snippet")
                                },
                                modifier = Modifier.minimumInteractiveComponentSize()
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.ContentCopy,
                                    contentDescription = "Copy preview snippet",
                                    tint = MaterialTheme.colorScheme.primary
                                )
                            }
                        }

                        HorizontalDivider(color = syntax.borderSubtle)
                        Text(
                            text = previewText,
                            style = MonoCodeStyle,
                            color = syntax.register,
                            modifier = Modifier
                                .fillMaxWidth()
                                .horizontalScroll(rememberScrollState())
                                .padding(top = 6.dp)
                        )
                    }
                }
            }
        }

        if (exportStatus is ExportStatus.SavedToDocument || exportStatus is ExportStatus.ReadyToShare) {
            val info = (exportStatus as? ExportStatus.SavedToDocument)?.info
                ?: (exportStatus as ExportStatus.ReadyToShare).info
            item {
                TerminalCard(modifier = Modifier.widthIn(max = 760.dp)) {
                    Row(
                        modifier = Modifier.padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Filled.CheckCircle,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.tertiary
                        )
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Bundle Ready: ${info.fileName}",
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = "${info.entryCount} entries packaged · SHA-256 ${info.sha256.take(16)}…",
                                style = MonoLabelStyle,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        } else if (exportStatus is ExportStatus.Failed) {
            item {
                TerminalCard(modifier = Modifier.widthIn(max = 760.dp)) {
                    Text(
                        text = "Export failed: ${exportStatus.message}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(14.dp)
                    )
                }
            }
        }

        item {
            Column(
                modifier = Modifier.widthIn(max = 760.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Button(
                    onClick = onSaveBundleClick,
                    enabled = !isExporting && (preview?.includedPaths?.isNotEmpty() == true),
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 50.dp)
                        .testTag("export_save_zip_button")
                ) {
                    if (isExporting) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onPrimary
                        )
                    } else {
                        Icon(Icons.Filled.Download, contentDescription = null, modifier = Modifier.size(18.dp))
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.action_save_bundle))
                }
                OutlinedButton(
                    onClick = onShareBundleClick,
                    enabled = !isExporting && (preview?.includedPaths?.isNotEmpty() == true),
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag("export_share_zip_button")
                ) {
                    Icon(Icons.Filled.Share, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.action_share_bundle))
                }
                Spacer(modifier = Modifier.height(12.dp))
            }
        }
    }
}

@Composable
private fun ExportToggleRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyLarge,
                color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            enabled = enabled
        )
    }
}
