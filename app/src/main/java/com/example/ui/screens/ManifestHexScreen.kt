package com.example.ui.screens

import androidx.activity.compose.BackHandler
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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.WarningAmber
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.model.ApkAnalysis
import com.example.model.HexDumpLine
import com.example.model.StringFindingCategory
import com.example.parser.BinaryFormatters
import com.example.ui.components.StatusPill
import com.example.ui.components.TerminalCard
import com.example.ui.theme.LocalDexScopeSyntax
import com.example.ui.theme.MonoCodeStyle
import com.example.ui.theme.MonoLabelStyle

@OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)
@Composable
fun ManifestHexScreen(
    analysis: ApkAnalysis,
    stringSearchQuery: String,
    leaksOnlyFilter: Boolean,
    stringCategoryFilter: StringFindingCategory?,
    entrySearch: String,
    hexEntryPath: String?,
    hexLines: List<HexDumpLine>,
    onStringSearchChange: (String) -> Unit,
    onToggleLeaksOnly: () -> Unit,
    onSelectStringCategory: (StringFindingCategory?) -> Unit,
    onEntrySearchChange: (String) -> Unit,
    onOpenHexEntry: (String) -> Unit,
    onCloseHexEntry: () -> Unit,
    onCopiedNotice: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    if (hexEntryPath != null) {
        BackHandler { onCloseHexEntry() }
        HexInspectorView(
            entryPath = hexEntryPath,
            lines = hexLines,
            onBack = onCloseHexEntry,
            onCopiedNotice = onCopiedNotice,
            modifier = modifier
        )
        return
    }

    var activeTab by rememberSaveable { mutableIntStateOf(0) }
    val clipboard = LocalClipboardManager.current
    val syntax = LocalDexScopeSyntax.current
    val manifest = analysis.manifest

    Column(modifier = modifier.fillMaxSize()) {
        PrimaryTabRow(selectedTabIndex = activeTab) {
            Tab(
                selected = activeTab == 0,
                onClick = { activeTab = 0 },
                text = { Text("Strings (${analysis.printableStrings.size})") }
            )
            Tab(
                selected = activeTab == 1,
                onClick = { activeTab = 1 },
                text = { Text("Manifest XML") }
            )
            Tab(
                selected = activeTab == 2,
                onClick = { activeTab = 2 },
                text = { Text("Hex (${analysis.entries.size})") }
            )
        }

        when (activeTab) {
            0 -> {
                val filteredStrings = remember(
                    analysis.printableStrings,
                    stringSearchQuery,
                    leaksOnlyFilter,
                    stringCategoryFilter
                ) {
                    analysis.printableStrings.filter { item ->
                        val leakMatch = !leaksOnlyFilter || item.category.isPotentialLeak
                        val catMatch = stringCategoryFilter == null || item.category == stringCategoryFilter
                        val queryMatch = stringSearchQuery.isBlank() ||
                            item.value.contains(stringSearchQuery, ignoreCase = true) ||
                            item.sourceFile.contains(stringSearchQuery, ignoreCase = true)
                        leakMatch && catMatch && queryMatch
                    }
                }

                TerminalCard(
                    modifier = Modifier
                        .padding(horizontal = 16.dp, vertical = 8.dp)
                        .widthIn(max = 760.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 14.dp, vertical = 10.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Filled.WarningAmber,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.secondary,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "${analysis.leakFindingsCount} potential leaks / hardcoded strings",
                                style = MaterialTheme.typography.labelLarge,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                        Text(
                            text = "${filteredStrings.size} shown",
                            style = MonoLabelStyle,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }

                OutlinedTextField(
                    value = stringSearchQuery,
                    onValueChange = onStringSearchChange,
                    placeholder = { Text("Search URLs, keys, IPs, paths, or printable strings…") },
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    trailingIcon = {
                        if (stringSearchQuery.isNotEmpty()) {
                            IconButton(
                                onClick = { onStringSearchChange("") },
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
                        .testTag("strings_search_input")
                )

                LazyRow(
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 6.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    item {
                        FilterChip(
                            selected = leaksOnlyFilter,
                            onClick = onToggleLeaksOnly,
                            label = { Text("Potential Leaks Only", style = MonoLabelStyle) },
                            modifier = Modifier.testTag("filter_leaks_only_chip")
                        )
                    }
                    items(StringFindingCategory.entries) { cat ->
                        FilterChip(
                            selected = stringCategoryFilter == cat,
                            onClick = { onSelectStringCategory(cat) },
                            label = { Text(cat.label, style = MonoLabelStyle) }
                        )
                    }
                }

                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    if (filteredStrings.isEmpty()) {
                        item {
                            Text(
                                text = "No printable strings match the current filter.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    items(filteredStrings.take(500), key = { it.id }) { finding ->
                        TerminalCard(modifier = Modifier.widthIn(max = 760.dp)) {
                            Column(
                                modifier = Modifier.padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    StatusPill(
                                        text = finding.category.label,
                                        containerColor = if (finding.category.isPotentialLeak) {
                                            MaterialTheme.colorScheme.errorContainer
                                        } else {
                                            MaterialTheme.colorScheme.surfaceVariant
                                        },
                                        contentColor = if (finding.category.isPotentialLeak) {
                                            MaterialTheme.colorScheme.onErrorContainer
                                        } else {
                                            MaterialTheme.colorScheme.onSurfaceVariant
                                        }
                                    )
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(
                                            text = finding.sourceFile.substringAfterLast('/'),
                                            style = MonoLabelStyle,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                        IconButton(
                                            onClick = {
                                                clipboard.setText(AnnotatedString(finding.value))
                                                onCopiedNotice("String finding")
                                            },
                                            modifier = Modifier.minimumInteractiveComponentSize()
                                        ) {
                                            Icon(
                                                imageVector = Icons.Filled.ContentCopy,
                                                contentDescription = "Copy string",
                                                tint = MaterialTheme.colorScheme.primary,
                                                modifier = Modifier.size(16.dp)
                                            )
                                        }
                                    }
                                }
                                Text(
                                    text = finding.value,
                                    style = MonoCodeStyle,
                                    color = if (finding.category.isPotentialLeak) {
                                        syntax.opcode
                                    } else {
                                        MaterialTheme.colorScheme.onSurface
                                    }
                                )
                            }
                        }
                    }
                }
            }

            1 -> {
                if (manifest == null) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(24.dp),
                        verticalArrangement = Arrangement.Center,
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "AndroidManifest.xml was not found in this archive.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        if (manifest.permissions.isNotEmpty()) {
                            item {
                                TerminalCard(modifier = Modifier.widthIn(max = 760.dp)) {
                                    Column(
                                        modifier = Modifier.padding(14.dp),
                                        verticalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        Text(
                                            text = "Declared Permissions (${manifest.permissions.size})",
                                            style = MaterialTheme.typography.titleMedium,
                                            color = MaterialTheme.colorScheme.onSurface
                                        )
                                        FlowRow(
                                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                                            verticalArrangement = Arrangement.spacedBy(6.dp)
                                        ) {
                                            manifest.permissions.forEach { perm ->
                                                StatusPill(
                                                    text = perm.removePrefix("android.permission."),
                                                    containerColor = MaterialTheme.colorScheme.secondaryContainer,
                                                    contentColor = MaterialTheme.colorScheme.onSecondaryContainer
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        item {
                            TerminalCard(modifier = Modifier.widthIn(max = 760.dp)) {
                                Column(modifier = Modifier.padding(14.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = "Decoded AXML",
                                            style = MaterialTheme.typography.titleMedium,
                                            color = MaterialTheme.colorScheme.onSurface
                                        )
                                        IconButton(
                                            onClick = {
                                                clipboard.setText(AnnotatedString(manifest.decodedXml))
                                                onCopiedNotice("AndroidManifest.xml")
                                            },
                                            modifier = Modifier
                                                .minimumInteractiveComponentSize()
                                                .testTag("copy_manifest_xml_button")
                                        ) {
                                            Icon(
                                                imageVector = Icons.Filled.ContentCopy,
                                                contentDescription = "Copy decoded manifest XML",
                                                tint = MaterialTheme.colorScheme.primary
                                            )
                                        }
                                    }
                                    HorizontalDivider(color = syntax.borderSubtle)
                                    Spacer(modifier = Modifier.height(10.dp))
                                    Text(
                                        text = manifest.decodedXml,
                                        style = MonoCodeStyle,
                                        color = syntax.register,
                                        modifier = Modifier.horizontalScroll(rememberScrollState())
                                    )
                                }
                            }
                        }
                    }
                }
            }

            else -> {
                val filteredEntries = remember(analysis.entries, entrySearch) {
                    if (entrySearch.isBlank()) analysis.entries
                    else analysis.entries.filter {
                        it.path.contains(entrySearch, ignoreCase = true) ||
                            it.category.label.contains(entrySearch, ignoreCase = true)
                    }
                }

                OutlinedTextField(
                    value = entrySearch,
                    onValueChange = onEntrySearchChange,
                    placeholder = { Text("Search APK entries (e.g. .dex, .so, assets/)…") },
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    trailingIcon = {
                        if (entrySearch.isNotEmpty()) {
                            IconButton(
                                onClick = { onEntrySearchChange("") },
                                modifier = Modifier.minimumInteractiveComponentSize()
                            ) {
                                Icon(Icons.Filled.Clear, contentDescription = "Clear search")
                            }
                        }
                    },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 8.dp)
                        .testTag("archive_search_input")
                )

                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    items(filteredEntries.take(400), key = { it.path }) { entry ->
                        TerminalCard(
                            modifier = Modifier
                                .widthIn(max = 760.dp)
                                .testTag("apk_entry_${entry.path}"),
                            onClick = { onOpenHexEntry(entry.path) }
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = entry.path,
                                        style = MonoCodeStyle,
                                        color = MaterialTheme.colorScheme.onSurface,
                                        maxLines = 2,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Text(
                                        text = "${entry.category.label} · CRC32 ${entry.crc32Hex} · ${entry.compressionMethod}",
                                        style = MonoLabelStyle,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = BinaryFormatters.formatBytes(entry.uncompressedSize),
                                    style = MonoLabelStyle,
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun HexInspectorView(
    entryPath: String,
    lines: List<HexDumpLine>,
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
                    .testTag("hex_viewer_back")
            ) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back to archive entries")
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = entryPath.substringAfterLast('/'),
                    style = MaterialTheme.typography.titleLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "$entryPath · first ${lines.size * 16} bytes",
                    style = MonoLabelStyle,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            IconButton(
                onClick = {
                    val dump = lines.joinToString("\n") { "${it.offsetHex}  ${it.hexBytes}  |${it.asciiText}|" }
                    clipboard.setText(AnnotatedString(dump))
                    onCopiedNotice("Hex dump")
                },
                modifier = Modifier.minimumInteractiveComponentSize()
            ) {
                Icon(Icons.Filled.ContentCopy, contentDescription = "Copy hex dump")
            }
        }

        HorizontalDivider(color = syntax.borderSubtle)

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .horizontalScroll(rememberScrollState()),
            contentPadding = PaddingValues(14.dp),
            verticalArrangement = Arrangement.spacedBy(3.dp)
        ) {
            items(lines, key = { it.offsetHex }) { line ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = line.offsetHex,
                        style = MonoCodeStyle,
                        color = syntax.addressOffset,
                        modifier = Modifier.width(84.dp)
                    )
                    Text(
                        text = line.hexBytes,
                        style = MonoCodeStyle,
                        color = syntax.register,
                        modifier = Modifier.width(420.dp)
                    )
                    Text(
                        text = "|${line.asciiText}|",
                        style = MonoCodeStyle,
                        color = syntax.stringLiteral
                    )
                }
            }
        }
    }
}
