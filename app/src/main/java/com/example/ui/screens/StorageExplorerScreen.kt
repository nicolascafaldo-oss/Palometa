package com.example.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.CreateNewFolder
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.model.StorageDocumentItem
import com.example.parser.BinaryFormatters
import com.example.ui.components.SectionLabel
import com.example.ui.components.StatusPill
import com.example.ui.components.TerminalCard
import com.example.ui.theme.LocalDexScopeSyntax
import com.example.ui.theme.MonoLabelStyle
import com.example.viewmodel.StorageExplorerState

@Composable
fun StorageExplorerOverlay(
    state: StorageExplorerState,
    onClose: () -> Unit,
    onMountFolderClick: () -> Unit,
    onSystemFilePickerClick: () -> Unit,
    onInspectSelfClick: () -> Unit,
    onSelectRecentUri: (String) -> Unit,
    onEnterDirectory: (StorageDocumentItem) -> Unit,
    onSelectApkDocument: (StorageDocumentItem) -> Unit,
    onNavigateBreadcrumb: (Int) -> Unit,
    onToggleApkOnlyFilter: () -> Unit,
    modifier: Modifier = Modifier
) {
    BackHandler {
        if (state.breadcrumbs.size > 1) {
            onNavigateBreadcrumb(state.breadcrumbs.lastIndex - 1)
        } else {
            onClose()
        }
    }

    val syntax = LocalDexScopeSyntax.current
    val displayedItems = remember(state.items, state.apkOnlyFilter) {
        if (state.apkOnlyFilter) {
            state.items.filter { it.isDirectory || it.isApk }
        } else {
            state.items
        }
    }

    Surface(
        modifier = modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .windowInsetsPadding(WindowInsets.safeDrawing)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 8.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(
                    onClick = onClose,
                    modifier = Modifier
                        .minimumInteractiveComponentSize()
                        .testTag("storage_explorer_close")
                ) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Close file explorer")
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Device APK File Explorer",
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.onBackground
                    )
                    Text(
                        text = "Browse storage folders or pick an .apk package",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            HorizontalDivider(color = syntax.borderSubtle)

            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                item {
                    TerminalCard(modifier = Modifier.widthIn(max = 760.dp)) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            SectionLabel(
                                title = "Storage Access",
                                subtitle = "Mount a device directory (e.g. Downloads) or pick a single .apk file"
                            )
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Button(
                                    onClick = onMountFolderClick,
                                    modifier = Modifier
                                        .weight(1f)
                                        .heightIn(min = 48.dp)
                                        .testTag("explorer_mount_folder_button")
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.CreateNewFolder,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(if (state.mountedTreeUri == null) "Mount Folder" else "Change Folder")
                                }
                                OutlinedButton(
                                    onClick = onSystemFilePickerClick,
                                    modifier = Modifier
                                        .weight(1f)
                                        .heightIn(min = 48.dp)
                                        .testTag("explorer_system_picker_button")
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.FolderOpen,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Quick Pick .apk")
                                }
                            }
                            OutlinedButton(
                                onClick = onInspectSelfClick,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .heightIn(min = 48.dp)
                                    .testTag("explorer_self_apk_button")
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Memory,
                                    contentDescription = null,
                                    modifier = Modifier.size(18.dp)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Inspect Built-in Demo APK (Palometa-self.apk)")
                            }
                        }
                    }
                }

                if (state.recentApks.isNotEmpty()) {
                    item {
                        Column(
                            modifier = Modifier.widthIn(max = 760.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = Icons.Filled.History,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.secondary,
                                    modifier = Modifier.size(18.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    text = "Recent APKs",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = MaterialTheme.colorScheme.onBackground
                                )
                            }
                            state.recentApks.forEach { recent ->
                                TerminalCard(
                                    onClick = { onSelectRecentUri(recent.uriString) },
                                    modifier = Modifier.testTag("recent_apk_${recent.name}")
                                ) {
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(12.dp),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Row(
                                            verticalAlignment = Alignment.CenterVertically,
                                            modifier = Modifier.weight(1f)
                                        ) {
                                            Icon(
                                                imageVector = Icons.Filled.Android,
                                                contentDescription = null,
                                                tint = MaterialTheme.colorScheme.tertiary,
                                                modifier = Modifier.size(20.dp)
                                            )
                                            Spacer(modifier = Modifier.width(10.dp))
                                            Column {
                                                Text(
                                                    text = recent.name,
                                                    style = MaterialTheme.typography.bodyLarge,
                                                    maxLines = 1,
                                                    overflow = TextOverflow.Ellipsis
                                                )
                                                Text(
                                                    text = BinaryFormatters.formatBytes(recent.sizeBytes),
                                                    style = MonoLabelStyle,
                                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                                )
                                            }
                                        }
                                        StatusPill(
                                            text = "LOAD",
                                            containerColor = MaterialTheme.colorScheme.primaryContainer,
                                            contentColor = MaterialTheme.colorScheme.onPrimaryContainer
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                if (state.browserError != null) {
                    item {
                        TerminalCard(modifier = Modifier.widthIn(max = 760.dp)) {
                            Text(
                                text = state.browserError,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.error,
                                modifier = Modifier.padding(14.dp)
                            )
                        }
                    }
                }

                if (state.mountedTreeUri != null) {
                    item {
                        Column(
                            modifier = Modifier.widthIn(max = 760.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "Directory Browser",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = MaterialTheme.colorScheme.onBackground
                                )
                                FilterChip(
                                    selected = state.apkOnlyFilter,
                                    onClick = onToggleApkOnlyFilter,
                                    label = { Text(".apk only", style = MonoLabelStyle) }
                                )
                            }

                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .horizontalScroll(rememberScrollState()),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                state.breadcrumbs.forEachIndexed { idx, crumb ->
                                    TextButton(
                                        onClick = { onNavigateBreadcrumb(idx) },
                                        modifier = Modifier.minimumInteractiveComponentSize()
                                    ) {
                                        Text(
                                            text = crumb.label,
                                            style = MonoLabelStyle,
                                            fontWeight = if (idx == state.breadcrumbs.lastIndex) FontWeight.Bold else FontWeight.Normal
                                        )
                                    }
                                    if (idx < state.breadcrumbs.lastIndex) {
                                        Icon(
                                            imageVector = Icons.Filled.ChevronRight,
                                            contentDescription = null,
                                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                            modifier = Modifier.size(16.dp)
                                        )
                                    }
                                }
                            }
                        }
                    }

                    if (state.isBrowsing) {
                        item {
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(24.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                CircularProgressIndicator()
                            }
                        }
                    } else if (displayedItems.isEmpty()) {
                        item {
                            TerminalCard(modifier = Modifier.widthIn(max = 760.dp)) {
                                Text(
                                    text = if (state.apkOnlyFilter) {
                                        "No folders or .apk files in this directory. Toggle '.apk only' to view all files."
                                    } else {
                                        "This directory is empty."
                                    },
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(16.dp)
                                )
                            }
                        }
                    } else {
                        items(displayedItems, key = { it.documentId }) { item ->
                            TerminalCard(
                                modifier = Modifier
                                    .widthIn(max = 760.dp)
                                    .testTag("explorer_item_${item.name}"),
                                onClick = when {
                                    item.isDirectory -> ({ onEnterDirectory(item) })
                                    item.isApk -> ({ onSelectApkDocument(item) })
                                    else -> null
                                }
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier.weight(1f)
                                    ) {
                                        Icon(
                                            imageVector = when {
                                                item.isDirectory -> Icons.Filled.Folder
                                                item.isApk -> Icons.Filled.Android
                                                else -> Icons.AutoMirrored.Filled.InsertDriveFile
                                            },
                                            contentDescription = null,
                                            tint = when {
                                                item.isDirectory -> MaterialTheme.colorScheme.secondary
                                                item.isApk -> MaterialTheme.colorScheme.primary
                                                else -> MaterialTheme.colorScheme.onSurfaceVariant
                                            },
                                            modifier = Modifier.size(22.dp)
                                        )
                                        Spacer(modifier = Modifier.width(12.dp))
                                        Column {
                                            Text(
                                                text = item.name,
                                                style = MaterialTheme.typography.bodyLarge,
                                                color = if (item.isDirectory || item.isApk) {
                                                    MaterialTheme.colorScheme.onSurface
                                                } else {
                                                    MaterialTheme.colorScheme.onSurfaceVariant
                                                },
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                            Text(
                                                text = if (item.isDirectory) {
                                                    "Directory"
                                                } else {
                                                    BinaryFormatters.formatBytes(item.sizeBytes)
                                                },
                                                style = MonoLabelStyle,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                    }
                                    if (item.isApk) {
                                        StatusPill(
                                            text = "APK",
                                            containerColor = MaterialTheme.colorScheme.primaryContainer,
                                            contentColor = MaterialTheme.colorScheme.onPrimaryContainer
                                        )
                                    } else if (item.isDirectory) {
                                        Icon(
                                            imageVector = Icons.Filled.ChevronRight,
                                            contentDescription = "Open directory",
                                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                item { Spacer(modifier = Modifier.height(16.dp)) }
            }
        }
    }
}
