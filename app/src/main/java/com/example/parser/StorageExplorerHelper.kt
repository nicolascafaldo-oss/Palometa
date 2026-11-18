package com.example.parser

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import com.example.model.RecentApkItem
import com.example.model.StorageDocumentItem

object StorageExplorerHelper {

    private const val PREFS_NAME = "palometa_storage_prefs"
    private const val KEY_TREE_URI = "mounted_tree_uri"
    private const val KEY_RECENT_APKS = "recent_apks"

    fun saveMountedTreeUri(context: Context, treeUri: Uri) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_TREE_URI, treeUri.toString())
            .apply()
    }

    fun getMountedTreeUri(context: Context): Uri? {
        val raw = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(KEY_TREE_URI, null) ?: return null
        return runCatching { Uri.parse(raw) }.getOrNull()
    }

    fun clearMountedTreeUri(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_TREE_URI)
            .apply()
    }

    fun listTreeChildren(
        context: Context,
        treeUri: Uri,
        parentDocumentId: String? = null
    ): Pair<String, List<StorageDocumentItem>> {
        val docId = parentDocumentId ?: DocumentsContract.getTreeDocumentId(treeUri)
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, docId)
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_SIZE,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED
        )

        val items = mutableListOf<StorageDocumentItem>()
        context.contentResolver.query(childrenUri, projection, null, null, null)?.use { cursor ->
            val idIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
            val nameIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
            val mimeIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
            val sizeIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)
            val modIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)

            while (cursor.moveToNext()) {
                val childId = if (idIdx >= 0) cursor.getString(idIdx) else continue
                val name = if (nameIdx >= 0) cursor.getString(nameIdx) ?: "unnamed" else "unnamed"
                val mime = if (mimeIdx >= 0) cursor.getString(mimeIdx) ?: "" else ""
                val size = if (sizeIdx >= 0 && !cursor.isNull(sizeIdx)) cursor.getLong(sizeIdx) else 0L
                val mod = if (modIdx >= 0 && !cursor.isNull(modIdx)) cursor.getLong(modIdx) else 0L
                val isDir = mime == DocumentsContract.Document.MIME_TYPE_DIR
                val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, childId)

                items.add(
                    StorageDocumentItem(
                        documentId = childId,
                        name = name,
                        isDirectory = isDir,
                        sizeBytes = size,
                        lastModifiedMs = mod,
                        mimeType = mime,
                        documentUriString = docUri.toString()
                    )
                )
            }
        }

        val sorted = items.sortedWith(
            compareByDescending<StorageDocumentItem> { it.isDirectory }
                .thenByDescending { it.isApk }
                .thenBy(String.CASE_INSENSITIVE_ORDER) { it.name }
        )
        return docId to sorted
    }

    fun addRecentApk(context: Context, name: String, uri: Uri, sizeBytes: Long) {
        val current = getRecentApks(context).toMutableList()
        val uriStr = uri.toString()
        current.removeAll { it.uriString == uriStr }
        current.add(0, RecentApkItem(name = name, uriString = uriStr, sizeBytes = sizeBytes))
        val serialized = current.take(8).joinToString("\n") {
            "${it.name.replace("|", "_")}|${it.sizeBytes}|${it.uriString}"
        }
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_RECENT_APKS, serialized)
            .apply()
    }

    fun getRecentApks(context: Context): List<RecentApkItem> {
        val raw = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(KEY_RECENT_APKS, null) ?: return emptyList()
        return raw.lineSequence()
            .mapNotNull { line ->
                val parts = line.split('|', limit = 3)
                if (parts.size == 3) {
                    RecentApkItem(
                        name = parts[0],
                        sizeBytes = parts[1].toLongOrNull() ?: 0L,
                        uriString = parts[2]
                    )
                } else null
            }
            .toList()
    }
}
