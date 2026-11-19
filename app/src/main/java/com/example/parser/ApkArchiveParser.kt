package com.example.parser

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.example.model.ApkAnalysis
import com.example.model.ApkEntryInfo
import com.example.model.DalvikInstruction
import com.example.model.DexClassInfo
import com.example.model.DexMethodInfo
import com.example.model.ElfAnalysis
import com.example.model.EntryCategory
import com.example.model.HexDumpLine
import com.example.model.ManifestAnalysis
import java.io.File
import java.io.RandomAccessFile
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

class LoadedApkSession(
    val analysis: ApkAnalysis,
    private val dexHandles: Map<String, ParsedDexHandle>
) {
    fun disassembleMethod(dexEntryName: String, method: DexMethodInfo): List<DalvikInstruction> {
        return dexHandles[dexEntryName]?.disassemble(method) ?: emptyList()
    }

    fun generateClassSmali(dexEntryName: String, cls: DexClassInfo): String {
        return SmaliGenerator.generateClassSmali(cls, dexHandles[dexEntryName])
    }

    fun readEntryHexDump(entryPath: String, maxBytes: Int = 8192): List<HexDumpLine> {
        val file = File(analysis.cachedApkPath)
        if (!file.exists()) return emptyList()
        return ZipFile(file).use { zip ->
            val entry = zip.getEntry(entryPath) ?: return emptyList()
            zip.getInputStream(entry).use { input ->
                val bytes = BinaryFormatters.readStreamBounded(input, maxBytes)
                BinaryFormatters.buildHexDump(bytes, maxBytes)
            }
        }
    }
}

object ApkArchiveParser {

    fun parseFromUri(context: Context, uri: Uri): LoadedApkSession {
        val workspaceDir = File(context.cacheDir, "workspace").apply { mkdirs() }
        workspaceDir.listFiles()?.forEach { it.delete() }

        val displayName = resolveDisplayName(context, uri)
        val targetFile = File(workspaceDir, "current_target.apk")

        context.contentResolver.openInputStream(uri)?.use { input ->
            targetFile.outputStream().use { output ->
                input.copyTo(output, bufferSize = 32 * 1024)
            }
        } ?: error("Unable to open selected APK stream.")

        return parseFile(targetFile, displayName)
    }

    fun parseFromFilePath(context: Context, filePath: String, displayName: String): LoadedApkSession {
        val sourceFile = File(filePath)
        require(sourceFile.exists() && sourceFile.canRead()) {
            "Selected APK file cannot be read from storage."
        }
        val workspaceDir = File(context.cacheDir, "workspace").apply { mkdirs() }
        workspaceDir.listFiles()?.forEach { it.delete() }
        val targetFile = File(workspaceDir, "current_target.apk")
        sourceFile.copyTo(targetFile, overwrite = true)
        return parseFile(targetFile, displayName)
    }

    fun parseSelfApk(context: Context): LoadedApkSession {
        val sourcePath = context.applicationInfo.sourceDir
        val sourceFile = File(sourcePath)
        require(sourceFile.exists()) { "App source APK is unavailable on this device." }
        val workspaceDir = File(context.cacheDir, "workspace").apply { mkdirs() }
        workspaceDir.listFiles()?.forEach { it.delete() }
        val targetFile = File(workspaceDir, "self_target.apk")
        sourceFile.copyTo(targetFile, overwrite = true)
        return parseFile(targetFile, "Palometa-self.apk")
    }

    private fun parseFile(apkFile: File, displayName: String): LoadedApkSession {
        require(apkFile.length() >= 4) { "Selected file is too small to be a valid .apk archive." }
        val header = ByteArray(4)
        apkFile.inputStream().use { it.read(header) }
        require(header[0] == 0x50.toByte() && header[1] == 0x4B.toByte()) {
            "'$displayName' is not a valid APK/ZIP archive."
        }
        val startMs = System.currentTimeMillis()
        val fileSize = apkFile.length()
        val sha256 = BinaryFormatters.digestFile(apkFile, "SHA-256")
        val md5 = BinaryFormatters.digestFile(apkFile, "MD5")

        val entries = mutableListOf<ApkEntryInfo>()
        var manifestAnalysis: ManifestAnalysis? = null
        val dexHandles = linkedMapOf<String, ParsedDexHandle>()
        val elfAnalyses = mutableListOf<ElfAnalysis>()
        val nativeStringBuffers = mutableListOf<Pair<String, ByteArray>>()
        val assetTextBuffers = mutableListOf<Pair<String, ByteArray>>()
        var hasV1Signature = false

        ZipFile(apkFile).use { zip ->
            val enumEntries = zip.entries()
            while (enumEntries.hasMoreElements()) {
                val entry = enumEntries.nextElement()
                if (entry.isDirectory) continue

                val path = entry.name
                val category = classifyEntry(path)
                if (category == EntryCategory.SIGNATURE &&
                    (path.endsWith(".RSA") || path.endsWith(".DSA") || path.endsWith(".EC") || path.endsWith(".SF"))
                ) {
                    hasV1Signature = true
                }

                entries.add(
                    ApkEntryInfo(
                        path = path,
                        category = category,
                        compressedSize = entry.compressedSize.coerceAtLeast(0L),
                        uncompressedSize = entry.size.coerceAtLeast(0L),
                        crc32Hex = String.format(Locale.US, "%08X", entry.crc),
                        compressionMethod = if (entry.method == ZipEntry.DEFLATED) "DEFLATED" else "STORED"
                    )
                )

                when {
                    path == "AndroidManifest.xml" -> {
                        zip.getInputStream(entry).use { input ->
                            val bytes = BinaryFormatters.readStreamBounded(input, 8 * 1024 * 1024)
                            manifestAnalysis = AxmlDecoder.decode(bytes)
                        }
                    }
                    path.matches(Regex("^classes\\d*\\.dex$")) -> {
                        zip.getInputStream(entry).use { input ->
                            val bytes = BinaryFormatters.readStreamBounded(input, 32 * 1024 * 1024)
                            DexParser.parse(path, bytes)?.let { handle ->
                                dexHandles[path] = handle
                            }
                        }
                    }
                    path.startsWith("lib/") && path.endsWith(".so") -> {
                        zip.getInputStream(entry).use { input ->
                            val bytes = BinaryFormatters.readStreamBounded(input, 24 * 1024 * 1024)
                            ElfParser.parse(path, bytes)?.let { elf ->
                                elfAnalyses.add(elf)
                            }
                            if (nativeStringBuffers.size < 16) {
                                nativeStringBuffers.add(path to bytes)
                            }
                        }
                    }
                    (path.startsWith("assets/") || path.startsWith("res/raw/")) &&
                        isLikelyTextAsset(path) &&
                        assetTextBuffers.size < 20 -> {
                        zip.getInputStream(entry).use { input ->
                            val bytes = BinaryFormatters.readStreamBounded(input, 256 * 1024)
                            assetTextBuffers.add(path to bytes)
                        }
                    }
                }
            }
        }

        val signingSchemes = detectSigningSchemes(apkFile, hasV1Signature)
        val sortedDex = dexHandles.entries.sortedBy { it.key }.associate { it.key to it.value }
        val dexSummaries = sortedDex.values.map { it.summary }

        val printableStrings = ApkStringScanner.scanAll(
            dexFiles = dexSummaries,
            manifest = manifestAnalysis,
            nativeBuffers = nativeStringBuffers,
            assetTextBuffers = assetTextBuffers
        )

        val durationMs = (System.currentTimeMillis() - startMs).coerceAtLeast(1L)

        val analysis = ApkAnalysis(
            fileName = displayName,
            cachedApkPath = apkFile.absolutePath,
            fileSizeBytes = fileSize,
            sha256 = sha256,
            md5 = md5,
            signingSchemes = signingSchemes,
            entries = entries.sortedBy { it.path },
            manifest = manifestAnalysis,
            dexFiles = dexSummaries,
            elfFiles = elfAnalyses.sortedWith(compareBy({ it.abi }, { it.fileName })),
            printableStrings = printableStrings,
            analysisDurationMs = durationMs
        )

        return LoadedApkSession(analysis = analysis, dexHandles = sortedDex)
    }

    private fun isLikelyTextAsset(path: String): Boolean {
        val lower = path.lowercase(Locale.US)
        return lower.endsWith(".json") ||
            lower.endsWith(".xml") ||
            lower.endsWith(".txt") ||
            lower.endsWith(".properties") ||
            lower.endsWith(".cfg") ||
            lower.endsWith(".conf") ||
            lower.endsWith(".yaml") ||
            lower.endsWith(".yml") ||
            lower.endsWith(".js")
    }

    private fun classifyEntry(path: String): EntryCategory = when {
        path.endsWith(".dex") -> EntryCategory.DEX
        path.startsWith("lib/") && path.endsWith(".so") -> EntryCategory.NATIVE_SO
        path == "AndroidManifest.xml" -> EntryCategory.MANIFEST
        path == "resources.arsc" || path.startsWith("res/") -> EntryCategory.RESOURCES
        path.startsWith("META-INF/") -> EntryCategory.SIGNATURE
        path.startsWith("assets/") -> EntryCategory.ASSETS
        else -> EntryCategory.OTHER
    }

    private fun detectSigningSchemes(apkFile: File, hasV1: Boolean): List<String> {
        val schemes = mutableListOf<String>()
        if (hasV1) schemes.add("v1 (JAR)")

        runCatching {
            RandomAccessFile(apkFile, "r").use { raf ->
                val len = raf.length()
                if (len < 64) return@use
                val searchWindow = minOf(len, 65560L).toInt()
                val tail = ByteArray(searchWindow)
                raf.seek(len - searchWindow)
                raf.readFully(tail)

                var eocdOffset = -1
                for (i in tail.size - 22 downTo 0) {
                    if (tail[i] == 0x50.toByte() &&
                        tail[i + 1] == 0x4B.toByte() &&
                        tail[i + 2] == 0x05.toByte() &&
                        tail[i + 3] == 0x06.toByte()
                    ) {
                        eocdOffset = i
                        break
                    }
                }
                if (eocdOffset < 0) return@use

                val cursor = BinaryCursor(tail, littleEndian = true)
                val cdOffset = cursor.u32At(eocdOffset + 16)
                if (cdOffset < 32 || cdOffset > len) return@use

                val magicBuf = ByteArray(16)
                raf.seek(cdOffset - 16)
                raf.readFully(magicBuf)
                val magicStr = String(magicBuf, Charsets.US_ASCII)
                if (magicStr == "APK Sig Block 42") {
                    val sizeLow = ByteArray(8)
                    raf.seek(cdOffset - 24)
                    raf.readFully(sizeLow)
                    val blockSize = BinaryCursor(sizeLow, littleEndian = true).u64At(0)
                    val blockStart = (cdOffset - blockSize - 8).coerceAtLeast(0L)
                    val blockLen = (cdOffset - blockStart).toInt().coerceIn(0, 1024 * 1024)
                    val blockBytes = ByteArray(blockLen)
                    raf.seek(blockStart)
                    raf.readFully(blockBytes)

                    val blockText = BinaryFormatters.toHexString(blockBytes)
                    if (blockText.contains("1a870971")) schemes.add("v2 (APK Sig)")
                    if (blockText.contains("c06853f0")) schemes.add("v3 (Key Rotation)")
                }
            }
        }

        return if (schemes.isEmpty()) listOf("Unsigned") else schemes
    }

    private fun resolveDisplayName(context: Context, uri: Uri): String {
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && cursor.moveToFirst()) {
                val name = cursor.getString(idx)
                if (!name.isNullOrBlank()) return name
            }
        }
        return uri.lastPathSegment?.substringAfterLast('/') ?: "selected.apk"
    }
}
