package com.example.export

import android.content.Context
import com.example.model.ApkAnalysis
import com.example.model.EntryCategory
import com.example.model.ExportBundlePreview
import com.example.model.ExportConfig
import com.example.model.ExportSuccessInfo
import com.example.parser.BinaryFormatters
import java.io.File
import java.io.OutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

object WorkstationExporter {

    fun buildPreview(analysis: ApkAnalysis, config: ExportConfig): ExportBundlePreview {
        val included = mutableListOf<String>()
        var estimatedBytes = 0L

        if (config.includeDex) {
            analysis.entries.filter { it.category == EntryCategory.DEX }.forEach {
                included.add("dex/${it.path.substringAfterLast('/')}")
                estimatedBytes += it.uncompressedSize
            }
        }

        if (config.includeNativeLibs) {
            val activeAbis = config.selectedAbis.ifEmpty { analysis.availableAbis.toSet() }
            analysis.entries.filter { entry ->
                entry.category == EntryCategory.NATIVE_SO &&
                    activeAbis.any { abi -> entry.path.startsWith("lib/$abi/") }
            }.forEach {
                included.add("native/${it.path.removePrefix("lib/")}")
                estimatedBytes += it.uncompressedSize
            }
        }

        if (config.includeDecodedManifest && analysis.manifest != null) {
            included.add("decoded/AndroidManifest.xml")
            estimatedBytes += analysis.manifest.decodedXml.length
        }

        if (config.includeSigningMeta) {
            analysis.entries.filter { it.category == EntryCategory.SIGNATURE }.forEach {
                included.add("meta/${it.path.removePrefix("META-INF/")}")
                estimatedBytes += it.uncompressedSize
            }
        }

        val manifestJson = buildImportManifestJson(analysis, config)
        val pythonScript = buildGhidraHelperScript(analysis, config)
        val readmeMd = buildReadmeMarkdown(analysis, config)

        if (config.includeGhidraScripts) {
            included.add("ghidra_workspace/import_manifest.json")
            included.add("ghidra_workspace/ghidra_import_helper.py")
            included.add("ghidra_workspace/README_ANALYSIS.md")
            estimatedBytes += manifestJson.length + pythonScript.length + readmeMd.length
        }

        val safeProject = sanitizeName(config.projectName)
        val firstElf = analysis.elfFiles.firstOrNull()
        val sampleTarget = if (firstElf != null) {
            "native/${firstElf.abi}/${firstElf.fileName}"
        } else {
            "dex/classes.dex"
        }
        val headlessCmd = buildString {
            append("analyzeHeadless ~/ghidra_projects ")
            append(safeProject)
            append(" -import ./")
            append(sampleTarget)
            if (firstElf != null) {
                append(" -processor \"${firstElf.ghidraLanguageId}\"")
            } else {
                append(" -processor \"Dalvik:LE:32:default\"")
            }
            append(" -postScript ./ghidra_workspace/ghidra_import_helper.py")
        }

        return ExportBundlePreview(
            includedPaths = included,
            estimatedUncompressedBytes = estimatedBytes,
            importManifestJson = manifestJson,
            ghidraPythonScript = pythonScript,
            headlessCommand = headlessCmd
        )
    }

    fun exportToCache(
        context: Context,
        analysis: ApkAnalysis,
        config: ExportConfig
    ): ExportSuccessInfo {
        val exportsDir = File(context.cacheDir, "exports").apply { mkdirs() }
        exportsDir.listFiles()?.forEach { it.delete() }
        val safeName = sanitizeName(config.projectName)
        val outFile = File(exportsDir, "${safeName}_ghidra_bundle.zip")
        val count = outFile.outputStream().use { out ->
            writeZipBundle(analysis, config, out)
        }
        return ExportSuccessInfo(
            fileName = outFile.name,
            byteSize = outFile.length(),
            sha256 = BinaryFormatters.digestFile(outFile, "SHA-256"),
            entryCount = count,
            cachedZipPath = outFile.absolutePath
        )
    }

    fun exportToStream(
        analysis: ApkAnalysis,
        config: ExportConfig,
        outputStream: OutputStream,
        targetName: String
    ): ExportSuccessInfo {
        val count = writeZipBundle(analysis, config, outputStream)
        return ExportSuccessInfo(
            fileName = targetName,
            byteSize = 0L,
            sha256 = analysis.sha256,
            entryCount = count,
            cachedZipPath = ""
        )
    }

    private fun writeZipBundle(
        analysis: ApkAnalysis,
        config: ExportConfig,
        outputStream: OutputStream
    ): Int {
        val sourceApk = File(analysis.cachedApkPath)
        require(sourceApk.exists()) { "Cached APK source missing; please re-open the APK." }

        var writtenEntries = 0
        val activeAbis = config.selectedAbis.ifEmpty { analysis.availableAbis.toSet() }

        ZipOutputStream(outputStream).use { zos ->
            ZipFile(sourceApk).use { srcZip ->
                if (config.includeDex) {
                    analysis.entries.filter { it.category == EntryCategory.DEX }.forEach { entry ->
                        val destPath = "dex/${entry.path.substringAfterLast('/')}"
                        copyZipEntry(srcZip, entry.path, zos, destPath)
                        writtenEntries++
                    }
                }

                if (config.includeNativeLibs) {
                    analysis.entries.filter { entry ->
                        entry.category == EntryCategory.NATIVE_SO &&
                            activeAbis.any { abi -> entry.path.startsWith("lib/$abi/") }
                    }.forEach { entry ->
                        val destPath = "native/${entry.path.removePrefix("lib/")}"
                        copyZipEntry(srcZip, entry.path, zos, destPath)
                        writtenEntries++
                    }
                }

                if (config.includeSigningMeta) {
                    analysis.entries.filter { it.category == EntryCategory.SIGNATURE }.forEach { entry ->
                        val destPath = "meta/${entry.path.removePrefix("META-INF/")}"
                        copyZipEntry(srcZip, entry.path, zos, destPath)
                        writtenEntries++
                    }
                }
            }

            if (config.includeDecodedManifest && analysis.manifest != null) {
                writeTextEntry(zos, "decoded/AndroidManifest.xml", analysis.manifest.decodedXml)
                writtenEntries++
            }

            if (config.includeGhidraScripts) {
                writeTextEntry(
                    zos,
                    "ghidra_workspace/import_manifest.json",
                    buildImportManifestJson(analysis, config)
                )
                writeTextEntry(
                    zos,
                    "ghidra_workspace/ghidra_import_helper.py",
                    buildGhidraHelperScript(analysis, config)
                )
                writeTextEntry(
                    zos,
                    "ghidra_workspace/README_ANALYSIS.md",
                    buildReadmeMarkdown(analysis, config)
                )
                writtenEntries += 3
            }
        }
        return writtenEntries
    }

    private fun copyZipEntry(srcZip: ZipFile, srcPath: String, zos: ZipOutputStream, destPath: String) {
        val entry = srcZip.getEntry(srcPath) ?: return
        zos.putNextEntry(ZipEntry(destPath))
        srcZip.getInputStream(entry).use { input ->
            input.copyTo(zos, bufferSize = 32 * 1024)
        }
        zos.closeEntry()
    }

    private fun writeTextEntry(zos: ZipOutputStream, destPath: String, content: String) {
        zos.putNextEntry(ZipEntry(destPath))
        zos.write(content.toByteArray(Charsets.UTF_8))
        zos.closeEntry()
    }

    private fun buildImportManifestJson(analysis: ApkAnalysis, config: ExportConfig): String {
        val manifest = analysis.manifest
        val activeAbis = config.selectedAbis.ifEmpty { analysis.availableAbis.toSet() }
        val filteredElfs = analysis.elfFiles.filter { it.abi in activeAbis }

        return buildString {
            appendLine("{")
            appendLine("  \"projectName\": \"${jsonEsc(sanitizeName(config.projectName))}\",")
            appendLine("  \"sourceApk\": \"${jsonEsc(analysis.fileName)}\",")
            appendLine("  \"apkSizeBytes\": ${analysis.fileSizeBytes},")
            appendLine("  \"sha256\": \"${analysis.sha256}\",")
            appendLine("  \"md5\": \"${analysis.md5}\",")
            appendLine("  \"signingSchemes\": [${analysis.signingSchemes.joinToString(", ") { "\"${jsonEsc(it)}\"" }}],")
            appendLine("  \"packageName\": \"${jsonEsc(manifest?.packageName ?: "unknown")}\",")
            appendLine("  \"versionName\": \"${jsonEsc(manifest?.versionName ?: "?")}\",")
            appendLine("  \"versionCode\": \"${jsonEsc(manifest?.versionCode ?: "?")}\",")
            appendLine("  \"minSdk\": \"${jsonEsc(manifest?.minSdk ?: "?")}\",")
            appendLine("  \"targetSdk\": \"${jsonEsc(manifest?.targetSdk ?: "?")}\",")
            appendLine("  \"dexTargets\": [")
            analysis.dexFiles.forEachIndexed { idx, dex ->
                val comma = if (idx < analysis.dexFiles.lastIndex) "," else ""
                appendLine("    {")
                appendLine("      \"path\": \"dex/${jsonEsc(dex.entryName)}\",")
                appendLine("      \"version\": \"${dex.version}\",")
                appendLine("      \"ghidraLanguageId\": \"Dalvik:LE:32:default\",")
                appendLine("      \"classCount\": ${dex.classDefCount},")
                appendLine("      \"methodCount\": ${dex.methodCount},")
                appendLine("      \"stringCount\": ${dex.stringCount}")
                appendLine("    }$comma")
            }
            appendLine("  ],")
            appendLine("  \"nativeElfTargets\": [")
            filteredElfs.forEachIndexed { idx, elf ->
                val comma = if (idx < filteredElfs.lastIndex) "," else ""
                appendLine("    {")
                appendLine("      \"path\": \"native/${jsonEsc(elf.abi)}/${jsonEsc(elf.fileName)}\",")
                appendLine("      \"abi\": \"${jsonEsc(elf.abi)}\",")
                appendLine("      \"elfClass\": \"${elf.elfClass}\",")
                appendLine("      \"machine\": \"${jsonEsc(elf.machineName)}\",")
                appendLine("      \"ghidraLanguageId\": \"${jsonEsc(elf.ghidraLanguageId)}\",")
                appendLine("      \"ghidraCompilerSpec\": \"${jsonEsc(elf.ghidraCompilerSpec)}\",")
                appendLine("      \"hasJniOnLoad\": ${elf.hasJniOnLoad},")
                appendLine("      \"jniExportsCount\": ${elf.jniExports.size}")
                appendLine("    }$comma")
            }
            appendLine("  ]")
            appendLine("}")
        }
    }

    private fun buildGhidraHelperScript(analysis: ApkAnalysis, config: ExportConfig): String {
        val pkg = analysis.manifest?.packageName ?: "unknown"
        return """
# Palometa Ghidra Workstation Post-Import Helper
# Run via Ghidra Script Manager or analyzeHeadless -postScript ghidra_import_helper.py
# Source APK: ${analysis.fileName} (${pkg})
# SHA-256: ${analysis.sha256}
#@category Palometa
#@author Palometa Mobile Workbench

import json
import os

def run():
    program = currentProgram
    if program is None:
        printerr("No active program open in Ghidra.")
        return

    println("=== Palometa Ghidra Helper ===")
    println("Program: " + program.getName())
    println("Language: " + str(program.getLanguageID()))
    println("Image Base: " + str(program.getImageBase()))

    sym_table = program.getSymbolTable()
    bm_mgr = program.getBookmarkManager()
    jni_count = 0

    for sym in sym_table.getAllSymbols(True):
        name = sym.getName()
        if name == "JNI_OnLoad" or name.startswith("Java_"):
            jni_count += 1
            addr = sym.getAddress()
            bm_mgr.setBookmark(addr, "Analysis", "Palometa_JNI", "JNI Export: " + name)
            println("Bookmarked JNI symbol: " + name + " @ " + str(addr))

    manifest_path = os.path.join(os.path.dirname(str(sourceFile)), "import_manifest.json") if "sourceFile" in globals() else ""
    if manifest_path and os.path.exists(manifest_path):
        with open(manifest_path, "r") as f:
            meta = json.load(f)
            println("Source APK SHA-256: " + meta.get("sha256", "unknown"))

    println("Palometa helper finished. JNI bookmarks created: " + str(jni_count))

run()
""".trimIndent()
    }

    private fun buildReadmeMarkdown(analysis: ApkAnalysis, config: ExportConfig): String {
        val previewPkg = analysis.manifest?.packageName ?: "unknown"
        val safeProj = sanitizeName(config.projectName)
        return buildString {
            appendLine("# Palometa Workstation Analysis Bundle")
            appendLine()
            appendLine("- **Project:** `$safeProj`")
            appendLine("- **Source APK:** `${analysis.fileName}` (`$previewPkg`)")
            appendLine("- **Size:** ${BinaryFormatters.formatBytes(analysis.fileSizeBytes)}")
            appendLine("- **SHA-256:** `${analysis.sha256}`")
            appendLine("- **Signing Schemes:** ${analysis.signingSchemes.joinToString(", ")}")
            appendLine()
            appendLine("## Directory Layout")
            appendLine("- `dex/` — Extracted `classes*.dex` Dalvik executables (`Dalvik:LE:32:default`)")
            appendLine("- `native/` — Extracted `.so` ELF shared libraries organized by ABI")
            appendLine("- `decoded/AndroidManifest.xml` — Human-readable decoded manifest")
            appendLine("- `ghidra_workspace/import_manifest.json` — Processor IDs and target metadata")
            appendLine("- `ghidra_workspace/ghidra_import_helper.py` — Ghidra script to bookmark JNI symbols")
            appendLine()
            appendLine("## Quick Desktop Import (Ghidra Headless)")
            appendLine("```bash")
            appendLine("unzip ${safeProj}_ghidra_bundle.zip -d ${safeProj}_ws && cd ${safeProj}_ws")
            analysis.dexFiles.forEach { dex ->
                appendLine("analyzeHeadless ~/ghidra_projects $safeProj -import ./dex/${dex.entryName} -processor \"Dalvik:LE:32:default\"")
            }
            analysis.elfFiles.take(4).forEach { elf ->
                appendLine("analyzeHeadless ~/ghidra_projects $safeProj -import ./native/${elf.abi}/${elf.fileName} -processor \"${elf.ghidraLanguageId}\" -postScript ./ghidra_workspace/ghidra_import_helper.py")
            }
            appendLine("```")
        }
    }

    private fun sanitizeName(raw: String): String =
        raw.trim().replace(Regex("[^a-zA-Z0-9._-]"), "_").ifBlank { "dexscope_export" }

    private fun jsonEsc(s: String): String =
        s.replace("\\", "\\\\").replace("\"", "\\\"")
}
