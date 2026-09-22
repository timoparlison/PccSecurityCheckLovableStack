package cloud.parlisoncodecouture.securitycheck.main

import cloud.parlisoncodecouture.securitycheck.config.ConfigLoader
import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import cloud.parlisoncodecouture.securitycheck.db.CatalogAccess
import cloud.parlisoncodecouture.securitycheck.db.CatalogSources
import cloud.parlisoncodecouture.securitycheck.db.SnapshotSql
import cloud.parlisoncodecouture.securitycheck.report.HtmlReportGenerator
import cloud.parlisoncodecouture.securitycheck.runner.CheckRegistry
import cloud.parlisoncodecouture.securitycheck.runner.CheckRunner
import java.nio.file.Files
import java.nio.file.Path

private const val SINGLE_TEST_ENV = "SINGLE_TEST"
private const val SINGLE_TEST_PROP = "single.test"

private const val MODE_ENV = "MODE"
private const val MODE_PROP = "mode"
private const val MODE_SQL_EXPORT = "sql-export"

fun main() {
    val config = ConfigLoader.load()
    when (val mode = runtimeValue(MODE_ENV, MODE_PROP)) {
        null, "run" -> runChecks(config)
        MODE_SQL_EXPORT -> exportSnapshotSql(config)
        else -> error("Unbekannter mode='$mode'. Erlaubt: run (Default), $MODE_SQL_EXPORT.")
    }
}

/**
 * Schreibt das Statement für den manuellen Weg: ausführen im SQL-Editor, Ergebnis als JSON
 * zurück auf die Platte. Braucht selbst keinerlei Zugang zum Zielsystem.
 */
private fun exportSnapshotSql(config: SupabaseConfig) {
    val profile = config.activeProfile ?: "default"
    val target = Path.of("sql", "$profile-snapshot.sql").toAbsolutePath()
    Files.createDirectories(target.parent)
    Files.writeString(target, SnapshotSql.build(config) + "\n")

    println()
    println("=".repeat(72))
    println("SQL-Export für Profil '$profile' geschrieben:")
    println("  $target")
    println()
    println("Nächste Schritte:")
    println("  1. Datei öffnen, Inhalt in den Supabase SQL-Editor kopieren, ausführen")
    println("  2. Ergebnis als JSON exportieren")
    println("  3. Datei ablegen unter: ${config.snapshotPath}")
    println("  4. Lauf starten: ACTIVE_PROFILE=$profile mvn -q compile exec:java")
    println("=".repeat(72))
}

private fun runChecks(config: SupabaseConfig) {
    val catalog = CatalogSources.resolve(config)
    try {
        val allChecks = CheckRegistry.discover(config, catalog)

        val requested = runtimeValue(SINGLE_TEST_ENV, SINGLE_TEST_PROP)
        val toRun = if (requested != null) {
            val match = allChecks.firstOrNull { it.id == requested }
                ?: error(
                    "Kein Check mit id='$requested' gefunden. Verfügbar: " +
                        allChecks.joinToString { it.id }
                )
            listOf(match)
        } else {
            allChecks
        }

        val results = CheckRunner(toRun).runAll()
        val profile = config.activeProfile ?: "unknown"
        val label = if (requested != null) "$profile-$requested" else profile
        val reportPath = HtmlReportGenerator().writeReport(config, runLabel = label, results = results, catalog = catalog)

        val overall = CheckStatus.worstOf(results.map { it.status })
        println()
        println("=".repeat(72))
        println("Profil: $profile  ·  Lauf: ${requested ?: "all"}  ·  Gesamtbewertung: $overall")
        println("Katalogdaten: ${catalogLine(catalog)}")
        catalog.sourceOrNull?.warnings?.forEach { println("  ! $it") }
        results.forEach { println("  [${it.status}] ${it.checkName} — ${it.summary}") }
        println()
        println("HTML-Report: ${reportPath.toAbsolutePath().toUri()}")
        println("=".repeat(72))
    } finally {
        catalog.sourceOrNull?.close()
    }
}

private fun catalogLine(catalog: CatalogAccess): String = when (catalog) {
    is CatalogAccess.Available -> catalog.source.provenance
    is CatalogAccess.Unavailable -> "keine Quelle — ${catalog.reason}"
}

private fun runtimeValue(envName: String, propName: String): String? =
    System.getenv(envName)?.trim()?.ifEmpty { null }
        ?: System.getProperty(propName)?.trim()?.ifEmpty { null }
