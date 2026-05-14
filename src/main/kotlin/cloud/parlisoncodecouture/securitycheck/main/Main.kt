package cloud.parlisoncodecouture.securitycheck.main

import cloud.parlisoncodecouture.securitycheck.config.ConfigLoader
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import cloud.parlisoncodecouture.securitycheck.report.HtmlReportGenerator
import cloud.parlisoncodecouture.securitycheck.runner.CheckRegistry
import cloud.parlisoncodecouture.securitycheck.runner.CheckRunner

private const val SINGLE_TEST_ENV = "SINGLE_TEST"
private const val SINGLE_TEST_PROP = "single.test"

fun main() {
    val config = ConfigLoader.load()
    val allChecks = CheckRegistry.discover(config)

    val requested = System.getenv(SINGLE_TEST_ENV)?.trim()?.ifEmpty { null }
        ?: System.getProperty(SINGLE_TEST_PROP)?.trim()?.ifEmpty { null }

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
    val label = requested ?: "all"
    val reportPath = HtmlReportGenerator().writeReport(config, runLabel = label, results = results)

    val overall = CheckStatus.worstOf(results.map { it.status })
    println()
    println("=".repeat(72))
    println("Lauf: $label  ·  Gesamtbewertung: $overall")
    results.forEach { println("  [${it.status}] ${it.checkName} — ${it.summary}") }
    println()
    println("HTML-Report: ${reportPath.toAbsolutePath().toUri()}")
    println("=".repeat(72))
}
