package cloud.parlisoncodecouture.securitycheck.main

import cloud.parlisoncodecouture.securitycheck.checks.supabase.AnonReadExposureCheck
import cloud.parlisoncodecouture.securitycheck.checks.supabase.ConfigSanityCheck
import cloud.parlisoncodecouture.securitycheck.config.ConfigLoader
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import cloud.parlisoncodecouture.securitycheck.report.HtmlReportGenerator
import cloud.parlisoncodecouture.securitycheck.runner.CheckRunner

fun main() {
    val config = ConfigLoader.load()
    val checks = listOf(
        ConfigSanityCheck(config),
        AnonReadExposureCheck(config),
    )
    val results = CheckRunner(checks).runAll()
    val reportPath = HtmlReportGenerator().writeReport(config, runLabel = "all", results = results)

    val overall = CheckStatus.worstOf(results.map { it.status })
    println()
    println("=".repeat(72))
    println("Gesamtbewertung: $overall")
    results.forEach { println("  [${it.status}] ${it.checkName} — ${it.summary}") }
    println()
    println("HTML-Report: ${reportPath.toAbsolutePath().toUri()}")
    println("=".repeat(72))
}
