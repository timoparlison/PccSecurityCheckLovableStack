package cloud.parlisoncodecouture.securitycheck.main

import cloud.parlisoncodecouture.securitycheck.checks.supabase.AnonReadExposureCheck
import cloud.parlisoncodecouture.securitycheck.config.ConfigLoader
import cloud.parlisoncodecouture.securitycheck.report.HtmlReportGenerator
import cloud.parlisoncodecouture.securitycheck.runner.CheckRunner

fun main() {
    val config = ConfigLoader.load()
    val check = AnonReadExposureCheck(config)
    val results = CheckRunner(listOf(check)).runAll()
    val reportPath = HtmlReportGenerator().writeReport(config, runLabel = check.id, results = results)
    val r = results.single()
    println()
    println("[${r.status}] ${r.checkName} — ${r.summary}")
    println("HTML-Report: ${reportPath.toAbsolutePath().toUri()}")
}
