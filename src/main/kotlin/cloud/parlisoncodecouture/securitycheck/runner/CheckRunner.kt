package cloud.parlisoncodecouture.securitycheck.runner

import cloud.parlisoncodecouture.securitycheck.core.CheckResult
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import cloud.parlisoncodecouture.securitycheck.core.SecurityCheck
import io.github.oshai.kotlinlogging.KotlinLogging
import java.time.Duration
import java.time.Instant

private val log = KotlinLogging.logger {}

class CheckRunner(private val checks: List<SecurityCheck>) {
    fun runAll(): List<CheckResult> = checks.map { runOne(it) }

    fun runOne(check: SecurityCheck): CheckResult {
        log.info { "Running check '${check.name}' (${check.id})" }
        val start = Instant.now()
        return runCatching { check.run() }
            .onSuccess { log.info { "  -> ${it.status} :: ${it.summary}" } }
            .getOrElse { ex ->
                log.error(ex) { "Check '${check.id}' threw an exception" }
                CheckResult(
                    checkId = check.id,
                    checkName = check.name,
                    checkDescription = check.description,
                    category = check.category,
                    status = CheckStatus.ERROR,
                    summary = "Exception: ${ex.message ?: ex::class.simpleName}",
                    findings = emptyList(),
                    executedAt = start,
                    durationMs = Duration.between(start, Instant.now()).toMillis(),
                    errorMessage = ex.stackTraceToString(),
                )
            }
    }
}
