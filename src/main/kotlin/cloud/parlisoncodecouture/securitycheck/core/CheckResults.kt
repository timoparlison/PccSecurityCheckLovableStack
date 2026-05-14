package cloud.parlisoncodecouture.securitycheck.core

import java.time.Duration
import java.time.Instant

/** Build a SKIPPED CheckResult — used when a check's required inputs are missing. */
fun SecurityCheck.skipped(reason: String, start: Instant = Instant.now()): CheckResult = CheckResult(
    checkId = id,
    checkName = name,
    checkDescription = description,
    category = category,
    status = CheckStatus.SKIPPED,
    summary = reason,
    findings = emptyList(),
    executedAt = start,
    durationMs = Duration.between(start, Instant.now()).toMillis(),
)

/** Build a result with the given findings, status derived from worst severity. */
fun SecurityCheck.resultOf(
    findings: List<Finding>,
    summary: String,
    start: Instant,
    forcedStatus: CheckStatus? = null,
): CheckResult = CheckResult(
    checkId = id,
    checkName = name,
    checkDescription = description,
    category = category,
    status = forcedStatus ?: CheckStatus.worstOf(findings.map { it.severity }),
    summary = summary,
    findings = findings,
    executedAt = start,
    durationMs = Duration.between(start, Instant.now()).toMillis(),
)
