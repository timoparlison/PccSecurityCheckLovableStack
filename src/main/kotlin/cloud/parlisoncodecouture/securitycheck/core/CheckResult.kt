package cloud.parlisoncodecouture.securitycheck.core

import java.time.Instant

data class CheckResult(
    val checkId: String,
    val checkName: String,
    val checkDescription: String,
    val category: String,
    val status: CheckStatus,
    val summary: String,
    val findings: List<Finding>,
    val executedAt: Instant,
    val durationMs: Long,
    val errorMessage: String? = null,
)
