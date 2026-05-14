package cloud.parlisoncodecouture.securitycheck.core

data class Finding(
    val severity: CheckStatus,
    val title: String,
    val detail: String,
    val evidence: String? = null,
)
