package cloud.parlisoncodecouture.securitycheck.core

interface SecurityCheck {
    val id: String
    val name: String
    val description: String
    val category: String

    fun run(): CheckResult
}
