package cloud.parlisoncodecouture.securitycheck.core

interface SecurityCheck {
    val id: String
        get() = this::class.java.getAnnotation(CheckId::class.java)?.name
            ?: error("${this::class.simpleName} is missing the @CheckId annotation")

    val name: String
    val description: String
    val category: String

    fun run(): CheckResult
}
