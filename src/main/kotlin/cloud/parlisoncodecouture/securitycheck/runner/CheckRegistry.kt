package cloud.parlisoncodecouture.securitycheck.runner

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import cloud.parlisoncodecouture.securitycheck.core.CheckId
import cloud.parlisoncodecouture.securitycheck.core.SecurityCheck
import io.github.classgraph.ClassGraph

object CheckRegistry {
    private const val SCAN_PACKAGE = "cloud.parlisoncodecouture.securitycheck.checks"

    fun discover(config: SupabaseConfig): List<SecurityCheck> {
        ClassGraph()
            .enableClassInfo()
            .enableAnnotationInfo()
            .acceptPackages(SCAN_PACKAGE)
            .scan()
            .use { scan ->
                return scan.getClassesWithAnnotation(CheckId::class.java.name)
                    .map { it.loadClass() }
                    .map { clazz -> instantiate(clazz, config) }
                    .sortedBy { it.id }
            }
    }

    private fun instantiate(clazz: Class<*>, config: SupabaseConfig): SecurityCheck {
        val constructor = clazz.getDeclaredConstructor(SupabaseConfig::class.java)
        constructor.isAccessible = true
        return constructor.newInstance(config) as SecurityCheck
    }
}
