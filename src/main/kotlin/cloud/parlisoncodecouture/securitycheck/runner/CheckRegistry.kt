package cloud.parlisoncodecouture.securitycheck.runner

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import cloud.parlisoncodecouture.securitycheck.core.CheckId
import cloud.parlisoncodecouture.securitycheck.core.SecurityCheck
import cloud.parlisoncodecouture.securitycheck.db.CatalogAccess
import io.github.classgraph.ClassGraph

object CheckRegistry {
    private const val SCAN_PACKAGE = "cloud.parlisoncodecouture.securitycheck.checks"

    fun discover(config: SupabaseConfig, catalog: CatalogAccess): List<SecurityCheck> {
        ClassGraph()
            .enableClassInfo()
            .enableAnnotationInfo()
            .acceptPackages(SCAN_PACKAGE)
            .scan()
            .use { scan ->
                return scan.getClassesWithAnnotation(CheckId::class.java.name)
                    .map { it.loadClass() }
                    .map { clazz -> instantiate(clazz, config, catalog) }
                    .sortedBy { it.id }
            }
    }

    /**
     * Katalog-basierte Checks deklarieren (SupabaseConfig, CatalogAccess), alle übrigen nur
     * (SupabaseConfig). So teilen sich alle DB-Checks eine Quelle — statt wie früher jeweils
     * eine eigene Verbindung aufzubauen.
     */
    private fun instantiate(clazz: Class<*>, config: SupabaseConfig, catalog: CatalogAccess): SecurityCheck {
        val withCatalog = runCatching {
            clazz.getDeclaredConstructor(SupabaseConfig::class.java, CatalogAccess::class.java)
        }.getOrNull()
        val constructor = withCatalog ?: clazz.getDeclaredConstructor(SupabaseConfig::class.java)
        constructor.isAccessible = true
        val instance = if (withCatalog != null) {
            constructor.newInstance(config, catalog)
        } else {
            constructor.newInstance(config)
        }
        return instance as SecurityCheck
    }
}
