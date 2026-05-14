package cloud.parlisoncodecouture.securitycheck.checks.supabase

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import cloud.parlisoncodecouture.securitycheck.core.CheckId
import cloud.parlisoncodecouture.securitycheck.core.CheckResult
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import cloud.parlisoncodecouture.securitycheck.core.Finding
import cloud.parlisoncodecouture.securitycheck.core.SecurityCheck
import cloud.parlisoncodecouture.securitycheck.core.resultOf
import cloud.parlisoncodecouture.securitycheck.core.skipped
import cloud.parlisoncodecouture.securitycheck.db.PostgresQueryClient
import java.time.Instant

@CheckId(name = "storage-objects-rls")
class StorageObjectsRlsCheck(
    private val config: SupabaseConfig,
) : SecurityCheck {
    override val name = "Storage-Objects RLS-Policies"
    override val description =
        "Liest pg_policies für storage.objects via JDBC (read-only). Das public-Flag auf Buckets steuert " +
            "nur den anonymen Lesepfad — alle anderen Operationen laufen über RLS-Policies auf " +
            "storage.objects. Permissive Policies hier sind besonders riskant, weil Dateinamen meist " +
            "vorhersagbar sind und USER-Daten direkt durchsickern. Geprüft werden: USING(true)/WITH " +
            "CHECK(true), wide-open SELECT für anon/public, fehlendes WITH CHECK bei INSERT/UPDATE."
    override val category = "Supabase / Storage"

    private data class Policy(
        val policyName: String,
        val cmd: String,
        val roles: List<String>,
        val qual: String?,
        val withCheck: String?,
    )

    override fun run(): CheckResult {
        val start = Instant.now()
        if (!config.hasDbAccess) {
            return skipped(
                "DB-Zugang fehlt. Setze SUPABASE_DB_PASSWORD (Env) bzw. -Dsupabase.db.password=... und " +
                    "optional db.host in den properties.",
                start,
            )
        }

        val policies = try {
            PostgresQueryClient(config).use { client ->
                client.query(
                    """
                    SELECT policyname, cmd, roles, qual, with_check
                    FROM pg_policies
                    WHERE schemaname = 'storage' AND tablename = 'objects'
                    ORDER BY policyname
                    """.trimIndent(),
                ) { rs ->
                    val rolesArray = rs.getArray("roles")
                    val rolesList = if (rolesArray != null) {
                        (rolesArray.array as? Array<*>)?.mapNotNull { it?.toString() } ?: emptyList()
                    } else emptyList()
                    Policy(
                        policyName = rs.getString("policyname"),
                        cmd = (rs.getString("cmd") ?: "").uppercase(),
                        roles = rolesList,
                        qual = rs.getString("qual")?.trim(),
                        withCheck = rs.getString("with_check")?.trim(),
                    )
                }
            }
        } catch (e: Exception) {
            return resultOf(
                findings = listOf(
                    Finding(
                        CheckStatus.ERROR,
                        "DB-Query fehlgeschlagen",
                        "JDBC-Aufruf nach Postgres fehlgeschlagen: ${e.message ?: e::class.simpleName}",
                    ),
                ),
                summary = "DB nicht erreichbar oder Query fehlgeschlagen.",
                start = start,
            )
        }

        if (policies.isEmpty()) {
            return resultOf(
                findings = listOf(
                    Finding(
                        CheckStatus.YELLOW,
                        "Keine RLS-Policies auf storage.objects",
                        "Ohne Policies ist storage.objects für anon/authenticated effektiv geschlossen — " +
                            "Uploads/Downloads über Supabase-Storage funktionieren nicht. Wenn das gewollt " +
                            "ist (rein public-Buckets), OK; sonst fehlen Policies.",
                    ),
                ),
                summary = "0 Policies auf storage.objects.",
                start = start,
            )
        }

        val findings = mutableListOf<Finding>()
        for (p in policies) {
            val rolesStr = if (p.roles.isEmpty()) "PUBLIC" else p.roles.joinToString(",")
            val rolesLc = p.roles.map { it.lowercase() }
            val hitsAnon = p.roles.isEmpty() || "anon" in rolesLc || "public" in rolesLc
            val hitsAuth = "authenticated" in rolesLc
            val qualIsTrue = p.qual == "true"
            val checkIsTrue = p.withCheck == "true"

            when {
                qualIsTrue && hitsAnon && p.cmd in listOf("SELECT", "ALL") -> findings += Finding(
                    CheckStatus.RED,
                    "Storage-Policy '${p.policyName}': anonymer Read-All auf alle Objekte",
                    "cmd=${p.cmd}, roles=$rolesStr, USING=true. Jeder anonyme Client kann jedes Storage-Objekt " +
                        "auflisten und herunterladen — unabhängig vom Bucket-public-Flag. Sehr kritisch.",
                )
                qualIsTrue && hitsAuth && p.cmd in listOf("SELECT", "ALL") -> findings += Finding(
                    CheckStatus.YELLOW,
                    "Storage-Policy '${p.policyName}': authenticated Read-All",
                    "cmd=${p.cmd}, roles=$rolesStr, USING=true. Jeder eingeloggte User sieht alle Files in " +
                        "allen Buckets — typischerweise nicht gewollt (Multi-Tenancy gebrochen).",
                )
                qualIsTrue && p.cmd in listOf("DELETE", "UPDATE", "ALL") -> findings += Finding(
                    CheckStatus.RED,
                    "Storage-Policy '${p.policyName}': USING=true für ${p.cmd}",
                    "Beliebige Rolle ($rolesStr) darf ${p.cmd} auf allen Storage-Objekten. Dateilöschung/" +
                        "-überschreibung ohne Owner-Check.",
                )
                checkIsTrue && p.cmd in listOf("INSERT", "UPDATE", "ALL") -> findings += Finding(
                    CheckStatus.RED,
                    "Storage-Policy '${p.policyName}': WITH CHECK=true für ${p.cmd}",
                    "Keine Validierung beim Upload — beliebige Bucket-/Pfad-Werte gehen durch. Kann zum " +
                        "Überschreiben fremder Objekte missbraucht werden.",
                )
                p.cmd == "UPDATE" && p.withCheck.isNullOrBlank() -> findings += Finding(
                    CheckStatus.YELLOW,
                    "Storage-Policy '${p.policyName}': UPDATE ohne WITH CHECK",
                    "User darf eigene Objekte ändern, kann dabei aber Owner/Pfad auf einen fremden User " +
                        "umbiegen. WITH CHECK fehlt.",
                )
                else -> findings += Finding(
                    CheckStatus.GREEN,
                    "Storage-Policy '${p.policyName}' (${p.cmd}, roles=$rolesStr)",
                    "USING=${p.qual?.take(120) ?: "-"}, WITH CHECK=${p.withCheck?.take(120) ?: "-"}",
                )
            }
        }

        val red = findings.count { it.severity == CheckStatus.RED }
        val yellow = findings.count { it.severity == CheckStatus.YELLOW }
        val green = findings.count { it.severity == CheckStatus.GREEN }
        val summary = "${policies.size} Policy(s) auf storage.objects: $green OK, $yellow Warnung(en), $red kritisch."
        return resultOf(findings, summary, start)
    }
}
