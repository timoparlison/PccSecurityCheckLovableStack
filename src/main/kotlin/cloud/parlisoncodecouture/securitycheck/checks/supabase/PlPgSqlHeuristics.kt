package cloud.parlisoncodecouture.securitycheck.checks.supabase

/**
 * Gemeinsame Quelltext-Heuristiken für Function-Rümpfe. Genutzt vom statischen
 * Migrations-Audit (plpgsql-secdef-audit) und vom Live-Katalog-Check (db-function-exposure),
 * damit beide Checks dieselben Regeln anwenden.
 */
internal object PlPgSqlHeuristics {

    private val lineComment = Regex("""--[^\n]*""")

    private val authOrRoleCheck = Regex(
        """auth\.uid\(\)|auth\.jwt\(\)|current_setting\(\s*'request\.jwt|has_role\(""",
        RegexOption.IGNORE_CASE,
    )

    private val unsafeFormatExecute = Regex(
        """\bEXECUTE\s+format\s*\([^)]*%[ILs][^)]*\)(?![^;]*USING\b)""",
        setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
    )

    private val concatExecute = Regex(
        """\bEXECUTE\s+['"]?[^;]*\|\|""",
        RegexOption.IGNORE_CASE,
    )

    /** Entfernt `--`-Zeilenkommentare, damit z. B. ein auskommentiertes auth.uid() nicht als Check zählt. */
    fun stripLineComments(body: String): String = body.replace(lineComment, "")

    /**
     * [guards]: projekteigene Guard-Functions (z. B. user_org_id(), has_full_access()), deren Aufruf als
     * Check zählt — siehe [guardFunctions].
     */
    fun hasAuthOrRoleCheck(body: String, guards: Set<String> = emptySet()): Boolean {
        val code = stripLineComments(body)
        if (authOrRoleCheck.containsMatchIn(code)) return true
        return guards.isNotEmpty() && callsAny(code, guards)
    }

    /** Quelltext einer Function, soweit ihn [guardFunctions] braucht. */
    data class FunctionSource(val name: String, val hasNoArgs: Boolean, val returnsSimpleScalar: Boolean, val body: String)

    /**
     * Ermittelt die projekteigenen Guard-Functions: parameterlose Functions mit einfachem Rückgabetyp
     * (siehe [returnsSimpleScalar]), die direkt oder über andere Guards auth.uid()/auth.jwt() lesen —
     * also user_org_id(), has_full_access(), is_portal_user(), portal_customer_ids().
     * Bewusst eng: Functions mit Parametern (is_working_day(date)) oder Datenrückgabe (list_…() → jsonb)
     * lesen zwar ebenfalls die Organisation des Aufrufers, prüfen aber nichts. Sie als Guard zu zählen,
     * würde echte Befunde verstecken.
     */
    fun guardFunctions(functions: Collection<FunctionSource>): Set<String> {
        val candidates = functions.filter { it.hasNoArgs && it.returnsSimpleScalar }
        val guards = mutableSetOf<String>()
        do {
            val added = candidates
                .filter { it.name.lowercase() !in guards && hasAuthOrRoleCheck(it.body, guards) }
                .map { it.name.lowercase() }
            guards += added
        } while (added.isNotEmpty())
        return guards
    }

    private val simpleScalarReturn = Regex(
        """\bRETURNS\s+(?:boolean|uuid|text|uuid\[]|SETOF\s+uuid|TABLE\s*\(\s*\w+\s+uuid\s*\))(?=\s)""",
        RegexOption.IGNORE_CASE,
    )

    /** RETURNS boolean/uuid/text/uuid[]/SETOF uuid/TABLE(x uuid) — der Kopf einer Function-Definition. */
    fun returnsSimpleScalar(header: String): Boolean = simpleScalarReturn.containsMatchIn(header)

    private val functionCall = Regex("""\b(?:public\.)?([a-z_][a-z0-9_]*)\s*\(""", RegexOption.IGNORE_CASE)

    private fun callsAny(code: String, names: Set<String>): Boolean =
        functionCall.findAll(code).any { it.groupValues[1].lowercase() in names }

    fun hasUnsafeFormatExecute(body: String): Boolean = unsafeFormatExecute.containsMatchIn(stripLineComments(body))

    fun hasConcatExecute(body: String): Boolean = concatExecute.containsMatchIn(stripLineComments(body))

    /**
     * true, wenn an [offset] ein String-Literal beginnt, z. B. `EXECUTE format('CREATE OR REPLACE FUNCTION …')`
     * in einem DO-Block. Solche Stellen sind keine Function-Definition, sondern Text, den eine Migration
     * zur Laufzeit ausführt — der Rumpf der Function steht nicht im Dateitext.
     */
    fun startsInsideStringLiteral(content: String, offset: Int): Boolean {
        var i = offset - 1
        while (i >= 0 && content[i].isWhitespace()) i--
        return i >= 0 && content[i] == '\''
    }
}
