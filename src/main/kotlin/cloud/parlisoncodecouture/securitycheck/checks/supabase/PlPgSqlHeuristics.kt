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

    fun hasAuthOrRoleCheck(body: String): Boolean = authOrRoleCheck.containsMatchIn(stripLineComments(body))

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
