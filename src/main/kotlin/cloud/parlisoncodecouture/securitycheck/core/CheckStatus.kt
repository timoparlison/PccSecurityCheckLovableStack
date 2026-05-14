package cloud.parlisoncodecouture.securitycheck.core

enum class CheckStatus(val label: String, val color: String, val rank: Int) {
    SKIPPED("Übersprungen", "#9ca3af", -2),
    // ACCEPTED: bewusst zugelassene Ausnahme (Allowlist-Treffer). Wertet nicht zu Warnung hoch,
    // bleibt aber visuell sichtbar als "konfigurierte Ausnahme" (blau).
    ACCEPTED("Ausnahme", "#2563eb", -1),
    GREEN("OK", "#16a34a", 0),
    YELLOW("Warnung", "#ca8a04", 1),
    RED("Kritisch", "#dc2626", 2),
    ERROR("Fehler", "#6b7280", 3);

    companion object {
        fun worstOf(statuses: Iterable<CheckStatus>): CheckStatus =
            statuses.maxByOrNull { it.rank } ?: GREEN
    }
}
