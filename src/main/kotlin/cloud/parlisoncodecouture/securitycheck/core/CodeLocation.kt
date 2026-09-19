package cloud.parlisoncodecouture.securitycheck.core

import java.nio.file.Path

/**
 * Verweist auf eine konkrete Stelle im Quellcode, die zu einem Finding gehört.
 *
 * Der Renderer (HtmlReportGenerator) lädt zur Generierungszeit die Datei und zeigt
 * `startLine..endLine` mit Kontext drumherum an. `file` ist der absolute Pfad zum
 * Laden, `displayPath` der projektrelative Pfad zur Anzeige.
 */
data class CodeLocation(
    val file: Path,
    val displayPath: String,
    val startLine: Int,
    val endLine: Int = startLine,
)
