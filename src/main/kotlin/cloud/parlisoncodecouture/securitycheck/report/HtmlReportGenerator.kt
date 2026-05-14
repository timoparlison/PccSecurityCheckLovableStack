package cloud.parlisoncodecouture.securitycheck.report

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import cloud.parlisoncodecouture.securitycheck.core.CheckResult
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import kotlinx.html.DIV
import kotlinx.html.FlowContent
import kotlinx.html.HTML
import kotlinx.html.article
import kotlinx.html.body
import kotlinx.html.details
import kotlinx.html.div
import kotlinx.html.footer
import kotlinx.html.h1
import kotlinx.html.h2
import kotlinx.html.head
import kotlinx.html.header
import kotlinx.html.html
import kotlinx.html.li
import kotlinx.html.meta
import kotlinx.html.p
import kotlinx.html.pre
import kotlinx.html.script
import kotlinx.html.small
import kotlinx.html.span
import kotlinx.html.strong
import kotlinx.html.style
import kotlinx.html.stream.appendHTML
import kotlinx.html.summary
import kotlinx.html.title
import kotlinx.html.ul
import kotlinx.html.unsafe
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

class HtmlReportGenerator(
    private val outputDir: Path = Path.of("reports"),
) {
    private val fileFormatter =
        DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneId.systemDefault())
    private val displayFormatter =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z").withZone(ZoneId.systemDefault())

    fun writeReport(
        config: SupabaseConfig,
        runLabel: String,
        results: List<CheckResult>,
    ): Path {
        Files.createDirectories(outputDir)
        val now = Instant.now()
        val filename = "${fileFormatter.format(now)}-$runLabel.html"
        val target = outputDir.resolve(filename)
        Files.newBufferedWriter(target, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING).use { writer ->
            writer.appendLine("<!DOCTYPE html>")
            writer.appendHTML().html { renderHtml(config, runLabel, results, now) }
        }
        return target
    }

    private fun HTML.renderHtml(
        config: SupabaseConfig,
        runLabel: String,
        results: List<CheckResult>,
        now: Instant,
    ) {
        val overall = CheckStatus.worstOf(results.map { it.status })
        head {
            meta { attributes["charset"] = "UTF-8" }
            title("Supabase Security Report — ${config.projectRef ?: "unknown"}")
            style { unsafe { +inlineCss() } }
        }
        body {
            div("container") {
                header(classes = "card report-header") {
                    h1 { +"Supabase Security Check" }
                    div("meta") {
                        span { +"Projekt: ${config.projectRef ?: "(unbekannt)"}" }
                        span { +"URL: ${config.url}" }
                        span { +"Lauf: $runLabel" }
                        span { +"Zeit: ${displayFormatter.format(now)}" }
                    }
                    div("overall") {
                        attributes["style"] = "background:${overall.color}"
                        +"Gesamtbewertung: ${overall.label}"
                    }
                    div("counts") {
                        attributes["id"] = "status-filter"
                        span("filter-hint") { +"Filter (klick zum Toggle):" }
                        listOf(
                            CheckStatus.GREEN,
                            CheckStatus.YELLOW,
                            CheckStatus.RED,
                            CheckStatus.ERROR,
                            CheckStatus.SKIPPED,
                        ).forEach { st ->
                            val n = results.count { it.status == st }
                            span("badge filter-badge") {
                                attributes["style"] = "background:${st.color}"
                                attributes["data-status"] = st.name
                                +"${st.name}: $n"
                            }
                        }
                        span("filter-reset") {
                            attributes["id"] = "filter-reset"
                            +"Alle zeigen"
                        }
                    }
                }

                if (results.isEmpty()) {
                    div("card") { p { +"Keine Checks ausgeführt." } }
                } else {
                    results.forEach { renderCheck(it) }
                }

                footer(classes = "report-footer") {
                    small { +"Generiert von PccSecurityCheckLovableStack" }
                }
            }
            script { unsafe { +inlineFilterScript() } }
        }
    }

    private fun inlineFilterScript(): String = """
        (function() {
          var badges = document.querySelectorAll('.filter-badge');
          var checks = document.querySelectorAll('.check');
          var resetBtn = document.getElementById('filter-reset');
          var active = {}; // empty = no filter, otherwise only statuses with active[status]===true are shown
          function isAnyActive() { for (var k in active) if (active[k]) return true; return false; }
          function apply() {
            var anyActive = isAnyActive();
            badges.forEach(function(b) {
              var s = b.getAttribute('data-status');
              if (!anyActive || active[s]) { b.classList.remove('inactive'); }
              else { b.classList.add('inactive'); }
            });
            checks.forEach(function(c) {
              var s = c.getAttribute('data-status');
              if (!anyActive || active[s]) { c.classList.remove('hidden'); }
              else { c.classList.add('hidden'); }
            });
            if (resetBtn) { if (anyActive) resetBtn.classList.add('visible'); else resetBtn.classList.remove('visible'); }
          }
          badges.forEach(function(b) {
            b.addEventListener('click', function() {
              var s = b.getAttribute('data-status');
              active[s] = !active[s];
              apply();
            });
          });
          if (resetBtn) {
            resetBtn.addEventListener('click', function() { active = {}; apply(); });
          }
        })();
    """.trimIndent()

    private fun FlowContent.renderCheck(result: CheckResult) {
        article("card check") {
            attributes["data-status"] = result.status.name
            div("check-header") {
                span("status-dot") { attributes["style"] = "background:${result.status.color}" }
                div("check-title-block") {
                    h2 { +result.checkName }
                    span("category") { +"${result.category} · ${result.checkId}" }
                }
                span("badge") {
                    attributes["style"] = "background:${result.status.color}"
                    +result.status.label
                }
            }
            p("description") { +result.checkDescription }
            p("summary") { +result.summary }
            p("timing") {
                +"Dauer: ${result.durationMs} ms · gestartet ${displayFormatter.format(result.executedAt)}"
            }

            if (result.errorMessage != null) {
                details {
                    summary { +"Exception-Details" }
                    pre("evidence") { +result.errorMessage }
                }
            }

            if (result.findings.isNotEmpty()) {
                details {
                    attributes["open"] = ""
                    summary { +"${result.findings.size} Befund(e) anzeigen" }
                    ul("findings") {
                        result.findings.forEach { f ->
                            li("finding") {
                                span("severity-badge") {
                                    attributes["style"] = "background:${f.severity.color}"
                                    +f.severity.label
                                }
                                div("finding-body") {
                                    strong { +f.title }
                                    p { +f.detail }
                                    if (f.evidence != null) {
                                        pre("evidence") { +f.evidence }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private fun DIV.renderCheck(result: CheckResult) = (this as FlowContent).renderCheck(result)

    private fun inlineCss(): String = """
        :root { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #1f2937; }
        body { margin: 0; padding: 24px; background: #f3f4f6; }
        .container { max-width: 1040px; margin: 0 auto; }
        .card { background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); padding: 20px; margin-bottom: 16px; }
        .report-header h1 { margin: 0 0 8px; font-size: 24px; }
        .meta span { display: inline-block; margin-right: 16px; font-size: 13px; color: #6b7280; }
        .overall { display: inline-block; padding: 10px 16px; border-radius: 6px; color: white; font-weight: 600; margin: 12px 0 8px; }
        .counts { margin-top: 6px; display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 12px; color: white; font-size: 12px; font-weight: 600; }
        .filter-hint { font-size: 12px; color: #6b7280; margin-right: 4px; }
        .filter-badge { cursor: pointer; user-select: none; transition: opacity 0.15s, transform 0.05s; }
        .filter-badge:hover { transform: translateY(-1px); }
        .filter-badge.inactive { opacity: 0.3; }
        .filter-reset { font-size: 12px; color: #2563eb; cursor: pointer; text-decoration: underline; margin-left: 8px; display: none; }
        .filter-reset.visible { display: inline; }
        .check.hidden { display: none; }
        .check-header { display: flex; align-items: center; gap: 12px; }
        .check-title-block { flex-grow: 1; }
        .check-header h2 { margin: 0; font-size: 18px; }
        .status-dot { width: 14px; height: 14px; border-radius: 50%; flex-shrink: 0; }
        .category { font-size: 12px; color: #6b7280; }
        .description { font-size: 13px; color: #4b5563; margin: 8px 0; }
        .summary { font-size: 14px; font-weight: 500; margin: 6px 0; }
        .timing { font-size: 12px; color: #9ca3af; margin: 0; }
        .findings { list-style: none; padding: 0; margin: 8px 0 0; }
        .finding { display: flex; gap: 12px; padding: 10px; background: #f9fafb; border-radius: 6px; margin-bottom: 6px; align-items: flex-start; }
        .severity-badge { padding: 2px 8px; border-radius: 4px; color: white; font-size: 11px; font-weight: 600; flex-shrink: 0; }
        .finding-body { flex-grow: 1; }
        .finding-body p { margin: 4px 0 0; font-size: 13px; color: #4b5563; }
        .evidence { background: #1f2937; color: #f3f4f6; padding: 8px; border-radius: 4px; font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin-top: 6px; }
        details summary { cursor: pointer; font-size: 13px; color: #374151; margin-top: 8px; }
        .report-footer { text-align: center; color: #9ca3af; font-size: 12px; margin-top: 24px; }
    """.trimIndent()
}
