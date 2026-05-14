# Sicherheitschecks im Überblick

Dieses Dokument beschreibt **alle 14 Prüfungen** (`Checks`), die das Tool `PccSecurityCheckLovableStack` durchführt.

Die Beschreibungen sind so formuliert, dass auch **Nicht-ITler** verstehen, welches Risiko geprüft wird, wie der Test arbeitet und wie zuverlässig das Ergebnis ist.

> **Wichtiger Hinweis:** Ein Security-Scanner ist kein Ersatz für ein professionelles Penetration-Testing. Er hilft dabei, die **gängigsten Konfigurationsfehler und Anti-Patterns** in Supabase-Projekten (sogenannte „Lovable-Stacks“) schnell zu finden.

---

## Legende: Güte eines Tests

Jeder Test wird mit einer Sterne-Bewertung versehen. Diese bewertet **nicht** das gefundene Risiko, sondern die **Zuverlässigkeit und Vollständigkeit der Prüfung selbst**.

| Bewertung | Bedeutung |
|---|---|
| ⭐⭐⭐⭐⭐ **Exzellent** | Der Test ist sehr zuverlässig und deckt das Risiko nahezu lückenlos ab. False Negatives (übersehene Probleme) sind extrem unwahrscheinlich. |
| ⭐⭐⭐⭐ **Sehr gut** | Der Test ist solide und praxiserprobt. Es gibt kleinere theoretische Einschränkungen oder Randfälle, die er nicht sieht. |
| ⭐⭐⭐ **Gut** | Der Test liefert wertvolle Hinweise, arbeitet aber mit Heuristiken (Mustererkennung) oder hat bekannte Blindflecken. |
| ⭐⭐ **Mäßig** | Der Test deckt nur einen Teil des Risikos ab oder produziert unter Umständen viele Fehlalarme (False Positives). |
| ⭐ **Schwach** | Der Test ist rudimentär und sollte nicht als alleinige Entscheidungsgrundlage herangezogen werden. |

---

## 1. Konfiguration & Verbindungssicherheit

### `config-sanity` — Konfiguration & Schlüssel-Plausibilität

**Was wird geprüft?**
Ob die grundlegenden Verbindungsdaten korrekt und sicher konfiguriert sind: die Projekt-URL, die beiden API-Schlüssel (Anon-Key und Service-Role-Key) und ob eine Verbindung zur Supabase-API möglich ist.

**Warum ist das wichtig?**
Wenn die Schlüssel vertauscht, abgelaufen oder identisch sind, kann das bedeuten, dass der mächtige Service-Role-Key versehentlich im Frontend landet — mit katastrophalen Folgen für die Datensicherheit.

**Wie funktioniert der Test?**
- Prüft, ob die URL mit `https://` beginnt (statt unsicherem `http://`).
- Dekodiert beide Schlüssel (sie sind sogenannte JWT-Token) und liest deren Inhalt aus:
  - Passt die Rolle (`anon` vs. `service_role`)?
  - Ist der Schlüssel abgelaufen?
  - Gehört der Schlüssel wirklich zu diesem Projekt?
- Prüft, ob Anon-Key und Service-Role-Key identisch sind.
- Ruft die Supabase-Auth-API mit beiden Schlüsseln auf, um zu testen, ob sie akzeptiert werden.

**Güte: ⭐⭐⭐⭐⭐ Exzellent**

Dieser Test arbeitet rein analytisch (keine Ratenversuche) und prüft harte Fakten. Die JWT-Dekodierung ist standardkonform, und die Konnektivitätstests sind eindeutig. Einzige Einschränkung: Er erkennt nicht, ob ein Schlüssel *vorzeitig widerrufen* wurde (das sieht man nur am API-Fehler).

**Bekannte Grenzen**
- Er prüft nicht, ob die Schlüssel im Code-Repository oder in CI/CD-Pipelines ausversehen committed wurden.
- Er prüft nicht die Stärke des JWT-Signatur-Schlüssels selbst (das macht der `jwt-hardening`-Test).

---

## 2. Authentifizierung & Account-Sicherheit

### `auth-settings` — Auth-Settings Audit

**Was wird geprüft?**
Ob die zentralen Anmelde-Einstellungen des Projekts sicher konfiguriert sind: Offene Registrierung, automatische E-Mail-Bestätigung und SMS-Bestätigung.

**Warum ist das wichtig?**
Wenn jeder Besucher ohne E-Mail-Verifikation ein Konto anlegen kann, hat er sofort die Rechte eines „eingeloggten Nutzers“. Das ist besonders gefährlich, wenn Datenbank-Zugriffsregeln (RLS) darauf vertrauen, dass „eingeloggt = vertrauenswürdig".

**Wie funktioniert der Test?**
- Ruft die öffentliche Einstellungs-API von Supabase Auth ab (`/auth/v1/settings`).
- Prüft die Flags:
  - `disable_signup` (Registrierung erlaubt?)
  - `mailer_autoconfirm` (E-Mail-Bestätigung übersprungen?)
  - `phone_autoconfirm` (SMS-Bestätigung übersprungen?)
- Listet aktive OAuth-Anbieter (Google, GitHub, etc.) auf.

**Güte: ⭐⭐⭐⭐ Sehr gut**

Der Test liest die tatsächliche Server-Konfiguration aus und bewertet sie nach klaren Kriterien. Er ist sehr zuverlässig für das, was er prüft.

**Bekannte Grenzen**
- Er prüft **nicht**, ob die E-Mail-Verifikation wirklich funktioniert (nur ob sie theoretisch aktiv ist).
- Er prüft **nicht**, ob Multi-Faktor-Authentifizierung (MFA/2FA) erzwungen wird.
- Er prüft **nicht** Passwort-Richtlinien (Mindestlänge, Komplexität).
- Er prüft **nicht**, ob OAuth-Weiterleitungs-URLs (Redirect-URIs) korrekt beschränkt sind.

---

### `auth-user-enumeration` — User-Enumeration über Auth-API

**Was wird geprüft?**
Ob ein Angreifer durch geschickte Anfragen herausfinden kann, ob eine bestimmte E-Mail-Adresse in der Datenbank registriert ist.

**Warum ist das wichtig?**
User-Enumeration erleichtert gezielte Angriffe (Phishing, Brute-Force auf Passwörter). Eine sichere API antwortet auf „Passwort vergessen" immer gleich — unabhängig davon, ob die E-Mail existiert.

**Wie funktioniert der Test?**
- Erzeugt eine zufällige E-Mail-Adresse auf einer garantiert nicht existierenden Domain (`...@nonexistent.invalid`, gemäß Internet-Standard RFC 2606).
- Sendet Anfragen an zwei typische Endpunkte:
  1. Passwort-Wiederherstellung (`/auth/v1/recover`)
  2. Magic-Link / OTP (`/auth/v1/otp`)
- Bewertet die Antwort: Wenn der Server mit „User not found" oder HTTP 404 antwortet, leakt er Existenz-Information.

**Güte: ⭐⭐⭐⭐⭐ Exzellent**

Dieser Test ist methodisch sehr sauber: Durch die `.invalid`-Domain ist garantiert, dass keine echte Person eine E-Mail erhält. Die getesteten Endpunkte sind die häufigsten Quellen für Enumeration. Erkennung per String-Matching auf gängige Fehlertexte ist praxisnah.

**Bekannte Grenzen**
- Wenn das Projekt ein Rate-Limiting (Anfrage-Begrenzung) hat, kann der Test vorübergehend blockiert werden und liefert dann eine Warnung statt eines klaren Ergebnisses.
- Es gibt theoretisch weitere Enumeration-Pfade (z. B. über OAuth-Fehlerseiten), die nicht geprüft werden.

---

### `jwt-hardening` — JWT-Hardening (alg=none & schwache Secrets)

**Was wird geprüft?**
Ob die JWT-Validierung des Supabase-Servers sicher ist — insbesondere ob unsignierte Token oder mit bekannten Standard-Passwörtern signierte Token akzeptiert werden.

**Warum ist das wichtig?**
JWT-Token sind die Eintrittskarten zur API. Wenn ein Angreifer eigene Token mit `role='service_role'` erstellen kann, hat er vollen Zugriff auf die Datenbank.

**Wie funktioniert der Test?**
- Der Test **schmiedet** mehrere gefälschte JWT-Token:
  1. Einen Token mit `alg=none` (keine Signatur) und `role=service_role`.
  2. Mehrere Token mit `alg=HS256`, signiert mit bekannten schwachen Passwörtern (z. B. `secret`, `supabase`, `changeme`, dem lokalen Supabase-CLI-Default).
- Diese Token werden gegen den Admin-Endpunkt `/auth/v1/admin/users` geschickt.
- Wenn der Server mit Erfolg (HTTP 200) antwortet, ist das ein kritischer Sicherheitsmangel.

**Güte: ⭐⭐⭐⭐⭐ Exzellent**

Dies ist ein echter Angriffstest (Penetration-Testing-Pattern). Er prüft nicht die Konfiguration, sondern das tatsächliche Verhalten des Servers. Die gewählte Liste schwacher Secrets deckt die gängigsten Copy-Paste-Fehler ab.

**Bekannte Grenzen**
- Die Liste schwacher Secrets ist notwendigerweise endlich. Ein sehr schwaches, aber unbekanntes Passwort wird nicht erkannt (dann wäre aber auch der `config-sanity`-Test grün, und das Problem bliebe unsichtbar).
- Wenn der Admin-Endpunkt durch andere Schutzmechanismen blockiert ist, könnte der Test ein positives Ergebnis verfehlen (aber das ist unwahrscheinlich).

---

## 3. Datenzugriffsschutz (RLS)

### `rls-status` — RLS-Status pro Tabelle

**Was wird geprüft?**
Für jede Tabelle im öffentlichen Bereich der Datenbank (`public`-Schema): Ist der Zeilen-basierte Schutz (Row-Level Security, RLS) aktiviert, und wie viele Zugriffsregeln (Policies) existieren?

**Warum ist das wichtig?**
RLS ist das Herzstück der Datensicherheit in Supabase. Ohne RLS können eingeloggte oder anonyme Nutzer — je nach Datenbank-Grundrechten — potenziell alle Daten aller Nutzer sehen und verändern.

**Wie funktioniert der Test?**
- Verbindet sich direkt (nur lesend, verschlüsselt) zur Postgres-Datenbank über JDBC.
- Liest aus dem Systemkatalog (`pg_class`, `pg_namespace`): für jede Tabelle, ob `relrowsecurity = true` (RLS an) und wie viele Policies existieren.
- Bewertung:
  - **Rot:** RLS ist ausgeschaltet.
  - **Gelb:** RLS ist an, aber es gibt 0 Policies (Tabelle ist komplett gesperrt — oft ein Konfigurationsfehler).
  - **Grün:** RLS ist an und es gibt mindestens eine Policy.

**Güte: ⭐⭐⭐⭐⭐ Exzellent**

Dieser Test liest die Wahrheit direkt aus der Datenbank. Es gibt keinen Weg, ihm etwas vorzumachen. Er ist deterministisch und vollständig.

**Bekannte Grenzen**
- Er prüft nur das `public`-Schema. Tabellen in anderen Schemas (z. B. `auth`, `storage`) werden nicht betrachtet (für `storage.objects` gibt es jedoch den separaten `storage-objects-rls`-Check).
- Er sagt nicht, ob die Policies *gut* sind — nur ob sie existieren. Die Qualität der Regeln prüft der `permissive-policies`-Test.

---

### `permissive-policies` — Permissive RLS-Policies

**Was wird geprüft?**
Die Qualität der Zugriffsregeln (Policies) auf Tabellen im `public`-Schema. Der Test sucht nach „zu nachsichtigen" Regeln, die praktisch jedem alles erlauben.

**Warum ist das wichtig?**
Eine Policy, die für alle Nutzer `true` zurückgibt, ist so gut wie gar keine Policy. Das ist der häufigste Konfigurationsfehler bei Supabase-Einsteigern.

**Wie funktioniert der Test?**
- Liest alle Policies aus der Systemtabelle `pg_policies` im `public`-Schema.
- Analysiert jede Policy auf:
  - `USING (true)` für SELECT/ALL → jeder darf alles lesen.
  - `WITH CHECK (true)` für INSERT/UPDATE/ALL → jeder darf alles schreiben, ohne Prüfung.
  - UPDATE ohne `WITH CHECK` → Nutzer könnten fremde Datensätze übernehmen.
- Unterscheidet zwischen anonymen (`anon`) und eingeloggten (`authenticated`) Nutzern bei der Bewertung.

**Güte: ⭐⭐⭐⭐⭐ Exzellent**

Wie `rls-status` liest dieser Test direkt aus dem Datenbankkatalog. Die Analyse der Policy-Ausdrücke (`qual`, `with_check`) ist eindeutig. Ein `USING (true)` ist objektiv unsicher.

**Bekannte Grenzen**
- Er prüft nur das `public`-Schema.
- Er erkennt nicht subtile Logikfehler (z. B. `USING (user_id = auth.uid() OR is_admin = true)` — das ist syntaktisch korrekt, könnte aber ein Design-Fehler sein).
- Er berücksichtigt nicht, dass `USING (true)` manchmal bewusst gewählt wird (z. B. für öffentliche Blog-Posts). Die Bewertung geht daher konservativ von einem Risiko aus.

---

## 4. Datei-Speicher (Storage)

### `public-storage-buckets` — Public Storage Buckets

**Was wird geprüft?**
Ob Datei-Behälter (Buckets) in Supabase Storage für die Öffentlichkeit zugänglich sind, und ob deren Namen auf sensible Inhalte hindeuten.

**Warum ist das wichtig?**
Wenn ein Bucket „public" ist, kann jeder, der die URL errät, Dateien auflisten und herunterladen — unabhängig von Datenbank-Regeln. Das ist besonders kritisch bei Dokumenten, Rechnungen oder Nutzerdaten.

**Wie funktioniert der Test?**
- Listet alle Buckets über die Storage-API mit dem Service-Role-Key auf.
- Prüft das `public`-Flag jedes Buckets.
- Bewertet Bucket-Namen nach Sensitivität (z. B. `private`, `documents`, `invoices`, `user-uploads`).
- **Rot:** Public + sensibler Name.
- **Gelb:** Public + unspezifischer Name.
- **Grün:** Nicht public (Zugriff über RLS geregelt).

**Güte: ⭐⭐⭐⭐ Sehr gut**

Der Test ist einfach, aber effektiv. Er findet die offensichtlichsten Fehlkonfigurationen.

**Bekannte Grenzen**
- Er prüft **nicht** die RLS-Policies auf der `storage.objects`-Tabelle selbst. Ein „privater" Bucket kann trotzdem über unsichere Policies angreifbar sein (das prüft `storage-objects-rls`).
- Die Bewertung „sensibler Name" ist eine Heuristik. Ein Bucket namens `public-avatars` würde nicht als sensibel eingestuft, auch wenn er private Bilder enthält.

---

### `storage-objects-rls` — Storage-Objects RLS-Policies

**Was wird geprüft?**
Die Qualität der Zugriffsregeln (Policies) auf der internen `storage.objects`-Tabelle. Das ist der technische Unterbau des Datei-Speichers.

**Warum ist das wichtig?**
Das `public`-Flag auf einem Bucket steuert nur den anonymen Lesezugriff. Alle anderen Aktionen (Hochladen, Löschen, Umbenennen, Auflisten) laufen über RLS-Policies auf `storage.objects`. Wenn diese zu locker sind, kann ein Nutzer fremde Dateien überschreiben oder löschen.

**Wie funktioniert der Test?**
- Verbindet sich direkt (nur lesend) zur Datenbank.
- Liest alle Policies auf `storage.objects` aus `pg_policies`.
- Wendet die gleichen Regeln wie `permissive-policies` an:
  - `USING (true)` für SELECT/ALL → anonymer oder eingeloggter Lesezugriff auf alle Dateien.
  - `WITH CHECK (true)` für INSERT/UPDATE/ALL → beliebige Uploads ohne Prüfung.
  - UPDATE ohne `WITH CHECK` → mögliche Besitz-Übertragung auf fremde Dateien.

**Güte: ⭐⭐⭐⭐⭐ Exzellent**

Dieser Test schließt eine wichtige Lücke, die `public-storage-buckets` allein nicht deckt. Er liest direkt aus dem Datenbankkatalog und ist daher sehr zuverlässig.

**Bekannte Grenzen**
- Er setzt Datenbank-Zugang voraus (wird ohne Passwort übersprungen).
- Er erkennt wie `permissive-policies` keine subtilen Logikfehler in komplexen Regeln.

---

## 5. Frontend & Netzwerk

### `frontend-service-role-leak` — Service-Role-Key-Leak im Frontend

**Was wird geprüft?**
Ob der mächtige Service-Role-Key aus Versehen im öffentlich einsehbaren Frontend-Code (der Webseite) eingebettet ist.

**Warum ist das wichtig?**
Der Service-Role-Key umgeht alle Zugriffsregeln. Wenn er im JavaScript der Webseite landet, kann jeder Besucher die gesamte Datenbank lesen, ändern und löschen — ohne Anmeldung.

**Wie funktioniert der Test?**
- Lädt die konfigurierte Frontend-URL herunter.
- Sucht nach allen JavaScript-Dateien (extern geladen und inline im HTML).
- Durchsucht alles nach JWT-Token-Mustern (typische `eyJ...`-Strings).
- Dekodiert jeden gefundenen Token und prüft den `role`-Claim.
- Meldet jeden Token mit `role=service_role` als **kritischen** Fund.
- Prüft zusätzlich wichtige HTTP-Security-Header (HSTS, CSP, X-Frame-Options).

**Güte: ⭐⭐⭐⭐ Sehr gut**

Der Test greift ein reales und häufiges Problem auf (besonders bei No-Code/Low-Code-Tools wie Lovable). Das Durchsuchen externer Bundles und Inline-Scripts ist gründlich.

**Bekannte Grenzen**
- Der JWT-Regex erwartet das typische `eyJ`-Prefix (Base64 von `{"`). Ungewöhnliche Token-Formate könnten verpasst werden.
- Wenn der Key zur Laufzeit aus einer unsicheren API geladen wird (statt im Bundle zu liegen), findet der Test ihn nicht.
- Er findet den Key nicht, wenn er bewusst verschleiert (z. B. Base64-codiert) im Code liegt.

---

### `api-http-hardening` — API HTTP-Hardening (CORS & Security-Header)

**Was wird geprüft?**
Ob die HTTP-Schnittstelle der Supabase-API sicher gegen Angriffe aus dem Browser heraus konfiguriert ist — insbesondere CORS (Cross-Origin Resource Sharing) und wichtige Security-Header.

**Warum ist das wichtig?**
Wenn die API jedem beliebigen fremden Webseitenbetreiber erlaubt, Anfragen im Namen eingeloggter Nutzer zu stellen, öffnet das die Tür für Datendiebstahl und unerlaubte Aktionen.

**Wie funktioniert der Test?**
- Sendet Anfragen an drei Endpunkte (`/rest/v1/`, `/auth/v1/settings`, `/auth/v1/health`) mit einer fingierten bösen Herkunft (`Origin: https://evil.example.com`).
- Prüft die Antworten:
  - Wird die Origin gespiegelt **und** `Access-Control-Allow-Credentials: true` gesendet? → **Kritisch** (Session-Diebstahl möglich).
  - Wird `*` mit Credentials erlaubt? → **Kritisch** (verbotene Kombination).
  - Wird die Origin einfach nur gespiegelt (ohne Credentials)? → **Warnung** (bei Supabase mit Bearer-Token weniger kritisch, aber unüblich).
- Prüft zudem auf drei Defense-in-Depth-Header: HSTS, X-Content-Type-Options, Referrer-Policy.

**Güte: ⭐⭐⭐⭐ Sehr gut**

Der Test deckt zwei klassische OWASP/BSI-Patterns ab (CORS-Reflektion und fehlende Security-Header). Die Unterscheidung „mit/ohne Credentials" ist fachlich korrekt.

**Bekannte Grenzen**
- Supabase setzt für REST standardmäßig `Access-Control-Allow-Origin: *`. Das ist **kein Fehler** in diesem Kontext (da Bearer-Token statt Cookies verwendet werden), führt aber zu einer gelben Bewertung bei `X-Content-Type-Options` und `Referrer-Policy`. Die CORS-Bewertung ist daher pragmatisch.
- Der Test prüft nur drei ausgewählte Endpunkte. Ein anderes Verhalten auf selten genutzten Pfaden würde nicht erkannt.

---

### `anon-read-exposure` — Anonymer Lesezugriff auf Tabellen

**Was wird geprüft?**
Welche Tabellen ein anonymer Besucher (ohne Anmeldung) tatsächlich lesen kann — nicht theoretisch, sondern durch echte Anfragen.

**Warum ist das wichtig?**
Viele Entwickler glauben, ihre Daten seien geschützt, weil RLS „an" ist, vergessen aber Policies auf einzelne Tabellen. Dieser Test probiert es wirklich aus.

**Wie funktioniert der Test?**
- **Discovery:** Lädt die OpenAPI-Spezifikation von `/rest/v1/` mit dem Service-Role-Key (um die Tabellenliste zu erhalten).
- **Probing:** Ruft jede gefundene Tabelle mit dem Anon-Key auf (`GET /rest/v1/tabelle?limit=1`).
- Bewertet die Antwort:
  - HTTP 200 mit Daten → Tabelle ist lesbar.
  - HTTP 200, aber leer (`[]`) → vermutlich geschützt, aber leere Tabelle.
  - HTTP 401/403/404/406 → korrekt blockiert.
- Bei sensiblen Tabellennamen (`user`, `profile`, `payment`, `secret`, …) wird ein Lesezugriff besonders kritisch bewertet.

**Güte: ⭐⭐⭐⭐ Sehr gut**

Dieser Test ist besonders wertvoll, weil er **tatsächliches Probing** statt nur theoretischer Analyse macht. Er simuliert den Blickwinkel eines echten Angreifers.

**Bekannte Grenzen**
- **False-Negative-Risiko:** Wenn Supabase die OpenAPI-Spezifikation in einem anderen Format zurückgibt als erwartet, findet der Test 0 Tabellen und meldet „alles grün" — obwohl Tabellen existieren und eventuell exponiert sind.
- Er testet nur **Lesezugriff** (GET). Anonymes Schreiben (INSERT/UPDATE/DELETE) wird nicht ausprobiert (das wäre auf einem Produktivsystem zu riskant und wird durch `permissive-policies` abgedeckt).
- Die Liste „sensibler Namen" ist eine Heuristik. Eine Tabelle `cust_data` würde z. B. nicht als sensibel eingestuft.

---

## 6. Datenbank-Funktionen (Migrations-Analyse)

### `plpgsql-secdef-audit` — PL/pgSQL SECURITY DEFINER Audit

**Was wird geprüft?**
Ob Datenbank-Funktionen mit erweiterten Rechten (`SECURITY DEFINER`) sicher programmiert sind. Diese Funktionen können RLS umgehen und müssen daher besonders sorgfältig abgesichert sein.

**Warum ist das wichtig?**
Eine `SECURITY DEFINER`-Function läuft mit den Rechten ihres Erstellers. Wenn sie nicht prüft, *wer* sie aufruft, und wenn sie anfällig für SQL-Injection ist, kann ein Angreifer mit Datenbank-Admin-Rechten operieren.

**Wie funktioniert der Test?**
- Scannt alle lokalen SQL-Migrations-Dateien.
- Findet `CREATE FUNCTION ... SECURITY DEFINER` via Regex (unterstützt beliebige Dollar-Quote-Tags wie `$$`, `$func$`, `$body$`).
- Prüft jede gefundene Function auf drei Risiken:
  1. **Fehlender `SET search_path`:** Ohne expliziten Pfad kann ein Angreifer gleichnamige Objekte in temporären Schemas anlegen und die Funktion umlenken.
  2. **Fehlender Auth-Check:** Kein `auth.uid()`, `auth.jwt()` oder `has_role()` im Funktionskörper.
  3. **Unsichere dynamische SQL:** `EXECUTE format(...)` ohne `USING` oder String-Konkatenation mit `||`.

**Güte: ⭐⭐⭐⭐ Sehr gut**

Nach einer früheren Verbesserung unterstützt der Regex nun alle gängigen Dollar-Quote-Varianten. Die drei geprüften Risiken sind die wichtigsten Angriffsvektoren für DEFINER-Funktionen.

**Bekannte Grenzen**
- Es ist eine **statische Code-Analyse** (Heuristik). Der Test „versteht" den Code nicht wirklich.
- Wenn ein Auth-Check indirekt über eine Hilfsfunktion erfolgt, erkennt der Test ihn möglicherweise nicht (False Positive: Warnung trotz vorhandenem Schutz).
- Zeilenkommentare (`--`) im SQL werden nicht ausgeblendet. Wenn `auth.uid()` in einem Kommentar steht, könnte der Test fälschlich grün melden (praktisch aber sehr unwahrscheinlich).
- Der Test prüft nur lokale Migrations-Dateien. Funktionen, die direkt auf der Datenbank angelegt wurden (ohne Migration), sieht er nicht.

---

### `pg-search-path-hardening` — Postgres search_path-Hardening

**Was wird geprüft?**
Erweitert den `plpgsql-secdef-audit` auf **alle** Funktionen (auch solche ohne erweiterte Rechte) sowie auf datenbankweite oder rollenweite `search_path`-Einstellungen.

**Warum ist das wichtig?**
Selbst Funktionen, die mit normalen Nutzerrechten laufen (`SECURITY INVOKER`), können angreifbar sein, wenn sie aus einem privilegierten Kontext (z. B. einer Trigger-Funktion oder einer DEFINER-Funktion) aufgerufen werden. Der `search_path` bestimmt, in welchen Schemas Postgres nach Tabellen sucht — ein manipulierter Pfad kann zur Code-Ausführung führen.

**Wie funktioniert der Test?**
- Scannt wie `plpgsql-secdef-audit` die SQL-Migrations.
- Prüft **INVOKER**-Functions (nicht DEFINER, die werden vom anderen Check abgedeckt) auf fehlenden `SET search_path`.
- Sucht nach `ALTER ROLE ... SET search_path` und warnt, wenn der Pfad den variablen `$user`-Anteil enthält (nicht-deterministisch).
- Sucht nach `ALTER DATABASE ... SET search_path` und dokumentiert dies als systemische Konfiguration.

**Güte: ⭐⭐⭐⭐ Sehr gut**

Der Test ergänzt den DEFINER-Audit sinnvoll und deckt systemische Risiken ab. Die Trennung zwischen INVOKER und DEFINER verhindert doppelte Meldungen.

**Bekannte Grenzen**
- Gleiche Einschränkungen wie `plpgsql-secdef-audit`: statische Analyse, keine Semantik-Erkennung.
- Eine INVOKER-Function ohne `SET search_path` ist nicht automatisch angreifbar — sie wird nur dann zum Risiko, wenn sie aus einem höherprivilegierten Kontext aufgerufen wird. Der Test geht hier konservativ vor.
- `ALTER DATABASE`/`ALTER ROLE` sind selten in Migrations enthalten, da Supabase diese Einstellungen oft über das Dashboard steuert.

---

## 7. Edge Functions (Server-Code)

### `edge-fn-audit` — Edge-Function Audit

**Was wird geprüft?**
Ob die lokalen TypeScript-Dateien der Supabase Edge Functions typische Sicherheits-Anti-Patterns enthalten.

**Warum ist das wichtig?**
Edge Functions sind öffentlich erreichbarer Server-Code. Fehler dort betreffen oft die gesamte Datenbank, weil Functions mit dem Service-Role-Key arbeiten (und damit RLS umgehen).

**Wie funktioniert der Test?**
- Scannt alle `*.ts` und `*.tsx`-Dateien im konfigurierten `functions`-Pfad.
- Prüft heuristisch auf fünf Risiken:
  1. **Permissive CORS:** `Access-Control-Allow-Origin: *` kombiniert mit `Allow-Credentials: true`.
  2. **SQL-Injection:** Template-Literale mit `${...}` in `.rpc()`- oder `.query()`-Aufrufen.
  3. **Service-Role ohne Auth:** Nutzung von `SUPABASE_SERVICE_ROLE_KEY` zusammen mit Schreiboperationen (`insert`/`update`/`delete`), aber ohne erkennbaren `auth.getUser()`- oder JWT-Check.
  4. **Secret-Logging:** `console.log`-Aufrufe, die Begriffe wie `authorization`, `secret`, `password` enthalten.
  5. **Fehlende Input-Validation:** `req.json()` ohne erkennbaren Validator (zod, yup, joi, valibot).

**Güte: ⭐⭐⭐ Gut**

Der Test ist eine **Heuristik** — er „versteht" den Code nicht, sondern sucht nach Mustern. Das ist besser als nichts, aber keine Garantie. Er findet typische Copy-Paste-Fehler und Tutorial-Anti-Patterns sehr zuverlässig.

**Bekannte Grenzen**
- **False Positives:** Wenn ein Entwickler `SUPABASE_SERVICE_ROLE_KEY` in einem reinen Lese-Context nutzt (z. B. für öffentliche Aggregationsdaten), wird trotzdem eine Warnung ausgegeben.
- **False Negatives:** Wenn der Auth-Check nicht die erwarteten Schlüsselwörter (`auth.getUser`, `verifyJWT`) nutzt, sondern eine eigene Bibliothek, erkennt der Test den Schutz nicht.
- Die SQL-Injection-Heuristik für `.rpc()` ist konservativ: Viele `.rpc()`-Aufrufe mit Template-Literalen sind harmlos, weil PostgREST parametrisiert arbeitet — der Test warnt trotzdem.
- Es wird nur der **lokale Quellcode** geprüft, nicht die tatsächlich deployeden Functions.

---

## Zusammenfassung aller Checks

| # | Check-ID | Kategorie | Kurzbeschreibung | Güte |
|---|----------|-----------|------------------|------|
| 1 | `config-sanity` | Konfiguration | URL, JWT-Struktur, Schlüssel, Verbindung | ⭐⭐⭐⭐⭐ |
| 2 | `auth-settings` | Auth | Registrierung, Auto-Confirm, OAuth | ⭐⭐⭐⭐ |
| 3 | `auth-user-enumeration` | Auth | Leakt die API Existenz-Infos von E-Mails? | ⭐⭐⭐⭐⭐ |
| 4 | `jwt-hardening` | Auth | Werden unsignierte/schwache JWT akzeptiert? | ⭐⭐⭐⭐⭐ |
| 5 | `rls-status` | RLS | Ist RLS an/aus pro Tabelle? | ⭐⭐⭐⭐⭐ |
| 6 | `permissive-policies` | RLS | Sind Policies zu nachsichtig (true)? | ⭐⭐⭐⭐⭐ |
| 7 | `storage-objects-rls` | Storage | RLS-Policies auf `storage.objects` | ⭐⭐⭐⭐⭐ |
| 8 | `public-storage-buckets` | Storage | Sind Buckets public + sensible Namen? | ⭐⭐⭐⭐ |
| 9 | `frontend-service-role-leak` | Frontend | Ist der Service-Key im Frontend-Code? | ⭐⭐⭐⭐ |
| 10 | `api-http-hardening` | HTTP | CORS-Reflektion, Security-Header | ⭐⭐⭐⭐ |
| 11 | `anon-read-exposure` | API-Surface | Liest der Anon-Key wirklich Tabellen? | ⭐⭐⭐⭐ |
| 12 | `plpgsql-secdef-audit` | DB Functions | Sicherheit von DEFINER-Funktionen | ⭐⭐⭐⭐ |
| 13 | `pg-search-path-hardening` | DB Functions | search_path bei INVOKER + Rollen/DB | ⭐⭐⭐⭐ |
| 14 | `edge-fn-audit` | Edge Functions | CORS, SQLi, Auth, Secrets, Validation | ⭐⭐⭐ |

---

## Was das Tool (noch) nicht prüft

Folgende relevante Sicherheitsaspekte werden aktuell **nicht** abgedeckt. Das ist kein Mangel, sondern eine bewusste Grenze des aktuellen Scopes:

- **Multi-Faktor-Authentifizierung (MFA/2FA):** Ob MFA für Nutzer erzwungen wird.
- **Passwort-Richtlinien:** Mindestlänge, Komplexität, Wiederholungsverbot.
- **Session-Management:** Ablaufzeiten von Sessions, gleichzeitige Logins.
- **Network Restrictions:** IP-Allowlisting für den Datenbank-Zugriff.
- **Backup / PITR:** Ob Point-in-Time-Recovery aktiv ist.
- **Deployed Edge Functions:** Der Test scannt nur lokale Dateien, nicht den tatsächlichen Deploy-Status über die Supabase Management API.
- **Webhook / Trigger-Sicherheit:** Ob Datenbank-Trigger an unsichere Endpunkte senden.
- **Third-Party Extensions:** Ob riskante Postgres-Extensions installiert sind.
- **API-Rate-Limiting:** Ob Brute-Force-Angriffe durch Rate-Limits erschwert werden.

---

*Dokumentation generiert für PccSecurityCheckLovableStack. Stand: Mai 2026.*
