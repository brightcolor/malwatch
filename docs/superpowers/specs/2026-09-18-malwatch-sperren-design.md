# malwatch Teil 2 „Sperren" — Entwurf

Stand 18.09.2026. Teil 1 „Abwehr" läuft seit 0.19.0 auf web.herkules und schreibt
mit; dieser Entwurf beschreibt, wie aus einem Treffer eine Sperre wird.

## 1. Zweck

Wer den Server angreift, soll draußen bleiben — nachvollziehbar, zeitlich begrenzt
und jederzeit widerrufbar. Die Abwehr erkennt Angriffe bereits und kennt Herkunft
und Punktzahl jeder Adresse; es fehlt der Schritt, daraus eine Sperre zu machen.

Anlass: Ein Scanner holte sich am 17.09.2026 in zwei Wellen je rund 2.000 Anfragen
ab, beantwortet mit 503. Die beiden häufigsten Adressen in den gespeicherten
Treffern stehen bei 1.137 und 1.135 Anfragen.

## 2. Entscheidungen

| Frage | Antwort |
|---|---|
| Umfang | alles drei, gestaffelt: Automatik, Knopf im Panel, Liste für die OPNsense |
| Wo die Sperre greift | erst nginx auf web.herkules, danach die OPNsense an der Kante |
| Rolle von fail2ban | malwatch sperrt das Web selbst; das Panel zeigt zusätzlich die Sperren von fail2ban (Mail, SSH) mit Grund und Ende |
| Auslöser | Summe der Anomalie-Punkte einer Adresse in einem Zeitfenster |
| Dauer | gestaffelt nach Wiederholung: 1 Stunde, 24 Stunden, 7 Tage |
| Geschützt | eigene Netze und Dienste, eigene Ausnahmeliste, Suchmaschinen |
| Angemeldete Nutzer | zählen mit; wer angemeldet angreift, wird gesperrt |
| Einstieg | erst „vorschlagen", dann „sperren"; der Knopf von Hand geht sofort |
| Mechanik in nginx | `deny`-Liste im `http`-Kontext, dazu ein Zähler aus einem zweiten Zugriffslog |

## 3. Ausgangslage

- **Die echte Adresse kennt nur nginx.** TLS endet für 52 der 63 Websites auf der
  OPNsense; die Pakete erreichen nginx von `10.50.0.1`. `set_real_ip_from 10.50.0.1`
  und `real_ip_header X-Forwarded-For` setzen `$remote_addr` auf die echte Adresse.
  Deshalb wirkt `deny` in nginx, eine Sperre per iptables auf dem Webserver dagegen
  nicht — sie träfe den Proxy.
- **57 der 63 vhosts schreiben ihr eigenes `error_log`.** Die Meldung „access
  forbidden by rule" landet damit im Log der Website, nicht zentral. Ein Zähler
  braucht deshalb eine eigene Quelle.
- **fail2ban** hat fünf Jails (`dovecot`, `postfix-sasl`, `pure-ftpd`, `recidive`,
  `sshd`), keinen fürs Web. Seine iptables-Sperren wirken für Mail und SSH, weil
  diese Verbindungen direkt ankommen.
- **Die Abwehr** speichert jeden Treffer mit Adresse, Zeitpunkt, Punktzahl,
  Regel-IDs und dem Vermerk, ob er abgewiesen worden wäre (`malwatch_waf_hit`), dazu
  je Adresse Land, Provider und die Merkmale Tor, VPN, Rechenzentrum und Proxy
  (`malwatch_waf_ip`).
- **Werkzeuge**: `waf-switch` schaltet Websites und Notfälle, `waf-guard` prüft
  stündlich die Regeln, `waf-report` fasst zusammen. Änderungen an nginx laufen
  ausschließlich über `nginx -t` und Reload, nie über einen Neustart.

## 4. Stufen

| Stufe | Release | Inhalt |
|---|---|---|
| 1 | 0.23.0 | Sperrliste, Erkennung im Vorschlagsmodus, Seite „Sperren", Ausnahmeliste, Sperren von Hand, `deny`-Datei, Not-Aus, Zähler |
| 2 | 0.24.0 | fail2ban im Panel: Sperren mit Grund und Ende, Knopf zum Aufheben |
| 3 | 0.25.0 | URL-Tabelle für die OPNsense |

Jede Stufe ist für sich nutzbar. Stufe 1 sperrt bereits wirksam; Stufe 2 bringt
Überblick über die Sperren, die fail2ban ohnehin schon setzt; Stufe 3 verschiebt die
Abwehr an die Kante des Netzes.

## 5. Datenmodell

### Neue Einstellungen in `malwatch_config`

| Spalte | Typ, Vorgabe | Grenzen |
|---|---|---|
| `waf_block_mode` | enum `off`, `propose`, `block`; `off` | |
| `waf_block_score` | int; 50 | 5 bis 10000 |
| `waf_block_window_minutes` | int; 10 | 1 bis 1440 |
| `waf_block_hours_first` | int; 1 | 1 bis 8760 |
| `waf_block_hours_second` | int; 24 | 1 bis 8760 |
| `waf_block_hours_third` | int; 168 | 1 bis 8760 |
| `waf_block_max` | int; 5000 | 100 bis 100000 |
| `waf_block_keep_days` | int; 30 | 1 bis 365 |
| `waf_block_bots` | enum `off`, `on`; `on` | Suchmaschinen verschonen |
| `waf_block_token` | varchar(64); leer | Token der veröffentlichten Liste, Stufe 3; wird beim Einschalten erzeugt |

### `malwatch_waf_block` — eine Zeile je Adresse und Server

| Spalte | Inhalt |
|---|---|
| `server_id`, `ip` | Schlüssel |
| `state` | `proposed`, `active`, `expired`, `lifted`, `dismissed` |
| `reason` | Grund im Klartext, etwa „62 Punkte aus 14 Treffern in 10 Minuten, zuletzt Regel 930130" |
| `score`, `hits` | Punkte und Treffer, die zur Sperre führten |
| `level` | 1, 2 oder 3 — bestimmt die Dauer |
| `source` | `auto`, `manual` oder `fail2ban`; nur die ersten beiden kommen in die `deny`-Datei |
| `created_at`, `blocked_at`, `until` | angelegt, wirksam seit, Ende (`NULL` heißt dauerhaft) |
| `lifted_at`, `lifted_by` | aufgehoben wann und von wem |
| `denied`, `denied_at` | abgewehrte Versuche seit der Sperre und wann zuletzt |

Index auf (`server_id`, `state`, `until`) für das Schreiben der Datei und das
Ablaufen.

### `malwatch_waf_allow` — die Ausnahmeliste

| Spalte | Inhalt |
|---|---|
| `server_id`, `id` | Schlüssel |
| `cidr` | Adresse oder Bereich, etwa `203.0.113.7` oder `203.0.113.0/24` |
| `note` | warum |
| `created_at`, `created_by` | wann und von wem |

Fest im Code, ohne Zeile in der Tabelle: `127.0.0.0/8`, `::1`, `10.50.0.0/24` und
jede Adresse, die der Server selbst trägt. Diese vier lassen sich nicht löschen.

## 6. Erkennen

Der Schritt läuft in `cron_minute()` nach dem Einlesen und dem Nachschlagen der
Herkunft, unter demselben Lock.

1. Punkte je Adresse über das Fenster summieren:
   `SELECT client_ip, SUM(anomaly_score), COUNT(*) FROM malwatch_waf_hit
   WHERE server_id = ? AND seen_at >= ? GROUP BY client_ip HAVING SUM(anomaly_score) >= ?`
2. Adressen aussortieren, die geschützt sind (Abschnitt 10), schon eine Zeile mit
   `state` in (`proposed`, `active`) haben oder innerhalb des Fensters verworfen
   wurden (`state = 'dismissed'`).
3. Je übriger Adresse eine Zeile anlegen: `proposed` im Modus „vorschlagen",
   `active` im Modus „sperren". Im Modus `off` passiert nichts.
4. Der Grund nennt Punkte, Treffer, Fenster und die häufigste Regel des Fensters in
   Worten aus dem Regelkatalog: „62 Punkte aus 14 Treffern in 10 Minuten, meist
   Zugriff auf geschützte Datei (930130)".

Angemeldete Sitzungen zählen mit. Treffer von Websites, deren Abwehr aus ist,
entstehen gar nicht erst.

## 7. Sperren und Dauer

- **Stufe** ist die Zahl der Sperren derselben Adresse in den letzten
  `waf_block_keep_days` Tagen, begrenzt auf 3. Daraus folgt die Dauer:
  `waf_block_hours_first`, `_second`, `_third`.
- **Von Hand** gesperrt wird über den Knopf an einer Adresse oder auf der Seite
  „Sperren": Zustand sofort `active`, `source = manual`, Grund „von Hand gesperrt
  von <Benutzer>", Dauer wie Stufe 1 oder dauerhaft.
- **Dauerhaft** heißt `until = NULL`; solche Sperren laufen nie ab und stehen oben
  in der Liste.
- **Aufheben** setzt `state = lifted`, `lifted_at`, `lifted_by`; die Zeile bleibt
  sichtbar.
- **Verlängern** setzt `until` auf die nächste Stufe.

## 8. Anwenden in nginx

Dateien, von `waf/install.sh` angelegt und danach unverändert:

```
/etc/nginx/conf.d/waf-blocked.conf   include /etc/nginx/waf/blocked.conf;
                                     map $status $mw_denied { 403 1; default 0; }
                                     log_format mw_block '$time_iso8601 $remote_addr $status $host "$request"';
/etc/nginx/waf/blocked.conf          von malwatch geschrieben, je Zeile: deny 185.177.72.17;
```

Ablauf beim Anwenden, höchstens einmal je Cron-Durchgang und nur bei Änderung:

1. Gewünschten Inhalt aus den eigenen aktiven Sperren bilden — `state = 'active'`
   und `source` in `auto`, `manual`, aufsteigend nach Adresse, höchstens
   `waf_block_max` Zeilen —, mit Kopfzeile „von malwatch erzeugt, <Zeit>".
2. Unterscheidet er sich von der Datei: alte Datei nach
   `/var/lib/malwatch/waf/last-good/blocked.conf` sichern, neue schreiben.
3. `nginx -t`. Scheitert die Prüfung: alte Datei zurück, kein Reload, Fehler in den
   Auftrag und auf die Seite.
4. Sonst Reload. `waf-guard` prüft stündlich weiter mit und stellt bei einem Fehler
   den letzten guten Stand her — die Sperrdatei kommt in seine Obhut.

Die Datei gilt im `http`-Kontext und damit für alle Websites, auch für das Panel
selbst. Deshalb die Ausnahmeliste und der Not-Aus.

## 9. Zählen der abgewehrten Versuche

- In die `nginx_directives` jeder Website mit eingeschalteter Abwehr kommt eine
  zweite Zeile: `access_log /var/log/waf/blocked.log mw_block if=$mw_denied;`.
  nginx erlaubt mehrere Zugriffslogs je Website; das Log der Kundenwebsite bleibt
  unverändert.
- `/var/log/waf/blocked.log` gehört `root:adm`, Rechte 0640, und wird von derselben
  logrotate-Datei gedreht wie das Audit-Log.
- Der Cron liest die Datei wie das Audit-Log — Zustand aus Inode und Versatz in
  `/var/lib/malwatch/waf/blocked-reader.json` — und zählt je Adresse, die gesperrt
  ist, `denied` hoch und setzt `denied_at`.
- Zeilen mit Status 403 aus anderen Gründen (etwa eine Regel der Website selbst)
  zählen nur, wenn die Adresse gesperrt ist; alles andere wird verworfen.

## 10. Ausnahmen

Vor jeder Sperre wird geprüft, in dieser Reihenfolge:

1. **Eigene Netze und Dienste** — fest im Code: `127.0.0.0/8`, `::1`,
   `10.50.0.0/24`, alle Adressen des Servers (`ip -o addr`, einmal je Cronlauf
   gelesen).
2. **Ausnahmeliste** aus `malwatch_waf_allow`, Adressen und Bereiche in CIDR.
3. **Suchmaschinen**, wenn `waf_block_bots` auf `on` steht. Ihre Adressbereiche
   kommen über die Maschinerie der Herkunft aus 0.21.0: eine weitere Quelle
   `searchbots` lädt die veröffentlichten Listen von Google
   (`https://developers.google.com/static/search/apis/ipranges/googlebot.json`) und
   Bing (`https://www.bing.com/toolbox/bingbot.json`), baut sie in eine Bereichsdatei
   unter `/var/lib/malwatch/waf/origin/searchbots.bin` um und prüft mit derselben
   binären Suche. Die Dateien nennen Bereiche als `ipv4Prefix` und `ipv6Prefix`; ein
   eigener Leser im Format der Herkunft genügt.

Wird eine Adresse in die Ausnahmen aufgenommen, während sie gesperrt ist, hebt
derselbe Schritt ihre Sperre auf.

## 11. Bedienung im Panel

Neuer Menüpunkt **Security > Abwehr > Sperren**.

- **Kopf**: Zustand der Automatik (`aus`, `vorschlagen`, `sperren`) mit Knöpfen zum
  Umschalten, Zahl der aktiven Sperren, Knopf „Alle Sperren aufheben" mit Rückfrage.
- **Aktive Sperren**: Adresse mit Land, Provider und den Merkmalen aus der Herkunft,
  Grund, seit, bis (oder „dauerhaft"), Treffer davor, abgewehrte Versuche. Je Zeile:
  „aufheben", „verlängern", „dauerhaft", „nie sperren".
- **Vorschläge**: dieselbe Darstellung mit „jetzt sperren" und „verwerfen". Ein
  verworfener Vorschlag bekommt `state = 'dismissed'` und kommt für die Dauer des
  Fensters nicht wieder.
- **Abgelaufen und aufgehoben**: die letzten `waf_block_keep_days` Tage, knapp.
- **Nie sperren**: die Ausnahmeliste mit Notiz, Knöpfen zum Anlegen und Löschen.

Dazu ein Knopf **„sperren"** an jeder Adresse in den Regel-Karten und in den
Einzeltreffern der Website-Seite.

Alle Knöpfe legen einen Auftrag an (`job_kind = 'waf'`), wie die übrigen Aktionen
der Abwehr; die Seite lädt sich nach, sobald er fertig ist.

## 12. fail2ban im Panel (Stufe 2)

Ein Abschnitt auf derselben Seite, unter den eigenen Sperren:

- Der Cron liest je Jail `fail2ban-client status <jail>` und hält Jail, Adresse und
  Zeitpunkt in `malwatch_waf_block` mit `source = 'fail2ban'` fest — dieselbe
  Darstellung, dieselbe Herkunft, aber ohne eigene Datei: die Sperre gehört fail2ban.
- Grund ist der Jail im Klartext: „Mail: zu viele fehlgeschlagene Anmeldungen
  (postfix-sasl)".
- Der Knopf „aufheben" ruft `fail2ban-client set <jail> unbanip <ip>`.
- Sperren, die fail2ban selbst entfernt hat, verschwinden beim nächsten Durchgang.

## 13. URL-Tabelle für die OPNsense (Stufe 3)

- Der Cron schreibt bei jeder Änderung `/var/lib/malwatch/waf/blocked.txt`: eine
  Adresse je Zeile, nur aktive Sperren, ohne Kommentare.
- Ausgeliefert wird sie über eine eigene Stelle im Panel-vhost unter einem Pfad mit
  Token aus der Konfiguration (`waf_block_token`, 32 Zeichen, beim Einschalten
  erzeugt). Ohne Token antwortet die Stelle mit 404.
- Die OPNsense holt die Liste als „URL Table (IPs)"-Alias in ihrem eigenen Takt und
  sperrt an der Kante. Eingerichtet wird das dort von Hand; die Spec nennt nur die
  Adresse der Liste und den Takt.
- Die Liste enthält Adressen, sonst nichts.

## 14. Aufräumen und Datenschutz

- `cron_hourly()` setzt abgelaufene Sperren auf `expired` und entfernt Zeilen, deren
  Ende länger als `waf_block_keep_days` zurückliegt.
- Adressen stehen ohnehin schon in `malwatch_waf_hit` und `malwatch_waf_ip`; die
  Sperrliste hält sie nicht länger als deren Aufbewahrung plus `waf_block_keep_days`.
- Die veröffentlichte Liste enthält keine Namen, keine Zeiten, keine Gründe.
- Auftragsprotokolle nennen Zahlen und Gründe, keine Zugangsdaten.
- Nur Administratoren sehen die Seiten, wie bisher.

## 15. Fehlerfälle

| Fall | Verhalten |
|---|---|
| `nginx -t` scheitert | alte Datei zurück, kein Reload, Auftrag auf Fehler, Meldung auf der Seite |
| Datei nicht schreibbar, Platte voll | wie oben, Meldung nennt Pfad und Rechte |
| Obergrenze `waf_block_max` erreicht | keine neue Sperre, Meldung auf der Seite, bestehende laufen weiter |
| Adresse steht in den Ausnahmen | Sperre wird nicht angelegt; eine bestehende wird aufgehoben |
| Der Betreiber sperrt sich selbst aus | `waf-switch sperren aus` leert die Datei und lädt nginx neu, ohne Panel |
| Suchmaschinenliste fehlt oder ist alt | Suchmaschinen werden nicht verschont; die Seite sagt es, gesperrt wird trotzdem |
| fail2ban antwortet nicht | der Abschnitt zeigt den Fehler, die eigenen Sperren bleiben unberührt |
| Zwei Cronläufe gleichzeitig | verhindert der bestehende Lock der Abwehr |

## 16. Prüfung

- **Reine Funktionen** in `ispconfig/tests`: Punktesumme und Entscheidung im Fenster,
  Stufe und Dauer, Grund als Satz, Ausnahmenprüfung mit CIDR für IPv4 und IPv6,
  Erzeugen der `deny`-Datei aus einer Liste, Lesen einer Zeile aus `blocked.log`,
  Leser der Suchmaschinenlisten mit Beispieldateien.
- **Klassenprobe** gegen eine Wegwerf-Datenbank: ein Durchlauf vom Treffer zur
  Sperre, Datei geschrieben, `nginx -t` und Reload nur aufgezeichnet, Ablauf,
  Aufheben, Not-Aus, Obergrenze.
- **`check_wiring.sh`**: die Datei entsteht nur über die Klasse, der Not-Aus
  existiert in `waf-switch`, Ausnahmen werden vor dem Sperren geprüft, die Texte
  stehen in beiden Wörterbüchern.
- **`render_pages.php`**: die neue Seite in allen Zuständen (leer, mit Vorschlägen,
  mit Sperren, Automatik aus).
- **Einspielen** auf web.herkules in Blöcken mit Freigabe, beginnend im
  Vorschlagsmodus; erst nach ein paar Tagen Beobachtung auf „sperren".

## 17. Nicht enthalten

- Sperren einzelner Websites statt des ganzen Servers
- Sperren nach Land oder Provider
- Listen fremder Anbieter (AbuseIPDB und andere)
- eigene Jails für fail2ban
- Meldung an den Angreifer, warum er gesperrt ist

## 18. Risiken

| Risiko | Antwort |
|---|---|
| Ein Fehlalarm sperrt einen Kunden aus | Vorschlagsmodus zuerst, Staffel beginnt bei einer Stunde, Ausnahmeliste, Not-Aus |
| Häufige Reloads belasten nginx | höchstens ein Reload je Minute und nur bei Änderung; Reload lädt neu, ohne Verbindungen zu kappen |
| Die Datei wächst unbegrenzt | Obergrenze und Ablauf der Sperren |
| Suchmaschine wird gesperrt | veröffentlichte Adressbereiche werden verschont, Prüfung vor jeder Sperre |
| Der Zähler braucht eine Zeile im vhost | betrifft nur Websites mit eingeschalteter Abwehr, ändert deren Kundenlog nicht, und ISPConfig schreibt die Zeile beim nächsten Lauf ohnehin neu |
| Angreifer wechselt die Adresse | erwartet; die Staffel und die Liste für die OPNsense begrenzen den Nutzen des Wechsels, mehr leistet dieser Teil nicht |
