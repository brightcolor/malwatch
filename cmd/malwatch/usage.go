package main

import (
	"fmt"
	"io"

	"github.com/brightcolor/malwatch/internal/version"
)

const usageText = `malwatch %s - Scanner für Schadcode und veraltete Web-Software

Aufruf:
  malwatch scan --path=/var/www [Optionen]
  malwatch repair --path=/var/www/web1/web --backup-dir=… [Optionen]
  malwatch update [--sig-dir=…]
  malwatch whitelist --file=/pfad/zur/datei.php [--whitelist-path=…]
  malwatch version

Prüfumfang:
  --path=PFAD              zu prüfender Pfad, mehrfach angebbar
  --exclude=MUSTER         Pfadmuster auslassen, mehrfach angebbar
                           * bleibt in einer Ebene, ** geht über Ebenen hinweg
  --exclude-from=DATEI     Muster zeilenweise aus einer Datei lesen
  --max-age=TAGE           nur Dateien der letzten TAGE Tage prüfen
  --max-size=BYTES         Dateien über dieser Größe auslassen
  --ignore-chmod0          Dateien mit Rechten 000 auslassen
  --threads=N              Anzahl paralleler Arbeiter (Vorgabe: Kerne)

Prüfstufen:
  --no-malware-scan        keine Suche nach Schadcode
  --no-version-scan        keine Suche nach veralteter Software
  --no-plugin-version-scan Plugins und Themes nicht prüfen
  --no-clamav              ClamAV nicht zusätzlich verwenden
  --offline                keine Abfragen bei den Herstellern
  --ignore=REGEL           diese Regel nicht anwenden, mehrfach angebbar

Ausgabe:
  --json                   Bericht als JSON statt als Text
  --out=DATEI              Bericht in eine Datei schreiben
  --min-severity=STUFE     ab welcher Stufe der Rückgabecode 1 wird
                           (low, medium, high, critical; Vorgabe: medium)
  --show-all               auch aktuelle Installationen aufführen
  --quiet                  keine Fortschrittsanzeige

Bericht per E-Mail:
  --email=ADRESSE          Bericht an diese Adresse senden, mehrfach angebbar
  --email-from=ADRESSE     Absender
  --email-empty            auch senden, wenn nichts gefunden wurde
  --smtp=HOST:PORT         über diesen SMTP-Server senden statt über sendmail
  --smtp-user=NAME         Anmeldename für den SMTP-Server
  --smtp-pass=WERT         Kennwort für den SMTP-Server
  --smtp-tls=MODUS         none, starttls oder tls (Vorgabe: starttls)

Wiederherstellung (repair):
  --path=PFAD              Webstamm der Installation
  --backup-dir=PFAD        wohin die ersetzten Ordner gesichert werden
                           (entfällt nur bei --dry-run)
  --staging-dir=PFAD       wo die Archive vor dem Tausch abgelegt werden
  --progress=DATEI         laufender Zustand als JSON, für die Oberfläche
  --dry-run                holen und prüfen, aber nichts ändern
  --vendor-base=URL        andere Bezugsadresse, für Tests

Ablagen:
  --sig-dir=PFAD           Signaturverzeichnis (Vorgabe: /var/lib/malwatch/signatures)
  --state-dir=PFAD         Zwischenspeicher (Vorgabe: /var/lib/malwatch/state)
  --cache=DATEI            Datei für bereits als sauber bewertete Dateien
  --whitelist-path=DATEI   eigene Freigabeliste (Vorgabe: ~/.malwatch.whitelist)

Rückgabecodes von scan:
  0  nichts gefunden
  1  Funde ab der eingestellten Stufe
  2  nur veraltete Software gefunden
  3  der Lauf selbst ist gescheitert

Rückgabecodes von repair:
  0  alles durch die Originale ersetzt
  2  fertig, aber Elemente ohne Original wurden gelöscht
  3  der Lauf ist gescheitert; die Website blieb unverändert,
     sofern der Abbruch vor dem Tauschen kam
`

func usage(w io.Writer) {
	fmt.Fprintf(w, usageText, version.Version)
}

func cmdVersion() int {
	fmt.Println(version.Version)
	return 0
}
