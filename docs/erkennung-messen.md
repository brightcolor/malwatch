# Erkennung messen

„Bessere Erkennung" ohne Zahl ist Gefühlssache. Eine Regel, die alles meldet,
sieht an einem einzelnen Beispiel großartig aus. Deshalb zwei Messungen, immer
beide, immer vorher und nachher.

## 1. Trefferquote auf echtem Befall

```bash
tools/detection-score.sh ./malwatch /var/www/clients/clientN/webM/web bekannte-schaddateien.txt
```

Die Liste enthält je Zeile einen absoluten Pfad. Wie man zu einer solchen Liste
kommt, hängt vom Fall ab; bei dem Befall, der diese Messung ausgelöst hat, trugen
die abgelegten Dateien alle einen Zufallsnamen aus elf Zeichen:

```bash
find "$WEBROOT" -type f -regextype posix-extended -regex '.*/[A-Za-z0-9]{11}\.php' \
  | sort > bekannte-schaddateien.txt
```

Das Muster ist nicht allgemeingültig — es ist die Handschrift *einer* Kampagne.
Eine Liste von Hand zu prüfen, bevor man sie als Wahrheit nimmt, gehört dazu.

## 2. Fehlalarme auf ehrlichem Code

Die Gegenprobe fährt der CI-Job `clean-cms` bei jedem Push: frisch geladenes
WordPress und Joomla müssen **null** Funde ergeben. Wer nur die erste Messung
ansieht, optimiert sich in Übererkennung hinein.

Für die schärfere Variante nimmt man echte Kundenseiten, die als sauber gelten,
und vergleicht die Zahl der Funde vor und nach der Änderung. Fremder
Produktionscode ist ein härterer Prüfstein als ein frisches WordPress: dort
liegen Bibliotheken mit Krypto-Konstanten, eingebettete Bilder und
minimierter Code.

```bash
alt=$(./malwatch-alt scan --path="$R" --offline --quiet --json | grep -c '"rule":')
neu=$(./malwatch-neu scan --path="$R" --offline --quiet --json | grep -c '"rule":')
```

## Der Stand vom 05.09.2026

Anlass war ein echter Befall auf einer betreuten Website: 149 abgelegte Dateien,
davon 67 verschiedene Nutzlasten.

| | vorher | nachher |
|---|---|---|
| 149 bekannte Schaddateien | 28 (18 %) | 144 (96 %) |
| frisches WordPress 6.6.2 | 0 | 0 |
| vier Kundenseiten in Betrieb | 0 / 34 / 0 / 0 | 0 / 34 / 0 / 0 |

Was die Lücke ausmachte, in der Reihenfolge ihres Gewichts:

1. **Zerlegte Funktionsnamen.** `'base'.'64'.'_dec'.'ode'` statt
   `base64_decode`. Jede Regel, die den Namen ausschreibt, lief ins Leere. Die
   Maschine liest die Datei jetzt ein zweites Mal mit zusammengesetzten
   Zeichenketten.
2. **Aufruf über Variablen.** `eval($a($b('…')))` — der Name steht nie neben
   `eval`. Dafür gibt es jetzt `php.eval.variable_call`.
3. **Schweigepräambel.** `error_reporting(0)` zusammen mit abgeschaltetem
   Fehlerprotokoll, am Dateianfang. `php.silence.preamble`.
4. **Ein Werkzeug mit Türsteher.** Leafmailer trägt gar keine Verschleierung und
   fiel deshalb durch jedes Raster; erkennbar am Sitzungsschlüssel aus dem Hash
   der eigenen Datei. `php.webshell.session_filehash_gate`.

## Die zweite Runde, 05.09.2026

Ein zweiter, gründlicherer Blick auf dieselbe Website — diesmal nicht über die
Namensform der abgelegten Dateien, sondern über den **Zeitraum des Befalls**:
alles, was zwischen dem 20. und dem 30. Juni geschrieben wurde.

| | vorher | nachher |
|---|---|---|
| 149 bekannte Schaddateien | 144 | 144 |
| 217 Dateien aus dem Befallszeitraum | 184 | **200** |
| frisches WordPress, vier Kundenseiten | unverändert | unverändert |

Vier weitere Kniffe, jeder mit eigener Antwort:

1. **Türsteher ohne eval.** Eine Shell prüfte ein Passwort gegen einen Hash im
   eigenen Quelltext und schrieb danach Dateien und holte über das Netz — die
   Regel verlangte aber `eval` oder `system` im Klartext.
2. **Lader aus einem Archiv.** `zip://jpc_….zip#b_….tmp`, mal über `require`,
   mal über `file_get_contents`.
3. **Superglobale in Escapes.** `"\x5f\107\x45\x54"` ist `_GET`. Die zweite
   Sicht löst jetzt Hex- und Oktal-Escapes mit auf.
4. **Verkettung mit Kommentaren dazwischen.** `"ra"/*-X8KKH~;-*/."nge"` ergibt
   `range`; die Nahtsuche übersprang bisher nur Leerraum.

Dazu **Leaf PHP Mailer** in einer zweiten Variante, die mit der ersten keine
Form teilt — die wird beim Namen genannt statt beschrieben.

### Zwei Regeln, die wieder verschwunden sind

Genau dafür gibt es den Fehlalarm-Korpus:

- `${$var}` als Aufruf ist eine gewöhnliche PHP-Möglichkeit. Doctrine, Mailster
  und BackupBuddy benutzen sie.
- Eine Adresse in ein Archiv hinein ist für sich harmlos: Roundcube kopiert mit
  `copy("zip://$path#$entry", …)` aus einem hochgeladenen Archiv. Die Regel
  greift jetzt nur noch, wenn die Adresse **fest verdrahtet** ist.

## Zwei Lehren aus der ersten Runde

**Die zusammengesetzte Sicht ist für Namen da, nicht für Daten.** Sie klebt auch
mehrzeilige Konstanten zusammen. phpseclib schreibt eine Diffie-Hellman-Primzahl
als verkettete Hex-Stücke, ein Galerie-Plugin trägt ein base64-PNG — beide wurden
dadurch zu Funden. Regeln, die auf einen langen Block sehen statt auf einen
Namen, tragen deshalb `RawOnly`.

**`'a' . 'b'` und `'.'` sehen im Text gleich aus.** Der Unterschied ist nur, ob
ein Anführungszeichen eine Zeichenkette öffnet oder schließt. Die erste Fassung
des Zusammensetzens war ein Suchen-und-Ersetzen und zerstörte jedes
`explode('.', $host)`. Es braucht einen kleinen Leser mit Zustand — und der gibt
auf, statt zu raten, wenn er den Faden verliert.
