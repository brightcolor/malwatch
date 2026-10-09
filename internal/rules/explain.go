package rules

import "github.com/brightcolor/malwatch/internal/report"

// Explanation tells an operator why a rule reported a file and what to do.
// The texts are German, like everything the panel shows.
type Explanation struct {
	// Why says in plain words what the rule saw and what that means.
	Why string
	// Advice says what to do. Empty takes the advice for the rule's
	// severity, see Advice.
	Advice string
}

// Sources of findings outside the rule catalog. Their findings carry these
// rule IDs, or, for the signature engines, the engine name after "engine:".
const (
	ExtraCoreModified = "core.modified"
	ExtraForeignFile  = "vendor.foreign_file"
	ExtraSignature    = "engine:signature"
	ExtraClamAV       = "engine:clamav"
)

// Extra describes a source of findings that is no catalog rule.
type Extra struct {
	ID       string
	Title    string
	Severity report.Severity
	AutoSafe bool
}

// Extras are the sources of findings besides the catalog, for the panel's
// rule table.
var Extras = []Extra{
	{ExtraCoreModified, "weicht von der Auslieferung des Herstellers ab", report.SeverityHigh, false},
	{ExtraForeignFile, "gehört nicht zur Auslieferung des Herstellers", report.SeverityHigh, false},
	{ExtraSignature, "gleicht einer bekannten Schadcode-Probe (Linux Malware Detect)", report.SeverityCritical, false},
	{ExtraClamAV, "vom Virenscanner ClamAV erkannt", report.SeverityCritical, false},
}

var explanations = map[string]Explanation{
	// ------------------------------------------------------------ eval
	"php.eval.encoded":         {Why: "Der Code entschlüsselt Text (etwa mit base64_decode oder gzinflate) und führt ihn sofort als Programm aus. So verstecken Angreifer ihren eigentlichen Schadcode; ehrlicher Code hat dafür keinen Grund."},
	"php.eval.request":         {Why: "Der Code führt aus, was in der Anfrage mitgeschickt wird ($_GET, $_POST, ein Cookie). Wer die Adresse der Datei kennt, kann damit beliebige Befehle auf der Website ausführen: eine klassische Hintertür."},
	"php.eval.hexname":         {Why: "Ein Funktionsname wie eval oder system steht in Hex-Schreibweise (\\x65\\x76…), damit ihn niemand findet. Das dient nur dem Verstecken."},
	"php.preg_replace.eval":    {Why: "preg_replace mit dem Modifikator /e führt das Ersetzte als Code aus. PHP hat das 2012 abgeschafft; heute steckt es fast nur noch in Hintertüren und in sehr alten Plugins."},
	"php.callback.request":     {Why: "Welche Funktion aufgerufen wird, kommt direkt aus der Anfrage. Damit kann ein Besucher jede PHP-Funktion starten, auch system oder eval."},
	"php.dynamic.request_call": {Why: "Der Name der aufgerufenen Funktion steht in der Anfrage ($_GET['f']()). Der Angreifer schickt den Namen und die Daten mit: eine Hintertür."},
	"php.eval.variable": {
		Why:    "eval führt den Inhalt einer Variablen als Code aus. Das steckt in Schadcode und in ehrlichen Werkzeugen, etwa Vorlagen-Systemen oder Testdateien von Bibliotheken. Was in die Variable kommt, entscheidet.",
		Advice: "In der Ansicht nachsehen, woher die Variable ihren Inhalt hat: aus der Anfrage oder aus entschlüsseltem Text heißt Schadcode, dann in die Quarantäne verschieben. In Test- und Vorlagendateien bekannter Bibliotheken ist es harmlos, dann freigeben.",
	},
	"php.eval.create_function": {Why: "create_function baut eine Funktion aus verschlüsseltem Text oder aus Anfragedaten. Das war der Ersatz für eval in älteren Befällen."},
	"php.eval.variable_call":   {Why: "eval führt das Ergebnis eines Aufrufs aus, dessen Funktionsname in einer Variablen steht (eval($a($b('…')))). So war jeder Schadcode des ersten untersuchten Befalls gebaut; ehrlicher Code ruft so nichts auf."},
	"php.silence.preamble":     {Why: "Die Datei schaltet die Fehlerausgabe und das Fehlerprotokoll zugleich ab. Niemand soll sehen, was sie tut; so beginnen viele Schadcode-Dateien."},

	// ----------------------------------------------------- obfuscation
	"php.obfuscation.base64_blob":       {Why: "Ein langer kodierter Block wird später entschlüsselt. Das kann ein eingebettetes Bild sein; häufiger ist es versteckter Code."},
	"php.include.decoy_guard":           {Why: "Eine Datei wird hinter einer Abfrage eingebunden, die immer zutrifft. Die Abfrage ist nur Tarnung. Diese Form lud auf einer befallenen Website 43-mal versteckten Schadcode nach."},
	"php.obfuscation.name_in_variable":  {Why: "Alltägliche Funktionsnamen stecken in Variablen mit Zufallsnamen ($DfgSFXZ = 'strlen'). So verschleiert ein Code-Generator, was die Datei tut."},
	"php.obfuscation.xor_literal":       {Why: "Ein Funktionsname entsteht erst durch das Verrechnen zweier Zeichenketten (XOR). Das hat nur einen Zweck: den Namen unsichtbar zu machen."},
	"php.obfuscation.substr_of_nothing": {Why: "Ein leerer Text wird umständlich erzeugt (substr(\"\", …)). So beginnt ein bekannter Entschlüssler, der Funktionsnamen aus einem verwürfelten Alphabet zusammensetzt."},
	"php.obfuscation.chr_arithmetic":    {Why: "Buchstaben werden als Rechnung geschrieben (chr(187-73) ergibt r). So bleibt ein verräterisches Wort aus der Datei heraus."},
	"php.obfuscation.base64_marker":     {Why: "Im kodierten Text steckt ein Aufruf wie eval(base64_decode…) oder system($_GET…). Der Schadcode ist nur verpackt."},
	"php.obfuscation.goto_spaghetti":    {Why: "Der Ablauf ist in Sprungmarken zerlegt, die auf einer Zeile hin- und herspringen. So sieht maschinell verschleierter Code aus."},
	"php.obfuscation.split_open_tag":    {Why: "Die Datei setzt das PHP-Starttag aus Stücken zusammen, lädt etwas aus dem Netz und prüft, ob es Code ist. Das ist ein Nachlader für Schadcode."},
	"php.obfuscation.chr_chain":         {Why: "Ein Text entsteht aus vielen chr()-Aufrufen hintereinander, Buchstabe für Buchstabe als Zahl. So verstecken Angreifer Funktionsnamen."},
	"php.obfuscation.hex_call":          {Why: "Ein in Hex geschriebener Name wird direkt aufgerufen. Das ist eine versteckte Funktion."},
	"php.obfuscation.variable_function": {Why: "Eine Funktion wird über eine zusammengesetzte Variable aufgerufen (${'…'}[…]). Das verschleiert, was aufgerufen wird."},
	"php.stream.archive_url":            {Why: "Die Datei zeigt mit zip:// oder compress:// in ein Archiv hinein. So laden Angreifer Code aus einer harmlos wirkenden Datei, etwa einem Bild."},
	"php.globals.extract_request":       {Why: "extract() legt aus den Anfragedaten beliebige Variablen an. Ein Besucher kann damit Variablen überschreiben und den Ablauf der Datei steuern."},

	// ------------------------------------------------------ execution
	"php.exec.request":       {Why: "Ein Systembefehl wird mit Teilen aus der Anfrage ausgeführt. Wer die Adresse der Datei kennt, startet damit Befehle auf dem Server."},
	"php.backtick.request":   {Why: "Ein Shell-Befehl in Backticks enthält Anfragedaten. Damit führt der Server Befehle aus, die ein Besucher vorgibt."},
	"php.dropper.write_code": {Why: "Die Datei schreibt entschlüsselten oder mitgeschickten Inhalt in eine Datei. So legen Angreifer weitere Hintertüren ab."},
	"php.dropper.cron":       {Why: "PHP macht eine Datei ausführbar und trägt sie per Shell in die Crontab ein. So nistet sich Schadcode auf dem Server ein und startet regelmäßig neu."},
	"php.exec.crontab":       {Why: "PHP ändert die Crontab über einen Shell-Aufruf. Damit kommen Angreifer nach einer Bereinigung wieder."},
	"php.exec.background": {
		Why:    "PHP startet einen Prozess im Hintergrund (nohup, setsid oder mit &). Das steht in Werkzeugen und Tests von Bibliotheken und in Schadcode, der unbemerkt weiterlaufen soll.",
		Advice: "Liegt die Datei in einem Testordner einer Bibliothek (vendor/…/test), ist sie harmlos: freigeben. Sonst in der Ansicht nachsehen, welches Programm gestartet wird.",
	},
	"shell.fetch_exec": {Why: "Ein Shell-Skript lädt ein Programm aus dem Netz, macht es ausführbar und startet es im Hintergrund. Das ist ein Nachlader."},
	"shell.in_uploads": {Why: "Ein Shell-Skript liegt in einem Ordner für hochgeladene Dateien. Dorthin gehören Bilder und Dokumente."},

	// ------------------------------------------------------- includes
	"php.include.assembled_path": {Why: "Der Pfad einer eingebundenen Datei wird aus Array-Teilen zusammengesetzt. So verbirgt ein Lader, welche Datei er einbindet."},
	"php.include.stream_wrapper": {Why: "Code wird aus einem Archiv, aus einem data://-Text oder aus php://input eingebunden, also aus Daten, die jemand mitschicken oder verstecken kann."},
	"php.tool.leaf_mailer":       {Why: "Das ist der Leaf PHP Mailer, ein Werkzeug für Massenmails. Angreifer legen ihn auf Websites ab, um darüber Spam zu verschicken."},
	"php.tool.file_manager": {
		Why:    "Ein eigenständiger Datei-Manager (Tiny File Manager). Manche Betreiber installieren ihn bewusst; Angreifer legen ihn ab, um Dateien auf der Website zu verwalten.",
		Advice: "Wurde er bewusst installiert, mit einem Kennwort schützen oder entfernen, sobald er nicht mehr gebraucht wird. Kennt ihn niemand, in die Quarantäne verschieben.",
	},
	"php.tool.file_manager_open": {
		Why:    "Ein Datei-Manager (PHP File Manager), bei dem die Anmeldung abgeschaltet ist. Wer die Datei aufruft, kann ohne Kennwort Dateien hochladen, ändern und ausführen. Angreifer legen ihn nach einem Einbruch ab, oft in einem Plugin-Ordner mit ausgedachtem Namen.",
		Advice: "In die Quarantäne verschieben und nachsehen, wie er auf die Website kam: Zugriffsprotokoll zum Zeitpunkt der Datei, neue Plugins, Anmeldungen im WordPress-Backend. Liegt er in einem Plugin, das per Upload kam, die Kennwörter aller Administratoren ändern.",
	},
	"php.include.remote":    {Why: "Die Datei bindet Code von einer fremden Internetadresse ein. Wer diese Adresse kontrolliert, kontrolliert die Website."},
	"php.remote.fetch_eval": {Why: "Die Datei lädt etwas von einer Internetadresse und führt es sofort als Code aus."},
	"php.remote.fetch_eval_indirect": {
		Why:    "Die Datei lädt etwas aus dem Netz und führt eine Variable als Code aus. Meist ist das ein Nachlader; manche alten Bibliotheken, etwa XML-RPC-Klassen, tun Ähnliches aus ehrlichen Gründen.",
		Advice: "Gehört die Datei zu einer bekannten Bibliothek (Ordnername, dieselbe Datei auf anderen Websites), freigeben. Sonst in die Quarantäne verschieben.",
	},

	// ------------------------------------------------------- webshells
	"php.webshell.known":                 {Why: "Die Datei trägt das Kennzeichen einer bekannten Webshell (c99, WSO, b374k, ALFA und andere). Das ist eine Hintertür mit Dateiverwaltung und Befehlszeile."},
	"php.webshell.column_cipher":         {Why: "Ein Lader, der seinen Code durch Vertauschen von Spalten entschlüsselt und ausführt. Diese Webshell-Familie ist bekannt."},
	"php.webshell.include_wrapper":       {Why: "Eine Funktion bindet nur ihren Parameter ein, daneben liegt ein verschlüsselter Block. So tarnt eine Webshell-Familie ihren Lader."},
	"php.obfuscation.hex_function_names": {Why: "Namen wie php_uname oder base64_decode stehen als Hex-Text in der Datei. So verstecken Webshells, welche Funktionen sie nutzen."},
	"php.backdoor.self_delete":           {Why: "Ein Upload-Skript, das sich auf ein Stichwort in der Anfrage selbst löscht. Damit verwischt ein Angreifer seine Spuren."},
	"php.dropper.temp_include":           {Why: "Die Datei schreibt entschlüsselten Code in eine Temp-Datei und bindet sie ein. So entgeht Schadcode einer Suche nach eval."},
	"php.webshell.password_gate":         {Why: "Ein Kennwort aus der Anfrage wird geprüft, danach führt die Datei Code aus. Das ist die Tür einer Webshell."},
	"php.webshell.hardcoded_gate":        {Why: "Das Kennwort aus der Anfrage wird mit einem fest eingetragenen Hash verglichen, danach laufen Befehle. Eine abgesicherte Hintertür."},
	"php.webshell.file_manager":          {Why: "Dateien werden mit Namen aus der Anfrage gelöscht, umbenannt oder angelegt. Das ist die Dateiverwaltung einer Webshell."},
	"php.webshell.auth_pass":             {Why: "Die Zeile $auth_pass = '…' ist das Kennwort bekannter Webshells (WSO und ihre Abkömmlinge)."},

	// --------------------------------------------------------- uploads
	"php.upload.unchecked": {
		Why:    "Eine hochgeladene Datei wird dorthin gelegt, wo die Anfrage es sagt, ohne erkennbare Prüfung. Damit kann ein Besucher PHP-Dateien auf die Website laden.",
		Advice: "In der Ansicht nachsehen, ob die Datei eine Anmeldung verlangt. Ohne Anmeldung ist sie eine offene Tür: in die Quarantäne verschieben.",
	},
	"php.upload.traversal": {Why: "Eine hochgeladene Datei wird in ein übergeordnetes Verzeichnis (../) gelegt. So landen Hintertüren außerhalb der Upload-Ordner."},
	"php.mailer.request":   {Why: "mail() bekommt Empfänger und Text aus der Anfrage. Das ist ein Spam-Versender."},

	// ------------------------------------------------ disguise and seo
	"php.cloaking.search_bot":   {Why: "Die Datei zeigt Suchmaschinen etwas anderes als Besuchern, etwa Links auf fremde Seiten. Das nennt sich Cloaking und schadet dem Ranking der Website."},
	"php.stealth.touch_mtime":   {Why: "Die Datei setzt den Zeitstempel einer Datei auf den einer anderen. So sieht eine neue Hintertür alt aus."},
	"web.iframe.hidden":         {Why: "Ein unsichtbarer Rahmen lädt eine fremde Seite. So werden Besucher unbemerkt auf fremde Inhalte geleitet."},
	"js.eval.encoded":           {Why: "JavaScript entschlüsselt Text und führt ihn aus. So verstecken Angreifer Umleitungen und eingeschleuste Werbung."},
	"js.fromcharcode_chain":     {Why: "Ein langer Text entsteht aus Zeichencodes (String.fromCharCode). Das verschleiert, was das Skript tut."},
	"js.miner":                  {Why: "Das Skript schürft Kryptowährung im Browser der Besucher."},
	"js.document_write_encoded": {Why: "JavaScript schreibt entschlüsselten Text in die Seite, oft eingeschleuste Links oder Skripte."},
	"malware.alfa_toolkit":      {Why: "Datei aus dem ALFA-Baukasten (ALFA_DATA, alfacgiapi). Das sind die Werkzeuge der ALFA-Webshell."},

	// ------------------------------------------------------- locations
	"php.in_uploads": {
		Why:    "Eine PHP-Datei liegt in einem Ordner für hochgeladene Dateien. Ruft jemand sie auf, führt der Server sie aus. Manche Plugins legen dort harmlose Dateien ab, etwa eine index.php mit „Silence is golden“ oder die Einstellungen eines Sicherheits-Plugins.",
		Advice: "Ist es eine leere index.php oder eine Datenablage eines bekannten Plugins, freigeben. Sonst in die Quarantäne verschieben.",
	},
	"php.disguised_as_image": {Why: "Eine PHP-Datei trägt einen Bildnamen (bild.jpg.php, …-300x200.php). So tarnen Angreifer Hintertüren zwischen Bildern."},
	"php.in_image":           {Why: "Eine Bilddatei enthält PHP-Code. Mit einer passenden Einstellung führt der Server sie als Programm aus."},
	"htaccess.php_handler":   {Why: "Die .htaccess macht eine fremde Endung zu PHP. Dann läuft auch eine Datei namens bild.jpg als Programm."},
	"htaccess.auto_prepend":  {Why: "Die .htaccess bindet bei jedem Aufruf eine eigene Datei vorab ein. So läuft Schadcode auf jeder Seite, obwohl keine Datei der Website verändert aussieht."},
	"htaccess.redirect_foreign": {
		Why:    "Die .htaccess leitet Besucher auf eine fremde Adresse um. Das kann gewollt sein, etwa nach einem Umzug, oder eingeschleust, etwa als Spam-Umleitung.",
		Advice: "Ist die Umleitung gewollt, freigeben. Sonst die Zeile entfernen und nach der Ursache suchen.",
	},
	"htaccess.cgi_handler":      {Why: "Die .htaccess macht eine fremde Endung über CGI ausführbar. So bringen Angreifer eigene Programme zum Laufen."},
	"htaccess.disable_security": {Why: "Die .htaccess schaltet die Web Application Firewall (ModSecurity) für diesen Ordner ab."},
	"htaccess.php_lockdown": {
		Why:    "Die .htaccess sperrt alles PHP außer einer eigenen Liste von Dateien. Angreifer schützen so ihre Hintertür vor anderen Angreifern.",
		Advice: "Die .htaccess in die Quarantäne verschieben. Die eigentliche Hintertür steht in ihrer Liste der erlaubten Dateien; diese ebenfalls prüfen.",
	},
	"binary.elf_in_uploads": {Why: "Ein Linux-Programm liegt in einem Ordner für hochgeladene Dateien. Dort gehört keines hin; meist ist es ein Bot oder ein Krypto-Miner."},
	"binary.elf": {
		Why:    "Ein Linux-Programm liegt im Webverzeichnis. Manche Bibliotheken bringen Hilfsprogramme mit, etwa für ihre Tests; eingeschleuste Programme sehen genauso aus.",
		Advice: "Gehört das Programm zu einer Bibliothek (Ordner vendor/, tests), wird es auf der Website nicht gebraucht: in die Quarantäne verschieben oder freigeben. Unbekannte Programme in die Quarantäne verschieben.",
	},

	// ---------------------------------------------------------- extras
	ExtraCoreModified: {
		Why:    "Die Datei weicht von der Fassung ab, die der Hersteller ausliefert (Prüfsumme von wordpress.org oder des Plugins). Jemand hat sie verändert: ein Angreifer oder eine Handkorrektur.",
		Advice: "Mit „Kern ersetzen“ das Original zurückholen. Danach klären, wer die Datei geändert hat.",
	},
	ExtraForeignFile: {
		Why:    "Die Datei liegt in einem Ordner, dessen Inhalt der Hersteller vollständig kennt (der WordPress-Kern oder ein Plugin), gehört aber nicht zur Auslieferung. Sie kam auf anderem Weg hinein: durch einen Angreifer, ein altes Update oder eine Vorlage.",
		Advice: "In der Ansicht und bei den Fähigkeiten nachsehen, was die Datei tut. Wird sie nicht gebraucht, in die Quarantäne verschieben; ist sie ein bekannter harmloser Rest, freigeben.",
	},
	ExtraSignature: {
		Why:    "Die Datei gleicht einer bekannten Schadcode-Probe aus der Signaturliste von Linux Malware Detect (Prüfsumme oder Byte-Muster).",
		Advice: "In die Quarantäne verschieben und klären, wie die Datei hineinkam: Zugangsdaten ändern, Plugins und Themes aktualisieren, das Zugriffsprotokoll um den Zeitpunkt der Datei ansehen.",
	},
	ExtraClamAV: {
		Why:    "Der Virenscanner ClamAV kennt diese Datei als Schadcode.",
		Advice: "In die Quarantäne verschieben und klären, wie die Datei hineinkam: Zugangsdaten ändern, Plugins und Themes aktualisieren, das Zugriffsprotokoll um den Zeitpunkt der Datei ansehen.",
	},
}

// Default advice by how sure a rule is. A rule whose hit alone justifies the
// quarantine (AutoSafe) gets the first; the others ask the reader to look.
const (
	adviceAutoSafe = "Diese Art Code hat keinen ehrlichen Zweck. In die Quarantäne verschieben und klären, wie die Datei hineinkam: Zugangsdaten ändern, Plugins und Themes aktualisieren, das Zugriffsprotokoll um den Zeitpunkt der Datei ansehen."
	adviceSevere   = "Prüfen, ob die Datei zu einem Plugin, Theme oder Update gehört (Ordner, Datum, dieselbe Datei auf anderen Websites). Gehört sie zu nichts, in die Quarantäne verschieben; ist sie Herstellercode, freigeben."
	adviceMild     = "Häufig harmlos. Die Ansicht und die Fähigkeiten zeigen, was die Datei tut: Befehle aus der Anfrage oder verschleierter Code sprechen gegen sie, eine Anmeldung und Rechteprüfung für sie."
)

// Explain returns the explanation of a rule or extra by ID.
func Explain(id string) (Explanation, bool) {
	e, ok := explanations[id]
	return e, ok
}

// Advice is what to do about a finding of the rule or extra: its own advice
// where it has one, otherwise the advice for its severity.
func Advice(id string, severity report.Severity, autoSafe bool) string {
	if e, ok := explanations[id]; ok && e.Advice != "" {
		return e.Advice
	}
	switch {
	case autoSafe:
		return adviceAutoSafe
	case severity.AtLeast(report.SeverityHigh):
		return adviceSevere
	}
	return adviceMild
}
