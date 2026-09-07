#!/bin/sh
# Checks the wiring between the extension files that PHP cannot see.
#
# Every failure below has actually happened during the first install: the
# files are syntactically fine, so php -l passes, and the page only breaks
# when someone opens it.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
status=0

# Ein Verzeichnis fuer die Zwischendateien, die einige Pruefungen brauchen.
# mktemp statt eines vorhersagbaren /tmp/check_wiring_$$_...: die PID ist zu
# erraten, und eine der drei Stellen legte ihre Datei ohne vorheriges rm -f an,
# war also auf einem geteilten System wirklich angreifbar. Der trap raeumt auf,
# auch wenn das Skript vorzeitig endet - und er aendert den Rueckgabewert
# nicht, weil er selbst kein exit aufruft.
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/check_wiring.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT INT TERM HUP

fail() {
	printf 'FAIL: %s\n' "$1" >&2
	status=1
}

# Eine Zeile, die nach fuehrenden Leerzeichen mit einem Kommentarzeichen
# beginnt, erklaert etwas - sie ruft nichts auf und zeigt niemandem einen Weg
# zum Gehen. Eine Erklaerung muss den Fehler, vor dem sie warnt, beim Namen
# nennen duerfen, sonst verbietet die Pruefung ihre eigene Begruendung.
# Benutzt von Pruefung 26, 28 und 32.
comment_start='[[:space:]]*(//|#|\*|/\*|<!--)'

# 1. A page using tform_actions must set $tform_def_file. tform_actions reads
#    it from the global scope and dies without it.
for page in "$root"/interface/*.php; do
	# The word boundary matters: "listform_actions" contains "tform_actions",
	# and without it every list page would be reported as a broken form page.
	if grep -qE '(^|[^a-z])tform_actions' "$page" && ! grep -q '\$tform_def_file' "$page"; then
		fail "$(basename "$page") uses tform_actions but sets no \$tform_def_file"
	fi
done

# 2. The same for listform_actions and $list_def_file.
for page in "$root"/interface/*.php; do
	if grep -q 'listform_actions' "$page" && ! grep -q '\$list_def_file' "$page"; then
		fail "$(basename "$page") uses listform_actions but sets no \$list_def_file"
	fi
done

# 3. Every form and list definition named in a page must exist.
for page in "$root"/interface/*.php; do
	for def in $(grep -ohE "(form|list)/[a-z_]+\.(tform|list)\.php" "$page" || true); do
		[ -f "$root/interface/$def" ] || fail "$(basename "$page") references $def, which does not exist"
	done
done

# 4. A list definition implies a template and a language file whose names
#    ISPConfig derives from the list name, not from the file name.
for def in "$root"/interface/list/*.list.php; do
	[ -f "$def" ] || continue
	name=$(grep -oE "liste\['name'\][[:space:]]*=[[:space:]]*'[a-z_]+'" "$def" | head -1 | sed "s/.*'\([a-z_]*\)'/\1/")
	[ -n "$name" ] || { fail "$(basename "$def") has no liste['name']"; continue; }
	[ -f "$root/interface/templates/${name}_list.htm" ] || fail "template templates/${name}_list.htm for list $name is missing"
	for lang in de en; do
		[ -f "$root/interface/lang/${lang}_${name}_list.lng" ] || fail "language file ${lang}_${name}_list.lng for list $name is missing"
	done
done

# 5. The same for form definitions.
for def in "$root"/interface/form/*.tform.php; do
	[ -f "$def" ] || continue
	name=$(grep -oE "form\['name'\][[:space:]]*=[[:space:]]*'[a-z_]+'" "$def" | head -1 | sed "s/.*'\([a-z_]*\)'/\1/")
	[ -n "$name" ] || { fail "$(basename "$def") has no form['name']"; continue; }
	for lang in de en; do
		[ -f "$root/interface/lang/${lang}_${name}.lng" ] || fail "language file ${lang}_${name}.lng for form $name is missing"
	done
	for tpl in $(grep -ohE "templates/[a-z_]+\.htm" "$def" || true); do
		[ -f "$root/interface/$tpl" ] || fail "$(basename "$def") references $tpl, which does not exist"
	done
done

# 6. Every source named in file.list must exist, and every interface file must
#    be listed. A file that ships but is never installed is invisible; a line
#    pointing at nothing aborts enable_files halfway.
while IFS=: read -r action source target; do
	case "$action" in
		c|s|d) ;;
		*) continue ;;
	esac
	[ -e "$root/$source" ] || fail "file.list names $source, which does not exist"
done < "$root/install/file.list"

for file in $(cd "$root" && find interface server -type f | sort); do
	grep -q ":$file:" "$root/install/file.list" || fail "$file is not in install/file.list"
done

# 7. No native submit buttons. The panel binds [data-submit-form] and posts
#    by AJAX; a type="submit" button inside the panel produces no request at
#    all, so the button looks fine and simply does nothing.
for tpl in "$root"/interface/templates/*.htm; do
	[ -f "$tpl" ] || continue
	if grep -q 'type="submit"' "$tpl"; then
		fail "$(basename "$tpl") uses type=\"submit\"; the panel needs type=\"button\" with data-submit-form"
	fi
done

# 8. A button that submits must name the form and the action, otherwise the
#    click is silently ignored.
for tpl in "$root"/interface/templates/*.htm; do
	[ -f "$tpl" ] || continue
	subs=$(grep -c 'data-submit-form' "$tpl" || true)
	acts=$(grep -c 'data-form-action' "$tpl" || true)
	if [ "$subs" != "$acts" ]; then
		fail "$(basename "$tpl") has $subs data-submit-form but $acts data-form-action"
	fi
done

# 9. Templates must not reference a language key that neither language file
#    defines - the page would then show an empty label.
for tpl in "$root"/interface/templates/*.htm; do
	[ -f "$tpl" ] || continue
	for key in $(grep -ohE "tmpl_var name=['\"][a-z_]+_txt['\"]" "$tpl" | sed -E "s/.*['\"]([a-z_]+_txt)['\"]/\1/" | sort -u); do
		if ! grep -qhE "\\\$wb\['$key'\]" "$root"/interface/lang/de_*.lng; then
			fail "$(basename "$tpl") uses {$key}, which no German language file defines"
		fi
	done
done

# 10. No template may open its own form. The panel wraps the whole content
#     area in <form id="pageForm">, and a second form of that name inside it
#     is a nested form: the browser hands the fields to the inner one, while
#     $('#pageForm') finds the outer one first. serialize() then posts a form
#     without any of the fields - no token, no action - and the panel answers
#     with "CSRF attempt blocked".
for tpl in "$root"/interface/templates/*.htm; do
	[ -f "$tpl" ] || continue
	if grep -qE '<form[ >]' "$tpl"; then
		fail "$(basename "$tpl") opens its own <form>; the panel already provides pageForm"
	fi
done

# 11. A page that checks the token must hand it to form.tpl.htm, which renders
#     the two hidden fields. Under any other variable name they stay empty and
#     every submit is rejected.
for page in "$root"/interface/*.php; do
	grep -q 'csrf_token_check' "$page" || continue
	for var in _csrf_id _csrf_key; do
		grep -q "setVar('$var'" "$page" || fail "$(basename "$page") checks the token but never sets $var"
	done
done

# 12. The schema must not be called install.sql. The framework picks that name
#     up on its own and loads it through load_install_sql(), which reads its
#     credentials from $conf['mysql'][...] - keys that exist only during the
#     ISPConfig setup. On a running system mysql is called without a password,
#     asks for one, reads it from the redirected SQL file and fails on the
#     remains. The install then prints a database error while reporting success.
if [ -f "$root/install/install.sql" ]; then
	fail "install/install.sql exists; the framework would load it and fail - the schema belongs in install/schema.sql"
fi
if [ ! -f "$root/install/schema.sql" ]; then
	fail "install/schema.sql is missing"
fi
grep -q 'install/schema.sql' "$root/install/manual_install.php" 	|| fail "manual_install.php does not load install/schema.sql"

# 13. The same for the uninstall schema, and the loader both sides share. The
#     framework's run_uninstall_sql() has the identical defect and runs while
#     an extension is being removed, where nobody watches the output.
if [ -f "$root/install/uninstall.sql" ]; then
	fail "install/uninstall.sql exists; run_uninstall_sql() would load it and fail - use install/uninstall-schema.sql"
fi
if [ ! -f "$root/install/uninstall-schema.sql" ]; then
	fail "install/uninstall-schema.sql is missing"
fi
if [ ! -f "$root/install/sql_loader.php" ]; then
	fail "install/sql_loader.php is missing"
fi
if ! grep -q 'uninstall-schema.sql' "$root/install/installer.php"; then
	fail "installer.php does not drop the tables from install/uninstall-schema.sql"
fi

# 14. Ein fertiger Lauf darf nicht daran scheitern, dass die Website noch
#     keine Einstellungszeile hat. Genau das verwarf das Ergebnis von 66
#     Prüfungen und zeigte 60 Websites als "ungeprüft" an.
if grep -q 'function update_site_state' "$root/server/lib/classes/malwatch_actions.inc.php"; then
	sed -n '/function update_site_state/,/^	}/p' "$root/server/lib/classes/malwatch_actions.inc.php" 		| grep -q 'create_site_row' 		|| fail "update_site_state verwirft das Ergebnis, wenn die Website keine Einstellungszeile hat"
fi

# 15. Eine neue Spalte in einer bestehenden Tabelle erreicht keine vorhandene
#     Installation: CREATE TABLE IF NOT EXISTS lässt sie unberührt. Jede
#     Erweiterung braucht deshalb einen Zusatz, der sich selbst prüft.
if grep -q 'job_kind' "$root/install/schema.sql"; then
	grep -q 'information_schema' "$root/install/schema.sql" 		|| fail "schema.sql fügt Spalten hinzu, ohne sie über information_schema zu prüfen"
fi

# 16. Ohne --progress schreibt kein Lauf aus dem Panel eine Fortschrittsdatei,
#     und die Ansicht bliebe für immer leer.
grep -q -- '--progress=' "$root/server/lib/classes/malwatch_runner.inc.php" 	|| fail "der Runner übergibt --progress nicht; die Fortschrittsansicht bekäme nie Daten"
for kind in repair quarantine; do
	grep -q "'$kind'" "$root/server/lib/classes/malwatch_runner.inc.php" 		|| fail "der Runner kennt die Auftragsart $kind nicht"
done

# 17. Ein Pfad aus einem Formularfeld darf nie ungeprüft in einen Auftrag
#     wandern. Die Prüfung gegen malwatch_finding ist die erste von zwei.
if grep -q 'function malwatch_queue_quarantine' "$root/interface/lib/malwatch_lib.inc.php"; then
	sed -n '/function malwatch_queue_quarantine/,/^}/p' "$root/interface/lib/malwatch_lib.inc.php" 		| grep -q 'malwatch_finding' 		|| fail "malwatch_queue_quarantine prüft die Pfade nicht gegen malwatch_finding"
fi

# 18. Eine Seite, die JSON liefert, darf keine Vorlage laden - sonst kommt
#     HTML mit, und der Aufrufer bekommt kein gültiges JSON.
if [ -f "$root/interface/malwatch_progress.php" ]; then
	if grep -q 'newTemplate\|tpl_defaults' "$root/interface/malwatch_progress.php"; then
		fail "malwatch_progress.php lädt eine Vorlage, liefert also kein reines JSON"
	fi
	grep -q 'is_admin' "$root/interface/malwatch_progress.php" 		|| fail "malwatch_progress.php prüft die Administratorrechte nicht"
fi

# 19. Jede Aktion, die löscht oder ersetzt, braucht eine Rückfrage. Ein
#     Fehlklick auf "Alle Funde löschen" wäre sonst endgültig.
for action in delete_one delete_all repair; do
	if grep -q "=== '$action'" "$root/interface/malwatch_site_show.php"; then
		grep -q "confirm_${action}_txt" "$root/interface/templates/malwatch_site_show.htm" 			|| fail "die Aktion $action hat keine Rückfrage in der Vorlage"
	fi
done

# 20. "Freigeben" liest sich neben einem Schadcode-Fund wie Durchwinken.
if grep -q "ignore_txt'\] = 'Freigeben'" "$root/interface/lang/de_malwatch.lng"; then
	fail "der Knopf heißt noch 'Freigeben'; er ändert nur den Zustand, er gibt nichts frei"
fi

# 21. Eine halb getauschte Installation darf nicht zurück ans Netz. Der
#     Rückweg hängt am Rückgabecode, nicht am blossen Ende des Laufs.
if grep -q 'function finish_repair' "$root/server/lib/classes/cron.d/560-malwatch.inc.php"; then
	sed -n '/function finish_repair/,/^	}/p' "$root/server/lib/classes/cron.d/560-malwatch.inc.php" 		| grep -q 'exit_code' 		|| fail "das Zurückschalten sieht den Rückgabecode nicht an"
fi

# 22. Der Fortschrittsbalken braucht einen Nenner. Ohne --expect meldet der
#     Scanner nur einen Zaehler, und die Anzeige faellt auf feste fuenf
#     Prozent zurueck - was ein Lauf ist, der aussieht wie ein Absturz.
#     Ein Filter auf einen Wert aus der falschen Tabelle (z.B. scan_state = 'done',
#     ein Wert aus malwatch_job.job_status) lässt die Abfrage stillschweigend
#     leer laufen und kein --expect wird je angehängt.
#     WICHTIG: Die nachfolgende Prüfung darf nicht in einer Pipe stehen, weil
#     fail() dann in einer Subshell läuft und status=1 in der Hauptshell nicht
#     wirkt. Das würde dazu führen, dass die Prüfung die Fehler zwar druckt, aber
#     das Skript trotzdem mit Rückgabewert 0 endet — genau die Sorte Fehler,
#     die sie fangen soll. Deshalb schreiben wir die Zeilen in eine temporäre
#     Datei und lesen daraus.
runner="$root/server/lib/classes/malwatch_runner.inc.php"
if ! grep -q -- "--expect=" "$runner"; then
	fail "der Runner reicht kein --expect durch, der Balken bleibt stehen"
fi
if ! grep -q 'files_scanned' "$runner"; then
	fail "der Runner liest die Dateizahl des letzten Laufs nicht"
fi
# Prüfe, dass der scan_state-Filter des Runners nur gültige Enum-Werte nutzt.
# Die gültigen Werte liest der Test aus schema.sql, nicht aus dem Runner.
schema="$root/install/schema.sql"
if grep -q 'scan_state' "$runner"; then
	# Extrahiere die gültigen Enum-Werte aus schema.sql
	# Beispiel: `scan_state` enum('clean','findings','outdated','error') NOT NULL
	valid_enum=$(grep '`scan_state` enum' "$schema" | sed "s/.*enum(\([^)]*\)).*/\1/")
	# Entferne Anführungszeichen und erstelle eine Liste der gültigen Werte
	valid_list=$(printf "%s" "$valid_enum" | sed "s/'//g" | sed "s/,/ /g")

	# Extrahiere jeden quoted Wert nach scan_state aus dem Runner.
	# Speichere die Zeilen in eine temporäre Datei und lese aus der Datei,
	# nicht aus einer Pipe — so läuft fail() in der Hauptshell.
	tmp="$tmpdir/scan_state"
	grep 'scan_state' "$runner" > "$tmp" 2>/dev/null || true

	while read line; do
		# Entferne alles bis scan_state
		after=$(printf "%s" "$line" | sed 's/^.*scan_state//')
		# Extrahiere den ersten quoted Wert
		first_val=$(printf "%s" "$after" | sed "s/[^']*'\([^']*\).*/\1/")

		if [ -n "$first_val" ]; then
			# Prüfe ob dieser Wert in der gültigen Liste ist.
			# Die Leerzeichen ringsum verhindern, dass „clean" als Treffer
			# für „cleanX" zählt.
			case " $valid_list " in
				*" $first_val "*)
					# Wert ist gültig
					;;
				*)
					# Wert ist ungültig
					fail "der Runner nutzt scan_state-Wert '$first_val', aber schema.sql kennt ihn nicht (gültig: $valid_list)"
					;;
			esac
		fi
	done < "$tmp"
fi

# Erweiterung von Prüfung 22 auf die zwei Aufzählungen, die dieser Zweig neu
# schreibt: action_type bekommt den Wert 'quarantine' dazu (das MODIFY COLUMN
# weiter unten in schema.sql), und malwatch_config.auto_action pflegt seine
# Whitelist im Formular getrennt von der Spalte selbst. Dieselbe Technik wie
# oben: die gültigen Werte kommen aus schema.sql, nicht aus einer Abschrift
# hier im Test, und die Treffer landen erst in einer Datei, damit fail() in
# der Hauptshell läuft statt in einer Pipe-Subshell.
actions="$root/server/lib/classes/malwatch_actions.inc.php"
if [ -f "$actions" ]; then
	valid_enum=$(grep -E '`malwatch_action_log`.*`action_type` enum' "$schema" | sed "s/.*enum(\([^)]*\)).*/\1/")
	valid_list=$(printf "%s" "$valid_enum" | sed "s/'//g" | sed "s/,/ /g")

	tmp="$tmpdir/action_type"
	grep -oE "log_action\([^,]+, '[a-z_]+'" "$actions" > "$tmp" 2>/dev/null || true

	while read line; do
		val=$(printf "%s" "$line" | sed "s/[^']*'\([^']*\).*/\1/")
		if [ -n "$val" ]; then
			case " $valid_list " in
				*" $val "*)
					;;
				*)
					fail "malwatch_actions.inc.php schreibt action_type='$val', aber schema.sql kennt ihn nicht (gültig: $valid_list)"
					;;
			esac
		fi
	done < "$tmp"
fi

tform="$root/interface/form/malwatch_config.tform.php"
if [ -f "$tform" ]; then
	valid_enum=$(grep -E '`malwatch_config`.*`auto_action` enum' "$schema" | sed "s/.*enum(\([^)]*\)).*/\1/")
	valid_list=$(printf "%s" "$valid_enum" | sed "s/'//g" | sed "s/,/ /g")

	# Nur der eigene Block des Feldes: 'value' => array(...) kommt in
	# derselben Datei auch bei anderen Feldern vor, mit fremden Schlüsseln.
	tmp="$tmpdir/auto_action"
	sed -n "/'auto_action' => array(/,/'auto_preset_id' => array(/p" "$tform" \
		| grep -oE "=> '[a-z]+'" | sed "s/=> '\([a-z]*\)'/\1/" | sort -u > "$tmp" 2>/dev/null || true

	while read val; do
		if [ -n "$val" ]; then
			case " $valid_list " in
				*" $val "*)
					;;
				*)
					fail "malwatch_config.tform.php erlaubt auto_action=$val, aber schema.sql kennt ihn nicht (gültig: $valid_list)"
					;;
			esac
		fi
	done < "$tmp"
fi

# 23. Das Modul braucht eine module.conf.php mit Namen und Startseite, sonst
#     erscheint der Punkt in der oberen Leiste ohne Inhalt.
conf="$root/interface/module.conf.php"
if [ ! -f "$conf" ]; then
	fail "interface/module.conf.php fehlt, das Modul erscheint nicht"
else
	for key in "name" "title" "startpage"; do
		if ! grep -qE "\\\$module\['$key'\]" "$conf"; then
			fail "module.conf.php setzt \$module['$key'] nicht"
		fi
	done
fi

# 24. Der Installer muss das Modul in sys_user.modules eintragen und beim
#     Deinstallieren wieder entfernen. Ohne den Eintrag sieht niemand den
#     neuen Punkt, mit einem verwaisten Eintrag zeigt das Panel einen
#     Menuepunkt ohne Ziel.
inst="$root/install/installer.php"
if ! grep -q 'sys_user' "$inst"; then
	fail "der Installer traegt das Modul nicht in sys_user.modules ein"
fi

# 25. Die alte Menuedatei darf nicht mehr existieren, sonst steht das Addon
#     doppelt im Panel - einmal oben und einmal in der Seitenleiste der Sites.
if [ -f "$root/interface/malwatch.menu.php" ]; then
	fail "interface/malwatch.menu.php ist noch da, das Addon stuende doppelt"
fi
if grep -q 'menu.d/malwatch.menu.php' "$root/install/file.list"; then
	fail "file.list installiert noch die alte Menuedatei"
fi

# 26. Nach dem Umzug darf nirgends mehr Code oder Benutzertexte auf sites/
#     zeigen: weder in check_module_permissions('sites') noch in Modulnamen
#     wie $_SESSION['s']['module']['name'] = 'sites', noch in Pfaden wie
#     web/sites/ noch in Meldungen wie "Websites > malwatch". Historische
#     Kommentare, die erklären WARUM es früher so war, sind ok - sie helfen,
#     den Kontext zu verstehen, nennen aber keinem Benutzer einen Weg zum Gehen.
#     Was eine Erklärung ist, entscheidet dieselbe Regel wie in Prüfung 28 und
#     32: eine Zeile, die nach führenden Leerzeichen mit einem Kommentarzeichen
#     beginnt. Vorher galt eine Liste von Schlüsselwörtern ("früher", "alt",
#     "historisch", "previously", "before") für die GANZE Zeile - womit
#     $app->auth->check_module_permissions('sites'); // wie früher
#     mit Rückgabewert 0 durchlief: eine Prüfung, die aussieht, als hielte sie.
#     Mit der Kommentarregel entfällt die Liste und die bekannte Umlautlücke
#     ("Frueher" ohne Umlaut) gleich mit.
#
#     Diese Prüfung sucht den GANZEN Erweiterungsbaum (install/, interface/,
#     server/, tests/, auch README.md), nicht nur interface/. Deshalb schreiben
#     wir potenzielle Fehler erst in eine Datei und lesen aus der Datei (wie in
#     Prüfung 22), um sicherzustellen, dass fail() in der Hauptshell läuft.

old_refs_file="$tmpdir/old_refs"

# Suchmuster, die auf den alten Ort zeigen:
# 1. check_module_permissions mit 'sites' oder "sites"
# 2. Modulnamens-Wert als 'sites' oder "sites" in $_SESSION['s']['module']['name']
#    oder $module['name'] - sowohl als Array-Literal ('name' => 'sites') als
#    auch als direkte Zuweisung ($module['name'] = 'sites'). Die Zuweisungsform
#    ist die, die interface/module.conf.php tatsaechlich benutzt
#    ($module['name'] = 'security';); sie fehlte hier drei Runden lang, obwohl
#    der Absatz oben sie schon immer als Beispiel nannte.
# 3. 'sites' in der modules-Liste, als Array-Literal ('modules' => '...sites...')
#    oder als Zuweisung ($x['modules'] = '...sites...')
# 4. 'sites' im startmodule-Wert, als Array-Literal ('startmodule' => 'sites')
#    oder als Zuweisung ($x['startmodule'] = 'sites')
# 5. Benutzer-lesbarer Text, der den alten Ort nennt: "Websites > malwatch",
#    "Websites-Modul", "Modul Websites", "Websites module". Frueher stand hier
#    "Websites.*module" - ein Muster, das jede Zeile traf, die irgendwo das Wort
#    Websites und irgendwo spaeter "module" enthaelt, also auch reine
#    Codezeilen ohne jeden Rueckfall.
# 6. Direkter Pfad sites/malwatch, interface/web/sites oder ein
#    panelrelatives web/sites/ - letzteres nur, wenn ihm KEIN Schrägstrich
#    vorausgeht. Sonst schlaegt jeder Dateipfad an, den malwatch selbst meldet:
#    /var/www/clients/client1/web7/web/sites/default/files/shell.php ist ein
#    Fund auf einer Drupal-Installation, kein Rueckfall. Der Rueckfall sieht
#    anders aus - load_language_file('web/sites/lib/lang/...') oder
#    'web/sites/lib/menu.d/...' -, dort steht am Anfang ein Anfuehrungszeichen
#    oder eine Klammer, kein Schrägstrich.
#
# Schließe die check_wiring.sh Datei selbst aus (sie beschreibt in Kommentaren,
# was sie sucht, und würde sich selbst finden).
#
# KEIN Ausschluss mehr fuer SQL-Kontexte wie "AS sites": der Fehlalarm, den er
# vermeiden sollte (COUNT(*) FROM malwatch_site AS sites in
# malwatch_config_edit.php), trifft auf keines der obigen Muster - ohne den
# Filter bleibt diese Zeile schon unentdeckt (kein Treffer, grep endet mit 1).
# Der Filter fing also nie den Fehlalarm, den es geben sollte, sondern nur
# noch echte Treffer, die zufaellig auf derselben Zeile wie "AS sites" standen.

grep -rn \
	-e "check_module_permissions('sites')" \
	-e 'check_module_permissions("sites")' \
	-e "'name' *=> *'sites'" \
	-e '"name" *=> *"sites"' \
	-e "\['name'\] *= *'sites'" \
	-e '\["name"\] *= *"sites"' \
	-e "'modules' *=> *'[^']*sites" \
	-e '"modules" *=> *"[^"]*sites' \
	-e "\['modules'\] *= *'[^']*sites" \
	-e '\["modules"\] *= *"[^"]*sites' \
	-e "'startmodule' *=> *'sites'" \
	-e '"startmodule" *=> *"sites"' \
	-e "\['startmodule'\] *= *'sites'" \
	-e '\["startmodule"\] *= *"sites"' \
	-e "Websites > malwatch" \
	-e "Websites-Modul" \
	-e "Modul Websites" \
	-e "Websites module" \
	-e "interface/web/sites" \
	-e "^web/sites/" \
	-e "[^/]web/sites/" \
	-e "sites/malwatch" \
	"$root" \
	2>/dev/null | grep -v "^Binary" | grep -v "check_wiring.sh" > "$old_refs_file" || true

# Lese die Treffer und prüfe, ob sie Benutzertexte oder aktiven Code sind.
# Eine Kommentarzeile erklärt, eine Codezeile handelt - dieselbe Regel wie in
# Prüfung 28 und 32, und dieselbe Definition ($comment_start).
while read line; do
	file=$(printf "%s" "$line" | cut -d: -f1)
	linenum=$(printf "%s" "$line" | cut -d: -f2)
	content=$(printf "%s" "$line" | cut -d: -f3-)

	# Eine Zeile, die nach führenden Leerzeichen mit einem Kommentarzeichen
	# beginnt, gibt historischen Kontext. Sie ruft nichts auf und nennt
	# niemandem einen Weg zum Gehen.
	if printf "%s" "$content" | grep -qE "^$comment_start"; then
		continue
	fi

	# Ansonsten: Das ist aktiver Code oder ein Benutzertext, der einen alten
	# Ort nennt - unerlaubt.
	fail "$(basename "$file"):$linenum: $content"
done < "$old_refs_file"

# 27. Der Endpunkt muss den Prozentwert deckeln. Der Erwartungswert ist die
#     Dateizahl des letzten Laufs, und eine Website waechst dazwischen - ein
#     Balken bei 140 Prozent ist schlimmer als einer ohne Prozentangabe.
prog="$root/interface/malwatch_progress.php"
if ! grep -q '99' "$prog"; then
	fail "malwatch_progress.php deckelt den Prozentwert nicht bei 99"
fi

# 28. DOMNodeRemoved ist ein Mutation Event, das Chrome seit Version 127
#     abgeschaltet hat. Ein Abbruch, der daran haengt, greift nie - der Timer
#     ueberlebt jede Navigation und zieht den Bediener aus jeder Seite zurueck.
#
#     Dieselbe Unterscheidung wie Pruefung 26: ein Kommentar, der den
#     historischen Grund erklaert, ist erlaubt - eine echte Benutzung nicht.
#     Ohne diese Ausnahme wuerde die Pruefung ihre eigene Erklaerung
#     verbieten: status.htm dokumentiert genau diesen Fehler in einem
#     Kommentar, und der Kommentar muss den Namen des Ereignisses nennen, um
#     ihn zu erklaeren. addEventListener('DOMNodeRemoved' und Verwandtes in
#     einer Codezeile ist eine Benutzung; eine Zeile, die (nach fuehrenden
#     Leerzeichen) mit einem Kommentarzeichen beginnt, ist Erklaerung. Wie in
#     Pruefung 26 schreiben wir Treffer erst in eine temporaere Datei und
#     lesen daraus, damit fail() in der Hauptshell laeuft statt in einer
#     Subshell der Pipe.
dom_refs_file="$tmpdir/dom_refs"
grep -rn 'DOMNodeRemoved' "$root/interface" 2>/dev/null | grep -v "^Binary" > "$dom_refs_file" || true

while read line; do
	file=$(printf "%s" "$line" | cut -d: -f1)
	linenum=$(printf "%s" "$line" | cut -d: -f2)
	content=$(printf "%s" "$line" | cut -d: -f3-)
	# Ein Kommentarzeichen am Zeilenanfang ist Erklaerung, kein Aufruf.
	if printf "%s" "$content" | grep -qE "^$comment_start"; then
		continue
	fi

	fail "DOMNodeRemoved wird noch benutzt, der Abbruch greift nicht ($(basename "$file"):$linenum)"
done < "$dom_refs_file"

# 29. Ein loadContent im Takt laedt die ganze Seite neu und reisst den
#     Bediener aus dem, was er gerade ansieht.
if grep -rnE 'set(Timeout|Interval)[^;]*loadContent' "$root/interface" >/dev/null 2>&1; then
	fail "eine Seite laedt sich im Takt selbst neu"
fi

# 30. Die Statusseite ist die Startseite des Moduls und muss existieren.
if [ ! -f "$root/interface/status.php" ]; then
	fail "interface/status.php fehlt, das Modul startet ins Leere"
fi

# 31. Jedes Kopierziel unter interface/web/security/ braucht ein Verzeichnis,
#     das der Installer selbst anlegt.
#
#     enable_files() im Kern legt kein Elternverzeichnis an und prueft den
#     Rueckgabewert von copy() nicht: fehlt das Verzeichnis, scheitert jede
#     einzelne Kopie STILL, enable_files() liefert trotzdem true, der Installer
#     schreibt "malwatch installed." - und die Seite ist nicht da. Genau das
#     traefe jede Erstinstallation. Vor dem Umzug fiel es nicht auf, weil das
#     damalige Zielverzeichnis zu ISPConfig gehoert; security/ gehoert niemandem.
#
#     Ueber 'd:'-Zeilen in file.list ist es nicht zu loesen: enable_files()
#     setzt auf ein so angelegtes Verzeichnis chmod 640 und nimmt ihm das x-Bit.
web_root="interface/web/security"
inst="$root/install/installer.php"
grep -q 'mkdir' "$inst" || fail "installer.php legt kein Verzeichnis an; die Kopien der Oberflaeche gingen ins Leere"
for dir in $(awk -F: '/^c:/ { print $3 }' "$root/install/file.list" | sed 's:/[^/]*$::' | sort -u); do
	case "$dir" in
		"$web_root"|"$web_root"/*) ;;
		*) continue ;;
	esac
	sub=${dir#$web_root}
	if [ -z "$sub" ]; then
		grep -q "$web_root" "$inst" || fail "file.list kopiert nach $dir, aber der Installer legt das Verzeichnis nicht an"
	else
		grep -q "'$sub'" "$inst" || fail "file.list kopiert nach $dir, aber der Installer legt das Verzeichnis nicht an ('$sub' fehlt in prepare_interface_dirs)"
	fi
done

# 32. Eine Seite, die $wb liest, muss ihre Sprachdatei per include holen.
#
#     $app->load_language_file() inkludiert die Datei INNERHALB der Methode und
#     legt das Ergebnis in der privaten Eigenschaft _wb ab. Ein include in einer
#     Methode erbt deren Geltungsbereich: im Aufrufer bleibt $wb ungesetzt.
#     setVar(null) setzt dann nichts, und die Seite rendert ohne einen einzigen
#     Text - keine Ueberschrift, kein Schild, kein Knopf. php -l sieht davon
#     nichts, die Seite liefert HTML, nur eben leeres.
#
#     Dazu der Rueckfall: ein Administrator mit einer Sprache, fuer die es keine
#     eigene Datei gibt, bekommt sonst ebenfalls nichts. check_language() haelt
#     ausserdem den Wert aus der Sitzung von der Pfadangabe fern.
for page in "$root"/interface/*.php; do
	grep -q '\$wb\[' "$page" || continue
	# Wie in Pruefung 28: eine Kommentarzeile, die den Namen der Methode nennt,
	# um vor ihr zu warnen, ist keine Benutzung.
	if grep -n 'load_language_file' "$page" | grep -qvE "^[0-9]+:$comment_start"; then
		fail "$(basename "$page") liest \$wb, holt die Sprachdatei aber ueber load_language_file - im Aufrufer bleibt \$wb leer"
	fi
	grep -qE '^[[:space:]]*include[[:space:]]+\$lng_file' "$page" \
		|| fail "$(basename "$page") liest \$wb, bindet aber keine Sprachdatei per include ein"
	grep -q 'check_language' "$page" \
		|| fail "$(basename "$page") baut den Namen der Sprachdatei ohne check_language()"
	grep -q "= 'lib/lang/en_" "$page" \
		|| fail "$(basename "$page") hat keinen en_-Rueckfall; eine Sprache ohne eigene Datei zeigt sonst gar nichts"
done

# 33. Jede Seite, die die Modulkonfiguration nennt - Startseite wie
#     Seitenleiste -, muss es geben und muss installiert werden. Ein
#     Menuepunkt ohne Ziel ist schlimmer als gar keiner; umgekehrt ist eine
#     Seite, die installiert wird und die nichts verlinkt, unerreichbar. Genau
#     das war malwatch_finding_list.php, seit die alte Menuedatei entfiel.
#     Gelesen werden nur die Zeilen, die 'link' oder 'startpage' setzen. Ein
#     Kommentar, der eine Seite nennt, die es noch nicht gibt - etwa als
#     Hinweis auf eine spaetere Stufe -, ist kein Menuepunkt und soll hier
#     nicht anschlagen.
conf="$root/interface/module.conf.php"
if [ -f "$conf" ]; then
	for link in $(grep -E "'(link|startpage)'" "$conf" | grep -oE "security/[a-z_]+\.php" | sed 's|^security/||' | sort -u); do
		[ -f "$root/interface/$link" ] \
			|| fail "module.conf.php verlinkt security/$link, die Datei gibt es nicht"
		grep -q ":interface/web/security/$link\$" "$root/install/file.list" \
			|| fail "module.conf.php verlinkt security/$link, file.list installiert die Seite aber nicht"
	done
fi


# 34. Ein Verweis muss den Parameternamen benutzen, den die Zielseite liest.
#     malwatch_site_show.php liest $_REQUEST['id']. Die Statusseite haengte
#     domain_id= an, also kam dort 0 an und jede Website meldete
#     "Ungueltige Website." - der Knopf "Ansehen" fuehrte bei jeder Website
#     ins Leere, und keine der bis dahin 33 Pruefungen sah es, weil beide
#     Namen fuer sich betrachtet plausibel aussehen.
#
#     Um die beiden Seiten dieser Stufe erweitert: malwatch_repair_start.php
#     liest denselben Namen id=, aus demselben Grund (siehe die Datei selbst).
#     malwatch_quarantine_download.php liest dagegen token=, nicht id= oder
#     domain_id= - der Download haengt an einem Exportauftrag, nicht an einer
#     Website.
for tpl in "$root"/interface/templates/*.htm "$root"/interface/*.php; do
	[ -f "$tpl" ] || continue
	if grep -q 'malwatch_site_show\.php?domain_id=' "$tpl"; then
		fail "$(basename "$tpl") verlinkt site_show mit domain_id=, die Seite liest id="
	fi
	if grep -q 'malwatch_repair_start\.php?domain_id=' "$tpl"; then
		fail "$(basename "$tpl") verlinkt repair_start mit domain_id=, die Seite liest id="
	fi
	if grep -qE 'malwatch_quarantine_download\.php\?(id|domain_id)=' "$tpl"; then
		fail "$(basename "$tpl") verlinkt quarantine_download mit id=/domain_id=, die Seite liest token="
	fi
done

# 35. Jede .php- und .htm-Datei unter interface/ muss in file.list stehen.
#     Pruefung 6 deckt das schon fuer den ganzen Baum ab (interface UND
#     server, jede Endung); diese Pruefung ist enger, aber genau die zwei
#     Endungen sind es, die eine Seite unerreichbar machen, wenn sie fehlen -
#     eine neue Seite dieser Stufe, die man zu installieren vergisst, faellt
#     sonst nur auf, wenn jemand sie von Hand aufruft.
for file in $(cd "$root" && find interface -type f \( -name '*.php' -o -name '*.htm' \) | sort); do
	grep -q ":$file:" "$root/install/file.list" || fail "$file ist nicht in install/file.list eingetragen"
done

# 36. Dieselbe Pruefung wie 9, aber fuer Englisch. Pruefung 9 deckt nur
#     Deutsch ab (siehe dort) - eine fehlende Zeile in der englischen Datei
#     zeigt derselben Seite in der zweiten Sprache ein leeres Etikett, und
#     faellt unauffaelliger auf als eine fehlende deutsche Zeile, weil die
#     deutsche Oberflaeche selbst dabei weiterhin richtig aussieht.
for tpl in "$root"/interface/templates/*.htm; do
	[ -f "$tpl" ] || continue
	for key in $(grep -ohE "tmpl_var name=['\"][a-z_]+_txt['\"]" "$tpl" | sed -E "s/.*['\"]([a-z_]+_txt)['\"]/\1/" | sort -u); do
		if ! grep -qhE "\\\$wb\['$key'\]" "$root"/interface/lang/en_*.lng; then
			fail "$(basename "$tpl") uses {$key}, which no English language file defines"
		fi
	done
done

# 37. Jeder Schalter, den der Runner an den Scanner uebergibt, muss in
#     usage.go stehen - sonst kennt die eingebaute Hilfe einen Schalter
#     nicht, den das Addon laengst benutzt, und niemand kann von der
#     Kommandozeile aus nachvollziehen, was ein Auftrag tatsaechlich aufruft.
usage_go="$root/../cmd/malwatch/usage.go"
if [ -f "$runner" ] && [ -f "$usage_go" ]; then
	tmp="$tmpdir/runner_flags"
	grep -ohE "'--[a-z-]+" "$runner" | sed "s/^'//" | sort -u > "$tmp" 2>/dev/null || true

	while read flag; do
		[ -n "$flag" ] || continue
		grep -q -- "$flag" "$usage_go" || fail "der Runner übergibt $flag, aber usage.go dokumentiert das nicht"
	done < "$tmp"
fi

if [ "$status" -eq 0 ]; then
	printf 'Wiring OK\n'
fi

exit "$status"
