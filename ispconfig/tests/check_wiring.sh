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
#    click is silently ignored. The shared dialog is left out: it submits
#    nothing itself, its script names data-submit-form only as a selector.
for tpl in "$root"/interface/templates/*.htm; do
	[ -f "$tpl" ] || continue
	[ "$(basename "$tpl")" = "malwatch_modal.htm" ] && continue
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
for kind in repair quarantine upgrade; do
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
#
#     malwatch_quarantine_list.php liest site=: die Website, auf die sich die
#     Liste beschraenkt.
for tpl in "$root"/interface/templates/*.htm "$root"/interface/*.php; do
	[ -f "$tpl" ] || continue
	if grep -qE 'malwatch_quarantine_list\.php\?(id|domain_id)=' "$tpl"; then
		fail "$(basename "$tpl") verlinkt quarantine_list mit id=/domain_id=, die Seite liest site="
	fi
	if grep -q 'malwatch_site_show\.php?domain_id=' "$tpl"; then
		fail "$(basename "$tpl") verlinkt site_show mit domain_id=, die Seite liest id="
	fi
	if grep -q 'malwatch_repair_start\.php?domain_id=' "$tpl"; then
		fail "$(basename "$tpl") verlinkt repair_start mit domain_id=, die Seite liest id="
	fi
	if grep -q 'malwatch_upgrade_start\.php?domain_id=' "$tpl"; then
		fail "$(basename "$tpl") verlinkt upgrade_start mit domain_id=, die Seite liest id="
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

# 38. Dieselbe Technik wie Pruefung 22, aber fuer die Aufzaehlungswerte, die
#     malwatch_ingest.inc.php schreibt. Zwei davon kommen aus dem JSON des
#     Scanners (entry_kind, origin) und werden dort gegen eine Liste geprueft;
#     zwei schreibt die Datei selbst als Literal (malwatch_site.last_state,
#     nach einem Zurueckholen). Beide Sorten muessen zu schema.sql passen -
#     eine Liste, die einen Wert zu wenig kennt, wirft eine gueltige Zeile weg;
#     eine, die einen zu viel kennt, laesst die INSERT-Anweisung im
#     Strict-Modus scheitern. Treffer wieder erst in eine Datei, damit fail()
#     in der Hauptshell laeuft statt in einer Subshell der Pipe.
ingest="$root/server/lib/classes/malwatch_ingest.inc.php"
if [ -f "$ingest" ]; then
	# Die drei Paare: PHP-Fundstelle, Tabelle, Spalte. Die ersten beiden sind
	# je eine einzeilige Liste, die dritte ein Methodenrumpf.
	tmp="$tmpdir/ingest_enums"
	: > "$tmp"
	sed -n 's/.*\$entry_kinds *= *array(\(.*\));.*/malwatch_quarantine entry_kind \1/p' "$ingest" >> "$tmp"
	sed -n 's/.*\$origins *= *array(\(.*\));.*/malwatch_quarantine origin \1/p' "$ingest" >> "$tmp"
	sed -n '/function restored_site_state/,/^	}/p' "$ingest" \
		| grep -oE "return '[a-z]+';" | sed "s/return \('[a-z]*'\);/malwatch_site last_state \1/" >> "$tmp"

	# Ohne diese drei Zeilen waere die Pruefung still wirkungslos, sobald
	# jemand eine der Fundstellen umbenennt: kein Treffer, keine Meldung.
	for expect in 'entry_kind' 'origin' 'last_state'; do
		grep -q " $expect " "$tmp" || fail "check_wiring 38 findet in malwatch_ingest.inc.php nichts zu $expect mehr; die Pruefung liefe ins Leere"
	done

	while read table column values; do
		[ -n "$values" ] || continue
		# Anders als bei action_type (Pruefung 22, dort ein MODIFY COLUMN auf
		# einer Zeile) stehen Tabelle und Spalte hier auf verschiedenen Zeilen:
		# erst den CREATE-TABLE-Block der Tabelle ausschneiden, dann darin die
		# Spalte suchen. Sonst faende der Ausdruck nie etwas und die Pruefung
		# meldete jede Spalte als fehlend.
		valid_enum=$(sed -n "/CREATE TABLE IF NOT EXISTS \`$table\`/,/^)/p" "$schema" \
			| grep -E "^[[:space:]]*\`$column\` enum" | sed "s/.*enum(\([^)]*\)).*/\1/")
		if [ -z "$valid_enum" ]; then
			fail "schema.sql hat keine Spalte $table.$column, malwatch_ingest.inc.php schreibt sie aber"
			continue
		fi
		valid_list=$(printf "%s" "$valid_enum" | sed "s/'//g" | sed "s/,/ /g")
		for val in $(printf "%s" "$values" | sed "s/'//g" | sed "s/,/ /g"); do
			case " $valid_list " in
				*" $val "*) ;;
				*) fail "malwatch_ingest.inc.php schreibt $table.$column='$val', aber schema.sql kennt ihn nicht (gültig: $valid_list)" ;;
			esac
		done
	done < "$tmp"
fi

# 39. Dieselbe Pruefung wie 9 und 36, aber fuer die Seiten statt der Vorlagen.
#     Ein $wb['...'], das keine Sprachdatei setzt, faellt in einer Vorlage als
#     leeres Etikett auf; in einer Seite wird daraus eine leere Fehlermeldung
#     oder ein sprintf() ueber null - eine Meldung, die nichts sagt, an genau
#     der Stelle, an der etwas schiefgegangen ist. Geprueft werden beide
#     Sprachen: eine fehlende englische Zeile sieht man auf der deutschen
#     Oberflaeche nie.
for page in "$root"/interface/*.php "$root"/interface/lib/*.php; do
	[ -f "$page" ] || continue
	for key in $(grep -ohE "\\\$wb\['[a-z_]+'\]" "$page" | sed -E "s/.*\['([a-z_]+)'\].*/\1/" | sort -u); do
		for lang in de en; do
			grep -qhE "\\\$wb\['$key'\]" "$root"/interface/lang/${lang}_*.lng \
				|| fail "$(basename "$page") liest {$key}, was keine ${lang}_-Sprachdatei definiert"
		done
	done
done

# 40. Jeder Scanneraufruf des Addons faengt mit einem Befehl an, den der
#     Scanner kennt.
#
#     Pruefung 37 vergleicht die Schalter und sah deshalb nicht, dass die
#     Quarantaeneliste mit ihrem Aktionswort statt mit "quarantine" begann: der
#     Auftrag rief "malwatch add --quarantine-dir=…" auf, der Scanner antwortete
#     mit seiner Hilfe und Rueckgabecode 3, und im Panel stand "Die Quarantaene
#     hat keinen Bericht hinterlassen". Ein Schalter fehlt sichtbar, ein
#     fehlendes erstes Wort nicht.
#
#     Es gibt zwei Bauweisen, und beide werden hier geprueft. Der Runner baut
#     eine Argumentliste; Cron und Installer setzen ihre Befehlszeile als
#     Zeichenkette zusammen. Die zweite fasste vorher keine Pruefung an -
#     dieselbe Fehlerklasse, anderer Ort.
usage="$root/../cmd/malwatch/usage.go"

# Meldet, wenn $1 kein Befehlswort ist, das usage.go kennt. Als Funktion, weil
# beide Bauweisen unten dieselbe Frage stellen - und in der Hauptshell
# aufgerufen, damit das fail() darin den Rueckgabewert wirklich setzt.
check_command_word() {
	if [ -z "$1" ]; then
		fail "$2 ruft den Scanner ohne Befehlswort auf"
		return
	fi
	grep -qE "^  malwatch $1( |\$)" "$usage" \
		|| fail "$2 ruft den Scanner mit '$1' auf, usage.go kennt den Befehl nicht"
}

runner="$root/server/lib/classes/malwatch_runner.inc.php"
if [ -f "$runner" ] && [ -f "$usage" ]; then
	# Jede Argumentliste des Runners ist eine array(…)-Zuweisung. Das erste
	# Element steht entweder gleich hinter der oeffnenden Klammer - eine
	# einzeilige Liste, die das frueherer Muster /= *array\($/ stillschweigend
	# uebersprang - oder auf der naechsten Zeile, die kein Kommentar ist. Eine
	# leere Liste ($output = array()) baut keinen Aufruf und faellt heraus.
	# Geprueft wird nicht, ob irgendwo ein gueltiger Befehl vorkommt, sondern
	# ob jede Liste mit einem anfaengt: der Fehler war, dass eine Liste mit
	# ihrem Aktionswort begann statt mit dem Befehl.
	awk '
		/= *array *\(/ {
			rest = $0
			sub(/^.*= *array *\(/, "", rest)
			sub(/^[[:space:]]+/, "", rest)
			if (rest ~ /^\)/) { next }
			if (rest != "") { print rest; next }
			want = 1
			next
		}
		want && /^[[:space:]]*(\/\/|#|\*)/ { next }
		want { print; want = 0 }
	' "$runner" > "$tmpdir/firstargs"

	# Ohne diese Zeile waere die Pruefung still wirkungslos, sobald der Runner
	# seine Listen anders baut: keine Fundstelle, keine Meldung.
	[ -s "$tmpdir/firstargs" ] \
		|| fail "check_wiring 40 findet in malwatch_runner.inc.php keine Argumentliste mehr; die Pruefung liefe ins Leere"

	while IFS= read -r first; do
		word=$(printf '%s' "$first" | sed -nE "s/^[[:space:]]*'([a-z]+)'[[:space:]]*[,)].*/\1/p")
		if [ -z "$word" ]; then
			fail "malwatch_runner.inc.php baut eine Argumentliste, die nicht mit einem Befehlswort beginnt: ${first# }"
			continue
		fi
		check_command_word "$word" "malwatch_runner.inc.php"
	done < "$tmpdir/firstargs"
fi

# Die andere Bauweise: escapeshellcmd(<binaerdatei>) . ' <befehl> …'. Gesucht
# wird nur dort, wo die Klammer die Binaerdatei nennt - der SQL-Lader setzt auf
# demselben Weg einen mysql-Aufruf zusammen, und der gehoert nicht hierher.
if [ -f "$usage" ]; then
	: > "$tmpdir/cmdstrings"
	find "$root" -name '*.php' -type f > "$tmpdir/phpfiles"
	while IFS= read -r php; do
		grep -ohE "escapeshellcmd\([^)]*[Bb][Ii][Nn][Aa][Rr][Yy][^)]*\)[[:space:]]*\.[[:space:]]*'[[:space:]]*[a-z]+([[:space:]]+[a-z]+)?" \
			"$php" >> "$tmpdir/cmdstrings" || true
	done < "$tmpdir/phpfiles"
	sed -E "s/.*'[[:space:]]*//" "$tmpdir/cmdstrings" | sort -u > "$tmpdir/cmdwords"

	[ -s "$tmpdir/cmdwords" ] \
		|| fail "check_wiring 40 findet keinen als Zeichenkette gebauten Scanneraufruf mehr; die Pruefung liefe ins Leere"

	while IFS= read -r line; do
		[ -n "$line" ] || continue
		word=${line%% *}
		check_command_word "$word" "ein Aufruf als Zeichenkette (\"$line …\")"

		# Bei quarantine steht hinter dem Befehl noch die Aktion, und genau da
		# ist der Fehler oben entstanden: die Aktion stand, wo der Befehl
		# hingehoert. Ein "quarantine" ohne Aktion ruft add auf, ohne dass es
		# jemand so gemeint haette.
		[ "$word" = "quarantine" ] || continue
		action=${line#* }
		if [ "$action" = "$line" ]; then
			fail "ein Aufruf als Zeichenkette ruft 'quarantine' ohne Aktionswort auf"
			continue
		fi
		grep -qE "^  malwatch quarantine $action( |\$)" "$usage" \
			|| fail "ein Aufruf als Zeichenkette ruft 'quarantine $action' auf, usage.go kennt die Aktion nicht"
	done < "$tmpdir/cmdwords"
fi

# 41. Rueckfragen laufen ueber den Dialog in malwatch_modal.htm.
#
#     a) Keine Vorlage ruft confirm() oder alert() auf. Der Dialog des
#        Browsers passt zu keinem Theme des Panels, und sein Satz musste als
#        JavaScript-Zeichenkette in ein onclick-Attribut, wo ein Apostroph den
#        Knopf lautlos lahmlegte.
#     b) Ein Satz aus der Sprachdatei in einem data-mw-*-Attribut geht vorher
#        durch malwatch_attr_texts(). setVar($wb) reicht ihn roh durch, und ein
#        gerades Anfuehrungszeichen beendet das Attribut mitten im Satz;
#        de_malwatch_quarantine.lng schreibt „Größe" mit einem.
#     c) Eine Vorlage mit data-mw-confirm oder data-mw-set-* bindet den Dialog
#        ein. Dessen Skript fragt nach und fuellt die Felder; ohne es geht der
#        Klick ohne Rueckfrage an das Panel.
modal_tpl="$root/interface/templates/malwatch_modal.htm"
[ -f "$modal_tpl" ] || fail "interface/templates/malwatch_modal.htm fehlt, die Rueckfragen haben keinen Dialog"
grep -lq 'data-mw-confirm=' "$root"/interface/templates/*.htm 2>/dev/null \
	|| fail "check_wiring 41 findet keinen Knopf mit data-mw-confirm mehr; die Pruefung liefe ins Leere"

for tpl in "$root"/interface/templates/*.htm; do
	[ -f "$tpl" ] || continue
	name=$(basename "$tpl")

	if grep -nE '(confirm|alert) *\(' "$tpl" | grep -vqE "^[0-9]+:$comment_start"; then
		fail "$name ruft confirm() oder alert() auf; Rueckfragen gehen ueber malwatch_modal.htm"
	fi

	[ "$tpl" = "$modal_tpl" ] && continue

	page="$root/interface/$(basename "$tpl" .htm).php"
	if [ -f "$page" ]; then
		for key in $(grep -ohE 'data-mw-[a-z_-]+="[^"]*"' "$tpl" | grep -oE "name='[a-z_]+_txt'" \
			| sed -E "s/name='([a-z_]+)'/\1/" | sort -u); do
			grep -q "malwatch_attr_texts" "$page" && grep -q "'$key'" "$page" \
				|| fail "$name setzt {$key} in ein data-mw-Attribut, $(basename "$page") schickt den Text nicht durch malwatch_attr_texts()"
		done
	fi

	if grep -qE 'data-mw-(confirm|set-)' "$tpl"; then
		grep -qE "tmpl_include file=['\"]templates/malwatch_modal\.htm['\"]" "$tpl" \
			|| fail "$name hat Knoepfe mit data-mw-*, bindet malwatch_modal.htm aber nicht ein"
	fi
done

# 42. Eine Vorlage mit Umschaltern (data-mw-toggle, data-mw-invert,
#     data-mw-count) bindet malwatch_selection.htm ein. Ohne dessen Skript
#     schalten die Umschalter nichts, und die Knoepfe der Ordner zeigen auch
#     mit Haekchen den Hinweis, mit dem die Seite sie ausliefert.
for tpl in "$root"/interface/templates/*.htm; do
	[ -f "$tpl" ] || continue
	[ "$(basename "$tpl")" = "malwatch_selection.htm" ] && continue
	if grep -qE 'data-mw-(toggle|invert|count)' "$tpl"; then
		grep -qE "tmpl_include file=['\"]templates/malwatch_selection\.htm['\"]" "$tpl" \
			|| fail "$(basename "$tpl") hat Umschalter, bindet malwatch_selection.htm aber nicht ein"
	fi
done

# 43. Eine Seite, die JSON liefert, laedt keine Vorlage und prueft die
#     Administratorrechte - dieselbe Regel wie Pruefung 18, fuer jede Seite
#     mit Content-Type application/json. Die Versionen hinter "Weitere
#     Versionen laden" auf der Seite "Updates" liefert
#     malwatch_upgrade_versions.php.
for page in "$root"/interface/*.php; do
	grep -q 'Content-Type: application/json' "$page" || continue
	if grep -q 'newTemplate\|tpl_defaults' "$page"; then
		fail "$(basename "$page") liefert JSON und laedt eine Vorlage"
	fi
	grep -q 'is_admin' "$page" || fail "$(basename "$page") liefert JSON und prueft die Administratorrechte nicht"
done
[ -f "$root/interface/malwatch_upgrade_versions.php" ] \
	|| fail "interface/malwatch_upgrade_versions.php fehlt; \"Weitere Versionen laden\" bekaeme keine Antwort"

# 44. Ein Verweis mit show= auf die Seite einer Website nennt einen Abschnitt,
#     den malwatch_site_jump() kennt. Mit einem Tippfehler oeffnete die Seite
#     oben, und der Knopf saehe aus, als taete er, was er verspricht.
jump_function=$(sed -n '/^function malwatch_site_jump/,/^}/p' "$root/interface/lib/malwatch_lib.inc.php")
for tpl in "$root"/interface/templates/*.htm; do
	[ -f "$tpl" ] || continue
	for show in $(grep -o 'malwatch_site_show\.php?id=[^"]*show=[a-z]*' "$tpl" | sed 's/.*show=//' | sort -u); do
		printf '%s\n' "$jump_function" | grep -q "'$show' =>" \
			|| fail "$(basename "$tpl") verlinkt show=$show, malwatch_site_jump() kennt diesen Abschnitt nicht"
	done
done

# 45. Ein Knopf, der eine Auswahl braucht (mw-needs-selection), erklaert
#     sich: er traegt data-mw-hint und wird nie gesperrt ausgeliefert. Ein
#     gesperrter Knopf tat bei einem Klick nichts, und im Panel sah man ihm
#     die Sperre nicht an ("wenn ich auf reparieren klicke, passiert nichts").
for tpl in "$root"/interface/templates/*.htm; do
	[ -f "$tpl" ] || continue
	case "$(basename "$tpl")" in malwatch_selection.htm|malwatch_modal.htm) continue ;; esac
	awk -v name="$(basename "$tpl")" '
		/mw-needs-selection/ && !/\.mw-needs-selection/ { open = NR; hint = 0; disabled = 0 }
		open {
			if ($0 ~ /data-mw-hint=/) { hint = 1 }
			if ($0 ~ / disabled([ ><]|$)/) { disabled = 1 }
		}
		open && /<\/button>/ {
			if (!hint) { printf "%s:%d: Knopf mit mw-needs-selection ohne data-mw-hint\n", name, open }
			if (disabled) { printf "%s:%d: Knopf mit mw-needs-selection wird gesperrt ausgeliefert\n", name, open }
			open = 0
		}
	' "$tpl" > "$tmpdir/needs_selection"
	while IFS= read -r problem; do
		[ -n "$problem" ] && fail "$problem"
	done < "$tmpdir/needs_selection"
done

# 46. Keine Vorlage vergibt eine Klasse, die ispconfig.js seitenweit
#     beschreibt. Nach jedem Laden einer Seite und dann fortlaufend fragt das
#     Panel datalogstatus.php ab und schreibt die Antwort in jedes
#     .modal-body ($('.modal-body').html(...)); .notification und
#     .notification_text blendet es ein und aus. Der Dialog in
#     malwatch_modal.htm verlor so seinen Text, das Fuellen brach ab, und jeder
#     Knopf mit Rueckfrage blieb im Panel ohne Wirkung.
for tpl in "$root"/interface/templates/*.htm; do
	[ -f "$tpl" ] || continue
	if grep -qE 'class="([^"]* )?(modal-body|notification|notification_text)( [^"]*)?"' "$tpl"; then
		fail "$(basename "$tpl") vergibt modal-body, notification oder notification_text; ispconfig.js beschreibt jedes Element mit dieser Klasse"
	fi
done

# 47. Die Rueckfrage von "Reparatur starten" nennt, was angehakt ist. Das
#     Skript der Reparaturseite setzt data-mw-confirm aus den Bausteinen
#     data-mw-q-* am Seitenelement zusammen. Mit einem festen Satz zaehlte der
#     Dialog Kern, Plugins und Themes auf, auch wenn nur ein Plugin angehakt war.
#     Dass jeder Baustein in beiden Sprachdateien steht und maskiert ankommt,
#     pruefen 9, 36 und 41.
repair_tpl="$root/interface/templates/malwatch_repair_start.htm"
for piece in replace replace-one core-one core-many plugin-one plugin-many theme-one theme-many two three safety no-original; do
	grep -q "data-mw-q-$piece=\"{tmpl_var name='confirm_" "$repair_tpl" \
		|| fail "malwatch_repair_start.htm fehlt der Baustein data-mw-q-$piece fuer die Rueckfrage der Reparatur"
done
grep -q "setAttribute('data-mw-confirm'" "$repair_tpl" \
	|| fail "malwatch_repair_start.htm setzt die Rueckfrage der Reparatur nicht aus den angehakten Elementen zusammen"

# 48. Ablage und Auftragsart des Dumps haengen zusammen: ohne die Tabellen
#     laeuft der Auftrag ins Leere, ohne das Verzeichnis findet der Lauf sein
#     Ziel nicht, und ohne die Auftragsart nimmt der Runner den Zweig fuer
#     einen Prueflauf.
grep -q "CREATE TABLE IF NOT EXISTS \`malwatch_dump\`" "$root/install/schema.sql" \
	|| fail "schema.sql kennt die Tabelle malwatch_dump nicht"
grep -q "CREATE TABLE IF NOT EXISTS \`malwatch_database\`" "$root/install/schema.sql" \
	|| fail "schema.sql kennt die Tabelle malwatch_database nicht"
grep -q "''dump''" "$root/install/schema.sql" \
	|| fail "job_kind kennt die Auftragsart dump nicht"
grep -q "'/dumps'" "$root/install/installer.php" \
	|| fail "der Installer legt <state_dir>/dumps nicht an"
# Die eine Spalte, die gegen eine Spalte von ISPConfig verbunden wird, traegt
# deren Sortierfolge. Ohne sie bricht die Abfrage der Auswahl mit "Illegal mix
# of collations" ab, und die Seite zeigt keine einzige Datenbank.
grep -q 'COLLATE utf8mb4_unicode_ci' "$root/install/schema.sql" \
	|| fail "malwatch_database.database_name traegt nicht die Sortierfolge von ISPConfigs web_database"
grep -q "/dumps" "$root/server/lib/classes/malwatch_runner.inc.php" \
	|| fail "der Runner stellt <state_dir>/dumps nicht sicher"

# 49. Das Archiv geht ueber eine eigene Seite heraus: sie prueft die
#     Administratorrechte und nimmt ihren Schluessel aus token=, und die Liste
#     verweist genauso darauf. Fehlt eines davon, zeigt die Liste einen Knopf,
#     der ins Leere fuehrt.
dump_dl="$root/interface/malwatch_dump_download.php"
if [ -f "$dump_dl" ]; then
	grep -q 'is_admin' "$dump_dl" \
		|| fail "malwatch_dump_download.php prueft die Administratorrechte nicht"
	grep -qE "_(REQUEST|GET)\['token'\]" "$dump_dl" \
		|| fail "malwatch_dump_download.php liest den Schluessel nicht aus token="
else
	fail "interface/malwatch_dump_download.php fehlt; der Verweis der Dump-Liste ginge ins Leere"
fi
grep -q 'malwatch_dump_download.php?token=' "$root/interface/templates/malwatch_dump_list.htm" \
	|| fail "malwatch_dump_list.htm verweist nicht mit token= auf die Downloadseite"

# 50. Die oeffentliche Freigabe oeffnet genau eine Tuer: die Downloadseite
#     nimmt public= entgegen, vergleicht den Schluessel mit hash_equals und
#     ein Passwort mit password_verify, und der Weg ohne oeffentlichen
#     Schluessel geht weiterhin durch die Rechtepruefung. Faellt eines davon
#     beim Umbau weg, stuende entweder die ganze Seite offen oder die Freigabe
#     liefe ins Leere.
if [ -f "$dump_dl" ]; then
	grep -qE "_(REQUEST|GET)\['public'\]" "$dump_dl" \
		|| fail "malwatch_dump_download.php nimmt keinen oeffentlichen Schluessel aus public= entgegen"
	grep -q 'check_module_permissions' "$dump_dl" \
		|| fail "malwatch_dump_download.php prueft ohne oeffentlichen Schluessel die Modulrechte nicht mehr"
	grep -q 'hash_equals' "$dump_dl" \
		|| fail "malwatch_dump_download.php vergleicht den Schluessel nicht mit hash_equals"
	grep -q 'password_verify' "$dump_dl" \
		|| fail "malwatch_dump_download.php prueft das Passwort der Freigabe nicht mit password_verify"
fi
for col in public_token public_mode public_until public_password public_hits public_last_at; do
	grep -q "\`$col\`" "$root/install/schema.sql" \
		|| fail "schema.sql kennt die Spalte $col der Freigabe nicht"
done

# 51. Die Abwehr braucht ihre vier Tabellen, die Zustandsspalte je Website, die
#     Einstellungen und den Wert waf in job_kind und action_type. Das
#     Entfernen des Addons nimmt die Tabellen wieder mit.
for table in malwatch_waf_hit malwatch_waf_site_day malwatch_waf_day malwatch_waf_exception; do
	grep -q "CREATE TABLE IF NOT EXISTS \`$table\`" "$root/install/schema.sql" \
		|| fail "schema.sql kennt die Tabelle $table nicht"
	grep -q "DROP TABLE IF EXISTS \`$table\`" "$root/install/uninstall-schema.sql" \
		|| fail "uninstall-schema.sql entfernt die Tabelle $table nicht"
done
for table in malwatch_dump malwatch_database; do
	grep -q "DROP TABLE IF EXISTS \`$table\`" "$root/install/uninstall-schema.sql" \
		|| fail "uninstall-schema.sql entfernt die Tabelle $table nicht"
done
grep -q "MODIFY COLUMN \`job_kind\` enum(.*''waf''" "$root/install/schema.sql" \
	|| fail "job_kind kennt die Auftragsart waf nicht"
grep -q "MODIFY COLUMN \`action_type\` enum(.*''waf''" "$root/install/schema.sql" \
	|| fail "action_type kennt den Wert waf nicht"
grep -q "ADD COLUMN \`waf_state\` enum(''off'',''detect'',''enforce'')" "$root/install/schema.sql" \
	|| fail "malwatch_site bekommt keine Spalte waf_state"
for col in waf_detail_days waf_stats_days waf_log_keep_days waf_preview_days waf_min_detect_days \
	waf_response_body waf_ingest_max_lines waf_job_deadline_minutes waf_audit_log waf_conf_dir \
	waf_emergency waf_emergency_since waf_card_hits; do
	grep -q "ADD COLUMN \`$col\`" "$root/install/schema.sql" \
		|| fail "malwatch_config bekommt keine Spalte $col"
	grep -q "'$col' =>" "$root/interface/lib/malwatch_waf_lib.inc.php" \
		|| fail "waf_settings_defaults() kennt die Spalte $col nicht"
done

# 52. Der Installer legt den Arbeitsbereich der Abwehr an: waf und
#     waf/responses mit der Gruppe des Panels (die Seite liefert
#     Seitenantworten aus), staging und last-good nur fuer root.
for sub in /waf /waf/responses /waf/staging /waf/last-good; do
	grep -q "'$sub'" "$root/install/installer.php" \
		|| fail "der Installer legt <state_dir>$sub nicht an"
done

# 53. WAF-Auftraege gehoeren dem Cron. Das Plugin laesst sie liegen,
#     start_pending und die Zaehlung nehmen sie aus, weder das Einsammeln noch
#     die Zeitsperre fassen sie an. Der Cron laedt malwatch_waf, ruft es jede
#     Minute und stuendlich zum Aufraeumen.
plugin="$root/server/plugins/malwatch_plugin.inc.php"
cron="$root/server/lib/classes/cron.d/560-malwatch.inc.php"
helper="$root/server/lib/classes/malwatch_helper.inc.php"
grep -q "job_kind'\] === 'waf'" "$plugin" \
	|| fail "malwatch_plugin.inc.php laesst WAF-Auftraege nicht liegen"
grep -q "job_kind NOT IN ('vulncheck','waf')" "$cron" \
	|| fail "start_pending nimmt WAF-Auftraege nicht aus"
grep -q "job_kind NOT IN ('vulncheck','waf')" "$helper" \
	|| fail "count_running_jobs zaehlt WAF-Auftraege mit"
[ "$(grep -c "job_kind != 'waf'" "$cron")" -ge 2 ] \
	|| fail "collect_finished oder die Zeitsperre fassen WAF-Auftraege an"
grep -q "uses('[^']*malwatch_waf" "$cron" \
	|| fail "der Cron laedt malwatch_waf nicht"
grep -q 'malwatch_waf->cron_minute()' "$cron" \
	|| fail "der Cron ruft malwatch_waf nicht jede Minute auf"
grep -q 'malwatch_waf->cron_hourly()' "$cron" \
	|| fail "der Cron raeumt die Treffer der WAF nicht auf"

# 54. Die Werkzeuge unter waf/ tragen die neuen Namen und nutzen die
#     gemeinsame Bibliothek. Die alten Namen stehen nur noch dort, wo
#     install.sh umstellt und README.md davon erzaehlt.
waf_dir="$root/../waf"
if [ -d "$waf_dir" ]; then
	for f in waf-switch waf-guard waf-report install.sh README.md conf/main.conf conf/waf.conf \
		conf/settings.conf conf/crs-extra.conf conf/exclusions-before.conf conf/exclusions-after.conf \
		conf/exclusions-panel-before.conf conf/exclusions-panel-after.conf conf/response-body.conf \
		conf/state.conf conf/logrotate-waf; do
		[ -f "$waf_dir/$f" ] || fail "waf/$f fehlt"
	done
	for f in waf-schalter waf-wache waf-bericht lib tests conf/einstellungen.conf conf/crs-zusatz.conf \
		conf/ausnahmen-vorher.conf conf/ausnahmen-nachher.conf conf/zustand.conf conf/antwortrumpf.conf; do
		if [ -e "$waf_dir/$f" ]; then
			fail "waf/$f gibt es noch; die Umstellung ersetzt die alten Namen"
		fi
	done
	grep -q 'malwatch_waf_lib.inc.php' "$waf_dir/waf-report" \
		|| fail "waf-report bindet malwatch_waf_lib.inc.php nicht ein"
	grep -q "uses('malwatch_helper,malwatch_waf')" "$waf_dir/waf-switch" \
		|| fail "waf-switch laedt malwatch_waf nicht"
	if grep -rlE 'einstellungen\.conf|zustand\.conf|antwortrumpf|waf-schalter|waf-wache|waf-bericht' "$waf_dir" \
		| grep -vE '/(install\.sh|README\.md)$' | grep -q .; then
		fail "unter waf/ nennt eine Datei ausser install.sh und README.md noch alte Namen"
	fi
fi

# 55. Die Seiten der Abwehr pruefen die Administratorrechte selbst, und die
#     Seitenantwort geht nur als Text hinaus: sie ist die Antwort auf die
#     Anfrage eines Angreifers und laeuft im Panel nie als HTML.
#     Einzige Ausnahme ist die Liste fuer die Firewall: Sie wird von einem Geraet
#     ohne Sitzung geholt und haengt darum an ihrem Schluessel (Pruefung 77).
for page in "$root"/interface/malwatch_waf_*.php; do
	[ -f "$page" ] || continue
	[ "$(basename "$page")" = "malwatch_waf_ban_url.php" ] && continue
	grep -q 'is_admin()' "$page" || fail "$(basename "$page") prueft die Administratorrechte nicht"
done
response_page="$root/interface/malwatch_waf_response.php"
if [ -f "$response_page" ]; then
	for header in 'Content-Type: text/plain' 'X-Content-Type-Options: nosniff' "Content-Security-Policy: default-src 'none'"; do
		grep -qF "$header" "$response_page" || fail "malwatch_waf_response.php sendet $header nicht"
	done
	grep -q 'basename(' "$response_page" || fail "malwatch_waf_response.php nimmt den Dateinamen ungeprueft"
else
	fail "interface/malwatch_waf_response.php fehlt"
fi

# 56. Die Abwehr steht im Menue, und die Uebersicht verfolgt laufende
#     Auftraege ueber malwatch_waf_jobs.php; neu geladen wird sie erst, wenn
#     keiner mehr laeuft.
#     The menu has two groups: Scanner and Abwehr. Every page of the Abwehr
#     with its own entry sits under Abwehr, and none of them under Scanner.
nav=$(php -r '
	if (!is_file($argv[1])) {
		fwrite(STDOUT, "file missing");
		exit(1);
	}
	$module = array();
	include $argv[1];
	if (empty($module["nav"]) || !is_array($module["nav"])) {
		fwrite(STDOUT, "no menu defined");
		exit(1);
	}
	foreach ($module["nav"] as $group) {
		foreach ($group["items"] as $item) {
			echo $group["title"], "|", $item["link"], "\n";
		}
	}' "$root/interface/module.conf.php" 2>&1) || fail "module.conf.php cannot be read: $nav"
for page in malwatch_waf_list.php malwatch_waf_exception_list.php malwatch_waf_config_edit.php; do
	printf '%s\n' "$nav" | grep -qxF "Abwehr|security/$page" \
		|| fail "module.conf.php does not list $page in the menu group Abwehr"
done
if printf '%s\n' "$nav" | grep -v '^Abwehr|' | grep -q 'malwatch_waf_'; then
	fail "module.conf.php lists a page of the Abwehr outside the menu group Abwehr"
fi
printf '%s\n' "$nav" | grep -qxF "Scanner|security/status.php" \
	|| fail "module.conf.php does not list the status page in the menu group Scanner"
if [ -f "$root/interface/templates/malwatch_waf_list.htm" ]; then
	grep -q 'data-mw-jobs="security/malwatch_waf_jobs.php' "$root/interface/templates/malwatch_waf_list.htm" \
		|| fail "malwatch_waf_list.htm fragt die laufenden Auftraege nicht ab"
else
	fail "interface/templates/malwatch_waf_list.htm fehlt"
fi

# 57. Die Seite einer Website traegt das Ausnahmeformular im Formular des
#     Panels: ein Dialog am Ende von <body> schickte seine Felder nie mit. Die
#     Vorschau kommt aus malwatch_waf_preview.php, die Seitenantwort oeffnet
#     malwatch_waf_response.php in einem eigenen Fenster.
show_tpl="$root/interface/templates/malwatch_waf_show.htm"
if [ -f "$show_tpl" ]; then
	for field in exc_site exc_scope exc_rule exc_path exc_param exc_note; do
		grep -q "name=\"$field\"" "$show_tpl" || fail "malwatch_waf_show.htm hat kein Feld $field"
	done
	grep -q 'data-mw-preview="security/malwatch_waf_preview.php' "$show_tpl" \
		|| fail "malwatch_waf_show.htm holt die Vorschau nicht aus malwatch_waf_preview.php"
	grep -q 'href="security/malwatch_waf_response.php?hit=[^"]*" target="_blank" rel="noopener"' "$show_tpl" \
		|| fail "malwatch_waf_show.htm oeffnet die Seitenantwort nicht in einem eigenen Fenster"
	if grep -q 'class="[^"]*mw-modal[^"]*"[^>]*>[^<]*<[^>]*name="exc_' "$show_tpl"; then
		fail "malwatch_waf_show.htm legt Felder der Ausnahme in einen Dialog"
	fi
else
	fail "interface/templates/malwatch_waf_show.htm fehlt"
fi

# 58. Die Ausnahmeliste schickt "Entfernen" an sich selbst, damit ihre Filter
#     nach dem Klick bleiben, und die Uebersicht fuehrt zu ihr.
exc_tpl="$root/interface/templates/malwatch_waf_exception_list.htm"
if [ -f "$exc_tpl" ]; then
	grep -q 'data-mw-set-mw-waf-action="exception_remove"' "$exc_tpl" \
		|| fail "malwatch_waf_exception_list.htm hat keinen Knopf Entfernen"
	grep -q 'data-form-action="security/malwatch_waf_exception_list.php"' "$exc_tpl" \
		|| fail "malwatch_waf_exception_list.htm schickt Entfernen nicht an die eigene Seite"
else
	fail "interface/templates/malwatch_waf_exception_list.htm fehlt"
fi
grep -q 'data-load-content="security/malwatch_waf_exception_list.php"' "$root/interface/templates/malwatch_waf_list.htm" \
	|| fail "malwatch_waf_list.htm fuehrt nicht zur Ausnahmeliste"

# 59. Die Einstellungsseite der Abwehr bekommt ihre Texte von tform, und tform
#     liest nur de_/en_malwatch_waf_config.lng. Ein Schluessel aus einer
#     anderen Sprachdatei besteht Pruefung 9 und bleibt trotzdem leer. Den
#     Token prueft tform beim Speichern selbst; eine eigene Pruefung der Seite
#     verbraucht ihn vorher, und das Speichern scheitert. Ueberschriften als
#     p.fieldset-legend blendet ispconfig.css aus.
cfg_tpl="$root/interface/templates/malwatch_waf_config_edit.htm"
if [ -f "$cfg_tpl" ]; then
	for key in $(grep -ohE "tmpl_var name=['\"][a-z_]+_txt['\"]" "$cfg_tpl" | sed -E "s/.*['\"]([a-z_]+_txt)['\"]/\1/" | sort -u); do
		for lang in de en; do
			grep -qE "\\\$wb\['$key'\]" "$root/interface/lang/${lang}_malwatch_waf_config.lng" 2>/dev/null \
				|| fail "malwatch_waf_config_edit.htm nutzt {$key}, das ${lang}_malwatch_waf_config.lng nicht setzt"
		done
	done
	grep -q 'data-form-action="security/malwatch_waf_config_edit.php"' "$cfg_tpl" \
		|| fail "malwatch_waf_config_edit.htm speichert nicht ueber die eigene Seite"
	grep -q 'formbutton-success' "$cfg_tpl" \
		|| fail "malwatch_waf_config_edit.htm hat keinen Knopf formbutton-success; Enter speichert dann nicht"
	if grep -q 'class="fieldset-legend"' "$cfg_tpl"; then
		fail "malwatch_waf_config_edit.htm setzt Ueberschriften als p.fieldset-legend; ispconfig.css blendet sie aus"
	fi
else
	fail "interface/templates/malwatch_waf_config_edit.htm fehlt"
fi
if grep -q -- '->csrf_token_check(' "$root/interface/malwatch_waf_config_edit.php" 2>/dev/null; then
	fail "malwatch_waf_config_edit.php prueft den Token selbst; tform findet ihn danach nicht mehr"
fi

# 60. No template gives an element the class fieldset-legend. ispconfig.css
#     hides p.fieldset-legend (display:none): the section headings of the
#     settings page never showed, and scrollIntoView() on a hidden jump
#     target does nothing. Headings carry the page's own class (mw-sec).
for tpl in "$root"/interface/templates/*.htm; do
	[ -f "$tpl" ] || continue
	if grep -qE "class=[\"']([^\"']* )?fieldset-legend[ \"']" "$tpl"; then
		fail "$(basename "$tpl") uses class=\"fieldset-legend\"; ispconfig.css hides it, a heading needs its own class"
	fi
done

# 61. A page built on tform_actions leaves the template variable error to
#     tform. tform_actions::onError() puts the validator messages there, and
#     tabbed_form.tpl.htm prints them. The settings page set error again in
#     onShowEnd() and blanked them: a value out of range came back as the
#     form with no reason. A form template that prints error as well shows
#     every message twice. Messages of the page itself use other variables.
for page in "$root"/interface/*.php; do
	grep -qE 'extends[[:space:]]+tform_actions' "$page" || continue
	if grep -qE "setVar\\([\"']error[\"']" "$page"; then
		fail "$(basename "$page") sets the template variable error; tform_actions::onError() puts the validator messages there"
	fi
done
for def in "$root"/interface/form/*.tform.php; do
	[ -f "$def" ] || continue
	for tpl in $(grep -ohE "templates/[a-z_]+\.htm" "$def" || true); do
		[ -f "$root/interface/$tpl" ] || continue
		if grep -qE "tmpl_(var|if|unless)[[:space:]]+name=[\"']error[\"']" "$root/interface/$tpl"; then
			fail "$(basename "$tpl") prints error; tabbed_form.tpl.htm already shows the messages of tform"
		fi
	done
done

# 62. The settings page checks the token itself only for "Zusammenstellung
#     speichern", the one action that skips tform's save.
#     auth::csrf_token_check() uses the token up, and tform_base::_encode()
#     checks it again on every save. "Auf die bestehenden Funde anwenden"
#     saves the form: with the token gone the save failed, after the sweep
#     had already been queued. The sweep runs once tform has accepted the
#     token and the fields, in onUpdateSave() or onAfterUpdate().
cfg_page="$root/interface/malwatch_config_edit.php"
cfg_onload=$(sed -n '/function onLoad()/,/^	}/p' "$cfg_page")
cfg_checks=$(printf '%s\n' "$cfg_onload" | grep -c -- '->csrf_token_check(' || true)
cfg_check_at=$(printf '%s\n' "$cfg_onload" | grep -n -- '->csrf_token_check(' | head -1 | cut -d: -f1)
cfg_preset_at=$(printf '%s\n' "$cfg_onload" | grep -n "=== 'save_preset'" | head -1 | cut -d: -f1)
cfg_apply_at=$(printf '%s\n' "$cfg_onload" | grep -n "=== 'apply_existing'" | head -1 | cut -d: -f1)
if [ "$cfg_checks" != "1" ] || [ -z "$cfg_preset_at" ] || [ -z "$cfg_apply_at" ] \
	|| [ "$cfg_check_at" -le "$cfg_preset_at" ] || [ "$cfg_check_at" -ge "$cfg_apply_at" ]; then
	fail "malwatch_config_edit.php checks the token outside the save_preset branch of onLoad(); tform checks it again when it saves"
fi
sed -n '/function onUpdateSave(/,/^	}/p;/function onAfterUpdate(/,/^	}/p' "$cfg_page" | grep -q 'handle_apply_existing(' \
	|| fail "malwatch_config_edit.php sweeps before tform has accepted the token; call handle_apply_existing() from onUpdateSave() or onAfterUpdate()"

# 63. waf/install.sh keeps every backup under its own name. The copy of
#     /etc/nginx/waf is "waf" in the backup directory, so /etc/logrotate.d/waf
#     copied there under its basename hits that directory: cp stops, and
#     set -e ends the run before anything is switched.
if [ -f "$waf_dir/install.sh" ]; then
	backup_part=$(sed -n '/-m 700 "\$BACKUP"/,/say "Sicherung in/p' "$waf_dir/install.sh")
	if ! printf '%s\n' "$backup_part" | grep -qF '/etc/logrotate.d/waf "$BACKUP/logrotate-waf"' \
		|| printf '%s\n' "$backup_part" | grep -F '/etc/logrotate.d/waf' | grep -qvF '"$BACKUP/logrotate-waf"'; then
		fail "waf/install.sh copies /etc/logrotate.d/waf into the backup as waf; the copy of /etc/nginx/waf already has that name"
	fi
fi

# 64. The address filter of the website page takes an address only through
#     waf_panel_ip_filter(), and that function lets FILTER_VALIDATE_IP decide.
#     The value ends up in links and in a query; a page that reads ip itself
#     skips the check.
if ! sed -n '/^function waf_panel_ip_filter(/,/^}/p' "$root/interface/lib/malwatch_waf_panel.inc.php" | grep -q 'FILTER_VALIDATE_IP'; then
	fail "waf_panel_ip_filter() does not check the address with FILTER_VALIDATE_IP"
fi
grep -q 'waf_panel_ip_filter(' "$root/interface/malwatch_waf_show.php" \
	|| fail "malwatch_waf_show.php takes the address filter without waf_panel_ip_filter()"
for page in "$root"/interface/*.php; do
	if grep -qE "\\\$_(GET|POST|REQUEST)\[['\"]ip['\"]\]" "$page"; then
		fail "$(basename "$page") reads the address filter itself; waf_panel_ip_filter() checks it"
	fi
done

# 65. The rule catalog reaches every rule title. A page of the Abwehr that
#     names rules loads the catalog next to its language file and hands it to
#     every helper that names one; without it the page shows the English
#     message of the rule set.
for page in "$root"/interface/malwatch_waf_*.php; do
	[ -f "$page" ] || continue
	calls=$(grep -E 'waf_panel_(rule_title|rules|hit|enforce)\(' "$page" || true)
	[ -n "$calls" ] || continue
	grep -qF "waf_panel_rule_catalog(waf_panel_rule_catalog_file('lib/lang', \$language))" "$page" \
		|| fail "$(basename "$page") names rules but does not load the rule catalog"
	if printf '%s\n' "$calls" | grep -qvF '$catalog'; then
		fail "$(basename "$page") names a rule without the catalog"
	fi
done
for lang in de en; do
	[ -f "$root/interface/lang/${lang}_malwatch_waf_rules.lng" ] \
		|| fail "interface/lang/${lang}_malwatch_waf_rules.lng is missing"
done

# 66. The address filter reads malwatch_waf_hit by website and address
#     through the index site_ip. CREATE TABLE brings it to new installs only,
#     the guarded ALTER TABLE to existing ones.
grep -qF 'KEY `site_ip` (`parent_domain_id`,`client_ip`,`seen_at`)' "$root/install/schema.sql" \
	|| fail "schema.sql creates malwatch_waf_hit without the index site_ip"
grep -qF 'ADD INDEX `site_ip` (`parent_domain_id`,`client_ip`,`seen_at`)' "$root/install/schema.sql" \
	|| fail "schema.sql does not add the index site_ip to existing installs"

# 69. The origin starts off. A default that turns a source on would make the
#     server download a list on its own; the operator picks the sources, and
#     the page says what each one means before he does.
lib="$root/interface/lib/malwatch_waf_lib.inc.php"
for key in waf_origin_geo waf_origin_tor waf_origin_net; do
	sed -n '/function waf_settings_defaults/,/^}/p' "$lib" | grep -qF "'$key' => 'off'," \
		|| fail "waf_settings_defaults() does not start $key as off"
done
for lang in de en; do
	for key in origin_intro_txt waf_origin_geo_hint_txt waf_origin_tor_hint_txt waf_origin_net_hint_txt \
		waf_origin_maxmind_key_hint_txt; do
		grep -q "\\\$wb\['$key'\]" "$root/interface/lang/${lang}_malwatch_waf_config.lng" \
			|| fail "${lang}_malwatch_waf_config.lng is missing $key"
	done
done


# 67. The origin update keeps keys out of the job log and the state row. The
#     class hands the licence key to curl and nowhere else: a note that names
#     waf_origin_maxmind_key would end up in malwatch_job.job_log, which the
#     panel shows to every administrator.
waf_class="$root/server/lib/classes/malwatch_waf.inc.php"
if [ -f "$waf_class" ]; then
	if sed -n '/private function run_origin_update/,/^	}/p' "$waf_class" | grep -q 'maxmind_key'; then
		fail "malwatch_waf::run_origin_update() names the licence key; the job log must not carry it"
	fi
	if sed -n '/private function origin_note/,/^	}/p' "$waf_class" | grep -q 'maxmind_key'; then
		fail "malwatch_waf::origin_note() names the licence key; the state row must not carry it"
	fi
	grep -q "case 'origin_update':" "$waf_class" \
		|| fail "malwatch_waf::start_job() knows no action origin_update"
	grep -q 'CURLOPT_SSL_VERIFYPEER, true' "$waf_class" \
		|| fail "malwatch_waf::fetch() loads without checking the certificate"
	sed -n '/public function cron_hourly/,/^	}/p' "$waf_class" | grep -q 'queue_origin_update' \
		|| fail "cron_hourly() never queues origin_update"
fi


# 68. The website page names the origin only from the table the cron fills and
#     shows the attribution of the chosen source. A page that read a range file
#     itself would open a file of the server from the panel; that is the job of
#     the cron alone.
show_page="$root/interface/malwatch_waf_show.php"
if [ -f "$show_page" ]; then
	grep -q 'waf_panel_origin_lookup(' "$show_page" \
		|| fail "malwatch_waf_show.php shows no origin; waf_panel_origin_lookup() reads it"
	if grep -q 'waf_origin_open(\|waf_origin_find(' "$show_page"; then
		fail "malwatch_waf_show.php reads a range file itself; the cron fills malwatch_waf_ip"
	fi
	grep -q 'waf_panel_origin_credit(' "$show_page" \
		|| fail "malwatch_waf_show.php leaves out the attribution of the origin source"
fi
for lang in de en; do
	for key in origin_credit_dbip_txt origin_credit_maxmind_txt origin_off_hint_txt; do
		grep -q "\\\$wb\['$key'\]" "$root/interface/lang/${lang}_malwatch_waf.lng" \
			|| fail "${lang}_malwatch_waf.lng is missing $key"
	done
done


# 69. The settings page shows the state of every chosen source. It reads its own
#     wordbook, so the names of the sources and the lines about their state have
#     to be in the wordbook of the settings page as well.
for lang in de en; do
	book="$root/interface/lang/${lang}_malwatch_waf_config.lng"
	[ -f "$book" ] || continue
	for key in origin_source_dbip_country_txt origin_source_dbip_asn_txt origin_source_maxmind_country_txt origin_source_maxmind_asn_txt origin_source_tor_txt origin_source_x4b_vpn_txt origin_source_x4b_datacenter_txt origin_state_txt origin_state_list_txt origin_state_none_txt origin_state_none_hint_txt origin_state_keep_txt origin_source_proxycheck_txt origin_state_external_txt origin_line_checked_txt; do
		grep -q "\\\$wb\['$key'\]" "$book" || fail "${lang}_malwatch_waf_config.lng is missing $key; the settings page shows the bare key instead of the name of the source"
	done
done


# 70. proxycheck.io answers per address, so it is no source with a range file.
#     An entry in waf_origin_sources() would make origin_update download it.
origin_lib="$root/interface/lib/malwatch_waf_origin.inc.php"
if [ -f "$origin_lib" ]; then
	grep -q 'function waf_origin_external(' "$origin_lib" \
		|| fail "malwatch_waf_origin.inc.php has no waf_origin_external(); nothing names the external source"
	if sed -n '/function waf_origin_sources(/,/^}/p' "$origin_lib" | grep -q 'proxycheck'; then
		fail "waf_origin_sources() names proxycheck; the external service has no range file"
	fi
fi

# 71. The external step runs in the cron of every minute, right after the local
#     lookup, and the class keeps the seam a probe replaces.
if [ -f "$waf_class" ]; then
	grep -q "public \$poster" "$waf_class" \
		|| fail "malwatch_waf.inc.php has no poster; a probe cannot answer for proxycheck.io"
	sed -n '/public function cron_minute(/,/^	}/p' "$waf_class" | grep -q 'origin_external(' \
		|| fail "cron_minute() never asks the external service"
	grep -q 'https://proxycheck.io/v3/' "$waf_class" \
		|| fail "malwatch_waf.inc.php never calls the v3 address of proxycheck.io"
fi

# 72. The key travels in the address of the request and nowhere else: never in
#     a job log, never in the log of ISPConfig, never in the state of the source.
if [ -f "$waf_class" ]; then
	if grep -n "\$key" "$waf_class" | grep -qE "finish\(|app->log\(|origin_external_state\("; then
		fail "malwatch_waf.inc.php puts the key into a log; it belongs into the address alone"
	fi
fi

# 73. The deny file of nginx is written by the class alone. A page would write it
#     as www-data and without the check of nginx.
for page in "$root"/interface/*.php; do
	[ -f "$page" ] || continue
	if grep -q 'blocked.conf' "$page" && grep -q 'file_put_contents' "$page"; then
		fail "$(basename "$page") writes blocked.conf; that belongs into malwatch_waf.inc.php"
	fi
done

# 74. Every block passes the exceptions first, and the file is written through the
#     same function in every case; nginx is tested before it is reloaded.
if [ -f "$waf_class" ]; then
	sed -n '/public function ban_scan(/,/^	}/p' "$waf_class" | grep -q 'waf_ban_allowed(' \
		|| fail "ban_scan() blocks without asking the exceptions"
	sed -n '/private function run_ban(/,/^	}/p' "$waf_class" | grep -q 'ban_apply(' \
		|| fail "run_ban() never writes the file of nginx"
	sed -n '/public function ban_apply(/,/^	}/p' "$waf_class" | grep -q "run_command('nginx_test'" \
		|| fail "ban_apply() reloads nginx without testing the configuration"
fi

# 75. The way back without the panel: whoever locked themselves out needs the
#     command line.
if [ -f "$root/../waf/waf-switch" ]; then
	grep -q "case 'ban':" "$root/../waf/waf-switch" \
		|| fail "waf-switch has no ban command; there is no way back without the panel"
fi

# 76. The texts of the page stand in both wordbooks.
for lang in de en; do
	book="$root/interface/lang/${lang}_malwatch_waf.lng"
	[ -f "$book" ] || continue
	for key in ban_state_active_txt ban_until_forever_txt ban_lift_all_confirm_txt ban_none_active_txt ban_site_never_txt; do
		grep -q "\\\$wb\['$key'\]" "$book" \
			|| fail "${lang}_malwatch_waf.lng is missing $key"
	done
done

# 77. Die veroeffentlichte Liste haengt an ihrem Schluessel: Die Stelle prueft die
#     Form, vergleicht mit hash_equals und verlangt weder Anmeldung noch Modul.
page="$root/interface/malwatch_waf_ban_url.php"
if [ -f "$page" ]; then
	grep -q 'waf_ban_token_ok' "$page" 		|| fail "malwatch_waf_ban_url.php does not check the shape of the key"
	grep -q 'hash_equals' "$page" 		|| fail "malwatch_waf_ban_url.php compares the key without hash_equals"
	grep -q '404 Not Found' "$page" 		|| fail "malwatch_waf_ban_url.php answers a wrong key with something other than 404"
	if grep -q 'check_module_permissions' "$page"; then
		fail "malwatch_waf_ban_url.php asks for a module permission; the firewall has no session"
	fi
	grep -q '^c:interface/malwatch_waf_ban_url.php:' "$root/install/file.list" 		|| fail "the installer does not copy malwatch_waf_ban_url.php"
fi

# 78. Der Cron schreibt die Liste, und die Stelle liest sie; der Schluessel selbst
#     steht in keinem Auftragsprotokoll.
class="$root/server/lib/classes/malwatch_waf.inc.php"
if [ -f "$class" ]; then
	grep -q 'blocked.txt' "$class" 		|| fail "the class never writes blocked.txt for the firewall"
	grep -q 'function ban_token' "$class" 		|| fail "the class has no ban_token()"
	if ! sed -n "/case 'ban_token_new':/,/break;/p" "$class" | grep -q 'Neuer Schl'; then
		fail "the job ban_token_new has no message of its own"
	fi
	if sed -n "/case 'ban_token_new':/,/break;/p" "$class" | grep -q 'note = .*\$token'; then
		fail "the job ban_token_new writes the key into its message"
	fi
fi

# 79. Die Woerter der Liste stehen in beiden Woerterbuechern.
for lang in de en; do
	book="$root/interface/lang/${lang}_malwatch_waf.lng"
	[ -f "$book" ] || continue
	for key in ban_url_head_txt ban_url_intro_txt ban_url_count_txt ban_url_hint_txt ban_url_none_txt 		ban_url_new_txt ban_url_new_confirm_txt; do
		grep -q "\$wb\['$key'\]" "$book" 			|| fail "${lang}_malwatch_waf.lng is missing $key"
	done
done

# 80. Die schaerfere Bewertung der Herkunft beginnt aus, in jedem einzelnen Wert.
lib="$root/interface/lib/malwatch_waf_lib.inc.php"
for key in waf_ban_origin waf_ban_origin_now waf_ban_origin_hosting waf_ban_origin_vpn waf_ban_origin_tor; do
	sed -n '/function waf_settings_defaults/,/^}/p' "$lib" | grep -qF "'$key' => 'off'," 		|| fail "waf_settings_defaults() does not start $key as off"
	grep -q "ADD COLUMN \`$key\`" "$root/install/schema.sql" 		|| fail "malwatch_config bekommt keine Spalte $key"
done
for key in waf_ban_origin_countries waf_ban_origin_asn; do
	sed -n '/function waf_settings_defaults/,/^}/p' "$lib" | grep -qF "'$key' => ''," 		|| fail "waf_settings_defaults() does not start $key empty"
done

# 81. Der Wille des Betreibers geht vor jedem Merkmal: Eine Website, die keine
#     Sperre ausloest, bleibt frei, und die Herkunft wird erst danach gefragt.
ban_lib="$root/interface/lib/malwatch_waf_ban.inc.php"
if [ -f "$ban_lib" ]; then
	sed -n '/function waf_ban_decide/,/^}/p' "$ban_lib" | grep -q '\$limit > 0' 		|| fail "waf_ban_decide() asks the origin before it looks at the will of the website"
	sed -n '/function waf_ban_origin_at_once/,/^}/p' "$ban_lib" | grep -q "waf_ban_origin_now" 		|| fail "waf_ban_origin_at_once() does not ask its own switch"
	grep -q "function waf_ban_origin_match" "$ban_lib" 		|| fail "the library has no waf_ban_origin_match()"
fi
if [ -f "$root/../waf/waf-switch" ]; then
	grep -q "sub === 'origin'" "$root/../waf/waf-switch" 		|| fail "waf-switch cannot switch the origin criterion off"
fi

# 83. waf-switch sagt, was der Auftrag gemeldet hat. Ein fester Satz wuerde
#     einen abgewiesenen Auftrag als Erfolg ausgeben.
tool="$root/../waf/waf-switch"
if [ -f "$tool" ]; then
	block=$(sed -n "/case 'ban':/,/^	default:/p" "$tool")
	for call in ban_mode ban_add ban_lift ban_allow_add ban_token_new; do
		printf '%s
' "$block" | grep -q "execute_now('$call'" 			|| fail "waf-switch does not run $call any more; the check needs an update"
	done
	printf '%s
' "$block" | grep -c 'waf_cli_report(' | grep -qE '^[5-9]|^[0-9]{2}' 		|| fail "a ban command of waf-switch answers with a fixed sentence instead of the job log"
fi

# 82. Die Woerter der Herkunft stehen in beiden Woerterbuechern.
for lang in de en; do
	for key in ban_origin_head_txt ban_origin_intro_txt ban_origin_days_txt ban_origin_save_txt 		ban_origin_none_txt ban_origin_save_hint_txt; do
		grep -q "\$wb\['$key'\]" "$root/interface/lang/${lang}_malwatch_waf.lng" 			|| fail "${lang}_malwatch_waf.lng is missing $key"
	done
	for key in waf_ban_origin_txt waf_ban_origin_score_txt waf_ban_origin_factor_txt waf_ban_origin_now_txt 		ban_origin_kind_on_txt ban_origin_head_txt; do
		grep -q "\$wb\['$key'\]" "$root/interface/lang/${lang}_malwatch_waf_config.lng" 			|| fail "${lang}_malwatch_waf_config.lng is missing $key"
	done
done

# 84. Jeder Knopf, der mit data-mw-set-<id> ein Feld fuellt, findet dieses Feld
#     in derselben Vorlage. Sonst ueberspringt malwatch_modal.htm den Wert still,
#     und der Auftrag bekommt ein leeres Feld - so blieben 0.23.0 bis 0.25.1 die
#     Knoepfe "Sperren" und "loest keine Sperre aus" und die Auswahl der Herkunft
#     wirkungslos.
for tpl in "$root"/interface/templates/*.htm; do
	[ -f "$tpl" ] || continue
	for target in $(grep -o 'data-mw-set-[a-z0-9-]*=' "$tpl" | sed 's/^data-mw-set-//; s/=$//' | sort -u); do
		grep -q "id=\"$target\"" "$tpl" 			|| fail "$(basename "$tpl"): data-mw-set-$target findet kein Feld mit id=\"$target\""
	done
done

# 85. Vorschlaege laufen ab, und die Seite zeigt je Abschnitt begrenzt viele
#     Zeilen. Beides sind Einstellungen mit Spalte, Vorgabe und Feld; und ein
#     Vorschlag darf eine Adresse nie vor einer Sperre schuetzen.
for col in waf_ban_proposal_days waf_ban_page_rows; do
	grep -q "ADD COLUMN \`$col\`" "$root/install/schema.sql" 		|| fail "malwatch_config bekommt keine Spalte $col"
	grep -q "'$col' =>" "$root/interface/lib/malwatch_waf_lib.inc.php" 		|| fail "waf_settings_defaults() kennt $col nicht"
	grep -q "name=\"$col\"" "$root/interface/templates/malwatch_waf_config_edit.htm" 		|| fail "die Einstellungsseite hat kein Feld $col"
done
class="$root/server/lib/classes/malwatch_waf.inc.php"
if [ -f "$class" ]; then
	grep -q "waf_ban_keeps_quiet(\$earlier, \$since, \$state)" "$class" 		|| fail "ban_scan() fragt nicht, was die Adresse werden wuerde, bevor es sie ruhen laesst"
	grep -q "state = 'proposed' \"" "$class" 		|| fail "ban_expire() laesst Vorschlaege nie ablaufen"
fi
if grep -q "LIMIT ?" "$root/interface/malwatch_waf_ban_list.php"; then :; else
	fail "die Seite Sperren laedt ihre Abschnitte ohne Grenze"
fi

# 86. Eine Sperre endet im Minutentakt, und wer von Hand sperrt, bekommt dieselbe
#     Stufe wie die Automatik: Beides lief bis 0.25.3 anders.
class="$root/server/lib/classes/malwatch_waf.inc.php"
if [ -f "$class" ]; then
	minute=$(sed -n '/public function cron_minute/,/^	}/p' "$class")
	printf '%s
' "$minute" | grep -q 'ban_expire()' 		|| fail "cron_minute() beendet faellige Sperren nicht; sie blieben bis zum Stundenlauf stehen"
	printf '%s
' "$minute" | awk '/ban_expire\(\)/ {e = NR} /ban_apply\(\)/ {a = NR} END {exit !(e > 0 && e < a)}' 		|| fail "cron_minute() ruft ban_expire() nicht vor ban_apply() auf"
	sed -n "/case 'ban_add':/,/break;/p" "$class" | grep -q 'waf_ban_next_level(' 		|| fail "ban_add rechnet die Stufe anders als die Automatik"
fi

if [ "$status" -eq 0 ]; then
	printf 'Wiring OK\n'
fi

exit "$status"
