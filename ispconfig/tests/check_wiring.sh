#!/bin/sh
# Checks the wiring between the extension files that PHP cannot see.
#
# Every failure below has actually happened during the first install: the
# files are syntactically fine, so php -l passes, and the page only breaks
# when someone opens it.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
status=0

fail() {
	printf 'FAIL: %s\n' "$1" >&2
	status=1
}

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

if [ "$status" -eq 0 ]; then
	printf 'Wiring OK\n'
fi

exit "$status"
