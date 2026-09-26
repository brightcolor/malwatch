#!/bin/bash
# Installs the WAF files and tools on the web server and moves the names of
# the first tool (waf-schalter, einstellungen.conf, ...) to the current ones.
# Runs any number of times. nginx only ever loads a checked configuration,
# and the websites keep their state.
#
# Every place comes from the settings of malwatch (waf-switch paths lists
# them). A place changes through the environment: the name of its setting in
# capitals with MALWATCH_ before it, for example
#
#   MALWATCH_WAF_CONF_DIR=/etc/nginx/waf2 waf/install.sh
#
# The script lays the new place out, checks everything with the rule check,
# nginx -t and nginx -T, stores the places only then, takes the files of the
# old places away and reloads nginx. On a failed step every file goes back
# and the settings keep their values. Logs and an old rule directory stay
# where they are; the output names them.
#
#   --check  shows the places and what would change; changes nothing
#   --yes    answers the question before a new block log
set -Eeuo pipefail
cd "$(dirname "$0")"
here=$(pwd)

check_only=
assume_yes=
for arg in "$@"; do
	case "$arg" in
		--check) check_only=1 ;;
		--yes) assume_yes=1 ;;
		*) echo "Unbekannte Option: $arg. Möglich sind --check und --yes." >&2; exit 2 ;;
	esac
done

# Where ISPConfig keeps the shared functions of malwatch. MALWATCH_WAF_LIB
# points at another copy for a check outside the server, as in waf-report;
# waf-switch then has to be a stand-in as well (ispconfig/tests/waf_install_probe.sh).
LIB=${MALWATCH_WAF_LIB:-/usr/local/ispconfig/interface/web/security/lib/malwatch_waf_lib.inc.php}
SWITCH="$here/waf-switch"

# waf-switch of this folder, through php when an archive lost its mode.
run_switch() {
	if [ -x "$SWITCH" ]; then "$SWITCH" "$@"; else php "$SWITCH" "$@"; fi
}

say() { echo "waf/install.sh: $*"; }

# Writes a text the shared functions produce: render <function> [arguments]
render() {
	php -r 'require $argv[1]; echo call_user_func_array($argv[2], array_slice($argv, 3));' "$LIB" "$@"
}

if [ ! -f "$LIB" ]; then
	echo "malwatch fehlt: $LIB gibt es nicht. Erst das Addon einspielen." >&2
	exit 1
fi
if ! php -r 'require $argv[1]; exit(function_exists("waf_path_settings") ? 0 : 1);' "$LIB"; then
	echo "Das Addon auf dem Server ist älter als malwatch 0.35.0 und kennt die Orte der Abwehr nicht. Erst das Addon einspielen." >&2
	exit 1
fi

# The places: the wanted ones with the changes of the environment, the stored
# ones as OLD_*. waf-switch refuses a bad value with its reason.
if ! places=$(run_switch paths shell); then
	echo "Nichts geändert. Bitte die Werte korrigieren und das Skript erneut aufrufen." >&2
	exit 1
fi
eval "$places"
PATH="$WAF_BIN_PATH:$PATH"

# changed <key>: true when the place of that setting moves.
changed() {
	case " $WAF_CHANGED " in *" $1 "*) return 0 ;; esac
	return 1
}

if [ -n "$check_only" ]; then
	run_switch paths
	echo
	if [ -z "$WAF_CHANGED" ]; then
		say "Mit dieser Umgebung bleiben alle Orte, wie sie sind."
	else
		say "Mit dieser Umgebung ändert sich:"
		for key in $WAF_CHANGED; do
			name=$(printf '%s' "$key" | tr 'a-z' 'A-Z')
			eval "old=\$OLD_$name new=\$$name"
			echo "  $key: $old -> $new"
		done
		if changed waf_blocked_log; then
			say "Das neue Sperrprotokoll schreibt $WAF_SITES Websites mit Abwehr neu, über ISPConfig wie beim Umschalten."
		fi
	fi
	exit 0
fi

# What the places need before anything changes. The dump of nginx -T goes
# through here-strings: grep -q at the end of a pipe would cut it off, and
# pipefail would count that as a failure.
if ! dump=$(nginx -T 2>&1); then
	echo "nginx -T meldet einen Fehler. Erst die Konfiguration von nginx reparieren; nichts geändert:" >&2
	tail -n 5 <<< "$dump" >&2
	exit 1
fi
if ! grep -q 'ngx_http_modsecurity_module' <<< "$dump" && ! grep -qi 'modsecurity' <<< "$(nginx -V 2>&1)"; then
	echo "Das nginx-Modul für ModSecurity fehlt: nginx -T nennt ngx_http_modsecurity_module nicht. Erst die Pakete einspielen (libnginx-mod-http-modsecurity)." >&2
	exit 1
fi
for file in "$WAF_MODSEC_BASE" "$WAF_CRS_SETUP"; do
	if [ ! -f "$file" ]; then
		echo "$file fehlt. Erst die Pakete von ModSecurity und CRS einspielen oder den Ort mit MALWATCH_WAF_MODSEC_BASE bzw. MALWATCH_WAF_CRS_SETUP angeben." >&2
		exit 1
	fi
done
if ! compgen -G "$WAF_CRS_RULES" > /dev/null; then
	echo "Die Regeln der CRS fehlen: $WAF_CRS_RULES findet keine Datei. Erst das Paket modsecurity-crs einspielen oder MALWATCH_WAF_CRS_RULES angeben." >&2
	exit 1
fi
for file in "$WAF_RULES_INCLUDE" "$WAF_BLOCKED_INCLUDE" "$WAF_LOGROTATE_FILE" "$WAF_CRON_FILE"; do
	if [ ! -d "$(dirname "$file")" ]; then
		echo "Das Verzeichnis $(dirname "$file") fehlt. $file gehört in ein Verzeichnis, das nginx, logrotate oder cron schon lesen. Nichts geändert." >&2
		exit 1
	fi
done

if changed waf_blocked_log && [ "$WAF_SITES" -gt 0 ] && [ -z "$assume_yes" ]; then
	say "Das Sperrprotokoll wechselt von $OLD_WAF_BLOCKED_LOG nach $WAF_BLOCKED_LOG."
	say "Dafür schreibt der Abgleich $WAF_SITES Websites mit Abwehr neu, über ISPConfig wie beim Umschalten."
	if [ ! -t 0 ]; then
		echo "Ohne Terminal bitte mit --yes bestätigen. Nichts geändert." >&2
		exit 1
	fi
	printf 'Weiter? [j/N] '
	answer=
	read -r answer || true
	case "$answer" in
		j|J|ja|Ja|y|Y|yes) ;;
		*) say "Nichts geändert."; exit 0 ;;
	esac
fi

# The audit log is read up to now before it moves.
if changed waf_audit_log; then
	run_switch ingest > /dev/null || true
fi

BACKUP="$WAF_BACKUP_DIR/install-$(date +%Y%m%d-%H%M%S)"
if [ ! -d "$WAF_BACKUP_DIR" ]; then install -d -o root -g root -m 700 "$WAF_BACKUP_DIR"; fi
install -d -o root -g root -m 700 "$BACKUP" "$BACKUP/new" "$BACKUP/prev"
# Every copy under a name of its own: "waf" is the copy of the rule directory.
if [ -d "$OLD_WAF_CONF_DIR" ]; then cp -a "$OLD_WAF_CONF_DIR" "$BACKUP/waf"; fi
crontab -l > "$BACKUP/crontab" 2>/dev/null || true
say "Sicherung in $BACKUP"

# While the places move, the workers of the Abwehr wait; see malwatch_waf::lock_file().
exec 9> "$WAF_LOCK"
if ! flock -n 9; then
	say "Warte, bis die Abwehr ihren laufenden Schritt beendet ..."
	flock 9
fi

changed_files=""
created_files=""
removed_files=""

# The name of a file in the backup: its path with _ for every /.
backup_name() { printf '%s' "$1" | sed 's#/#_#g'; }

# put <target> <mode>: writes the text from stdin when it differs. The file
# as it was before this run waits in the backup, so undo can put it back.
put() {
	staged="$BACKUP/new/$(backup_name "$1")"
	cat > "$staged"
	if [ -f "$1" ] && cmp -s "$staged" "$1"; then
		return 0
	fi
	case " $changed_files $created_files " in
		*" $1 "*) ;;
		*)
			if [ -f "$1" ]; then
				cp -p "$1" "$BACKUP/prev/$(backup_name "$1")"
				changed_files="$changed_files $1"
			else
				created_files="$created_files $1"
			fi
			;;
	esac
	install -o root -g root -m "$2" "$staged" "$1"
}

# put_text <target> <mode> <command ...>: the output of the command becomes
# the file. A failing command ends the run before the file changes.
put_text() {
	target=$1
	mode=$2
	shift 2
	text="$BACKUP/new/text$(backup_name "$target")"
	"$@" > "$text"
	put "$target" "$mode" < "$text"
}

# drop <file>: takes the file of an old place away; undo puts it back.
drop() {
	if [ -f "$1" ]; then
		cp -p "$1" "$BACKUP/prev/$(backup_name "$1")"
		rm -f "$1"
		removed_files="$removed_files $1"
	fi
}

# Every file back as it was before this run.
undo() {
	for file in $changed_files $removed_files; do
		cp -p "$BACKUP/prev/$(backup_name "$file")" "$file"
	done
	for file in $created_files; do
		rm -f "$file"
	done
}

fail() {
	trap - ERR
	undo
	echo "$1 Jede Datei liegt wieder an ihrem Platz, die Orte bleiben gespeichert, wie sie waren." >&2
	exit 1
}
# From here on every failed command puts the files back.
trap 'fail "Ein Schritt ist in Zeile $LINENO fehlgeschlagen."' ERR

# make_dir <dir> <owner> <group> <mode>: a missing directory is created;
# an existing one keeps its owner and mode.
make_dir() {
	if [ ! -d "$1" ]; then install -d -o "$2" -g "$3" -m "$4" "$1"; fi
}

# 1. The rule directory. A new place starts with everything of the old one:
#    the exceptions of the panel, the block list and the switches.
make_dir "$WAF_CONF_DIR" root root 755
if changed waf_conf_dir && [ -d "$OLD_WAF_CONF_DIR" ] && [ ! -f "$WAF_CONF_DIR/main.conf" ]; then
	for file in "$OLD_WAF_CONF_DIR"/*; do
		if [ -f "$file" ] && [ ! -e "$WAF_CONF_DIR/$(basename "$file")" ]; then
			put "$WAF_CONF_DIR/$(basename "$file")" 644 < "$file"
		fi
	done
fi
for file in crs-extra.conf exclusions-before.conf exclusions-after.conf; do
	put "$WAF_CONF_DIR/$file" 644 < "conf/$file"
done
put_text "$WAF_CONF_DIR/settings.conf" 644 run_switch paths render settings.conf
if [ ! -f "$WAF_CONF_DIR/state.conf" ]; then
	emergency=
	if [ -f "$WAF_CONF_DIR/zustand.conf" ] && grep -qE '^[[:space:]]*SecRuleEngine[[:space:]]+Off' "$WAF_CONF_DIR/zustand.conf"; then
		emergency=1
	fi
	put_text "$WAF_CONF_DIR/state.conf" 644 render waf_state_file_text "$emergency"
fi
if [ ! -f "$WAF_CONF_DIR/response-body.conf" ]; then
	mode=full
	if [ -f "$WAF_CONF_DIR/antwortrumpf.conf" ] && grep -qE '^[^#]*ctl:auditLogParts=-E' "$WAF_CONF_DIR/antwortrumpf.conf"; then
		mode=lean
	fi
	put_text "$WAF_CONF_DIR/response-body.conf" 644 render waf_response_body_text "$mode"
fi
# The panel owns these two; an existing file keeps its exceptions.
for file in exclusions-panel-before.conf exclusions-panel-after.conf; do
	if [ ! -f "$WAF_CONF_DIR/$file" ]; then put "$WAF_CONF_DIR/$file" 644 < "conf/$file"; fi
done
# The block list itself comes from malwatch; here it only starts empty.
if [ ! -f "$WAF_CONF_DIR/blocked.conf" ]; then
	put_text "$WAF_CONF_DIR/blocked.conf" 644 printf '# von malwatch erzeugt, leer\n'
fi
put_text "$WAF_CONF_DIR/main.conf" 644 run_switch paths render main.conf

# 2. The two includes. After a hard emergency stop this switches the rules
#    back on; the include of an old place goes.
put_text "$WAF_RULES_INCLUDE" 644 run_switch paths render rules-include
put_text "$WAF_BLOCKED_INCLUDE" 644 run_switch paths render blocked-include
drop "$WAF_RULES_INCLUDE.off"
if changed waf_rules_include; then
	drop "$OLD_WAF_RULES_INCLUDE"
	drop "$OLD_WAF_RULES_INCLUDE.off"
fi
if changed waf_blocked_include; then drop "$OLD_WAF_BLOCKED_INCLUDE"; fi

# 3. Logs and cache. The audit log holds form contents and stays root's; nginx
#    writes the block log as www-data, the cron reads it as root.
make_dir "$(dirname "$WAF_AUDIT_LOG")" www-data adm 750
make_dir "$(dirname "$WAF_BLOCKED_LOG")" www-data adm 750
make_dir "$(dirname "$WAF_GUARD_LOG")" www-data adm 750
make_dir "$WAF_CACHE_DIR" www-data root 750
if [ ! -f "$WAF_AUDIT_LOG" ]; then install -o root -g adm -m 600 /dev/null "$WAF_AUDIT_LOG"; fi
chown root:adm "$WAF_AUDIT_LOG"
chmod 600 "$WAF_AUDIT_LOG"
if [ ! -f "$WAF_BLOCKED_LOG" ]; then install -o www-data -g adm -m 640 /dev/null "$WAF_BLOCKED_LOG"; fi
chown www-data:adm "$WAF_BLOCKED_LOG"
chmod 640 "$WAF_BLOCKED_LOG"
put_text "$WAF_LOGROTATE_FILE" 644 run_switch paths render logrotate
if changed waf_logrotate_file; then drop "$OLD_WAF_LOGROTATE_FILE"; fi

# 4. The tools and the clock: the cron file starts the minute clock and the
#    hourly guard, apart from the cron of ISPConfig.
make_dir "$WAF_TOOLS_DIR" root root 755
for tool in waf-switch waf-guard waf-report; do
	put "$WAF_TOOLS_DIR/$tool" 755 < "$tool"
done
put_text "$WAF_CRON_FILE" 644 run_switch paths render cron
if changed waf_cron_file; then drop "$OLD_WAF_CRON_FILE"; fi
if changed waf_tools_dir; then
	for tool in waf-switch waf-guard waf-report; do drop "$OLD_WAF_TOOLS_DIR/$tool"; done
fi

# 5. The checks, when a file of nginx changed: the rule check, nginx -t, and
#    nginx -T for both includes. Any failure puts every file back.
reload=
for file in $changed_files $created_files $removed_files; do
	case "$file" in
		"$WAF_CONF_DIR"/*|"$OLD_WAF_CONF_DIR"/*|"$WAF_RULES_INCLUDE"*|"$OLD_WAF_RULES_INCLUDE"*|"$WAF_BLOCKED_INCLUDE"|"$OLD_WAF_BLOCKED_INCLUDE") reload=1 ;;
	esac
done
if [ -n "$reload" ]; then
	check=$(compgen -G "$WAF_RULES_CHECK" | head -n 1 || true)
	if [ -z "$check" ]; then check=$(command -v modsec-rules-check || true); fi
	if [ -n "$check" ] && ! "$check" "$WAF_CONF_DIR/main.conf"; then
		fail "Die Regelprüfung lehnt $WAF_CONF_DIR/main.conf ab."
	fi
	if ! nginx -t; then
		fail "nginx -t lehnt die neue Konfiguration ab."
	fi
	if ! nginx -T > "$BACKUP/nginx-T.txt" 2>/dev/null; then
		fail "nginx -T meldet einen Fehler."
	fi
	for file in "$WAF_RULES_INCLUDE" "$WAF_BLOCKED_INCLUDE"; do
		if ! grep -qF "# configuration file $file:" "$BACKUP/nginx-T.txt"; then
			fail "nginx lädt $file nicht: nginx.conf bindet dieses Verzeichnis nicht ein."
		fi
	done
fi
case " $changed_files $created_files " in
	*" $WAF_LOGROTATE_FILE "*)
		if ! logrotate -d "$WAF_LOGROTATE_FILE" > /dev/null 2>&1; then
			fail "logrotate lehnt $WAF_LOGROTATE_FILE ab; logrotate -d $WAF_LOGROTATE_FILE zeigt den Grund."
		fi
		;;
esac

# 6. The places are stored once they stand and nginx accepted them. From
#    here on the files stay, whatever follows.
run_switch paths save
trap - ERR

# 7. The old names go once nothing includes them any more.
rm -f "$WAF_CONF_DIR/einstellungen.conf" "$WAF_CONF_DIR/crs-zusatz.conf" "$WAF_CONF_DIR/ausnahmen-vorher.conf" \
	"$WAF_CONF_DIR/ausnahmen-nachher.conf" "$WAF_CONF_DIR/zustand.conf" "$WAF_CONF_DIR/antwortrumpf.conf" \
	"$WAF_CONF_DIR/main.conf.prev"
# The first tools lived in /usr/local/sbin and /usr/local/lib/waf.
rm -f /usr/local/sbin/waf-schalter /usr/local/sbin/waf-wache /usr/local/sbin/waf-bericht
rm -rf /usr/local/lib/waf

if [ -n "$reload" ]; then
	if ! systemctl reload "$WAF_NGINX_SERVICE"; then
		echo "Der Reload von nginx ist fehlgeschlagen; die geprüften Dateien liegen schon an ihrem Platz. Sofort prüfen: systemctl status $WAF_NGINX_SERVICE" >&2
		exit 1
	fi
	if ! systemctl is-active --quiet "$WAF_NGINX_SERVICE"; then
		echo "nginx läuft nach dem Reload nicht. Sofort prüfen: systemctl status $WAF_NGINX_SERVICE" >&2
		exit 1
	fi
	say "nginx neu geladen."
fi

# 8. The guard runs from the cron file; its line in the crontab of root goes,
#    every other line stays as it is.
current=$(crontab -l 2>/dev/null || true)
wanted=$(grep -vE '(^|[[:space:]/])waf-(guard|wache)([[:space:]]|$)' <<< "$current" || true)
if [ "$wanted" != "$current" ]; then
	printf '%s\n' "$wanted" | crontab -
	say "Die Wache läuft jetzt aus $WAF_CRON_FILE; ihre Zeile in der crontab von root ist entfernt."
fi
if [ -f /etc/hc-run.d/waf-wache.url ] && [ ! -f "/etc/hc-run.d/$WAF_HC_GUARD_NAME.url" ]; then
	mv /etc/hc-run.d/waf-wache.url "/etc/hc-run.d/$WAF_HC_GUARD_NAME.url"
fi

exec 9>&-

"$WAF_TOOLS_DIR/waf-switch" snapshot

# 9. Old markers, the state per website, the block log in the vhosts and the
#    files of the settings through the jobs.
if ! "$WAF_TOOLS_DIR/waf-switch" migrate; then
	say "Der Abgleich läuft über den Cron weiter: waf-switch jobs"
fi

for key in $WAF_CHANGED; do
	name=$(printf '%s' "$key" | tr 'a-z' 'A-Z')
	eval "old=\$OLD_$name"
	case "$key" in
		waf_conf_dir|waf_cache_dir|waf_backup_dir|waf_audit_log|waf_blocked_log|waf_guard_log)
			if [ -e "$old" ]; then say "Bleibt liegen, bitte nach einer Prüfung selbst entfernen: $old"; fi
			;;
	esac
done
say "Fertig. waf-switch status zeigt den Stand, waf-switch paths die Orte."
