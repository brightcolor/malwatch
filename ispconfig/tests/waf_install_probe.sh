#!/bin/bash
# Runs waf/install.sh against a scratch tree. nginx, systemctl, crontab,
# logrotate, flock, the rule check and the owners of install and chown are
# stand-ins; so is waf-switch, with the settings in a JSON file and the shared
# functions of the repository. Checks a first install, a run without
# changes, --check, a refused value, a move of places, the way back after a
# failed nginx -t, a failed rule check and an include nginx does not load,
# the end of a hard emergency stop and the question before a new block log.
#
#   bash ispconfig/tests/waf_install_probe.sh
set -euo pipefail
# Git Bash would turn every path handed to PHP into a Windows path.
export MSYS_NO_PATHCONV=1
repo=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0
fail() { echo "FAIL $*" >&2; failures=$((failures + 1)); }

# A path PHP can open: on Windows the mixed form of cygpath, elsewhere the path itself.
native() { if command -v cygpath > /dev/null; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

root="$tmp/root"
state="$tmp/state"
stubs="$tmp/stubs"
pkg="$tmp/pkg"
mkdir -p "$root" "$state" "$stubs" "$pkg"
cp -r "$repo/waf/." "$pkg/"
export PROBE_ROOT="$root" PROBE_STATE="$state"
export MALWATCH_WAF_LIB WAF_PROBE_STATE WAF_PROBE_LOCK="$state/lock" WAF_PROBE_SITES=0
MALWATCH_WAF_LIB=$(native "$repo/ispconfig/interface/lib/malwatch_waf_lib.inc.php")
WAF_PROBE_STATE=$(native "$state")

# --- stand-ins -------------------------------------------------------------------

cat > "$state/switch.php" <<'PHP'
<?php
// Stands in for waf-switch: the settings live in settings.json of the state directory.
require getenv('MALWATCH_WAF_LIB');
$dir = getenv('WAF_PROBE_STATE');
$row = json_decode((string) file_get_contents($dir . '/settings.json'), true);
$stored = waf_settings($row);
$args = array_slice($argv, 1);
file_put_contents($dir . '/calls.log', implode(' ', $args) . "\n", FILE_APPEND);
if ($args[0] !== 'paths' || !isset($args[1])) {
	exit(0);
}
if ($args[1] === 'get') {
	echo $stored[$args[2]], "\n";
	exit(0);
}
$overlay = waf_path_overlay($stored, getenv());
if (count($overlay['problems']) > 0) {
	foreach ($overlay['problems'] as $problem) {
		fwrite(STDERR, waf_path_problem_text($problem) . "\n");
	}
	exit(1);
}
if ($args[1] === 'shell') {
	echo waf_path_shell_text($stored, $overlay, getenv('WAF_PROBE_LOCK'), (int) getenv('WAF_PROBE_SITES'));
	exit(0);
}
if ($args[1] === 'render') {
	$text = waf_path_render_text($args[2], array_merge($stored, $overlay['values']));
	if ($text === null) {
		exit(2);
	}
	echo $text;
	exit(0);
}
foreach ($overlay['changed'] as $key) {
	$row[$key] = $overlay['values'][$key];
}
file_put_contents($dir . '/settings.json', json_encode($row));
PHP
if command -v cygpath > /dev/null; then
	# Git Bash hands PHP no path it could open, so a shell wrapper names the stand-in natively.
	printf '#!/bin/bash\nexec php %s "$@"\n' "$(native "$state/switch.php")" > "$pkg/waf-switch"
else
	# A PHP script like the real one, so the installer may also start it through php.
	printf "#!/usr/bin/env php\n<?php\nrequire '%s';\n" "$state/switch.php" > "$pkg/waf-switch"
fi

cat > "$stubs/nginx" <<'SH'
#!/bin/bash
# nginx -t fails while a file below etc/nginx holds the text of nginx-t-fails;
# nginx -T lists the files of conf.d.
broken() { [ -f "$PROBE_STATE/nginx-t-fails" ] && grep -rqF -f "$PROBE_STATE/nginx-t-fails" "$PROBE_ROOT/etc/nginx"; }
case "$1" in
	-t) ! broken ;;
	-T)
		echo "load_module modules/ngx_http_modsecurity_module.so;"
		for file in "$PROBE_ROOT"/etc/nginx/conf.d/*.conf; do
			if [ -f "$file" ]; then echo "# configuration file $file:"; cat "$file"; fi
		done
		! broken
		;;
	-V) echo "nginx version: probe" ;;
esac
SH
cat > "$stubs/systemctl" <<'SH'
#!/bin/bash
echo "$*" >> "$PROBE_STATE/systemctl.log"
SH
cat > "$stubs/crontab" <<'SH'
#!/bin/bash
if [ "$1" = "-l" ]; then cat "$PROBE_STATE/crontab"; else cat > "$PROBE_STATE/crontab"; fi
SH
cat > "$stubs/modsec-rules-check" <<'SH'
#!/bin/bash
# Refuses while a file below etc/nginx holds the text of rules-fail.
! { [ -f "$PROBE_STATE/rules-fail" ] && grep -rqF -f "$PROBE_STATE/rules-fail" "$PROBE_ROOT/etc/nginx"; }
SH
cat > "$stubs/install" <<'SH'
#!/bin/bash
# Leaves owner and group out: the probe runs without root. Git Bash on
# Windows cannot give a directory the mode 700, so there the mode goes too.
args=()
while [ $# -gt 0 ]; do
	case "$1" in
		-o|-g) shift 2 ;;
		-m) case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) shift 2 ;; *) args+=("$1" "$2"); shift 2 ;; esac ;;
		*) args+=("$1"); shift ;;
	esac
done
exec /usr/bin/install "${args[@]}"
SH
for tool in logrotate flock chown; do printf '#!/bin/bash\nexit 0\n' > "$stubs/$tool"; done
chmod +x "$stubs"/* "$pkg/waf-switch"
export PATH="$stubs:$PATH"

# --- the server before the first install -------------------------------------------

mkdir -p "$root/etc/nginx/conf.d" "$root/etc/modsecurity/crs" "$root/usr/share/modsecurity-crs/rules" \
	"$root/etc/logrotate.d" "$root/etc/cron.d"
echo "SecRuleEngine DetectionOnly" > "$root/etc/nginx/modsecurity.conf"
echo "# setup" > "$root/etc/modsecurity/crs/crs-setup.conf"
echo "# rules" > "$root/usr/share/modsecurity-crs/rules/REQUEST-901-INITIALIZATION.conf"
printf '%s\n' '5 * * * * /usr/local/sbin/hc-run waf-guard -- /usr/local/sbin/waf-guard > /dev/null' \
	'30 3 * * * /root/backup.sh' > "$state/crontab"
cat > "$state/settings.json" <<JSON
{"waf_conf_dir":"$root/etc/nginx/waf","waf_rules_include":"$root/etc/nginx/conf.d/waf.conf",
"waf_blocked_include":"$root/etc/nginx/conf.d/waf-blocked.conf","waf_modsec_base":"$root/etc/nginx/modsecurity.conf",
"waf_crs_setup":"$root/etc/modsecurity/crs/crs-setup.conf","waf_crs_rules":"$root/usr/share/modsecurity-crs/rules/*.conf",
"waf_rules_check":"$stubs/modsec-rules-check","waf_cache_dir":"$root/var/cache/waf",
"waf_audit_log":"$root/var/log/waf/audit.log","waf_blocked_log":"$root/var/log/waf/blocked.log",
"waf_guard_log":"$root/var/log/waf/guard.log","waf_backup_dir":"$root/var/backups/waf-switch",
"waf_logrotate_file":"$root/etc/logrotate.d/waf","waf_tools_dir":"$root/usr/local/sbin",
"waf_cron_file":"$root/etc/cron.d/malwatch-waf","waf_hc_run":"$root/usr/local/sbin/hc-run","waf_bin_dirs":"$stubs"}
JSON

# Every file of the scratch server and the stored settings, the backups left out.
fingerprint() {
	(cd "$root" && find . -type f ! -path './var/backups/*' | sort | while read -r file; do
		printf '%s %s\n' "$(md5sum < "$file" | cut -c1-32)" "$file"
	done)
	md5sum < "$state/settings.json"
}
reloads() { grep -c 'reload' "$state/systemctl.log" 2>/dev/null || true; }
install_waf() { bash "$pkg/install.sh" "$@" < /dev/null 2>&1; }

# --- 1. the first install -------------------------------------------------------------

if ! out=$(install_waf); then fail "first install: $out"; fi
grep -qF "Include $root/etc/nginx/waf/state.conf" "$root/etc/nginx/waf/main.conf" 2>/dev/null \
	|| fail "first install: main.conf does not include the state of the rule directory"
grep -qF "Include $root/usr/share/modsecurity-crs/rules/*.conf" "$root/etc/nginx/waf/main.conf" 2>/dev/null \
	|| fail "first install: main.conf does not include the CRS rules of the settings"
grep -qF "SecAuditLog $root/var/log/waf/audit.log" "$root/etc/nginx/waf/settings.conf" 2>/dev/null \
	|| fail "first install: settings.conf does not name the audit log of the settings"
grep -qF "modsecurity_rules_file $root/etc/nginx/waf/main.conf;" "$root/etc/nginx/conf.d/waf.conf" 2>/dev/null \
	|| fail "first install: the include of the rules is missing"
grep -qF "include $root/etc/nginx/waf/blocked.conf;" "$root/etc/nginx/conf.d/waf-blocked.conf" 2>/dev/null \
	|| fail "first install: the include of the block list is missing"
grep -qF "5 * * * * root if [ -x $root/usr/local/sbin/hc-run ]" "$root/etc/cron.d/malwatch-waf" 2>/dev/null \
	|| fail "first install: the cron file lacks the guard"
grep -qF "$root/var/log/waf/blocked.log {" "$root/etc/logrotate.d/waf" 2>/dev/null \
	|| fail "first install: logrotate does not rotate the block log of the settings"
[ -x "$root/usr/local/sbin/waf-guard" ] || fail "first install: waf-guard is missing"
[ -f "$root/var/log/waf/audit.log" ] && [ -f "$root/var/log/waf/blocked.log" ] || fail "first install: the logs are missing"
if grep -q 'waf-guard' "$state/crontab"; then fail "first install: the guard stays in the crontab of root"; fi
grep -q 'backup.sh' "$state/crontab" || fail "first install: another line of the crontab went"
[ "$(reloads)" = 1 ] || fail "first install: nginx reloaded $(reloads) times, expected once"
grep -q '^migrate' "$state/calls.log" || fail "first install: waf-switch migrate did not run"

# --- 2. a run without changes -----------------------------------------------------------

before=$(fingerprint)
if ! out=$(install_waf); then fail "second run: $out"; fi
[ "$(fingerprint)" = "$before" ] || fail "second run changed files"
[ "$(reloads)" = 1 ] || fail "second run reloaded nginx"

# --- 3. --check and a refused value change nothing --------------------------------------

out=$(MALWATCH_WAF_CONF_DIR="$root/etc/nginx/waf2" install_waf --check) || fail "check: $out"
grep -qF "waf_conf_dir: $root/etc/nginx/waf -> $root/etc/nginx/waf2" <<< "$out" || fail "check does not show the move: $out"
[ "$(fingerprint)" = "$before" ] || fail "check changed files"
if out=$(MALWATCH_WAF_AUDIT_LOG=audit.log install_waf); then fail "a relative audit log was taken"; fi
grep -q 'MALWATCH_WAF_AUDIT_LOG=audit.log ist kein absoluter Pfad' <<< "$out" || fail "refused value without its reason: $out"
if out=$(MALWATCH_WAF_CONFDIR=/x install_waf); then fail "a mistyped variable was taken"; fi
grep -q 'MALWATCH_WAF_CONFDIR ist keine Einstellung der Abwehr' <<< "$out" || fail "mistyped variable without its reason: $out"
[ "$(fingerprint)" = "$before" ] || fail "refused values changed files"

# --- 4. the way back after a failed nginx -t, rule check or include ---------------------

echo 'cache/waf3' > "$state/nginx-t-fails"
if out=$(MALWATCH_WAF_CACHE_DIR="$root/var/cache/waf3" install_waf); then fail "a failed nginx -t went through"; fi
grep -q 'nginx -t lehnt die neue Konfiguration ab. Jede Datei liegt wieder an ihrem Platz' <<< "$out" \
	|| fail "failed nginx -t without its message: $out"
[ "$(fingerprint)" = "$before" ] || fail "failed nginx -t left files changed"
rm -f "$state/nginx-t-fails"
echo 'cache/waf3' > "$state/rules-fail"
if out=$(MALWATCH_WAF_CACHE_DIR="$root/var/cache/waf3" install_waf); then fail "a failed rule check went through"; fi
grep -q 'Die Regelprüfung lehnt' <<< "$out" || fail "failed rule check without its message: $out"
[ "$(fingerprint)" = "$before" ] || fail "failed rule check left files changed"
rm -f "$state/rules-fail"
mkdir -p "$root/etc/nginx/other"
if out=$(MALWATCH_WAF_BLOCKED_INCLUDE="$root/etc/nginx/other/waf-blocked.conf" install_waf); then
	fail "an include nginx does not load went through"
fi
grep -qF "nginx lädt $root/etc/nginx/other/waf-blocked.conf nicht" <<< "$out" || fail "unloaded include without its message: $out"
[ "$(fingerprint)" = "$before" ] || fail "unloaded include left files changed"
[ "$(reloads)" = 1 ] || fail "a failed run reloaded nginx"

# --- 5. a move of the rule directory, the include of the rules and the cron file ----------

echo 'deny 192.0.2.1;' >> "$root/etc/nginx/waf/blocked.conf"
if ! out=$(MALWATCH_WAF_CONF_DIR="$root/etc/nginx/waf2" MALWATCH_WAF_RULES_INCLUDE="$root/etc/nginx/conf.d/waf-rules.conf" \
	MALWATCH_WAF_CRON_FILE="$root/etc/cron.d/malwatch-waf2" install_waf); then fail "move: $out"; fi
grep -q 'deny 192.0.2.1;' "$root/etc/nginx/waf2/blocked.conf" 2>/dev/null || fail "move: the block list stayed behind"
grep -qF "Include $root/etc/nginx/waf2/settings.conf" "$root/etc/nginx/waf2/main.conf" 2>/dev/null \
	|| fail "move: main.conf points at the old directory"
grep -qF "modsecurity_rules_file $root/etc/nginx/waf2/main.conf;" "$root/etc/nginx/conf.d/waf-rules.conf" 2>/dev/null \
	|| fail "move: the new include of the rules is missing"
[ ! -e "$root/etc/nginx/conf.d/waf.conf" ] || fail "move: the old include of the rules stayed"
grep -qF "include $root/etc/nginx/waf2/blocked.conf;" "$root/etc/nginx/conf.d/waf-blocked.conf" \
	|| fail "move: the include of the block list points at the old directory"
[ -f "$root/etc/cron.d/malwatch-waf2" ] && [ ! -e "$root/etc/cron.d/malwatch-waf" ] || fail "move: the cron file did not move"
grep -qF "\"waf_conf_dir\":\"$root/etc/nginx/waf2\"" <<< "$(sed 's#\\/#/#g' "$state/settings.json")" \
	|| fail "move: the new rule directory is not stored"
grep -qF "Bleibt liegen, bitte nach einer Prüfung selbst entfernen: $root/etc/nginx/waf" <<< "$out" \
	|| fail "move: the old rule directory is not named"
[ "$(reloads)" = 2 ] || fail "move: nginx reloaded $(reloads) times in all, expected twice"

# --- 6. the end of a hard emergency stop ------------------------------------------------

mv "$root/etc/nginx/conf.d/waf-rules.conf" "$root/etc/nginx/conf.d/waf-rules.conf.off"
if ! out=$(install_waf); then fail "end of a hard stop: $out"; fi
[ -f "$root/etc/nginx/conf.d/waf-rules.conf" ] && [ ! -e "$root/etc/nginx/conf.d/waf-rules.conf.off" ] \
	|| fail "end of a hard stop: the include is not back"

# --- 7. a new block log asks first ------------------------------------------------------

export WAF_PROBE_SITES=2
before=$(fingerprint)
if out=$(MALWATCH_WAF_BLOCKED_LOG="$root/var/log/waf/denied.log" install_waf); then fail "a new block log went without asking"; fi
grep -q 'Ohne Terminal bitte mit --yes bestätigen' <<< "$out" || fail "new block log without its question: $out"
[ "$(fingerprint)" = "$before" ] || fail "the unanswered question changed files"
if ! out=$(MALWATCH_WAF_BLOCKED_LOG="$root/var/log/waf/denied.log" install_waf --yes); then fail "new block log with --yes: $out"; fi
grep -qF "$root/var/log/waf/denied.log {" "$root/etc/logrotate.d/waf" || fail "new block log: logrotate keeps the old one"
[ -f "$root/var/log/waf/denied.log" ] || fail "new block log: the file is missing"

# --- 8. a folder whose scripts lost their mode, as an archive may leave them --------
# Git Bash counts every file with #! as executable, so this runs where chmod counts.
if ! command -v cygpath > /dev/null; then
	chmod -x "$pkg/waf-switch" "$pkg/install.sh"
	before=$(fingerprint)
	if ! out=$(install_waf); then fail "a waf-switch without its mode: $out"; fi
	[ "$(fingerprint)" = "$before" ] || fail "a run through php changed files"
	chmod +x "$pkg/waf-switch" "$pkg/install.sh"
fi

if [ "$failures" -gt 0 ]; then
	echo "$failures Fehler" >&2
	exit 1
fi
echo "waf_install_probe: alle Prüfungen bestanden"
