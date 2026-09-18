#!/bin/bash
# Installs the WAF files and tools on the web server and moves the names of
# the first tool (waf-schalter, einstellungen.conf, ...) to the current ones.
# Runs any number of times. nginx only ever loads a checked configuration,
# and the websites keep their state.
set -eu
cd "$(dirname "$0")"

WAF=/etc/nginx/waf
INCLUDE=/etc/nginx/conf.d/waf.conf
LIB=/usr/local/ispconfig/interface/web/security/lib/malwatch_waf_lib.inc.php
BACKUP=/var/backups/waf-switch/install-$(date +%Y%m%d-%H%M%S)

say() { echo "waf/install.sh: $*"; }

# Writes a text the shared functions produce: render <function> [arguments]
render() {
	php -r 'require $argv[1]; echo call_user_func_array($argv[2], array_slice($argv, 3));' "$LIB" "$@"
}

if [ ! -f /etc/nginx/modules-enabled/50-mod-http-modsecurity.conf ]; then
	echo "Das nginx-Modul fehlt. Erst die Pakete einspielen." >&2
	exit 1
fi
if [ ! -f "$LIB" ] || [ ! -f /usr/local/ispconfig/server/lib/classes/malwatch_waf.inc.php ]; then
	echo "malwatch 0.19.0 fehlt. Erst das Addon einspielen." >&2
	exit 1
fi

install -d -o root -g root -m 700 /var/backups/waf-switch
install -d -o root -g root -m 700 "$BACKUP"
if [ -d "$WAF" ]; then cp -a "$WAF" "$BACKUP/waf"; fi
for f in "$INCLUDE" "$INCLUDE.off"; do
	if [ -f "$f" ]; then cp -a "$f" "$BACKUP/"; fi
done
# Under its own name: "waf" in the backup is the copy of $WAF.
if [ -f /etc/logrotate.d/waf ]; then cp -a /etc/logrotate.d/waf "$BACKUP/logrotate-waf"; fi
crontab -l > "$BACKUP/crontab" 2>/dev/null || true
say "Sicherung in $BACKUP"

install -d -o root -g root -m 755 "$WAF"

# 1. The files under their current names, next to the old ones.
for f in settings.conf crs-extra.conf exclusions-before.conf exclusions-after.conf; do
	install -o root -g root -m 644 "conf/$f" "$WAF/$f"
done
if [ ! -f "$WAF/state.conf" ]; then
	emergency=
	if [ -f "$WAF/zustand.conf" ] && grep -qE '^[[:space:]]*SecRuleEngine[[:space:]]+Off' "$WAF/zustand.conf"; then
		emergency=1
	fi
	render waf_state_file_text "$emergency" > "$WAF/state.conf"
	chmod 644 "$WAF/state.conf"
fi
if [ ! -f "$WAF/response-body.conf" ]; then
	mode=full
	if [ -f "$WAF/antwortrumpf.conf" ] && grep -qE '^[^#]*ctl:auditLogParts=-E' "$WAF/antwortrumpf.conf"; then
		mode=lean
	fi
	render waf_response_body_text "$mode" > "$WAF/response-body.conf"
	chmod 644 "$WAF/response-body.conf"
fi
# The panel owns these two; an existing file keeps its exceptions.
for f in exclusions-panel-before.conf exclusions-panel-after.conf; do
	if [ ! -f "$WAF/$f" ]; then
		install -o root -g root -m 644 "conf/$f" "$WAF/$f"
	fi
done

# 2. The new main.conf only after the rules check; nginx -t decides, and on
#    failure the previous one comes back.
reload=
install -o root -g root -m 644 conf/main.conf "$WAF/main.conf.new"
if cmp -s "$WAF/main.conf.new" "$WAF/main.conf"; then
	rm -f "$WAF/main.conf.new"
else
	check=$(ls /usr/lib/*/libexec/modsec-rules-check 2>/dev/null | head -n 1 || true)
	if [ -n "$check" ] && ! "$check" "$WAF/main.conf.new"; then
		rm -f "$WAF/main.conf.new"
		echo "Die Regelprüfung lehnt die neue main.conf ab. Nichts umgestellt." >&2
		exit 1
	fi
	if [ -f "$WAF/main.conf" ]; then cp -p "$WAF/main.conf" "$WAF/main.conf.prev"; fi
	mv "$WAF/main.conf.new" "$WAF/main.conf"
	if ! nginx -t; then
		if [ -f "$WAF/main.conf.prev" ]; then
			mv "$WAF/main.conf.prev" "$WAF/main.conf"
		else
			rm -f "$WAF/main.conf"
		fi
		echo "nginx -t lehnt die neue main.conf ab. Die vorherige liegt wieder an ihrem Platz." >&2
		exit 1
	fi
	reload=1
fi

# 3. The old names go once nothing includes them any more.
rm -f "$WAF/einstellungen.conf" "$WAF/crs-zusatz.conf" "$WAF/ausnahmen-vorher.conf" \
	"$WAF/ausnahmen-nachher.conf" "$WAF/zustand.conf" "$WAF/antwortrumpf.conf" "$WAF/main.conf.prev"

install -d -o www-data -g adm -m 750 /var/log/waf
# The audit log holds form contents and stays root's.
if [ ! -f /var/log/waf/audit.log ]; then install -o root -g adm -m 600 /dev/null /var/log/waf/audit.log; fi
chown root:adm /var/log/waf/audit.log
chmod 600 /var/log/waf/audit.log
# Das zweite Zugriffslog: nginx schreibt es als www-data, der Cron liest es als root.
if [ ! -f /var/log/waf/blocked.log ]; then install -o www-data -g adm -m 640 /dev/null /var/log/waf/blocked.log; fi
chown www-data:adm /var/log/waf/blocked.log
chmod 640 /var/log/waf/blocked.log
# Die Sperrliste selbst schreibt malwatch; hier entsteht sie nur leer.
if [ ! -f "$WAF/blocked.conf" ]; then printf '# von malwatch erzeugt, leer
' > "$WAF/blocked.conf"; fi
chmod 644 "$WAF/blocked.conf"
install -o root -g root -m 644 conf/waf-blocked.conf /etc/nginx/conf.d/waf-blocked.conf
install -d -o www-data -g root -m 750 /var/cache/waf
# The settings page rewrites this file; only a file from before malwatch is replaced here.
if ! grep -q 'Managed by malwatch' /etc/logrotate.d/waf 2>/dev/null; then
	install -o root -g root -m 644 conf/logrotate-waf /etc/logrotate.d/waf
fi

# 4. The tools under their current names.
install -o root -g root -m 755 waf-switch /usr/local/sbin/waf-switch
install -o root -g root -m 755 waf-guard /usr/local/sbin/waf-guard
install -o root -g root -m 755 waf-report /usr/local/sbin/waf-report
rm -f /usr/local/sbin/waf-schalter /usr/local/sbin/waf-wache /usr/local/sbin/waf-bericht
rm -rf /usr/local/lib/waf

# 5. The hourly guard in root's crontab; every other line stays as it is.
current=$(crontab -l 2>/dev/null || true)
if printf '%s\n' "$current" | grep -q 'hc-run waf-guard'; then
	wanted=$current
elif printf '%s\n' "$current" | grep -q 'hc-run waf-wache'; then
	wanted=$(printf '%s\n' "$current" | sed 's#hc-run waf-wache -- /usr/local/sbin/waf-wache#hc-run waf-guard -- /usr/local/sbin/waf-guard#')
else
	wanted=$(printf '%s\n%s\n' "$current" '5 * * * * /usr/local/sbin/hc-run waf-guard -- /usr/local/sbin/waf-guard > /dev/null')
fi
if [ "$wanted" != "$current" ]; then
	printf '%s\n' "$wanted" | crontab -
	say "Cron-Zeile auf waf-guard umgestellt."
fi
if [ -f /etc/hc-run.d/waf-wache.url ] && [ ! -f /etc/hc-run.d/waf-guard.url ]; then
	mv /etc/hc-run.d/waf-wache.url /etc/hc-run.d/waf-guard.url
fi

# 6. The include last, so nginx sees the rules once everything is in place.
#    After a hard emergency stop this switches the rules back on.
if ! cmp -s conf/waf.conf "$INCLUDE"; then
	install -o root -g root -m 644 conf/waf.conf "$INCLUDE.new"
	mv "$INCLUDE.new" "$INCLUDE"
	if ! nginx -t; then
		rm -f "$INCLUDE"
		if [ -f "$BACKUP/waf.conf" ]; then cp -a "$BACKUP/waf.conf" "$INCLUDE"; fi
		echo "nginx -t lehnt die Einbindung ab. Der vorherige Stand liegt wieder." >&2
		exit 1
	fi
	reload=1
fi
rm -f "$INCLUDE.off"

/usr/local/sbin/waf-switch snapshot
if [ -n "$reload" ]; then
	systemctl reload nginx
	if ! systemctl is-active --quiet nginx; then
		echo "nginx läuft nach dem Reload nicht. Sofort prüfen: systemctl status nginx" >&2
		exit 1
	fi
	say "nginx neu geladen."
fi

# 7. Old markers, the state per website and the logrotate setting through the jobs.
if ! /usr/local/sbin/waf-switch migrate; then
	say "Der Abgleich läuft über den Cron weiter: waf-switch jobs"
fi
say "Fertig. waf-switch status zeigt den Stand."
