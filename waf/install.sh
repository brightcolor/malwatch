#!/bin/bash
# Spielt die WAF-Dateien und Werkzeuge auf web.herkules ein.
# Ändert nichts an den Websites: eingeschaltet wird getrennt über waf-schalter.
set -eu
cd "$(dirname "$0")"

if [ ! -f /etc/nginx/modules-enabled/50-mod-http-modsecurity.conf ]; then
	echo "Das nginx-Modul fehlt. Erst die Pakete einspielen." >&2
	exit 1
fi

install -d -o root -g root -m 755 /etc/nginx/waf
for f in main.conf einstellungen.conf crs-zusatz.conf ausnahmen-vorher.conf ausnahmen-nachher.conf zustand.conf; do
	install -o root -g root -m 644 "conf/$f" "/etc/nginx/waf/$f"
done
install -o root -g root -m 644 conf/logrotate-waf /etc/logrotate.d/waf

install -d -o www-data -g adm -m 750 /var/log/waf
# Das Audit-Log entsteht beim ersten Laden der Regeln als root und wäre sonst für
# alle lesbar. Es enthält Formularinhalte, deshalb gleich einengen.
[ -f /var/log/waf/audit.log ] || install -o root -g adm -m 600 /dev/null /var/log/waf/audit.log
chown root:adm /var/log/waf/audit.log
chmod 600 /var/log/waf/audit.log
install -d -o www-data -g root -m 750 /var/cache/waf
install -d -o root -g root -m 700 /var/backups/waf-schalter

install -d -o root -g root -m 755 /usr/local/lib/waf
install -o root -g root -m 644 lib/waf_block.inc.php /usr/local/lib/waf/waf_block.inc.php
install -o root -g root -m 644 lib/waf_audit.inc.php /usr/local/lib/waf/waf_audit.inc.php
install -o root -g root -m 755 waf-schalter /usr/local/sbin/waf-schalter
install -o root -g root -m 755 waf-wache /usr/local/sbin/waf-wache
install -o root -g root -m 755 waf-bericht /usr/local/sbin/waf-bericht

# Zuletzt die Einbindung, damit nginx die Regeln erst sieht, wenn alles liegt.
install -o root -g root -m 644 conf/waf.conf /etc/nginx/conf.d/waf.conf
nginx -t
echo "Eingespielt. Eingeschaltet ist noch keine Website."
