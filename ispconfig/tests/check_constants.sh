#!/bin/sh
# Guards against constants ISPConfig does not define.
#
# LOGLEVEL_INFO reads perfectly plausible, does not exist in ISPConfig, and
# php -l cannot see it: an undefined constant is only a fatal at run time. It
# broke the very first install, inside the installer, where nothing else runs
# and the extension is left half applied.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
status=0

# Defined in server/lib/config.inc.php and interface/lib/config.inc.php.
allowed='LOGLEVEL_DEBUG|LOGLEVEL_WARN|LOGLEVEL_ERROR'

found=$(grep -rhoE 'LOGLEVEL_[A-Z_]+' "$root" --include='*.php' | sort -u || true)

for name in $found; do
	if ! printf '%s' "$name" | grep -qE "^($allowed)$"; then
		printf 'Unknown constant %s. ISPConfig only defines: %s\n' "$name" "$allowed" >&2
		grep -rn "$name" "$root" --include='*.php' >&2
		status=1
	fi
done

if [ "$status" -eq 0 ]; then
	printf 'Constants OK: %s\n' "$(printf '%s' "$found" | tr '\n' ' ')"
fi

exit "$status"
