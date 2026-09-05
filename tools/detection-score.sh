#!/bin/sh
# Misst, wie viel von einem bekannten Befall der Scanner findet.
#
#   tools/detection-score.sh <malwatch> <webstamm> <liste-bekannter-schaddateien>
#
# Die Liste enthält je Zeile einen absoluten Pfad. Ohne eine solche Liste ist
# "bessere Erkennung" Gefühlssache: eine Regel, die alles meldet, sieht in
# einem einzelnen Beispiel großartig aus. Die Gegenprobe gegen sauberen Code
# fährt der CI-Job clean-cms.
set -eu

if [ $# -lt 3 ]; then
	echo "Aufruf: $0 <malwatch> <webstamm> <liste>" >&2
	exit 2
fi

binary=$1
root=$2
known=$3

for f in "$binary" "$known"; do
	[ -r "$f" ] || { echo "nicht lesbar: $f" >&2; exit 2; }
done
[ -d "$root" ] || { echo "kein Verzeichnis: $root" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

"$binary" scan --path="$root" --offline --quiet --json \
	--state-dir="$work/state" --cache="$work/cache.json" \
	> "$work/report.json" || true

# Nur die Fundstellen, nicht die erkannten Installationen: beide Listen im
# Bericht tragen ein Feld "path".
sed -n 's/.*"path": "\(.*\)",$/\1/p' "$work/report.json" \
	| sed 's/\\\\/\//g' | sort -u > "$work/hit.txt"
sort -u "$known" > "$work/known.txt"

total=$(wc -l < "$work/known.txt")
found=$(comm -12 "$work/known.txt" "$work/hit.txt" | wc -l)
missed=$(comm -23 "$work/known.txt" "$work/hit.txt" | wc -l)

if [ "$total" -eq 0 ]; then
	echo "Die Liste ist leer." >&2
	exit 2
fi

printf 'bekannte Schaddateien: %s\n' "$total"
printf 'davon erkannt:         %s  (%s %%)\n' "$found" "$((found * 100 / total))"
printf 'übersehen:             %s\n' "$missed"

if [ "$missed" -gt 0 ]; then
	echo
	echo 'die ersten übersehenen:'
	comm -23 "$work/known.txt" "$work/hit.txt" | head -10 | sed 's/^/  /'
fi
