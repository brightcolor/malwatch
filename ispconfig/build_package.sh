#!/bin/sh
# Builds the .pkg archive for the ISPConfig extension mechanism.
set -e

NAME=malwatch
VERSION=$(tr -d '\n\r ' < version)
OUT="${NAME}-${VERSION}.pkg"

rm -f "$OUT" "${NAME}.pkg"
zip -q -r "$OUT" \
	version \
	README.md \
	install \
	interface \
	server \
	-x "*.pkg" -x "build_package.sh" -x "*.git*"

cp "$OUT" "${NAME}.pkg"
echo "Built: $OUT (and ${NAME}.pkg)"
