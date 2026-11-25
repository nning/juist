#!/bin/sh
# Runs every model and compares each outcome with models/expected: what
# ProVerif proves or finds, and what TLC finds in each configuration.
# PROVERIF, JAVA and TLA2TOOLS name the tools; make models sets them.
set -eu
export LC_ALL=C
cd "$(dirname "$0")"
: "${PROVERIF:=proverif}" "${JAVA:=java}" "${TLA2TOOLS:?set TLA2TOOLS to tla2tools.jar}"
got=$(mktemp)
meta=$(mktemp -d)
trap 'rm -rf "$got" "$meta"' EXIT

for f in *.pv; do
	lib=${f%%-*}
	lib=${lib%.pv}
	echo "==> $f" >&2
	if [ -f "$lib.pvl" ]; then
		$PROVERIF -lib "$lib" "$f"
	else
		$PROVERIF "$f"
	fi | sed -n "s/^RESULT /$f: /p" >>"$got"
done
for c in log/*.cfg; do
	case $c in log/Trace* | log/PairKeyTrace*) continue ;; esac
	spec=Trace
	case $c in log/Freshness*) spec=Freshness ;; log/PairKey*) spec=PairKey ;; esac
	echo "==> $c" >&2
	out=$(cd log && $JAVA -XX:+UseParallelGC -cp "$TLA2TOOLS" tlc2.TLC -noGenerateSpecTE -workers auto \
		-metadir "$meta/$(basename "$c" .cfg)" -config "$(basename "$c")" "$spec.tla" 2>&1 || true)
	verdict=$(printf '%s\n' "$out" | grep -oE 'Invariant [A-Za-z]+ is violated|No error has been found' | head -1)
	if [ -z "$verdict" ]; then
		printf '%s\n' "$out" | tail -20 >&2
		verdict="no verdict"
	fi
	echo "$c: $verdict" >>"$got"
	printf '%s\n' "$out" | grep -E 'states generated' >&2 || true
done
if ! diff -u expected "$got"; then
	echo "models: the outcomes above differ from models/expected" >&2
	exit 1
fi
echo "models: every outcome is the expected one"
