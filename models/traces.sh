#!/bin/sh
# Writes the log model's traces anew into log/traces, which trust/log's
# TestTheCodeFollowsTheModelsTraces replays: N behaviours of each
# log/Trace*.cfg and log/PairKeyTrace*.cfg, from a fixed seed.
set -eu
export LC_ALL=C
cd "$(dirname "$0")/log"
: "${JAVA:=java}" "${TLA2TOOLS:?set TLA2TOOLS to tla2tools.jar}" "${N:=30}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rm -f traces/*.tla.gz
mkdir -p traces
for c in Trace*.cfg PairKeyTrace*.cfg; do
	name=$(basename "$c" .cfg)
	spec=Trace depth=16
	case $name in PairKey*) spec=PairKeyTrace depth=40 ;; esac
	$JAVA -cp "$TLA2TOOLS" tlc2.TLC -noGenerateSpecTE -simulate "file=$tmp/$name,num=$N" -depth $depth -seed 32 \
		-metadir "$tmp/meta" -config "$c" $spec.tla >"$tmp/$name.log" 2>&1 ||
		{ tail -20 "$tmp/$name.log" >&2; exit 1; }
	for f in "$tmp/$name"_*; do
		# The module line names the file TLC wrote, under this machine's paths.
		sed '1s/.*/---------------- MODULE trace ----------------/' "$f" |
			gzip -9n >"traces/$(basename "$f").tla.gz"
	done
done
# The counterexamples models/expected names, in the same form.
for c in $(sed -n 's/^log\/\(Log[A-Za-z]*\)\.cfg: Invariant .* is violated$/\1/p' ../expected); do
	$JAVA -XX:+UseParallelGC -cp "$TLA2TOOLS" tlc2.TLC -noGenerateSpecTE -workers auto -metadir "$tmp/meta-$c" -config "$c.cfg" Trace.tla \
		>"$tmp/$c.log" 2>&1 || true
	sed -n '/^Error: The behavior up to this point is:/,/states generated/p' "$tmp/$c.log" |
		sed '1d;$d; s/^State \([0-9]*\): .*/STATE_\1 ==/' |
		{ echo '---------------- MODULE trace ----------------'; cat; } |
		gzip -9n >"traces/$c.tla.gz"
done
ls traces | wc -l | xargs echo "traces: wrote"
