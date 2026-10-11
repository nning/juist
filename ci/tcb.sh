#!/bin/sh
# tcb.sh GO SCOPE BUDGET: checks that SCOPE places every package of the module,
# and reports the core's and the audit scope's sizes, failing past BUDGET for
# the core. Sizes count every platform's files, tests excepted.
set -eu
go=$1 scope=$2 budget=$3

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mod=$("$go" list -m)
"$go" list ./... | sed "s|^$mod/||" | sort >"$tmp/pkgs"
grep -v '^[[:space:]]*\(#.*\)\{0,1\}$' "$scope" >"$tmp/lines"

fail=0
awk -v scope="$scope" '
	NF < 2 || ($1 != "core" && $1 != "in" && $1 != "out") || ($1 == "out" && NF < 3) {
		print "tcb: " scope ": not core PKG, in PKG [FILE...] or out PKG REASON: " $0; bad = 1
	}
	END { exit bad }' "$tmp/lines" || fail=1
awk '{ print $2 }' "$tmp/lines" | sort >"$tmp/placed"
for p in $(uniq -d "$tmp/placed"); do
	echo "tcb: $p is placed twice in $scope"; fail=1
done
for p in $(sort -u "$tmp/placed" | comm -23 "$tmp/pkgs" -); do
	echo "tcb: $p is placed nowhere; add it to $scope as in or out"; fail=1
done
for p in $(sort -u "$tmp/placed" | comm -13 "$tmp/pkgs" -); do
	echo "tcb: $p in $scope is no package of the module"; fail=1
done

core=0 audit=0
while read -r kind pkg rest; do
	[ "$kind" != out ] || continue
	if [ "$kind" = in ] && [ -n "$rest" ]; then
		files=$(for f in $rest; do echo "$pkg/$f"; done)
	else
		files=$(ls "$pkg"/*.go 2>/dev/null | grep -v '_test\.go$' || true)
	fi
	for f in $files; do
		[ -f "$f" ] || { echo "tcb: $f in $scope is gone; list where it went"; fail=1; }
	done
	n=$(cat $files 2>/dev/null | wc -l)
	audit=$((audit + n))
	[ "$kind" != core ] || core=$((core + n))
done <"$tmp/lines"

echo "TCB: $core lines in the core (budget $budget), $audit in the audit scope ($scope, docs/06-verification.md)"
if [ "$core" -gt "$budget" ]; then
	echo "over budget: the core has grown past what docs/06-verification.md plans for"; fail=1
fi
exit $fail
