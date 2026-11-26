#!/usr/bin/env bash
# Proves every crate with SPARK code (silver: no run-time errors), or only the crates named. Fails on any unproved
# check. --list prints the crates as a JSON array (CI proves each in its own job). Needs gnatprove on the PATH
# (alr install gnatprove). Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")/.."

crates=(sparrow_core sparrow_io sparrow_crypto sparrow_json sparrow_jwt sparrow_postgres sparrow_http sparrow_valkey
        sparrow_client)

if [ "${1:-}" = "--list" ]; then
  printf '%s\n' "${crates[@]}" | sed 's/.*/"&"/' | paste -sd, | sed 's/.*/[&]/'
  exit 0
fi

chosen=("$@")
[ ${#chosen[@]} -eq 0 ] && chosen=("${crates[@]}")
for crate in "${chosen[@]}"; do
  case " ${crates[*]} " in
    *" $crate "*) ;;
    *) echo "prove.sh: $crate is not a proved crate (${crates[*]})" >&2; exit 2 ;;
  esac
done

for crate in "${chosen[@]}"; do
  echo "== $crate"
  # Alire writes config/ (which the project file imports) when it builds; generating it is enough here.
  (cd "$crate" && alr -n build --stop-after=generation >/dev/null \
     && alr -n exec -- gnatprove -P "$crate.gpr" --level=4 --prover=cvc5,z3 --steps=200000 --timeout=300 -j0 \
          --mode=silver --checks-as-errors=on --warnings=error --quiet)
done
