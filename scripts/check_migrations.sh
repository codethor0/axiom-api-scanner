#!/usr/bin/env bash
# Verify migrations/ uses golang-migrate-style paired .up.sql / .down.sql files.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
mig_dir="${repo_root}/migrations"
if [[ ! -d "${mig_dir}" ]]; then
  echo "check_migrations: missing ${mig_dir}" >&2
  exit 1
fi

fail=0
name_re='^[0-9]{6}_[a-z0-9_]+\.(up|down)\.sql$'

shopt -s nullglob
for f in "${mig_dir}"/*.sql; do
  base="$(basename "$f")"
  if [[ ! "${base}" =~ ${name_re} ]]; then
    echo "check_migrations: unexpected name (want NNNNNN_name.up.sql / .down.sql): ${base}" >&2
    fail=1
    continue
  fi
done

for up in "${mig_dir}"/*.up.sql; do
  [[ -e "${up}" ]] || break
  stem="${up%.up.sql}"
  down="${stem}.down.sql"
  if [[ ! -f "${down}" ]]; then
    echo "check_migrations: missing ${down} for ${up}" >&2
    fail=1
  fi
done

for down in "${mig_dir}"/*.down.sql; do
  [[ -e "${down}" ]] || break
  stem="${down%.down.sql}"
  up="${stem}.up.sql"
  if [[ ! -f "${up}" ]]; then
    echo "check_migrations: missing ${up} for ${down}" >&2
    fail=1
  fi
done

if [[ "${fail}" -ne 0 ]]; then
  exit 1
fi

echo "check_migrations: OK (${mig_dir})"
