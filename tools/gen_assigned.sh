#!/usr/bin/env bash
# Regenerate Bluetooth assigned-number tables from the installed Wireshark.
# (Bluetooth SIG company IDs, 16-bit UUIDs, appearance categories.)
set -euo pipefail
out="$(dirname "$0")/../fang/data"
mkdir -p "$out"
tshark -G values 2>/dev/null | awk -F'\t' -v out="$out" '
  $1=="V" && $2=="btcommon.eir_ad.entry.company_id" {print $3"\t"$4 > (out"/company_ids.tsv")}
  $1=="V" && $2=="btcommon.eir_ad.entry.uuid_16"   {print $3"\t"$4 > (out"/uuid16.tsv")}
  $1=="V" && $2=="btatt.appearance.category"       {print $3"\t"$4 > (out"/appearance.tsv")}
'
wc -l "$out"/*.tsv
