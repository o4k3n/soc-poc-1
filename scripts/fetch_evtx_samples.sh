#!/usr/bin/env bash
# Fetch the two EVTX attack samples the wmi-lsass generator derives from.
#
# They come from sbousseaden/EVTX-ATTACK-SAMPLES (GPL-3.0). They are NOT committed:
# cases/ is gitignored, and the generator re-seeds every identifier so the built case
# carries none of the samples' names. Run this once before make case-wmi-lsass.
set -euo pipefail

DEST="${1:-cases/_evtx}"
BASE="https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master"
mkdir -p "$DEST"

fetch() {
    local path="$1" name="$2"
    if [ -s "$DEST/$name" ]; then
        echo "  have $name"
    else
        echo "  fetching $name"
        curl -sSL -o "$DEST/$name" "$BASE/$path"
    fi
}

fetch "Lateral%20Movement/LM_WMI_4624_4688_TargetHost.evtx" \
      "LM_WMI_4624_4688_TargetHost.evtx"
fetch "Credential%20Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx" \
      "sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx"

echo "samples in $DEST/ (source: sbousseaden/EVTX-ATTACK-SAMPLES, GPL-3.0)"
