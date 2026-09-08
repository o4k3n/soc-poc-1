#!/usr/bin/env bash
# Fetch the EVTX attack samples the Windows case generators derive from.
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
fetch "Lateral%20Movement/LM_ScheduledTask_ATSVC_target_host.evtx" \
      "LM_ScheduledTask_ATSVC_target_host.evtx"
fetch "Lateral%20Movement/LM_sysmon_remote_task_src_powershell.evtx" \
      "LM_sysmon_remote_task_src_powershell.evtx"
fetch "Credential%20Access/CA_DCSync_4662.evtx" \
      "CA_DCSync_4662.evtx"

echo "samples in $DEST/ (source: sbousseaden/EVTX-ATTACK-SAMPLES, GPL-3.0)"
