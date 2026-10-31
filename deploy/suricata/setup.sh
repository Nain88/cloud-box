#!/usr/bin/env bash
set -euo pipefail
project=$(realpath "$1")
test -f "$project/deploy/suricata/run_sensor.py"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y suricata suricata-update python3-yaml curl
# Do not run the distribution's default capture service on an unknown interface.
systemctl stop suricata 2>/dev/null || true
systemctl disable suricata 2>/dev/null || true
mkdir -p "$project/sensor-data"
# Fetch the public Emerging Threats Open feed with the installed official tool.
# A download failure is a setup failure, never a claim of threat coverage.
suricata-update --no-reload
test -s /var/lib/suricata/rules/suricata.rules
python3 - "$project" <<'PY'
from pathlib import Path
import sys,yaml
root=Path(sys.argv[1])
config=yaml.safe_load(Path('/etc/suricata/suricata.yaml').read_text())
config['stats']={'enabled':True,'interval':8}
config['default-rule-path']='/var/lib/suricata/rules'
config['rule-files']=['suricata.rules']
config['outputs']=[{'eve-log':{'enabled':True,'filetype':'regular','filename':'eve.json','types':['alert','flow','dns','http','tls',{'stats':{'totals':True,'threads':False}}]}}]
target=root/'sensor-data/suricata.yaml'
target.write_text('%YAML 1.1\n---\n'+yaml.safe_dump(config,sort_keys=False))
PY
suricata -T -c "$project/sensor-data/suricata.yaml" -s "$project/rules/cbb-demo.rules" -l "$project/sensor-data"
suricata -V
printf 'Setup complete. ET Open plus the local benign marker rule loaded. Coverage depends on feed freshness, traffic visibility and encryption.\n'
