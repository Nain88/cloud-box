#!/usr/bin/env bash
# Operator-run installer. No service starts until an explicit systemctl start.
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "Usage: sudo bash install-linux.sh /absolute/project /absolute/enrolled-agent.json" >&2
  exit 2
fi
if [[ $EUID -ne 0 ]]; then echo 'Run explicitly as root to install the system service.' >&2; exit 1; fi
project=$(realpath -- "$1")
configuration=$(realpath -- "$2")
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ $project != /* || $project =~ [[:space:]] || $project == *'&'* || $project == *'|'* ]]; then
  echo 'Use an absolute project path without whitespace, ampersands, or vertical bars for this systemd template.' >&2
  exit 1
fi
if [[ ! -x "$project/.venv/bin/python" ]]; then echo 'Create the Python environment first.' >&2; exit 1; fi
if [[ -e /etc/systemd/system/cbb-agent.service || -e /etc/cbb-agent/agent.json ]]; then
  echo 'An installation already exists. Review it explicitly before replacing its service or credentials.' >&2
  exit 1
fi
"$project/.venv/bin/python" -c 'import json,sys; c=json.load(open(sys.argv[1])); assert c.get("collector_id") and not c["collector_id"].startswith("REPLACE"); assert c.get("token") and c.get("server_signing_key"); assert c.get("data")=="/var/lib/cbb-agent", "Enroll with --config /var/lib/cbb-agent/agent.json so durable sequence history stays in the same directory"' "$configuration"
if ! getent group cbb-agent >/dev/null; then groupadd --system cbb-agent; fi
if ! id cbb-agent >/dev/null 2>&1; then useradd --system --gid cbb-agent --home-dir /var/lib/cbb-agent --shell /usr/sbin/nologin cbb-agent; fi
install -d -o cbb-agent -g cbb-agent -m 0700 /var/lib/cbb-agent
install -d -o root -g cbb-agent -m 0750 /etc/cbb-agent
install -o root -g cbb-agent -m 0640 "$configuration" /etc/cbb-agent/agent.json
sed "s|@PROJECT_DIR@|$project|g" "$script_dir/cbb-agent.service" > /etc/systemd/system/cbb-agent.service
chmod 0644 /etc/systemd/system/cbb-agent.service
systemctl daemon-reload
echo 'Installed; not started. Grant only required watched-file, certificate and journal permissions first.'
echo 'Then run: sudo systemctl enable --now cbb-agent'
echo 'Keep /var/lib/cbb-agent intact: deleting it resets the sequence and loses unsent evidence.'
