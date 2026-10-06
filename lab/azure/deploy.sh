#!/usr/bin/env bash
# Create one Windows Server 2022 VM in Azure, turn on process-creation
# logging and Sysmon Event ID 1, and install Splunk if you pass an MSI URL.
#
# This bills your Azure subscription. It does not open RDP or Splunk Web
# to the internet. Auto-shutdown deallocates the VM at SHUTDOWN_TIME.
#
#   export MYIP="$(curl -4 -s https://ifconfig.me)"
#   export CONFIRM=yes
#   export SPLUNK_MSI_URL="https://download.splunk.com/products/splunk/releases/.../splunk-....msi"
#   lab/azure/deploy.sh
#
# Re-running is safe. An existing VM is kept and bootstrap runs again.
# Passwords are printed once. They are not written into the repo.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RG="${RG:-dac-lab}"
LOC="${LOC:-centralindia}"
VM="${VM:-dac-win-lab}"
SIZE="${SIZE:-Standard_B2ms}"
ADMIN_USER="${ADMIN_USER:-labadmin}"
SHUTDOWN_TIME="${SHUTDOWN_TIME:-1900}"
NSG="${VM}-nsg"

if [[ "${CONFIRM:-}" != "yes" ]]; then
  echo "Refusing to create a paid VM. Set CONFIRM=yes after you have read the cost note in the header." >&2
  exit 1
fi
if [[ ! "${MYIP:-}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Set MYIP to your own public IPv4 address. RDP and Splunk Web will allow only that address." >&2
  exit 1
fi
if ! command -v az >/dev/null 2>&1; then
  echo "Azure CLI is not installed. https://learn.microsoft.com/cli/azure/install-azure-cli" >&2
  exit 1
fi
if ! az account show >/dev/null 2>&1; then
  echo "No Azure login in this shell. Run: az login" >&2
  exit 1
fi

gen_pw() {
  python3 -c 'import secrets,string; alphabet=string.ascii_letters+string.digits; print("".join(secrets.choice(alphabet) for _ in range(24))+"aA1!")'
}

echo "Subscription: $(az account show --query name -o tsv)"
echo "Will use resource group ${RG} in ${LOC}, size ${SIZE}."
echo "Left on all month this is on the order of a hundred USD. Auto-shutdown is ${SHUTDOWN_TIME} India Standard Time, which deallocates the VM."
echo "Splunk Free cannot alert. Install the 60-day trial MSI. Without SPLUNK_MSI_URL the VM still gets Windows auditing and Sysmon."

az group create --name "$RG" --location "$LOC" --output none
if ! az network nsg show --resource-group "$RG" --name "$NSG" --output none 2>/dev/null; then
  az network nsg create --resource-group "$RG" --name "$NSG" --output none
fi
upsert_rule() {
  local name="$1" priority="$2" port="$3"
  if az network nsg rule show --resource-group "$RG" --nsg-name "$NSG" --name "$name" --output none 2>/dev/null; then
    az network nsg rule update --resource-group "$RG" --nsg-name "$NSG" --name "$name" \
      --source-address-prefixes "${MYIP}/32" --output none
  else
    az network nsg rule create --resource-group "$RG" --nsg-name "$NSG" \
      --name "$name" --priority "$priority" --direction Inbound --access Allow --protocol Tcp \
      --source-address-prefixes "${MYIP}/32" --destination-address-prefixes '*' \
      --destination-port-ranges "$port" --output none
  fi
}
upsert_rule AllowRdp 1000 3389
upsert_rule AllowSplunkWeb 1010 8000

ADMIN_PW=""
if az vm show --resource-group "$RG" --name "$VM" >/dev/null 2>&1; then
  echo "VM ${VM} already exists. Not creating another."
else
  ADMIN_PW="$(gen_pw)"
  az vm create \
    --resource-group "$RG" \
    --name "$VM" \
    --image Win2022Datacenter \
    --size "$SIZE" \
    --admin-username "$ADMIN_USER" \
    --admin-password "$ADMIN_PW" \
    --nsg "$NSG" \
    --nsg-rule NONE \
    --public-ip-sku Standard \
    --os-disk-size-gb 128 \
    --storage-sku StandardSSD_LRS \
    --output none
fi

if ! az vm auto-shutdown --resource-group "$RG" --name "$VM" --time "$SHUTDOWN_TIME" --timezone "India Standard Time" --output none; then
  echo "Auto-shutdown was not set. Deallocate the VM yourself when you stop, or it keeps billing." >&2
fi

SPLUNK_PW="$(gen_pw)"
LAUNCHER="$(mktemp)"
python3 - "$ROOT" "$SPLUNK_PW" "${SPLUNK_MSI_URL:-}" "$LAUNCHER" <<'PY'
import base64, pathlib, sys
root, pw, url, out = sys.argv[1:]
files = {
    r"C:\lab\bootstrap.ps1": "lab/windows/bootstrap.ps1",
    r"C:\lab\review-runner.ps1": "lab/windows/review-runner.ps1",
    r"C:\lab\sysmon-process-create.xml": "lab/windows/sysmon-process-create.xml",
    r"C:\lab\splunk\inputs.conf": "lab/splunk/inputs.conf",
    r"C:\lab\splunk\props.conf": "lab/splunk/props.conf",
    r"C:\lab\splunk\transforms.conf": "lab/splunk/transforms.conf",
}
lines = [
    '$ErrorActionPreference = "Stop"',
    '$map = @{',
]
for dest, rel in files.items():
    blob = base64.b64encode((pathlib.Path(root) / rel).read_bytes()).decode()
    lines.append(f"  '{dest}' = '{blob}'")
lines += [
    '}',
    'foreach ($dest in $map.Keys) {',
    '  New-Item -ItemType Directory -Force -Path (Split-Path $dest -Parent) | Out-Null',
    '  [IO.File]::WriteAllBytes($dest, [Convert]::FromBase64String($map[$dest]))',
    '}',
    f"& 'C:\\lab\\bootstrap.ps1' -SplunkPassword '{pw}' -SplunkMsiUrl '{url}'",
]
pathlib.Path(out).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

echo "Running bootstrap on the VM. The Splunk MSI download can take several minutes."
az vm run-command invoke \
  --resource-group "$RG" \
  --name "$VM" \
  --command-id RunPowerShellScript \
  --scripts @"$LAUNCHER" \
  --output jsonc
rm -f "$LAUNCHER"

IP="$(az vm show --resource-group "$RG" --name "$VM" --show-details --query publicIps --output tsv)"
echo
echo "Lab VM public IP: ${IP}"
echo "RDP: ${ADMIN_USER}@${IP}"
if [[ -n "$ADMIN_PW" ]]; then
  echo "Windows admin password (shown once): ${ADMIN_PW}"
else
  echo "Windows admin password: unchanged from the first deploy."
fi
if [[ -n "${SPLUNK_MSI_URL:-}" ]]; then
  echo "Splunk Web: https://${IP}:8000  user admin"
  echo "Splunk admin password (shown once; ignored if Splunk was already installed): ${SPLUNK_PW}"
else
  echo "Splunk was not installed. Set SPLUNK_MSI_URL to the trial MSI and re-run."
fi
echo "Review file on the VM: C:\\lab\\reviews\\latest.json"
echo "Application log source dac-lab is the human-review alert."
echo "Deallocate when you stop early: az vm deallocate --resource-group ${RG} --name ${VM}"
