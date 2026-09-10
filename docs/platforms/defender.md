# Microsoft Defender adoption and deployment

Defender detections in this repo use:

- **Advanced Hunting KQL** (Microsoft Defender for Endpoint / Defender XDR)
- Optional mapping to **Sentinel** analytics rules (future)

Detections live under `detections/defender/` with unified metadata and a `query.defender` KQL string.

## Portability

- No tenant-specific constants in detections.
- Prefer stable tables and schema: `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceLogonEvents`, `DeviceRegistryEvents`, etc.

See `pipelines/deploy/README.md` for deployment hooks and placeholders.
