---
id: RB-NET-001
title: Interface flapping on a router or switch
failure_types: [interface_flap]
---
## Confirm
- Syslog: `%LINK-3-UPDOWN` / `%LINEPROTO-5-UPDOWN` for the same interface repeatedly.
- `ifOperStatus` and `ifInErrors` / CRC counters from the SNMP exporter.
## Likely causes
1. Faulty optic/cable or patch panel; duplex mismatch.
2. Upstream carrier instability on WAN links (common on long-haul links during storms/power events).
## Safe actions
1. Check error counters; if CRC errors rise, schedule an optic/cable swap.
2. Engage the carrier with timestamps; fail traffic to the secondary link if available.
