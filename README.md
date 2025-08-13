# UWF-ZeekData24 Attack Graphs (Private)

## Overview
Pipeline to:
- ingest UWF-ZeekData24 (MITRE ATT&CK–labeled Zeek CSVs),
- merge to a canonical events table,
- identify cross-phase IPs (≥2 malicious tactics),
- build attack graphs + per-IP subgraphs,
- generate MITRE-style narratives.
