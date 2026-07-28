## Contents

**[Act 1 — AS-REP Roasting](act-01-asrep-roasting/)**
Kerberos pre-authentication disabled on a domain account. Exploitation,
telemetry correlation, detection engineering, and the enumeration blind
spot that no 4768-based rule covers.

## Environment

Single-DC lab domain (`lab.local`) on Windows Server 2022 Core, with
Windows Security and Sysmon telemetry forwarded to Splunk. Attacks run
from Kali on the same segment. All addresses and identifiers belong to
purpose-built lab infrastructure.
