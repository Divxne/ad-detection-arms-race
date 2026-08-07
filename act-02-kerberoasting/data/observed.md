# Act 2 — Observed Results (primary run)

**Run timestamp:** 2026-08-06 02:41:33
**Attack:** impacket-GetUserSPNs, authenticated as jdoe, requesting a
service ticket for svc-sql (SPN: MSSQLSvc/dc01.lab.local:1433)
**Source:** Kali, 10.168.168.58
**Target DC:** DC01, 10.168.168.250 (lab.local, Server 2022 Core)

## Events generated

| Time | EventCode | Account_Name | Service_Name | Client_Address | Ticket_Encryption_Type |
|---|---|---|---|---|---|
| 02:41:33.816 | 4624 | jdoe | — | — | — |
| 02:41:33.844 | 4768 | jdoe | krbtgt | ::ffff:10.168.168.58 | 0x17 |
| 02:41:33.869 | 4769 | jdoe@LAB.LOCAL | svc-sql | ::ffff:10.168.168.58 | 0x17 |

Total elapsed across all three events: 53 ms.

No 4770, 4771, 4772, or 4773 events were generated.

## Counts

| Metric | Value |
|---|---|
| Service tickets requested | 1 |
| 4624 events generated | 1 |
| 4768 events generated | 1 |
| 4769 events generated | 1 |
| Total attack-attributable events | 3 |
| Baseline 4769 volume (prior 24h) | 29 |
| Baseline encryption types observed | 0x12 (AES256) exclusively |
| Total events in surrounding 5-min window | 25 |
| Total events in surrounding 30-min window | 96 |

## Hash artifact

Returned hash prefix: `$krb5tgs$23$*svc-sql$LAB.LOCAL$lab.local/svc-sql*$`

Etype 23 (decimal) corresponds to 0x17, RC4-HMAC — consistent with the
Ticket_Encryption_Type field recorded on both the 4768 and 4769 events.

## Field observations

- `Client_Address` recorded the true source (Kali) in IPv4-mapped IPv6
  format: `::ffff:10.168.168.58`
- `Account_Name` formatting differs between event types: `jdoe` on the
  4768, `jdoe@LAB.LOCAL` on the 4769
- `Service_Name` on the 4769 names the targeted account (`svc-sql`),
  not the SPN string
- The 4768 (TGT request) also returned encryption type 0x17
- SPN enumeration (LDAP) generated no events in any monitored channel
- Account `svc-sql` showed `LastLogon: <never>` prior to the attack

## Environment notes

- Splunk indexing lag of approximately 1–2 minutes observed between
  event generation and searchability
- DESKTOP-SOTPVJH has no Sysmon installed and no forwarder configured;
  client-side telemetry is out of scope for this Act
- Baseline 4624 volume is dominated by DC01$ service logons at 60-second
  intervals (Splunk forwarder activity)
