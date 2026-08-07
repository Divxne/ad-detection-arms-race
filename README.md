# AD Detection Arms Race

This repository documents adversary tradecraft and the detection engineering that catches it, developed against a purpose-built, fully instrumented Windows domain.

Studying attack or defense in isolation creates blind spots. Traditional writeups teach execution but ignore the telemetry trail. Detection libraries offer static signatures but rarely show what it takes to bypass them.

Every entry here executes an attack against a live logging stack, builds a custom detection from the resulting telemetry, then attacks that detection logic. That second loop is the point: it reveals where signature-based detection fails and which behavioral signals survive an adversary actively trying to avoid them.

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


**[Act 2 — Kerberoasting](act-02-kerberoasting/)**
Service ticket extraction against an SPN-registered account. Three
detections at three durability tiers, each attacked in turn — including
the hardening change that silences the artifact rule while making the
crack 284× slower.
