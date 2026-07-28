#AD-Detection-Arms-Race

This repository documents adversary tradecraft and the detection engineering that catches it, developed against a purpose-built, fully instrumented Windows domain.

Studying attack or defense in isolation creates blind spots. Traditional writeups teach execution but ignore the telemetry trail. Detection libraries offer static signatures but rarely show what it takes to bypass them.

Every entry here executes an attack against a live logging stack, builds a custom detection from the resulting telemetry, then attacks that detection logic. That second loop is the point: it reveals where signature-based detection fails and which behavioral signals survive an adversary actively trying to avoid them.
