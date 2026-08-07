# Act 2 — Target Configuration

## Primary target

| Account | Property | Value |
|---|---|---|
| `svc-sql` | SPN | `MSSQLSvc/dc01.lab.local:1433` |
| `svc-sql` | LastLogon | `<never>` |
| `svc-sql` | PasswordLastSet | 2026-08-05 22:34 |

## Seeded mid-Act (phase boundary, 2026-08-07 04:56)

| Account | SPN |
|---|---|
| `svc-web` | `HTTP/svc-web.lab.local` |
| `svc-backup` | `HTTP/svc-backup.lab.local` |
| `svc-report` | `HTTP/svc-report.lab.local` |

Added to make volume-based detection testable. All enabled and SPN-registered;
`krbtgt` also carries an SPN but is disabled and does not appear in roast results.

## Encryption attribute (Run 2)

`msDS-SupportedEncryptionTypes` set to `8` (AES128) on `svc-sql`, then cleared
before Run 3. Bit values: 4 = RC4, 8 = AES128, 16 = AES256, 24 = both AES.
