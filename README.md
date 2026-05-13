# sslper

Single-file Python3 script to validate two common Nessus SSL findings:

- **Plugin 20007** — SSL Version 2 and 3 Protocol Detection
- **Plugin 26928** — SSL Weak Cipher Suites Supported

Wraps `sslscan`. No `pip`, no virtualenv, no dependencies beyond the Python 3 stdlib and `sslscan` itself.

## Requirements

- Python 3.8+
- `sslscan` on `PATH`

## Install

```sh
chmod +x sslper.py
```

## Usage

Run **one** check per invocation (mutually exclusive flags):

```sh
# SSLv2/SSLv3 protocol detection (Nessus 20007)
./sslper.py --sslv2v3 host1:443 host2:8443

# Weak cipher suites supported (Nessus 26928)
./sslper.py --weak-ciphers -f targets.txt

# Mix file + positional args
./sslper.py --sslv2v3 -f targets.txt extra.example.com:443
```

### Options

| Flag | Description |
| --- | --- |
| `--sslv2v3` | Check for SSLv2/SSLv3 protocol support (Nessus 20007) |
| `--weak-ciphers` | Check for weak cipher suites (Nessus 26928) |
| `-f FILE` | File of `host:port` targets, one per line. `#` comments allowed. |
| `--timeout N` | Per-host `sslscan` timeout in seconds (default 30) |
| `--workers N` | Concurrent scans (default 5) |
| `--no-color` | Disable ANSI colors (also respects `NO_COLOR` env var; auto-disabled when stdout is not a TTY) |

### Targets file

```
# web servers
example.com:443
example.com:8443
host.example.org:443
```

## Output

Per-host detail with evidence followed by a summary table:

```
[*] example.com:443
    SSLv3     enabled
    [VULNERABLE] SSL Version 2 and 3 Protocol Detection

[*] example.com:8443
    [NOT VULNERABLE] SSL Version 2 and 3 Protocol Detection

=== Summary: SSL Version 2 and 3 Protocol Detection ===
TARGET              STATUS           EVIDENCE
------------------  ---------------  --------
example.com:443     VULNERABLE       SSLv3 enabled
example.com:8443    NOT VULNERABLE   —
```

`[VULNERABLE]` is red, `[NOT VULNERABLE]` green, `[ERROR]` yellow — designed to crop cleanly into a pentest report.

## Detection logic

### `--sslv2v3`

Parses the `SSL/TLS Protocols:` section of `sslscan` output. A host is vulnerable if `SSLv2` or `SSLv3` shows `enabled`.

### `--weak-ciphers`

Parses the `Supported Server Cipher(s):` section. A cipher is flagged weak if **any** of:

- Key size `< 128` bits (catches EXPORT 40/56-bit, single-DES 56-bit)
- Cipher name matches `NULL`, `anon`, `ADH-`, `AECDH-`, `EXP`/`EXPORT`, `DES-` (excluding `3DES`/`DES-CBC3`), `RC2-`, `RC4`, `IDEA-`, or ends in `-MD5`

This matches Nessus 26928's "Low Strength" definition. **SWEET32/3DES is intentionally not flagged here** — that belongs to plugin 42873 ("SSL Medium Strength Cipher Suites Supported"). Keep validation aligned with the specific finding.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No vulnerable hosts |
| `1` | At least one vulnerable host |
| `2` | Usage error or `sslscan` missing |
| `130` | Interrupted (Ctrl-C) |

Useful for piping into other tooling or CI.

## Authorized use only

This is a validation tool intended for authorized penetration testing engagements. Only scan systems you have written permission to test.

---

Built with [Claude Code](https://claude.com/claude-code) (Opus 4.7).

