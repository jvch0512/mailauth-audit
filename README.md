# mailauth-audit

Rust CLI that audits **SPF, DKIM and DMARC** records **offline** and tells you how easy it is to spoof your domain. No network access and no dependencies: you paste in the TXT records (from `dig`, your DNS panel or a zone export) and get a prioritised list of findings with RFC references. That makes it safe to run in CI against a zone file in Git.

> Built with AI assistance (Claude) as a portfolio project. Review the code before relying on it.

## Usage

```bash
cargo install --path .
dig +short TXT example.com _dmarc.example.com default._domainkey.example.com   # gather records
mailauth-audit records.txt
mailauth-audit --json --fail-on high records.txt     # exit 1 at high or critical findings
```

Input format, one record per line:

```
spf: v=spf1 include:_spf.example.com -all
dmarc: v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s
dkim default: v=DKIM1; k=rsa; p=MIIBIjANBgkq...
```

## What it checks

| Area | Findings |
|------|----------|
| SPF | missing or duplicated record, `+all` / `?all` / `~all` / no `all`, `ptr`, **DNS lookup budget** (RFC 7208 limit of 10, warns near it), very long records |
| DMARC | missing or duplicated record, `p=none` / `quarantine` / invalid, `sp=none` leaving subdomains open, `pct` below 100, missing or malformed `rua`, relaxed alignment (info) |
| DKIM | revoked, missing or malformed key, **RSA key size estimated from the DER length** (512 / 1024 / 2048 bit), `t=y` test mode, `sha1` in `h=`, unknown key type, bad version |

Findings are sorted by severity. Exit code `0` clean, `1` findings at or above `--fail-on`, `2` input or usage error.

## Implementation notes

* Zero dependencies: even the base64 length decoder is hand-written and unit tested
* Tag parsing follows the DMARC rules: names are case-insensitive and the first occurrence of a tag wins
* Lookup counting treats `ip4`, `ip6` and `all` as free, and `include`, `a`, `mx`, `ptr`, `exists`, `redirect` as costly. Nested includes are not resolved offline, so the real count can be higher (the tool says so)
* Clippy clean with `-D warnings`; integration tests exercise the real binary

## Development

```bash
cargo clippy --all-targets -- -D warnings && cargo test
```

MIT licensed.
