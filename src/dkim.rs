use crate::{finding, parse_tags, tag, Finding, Severity};

/// Decode standard base64, ignoring whitespace. Returns None on invalid characters.
pub fn base64_len(input: &str) -> Option<usize> {
    let mut bits = 0u32;
    let mut count = 0u32;
    let mut bytes = 0usize;
    for c in input.chars().filter(|c| !c.is_whitespace()) {
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            '=' => break,
            _ => return None,
        };
        bits = (bits << 6) | v;
        count += 6;
        if count >= 8 {
            count -= 8;
            bits &= (1 << count) - 1;
            bytes += 1;
        }
    }
    Some(bytes)
}

/// Estimate the strength of an RSA key from the size of its SubjectPublicKeyInfo DER encoding.
pub fn rsa_bits_estimate(der_len: usize) -> u32 {
    match der_len {
        0..=100 => 512,
        101..=200 => 1024,
        201..=400 => 2048,
        401..=600 => 3072,
        _ => 4096,
    }
}

/// Audit one DKIM selector record (`<selector>._domainkey.<domain>`).
pub fn audit(selector: &str, record: &str) -> Vec<Finding> {
    let tags = parse_tags(record);
    let mut out = Vec::new();
    if let Some(v) = tag(&tags, "v") {
        if !v.eq_ignore_ascii_case("DKIM1") {
            out.push(finding(
                Severity::Medium,
                "DKIM_BAD_VERSION",
                format!("selector '{selector}': v= must be DKIM1"),
            ));
        }
    }
    let key_type = tag(&tags, "k").unwrap_or("rsa").to_ascii_lowercase();
    match tag(&tags, "p") {
        None => {
            return vec![finding(
                Severity::High,
                "DKIM_NO_KEY",
                format!("selector '{selector}': p= tag missing"),
            )]
        }
        Some("") => {
            return vec![finding(
                Severity::Info,
                "DKIM_REVOKED",
                format!("selector '{selector}': empty p= means the key is revoked"),
            )]
        }
        Some(p) => match base64_len(p) {
            None => out.push(finding(
                Severity::High,
                "DKIM_BAD_KEY",
                format!("selector '{selector}': public key is not valid base64"),
            )),
            Some(len) if key_type == "rsa" => {
                let bits = rsa_bits_estimate(len);
                if bits <= 512 {
                    out.push(finding(Severity::Critical, "DKIM_KEY_BROKEN", format!("selector '{selector}': RSA key of about {bits} bits can be factored cheaply")));
                } else if bits <= 1024 {
                    out.push(finding(Severity::High, "DKIM_KEY_WEAK", format!("selector '{selector}': RSA key of about {bits} bits; use 2048 (RFC 8301 requires at least 1024 and recommends 2048)")));
                }
            }
            Some(_) => {}
        },
    }
    if key_type != "rsa" && key_type != "ed25519" {
        out.push(finding(
            Severity::Medium,
            "DKIM_UNKNOWN_KEY_TYPE",
            format!("selector '{selector}': unknown key type '{key_type}'"),
        ));
    }
    if tag(&tags, "t").map(|t| t.split(':').any(|f| f.trim().eq_ignore_ascii_case("y")))
        == Some(true)
    {
        out.push(finding(Severity::Medium, "DKIM_TEST_MODE", format!("selector '{selector}': t=y marks the domain as testing; verifiers may treat failures as non-fatal")));
    }
    if let Some(h) = tag(&tags, "h") {
        if h.split(':').any(|a| a.trim().eq_ignore_ascii_case("sha1")) {
            out.push(finding(
                Severity::Medium,
                "DKIM_SHA1",
                format!("selector '{selector}': h= permits sha1, which RFC 8301 forbids"),
            ));
        }
    }
    out
}
