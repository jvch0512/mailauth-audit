use mailauth_audit::{dkim, dmarc, spf, Finding, Severity};

fn codes(f: &[Finding]) -> Vec<&'static str> {
    f.iter().map(|x| x.code).collect()
}

#[test]
fn spf_missing_multiple_and_policy_strength() {
    assert_eq!(codes(&spf::audit(&[])), ["SPF_MISSING"]);
    assert_eq!(
        codes(&spf::audit(&["v=spf1 -all", "v=spf1 ~all"])),
        ["SPF_MULTIPLE"]
    );
    assert!(spf::audit(&["v=spf1 mx -all"]).is_empty());
    assert_eq!(codes(&spf::audit(&["v=spf1 mx +all"])), ["SPF_PASS_ALL"]);
    assert_eq!(
        spf::audit(&["v=spf1 mx +all"])[0].severity,
        Severity::Critical
    );
    assert_eq!(codes(&spf::audit(&["v=spf1 mx ?all"])), ["SPF_NEUTRAL_ALL"]);
    assert_eq!(codes(&spf::audit(&["v=spf1 mx ~all"])), ["SPF_SOFTFAIL"]);
    assert_eq!(codes(&spf::audit(&["v=spf1 mx"])), ["SPF_NO_ALL"]);
    assert!(
        spf::audit(&["v=spf1 redirect=_spf.example.com"]).is_empty(),
        "redirect replaces all"
    );
    assert!(
        spf::audit(&["v=spf1 mx all"])
            .iter()
            .any(|f| f.code == "SPF_PASS_ALL"),
        "bare 'all' means +all"
    );
}

#[test]
fn spf_ignores_unrelated_txt_records() {
    assert_eq!(
        codes(&spf::audit(&["google-site-verification=abc"])),
        ["SPF_MISSING"]
    );
    assert!(
        spf::audit(&["google-site-verification=abc", "V=SPF1 -all"]).is_empty(),
        "version tag is case-insensitive"
    );
}

#[test]
fn spf_lookup_counting() {
    let ok = "v=spf1 include:a include:b include:c include:d include:e include:f include:g include:h -all";
    assert_eq!(codes(&spf::audit(&[ok])), ["SPF_NEAR_LOOKUP_LIMIT"]);
    let bad = "v=spf1 include:a include:b include:c include:d include:e include:f include:g include:h include:i include:j include:k -all";
    assert!(codes(&spf::audit(&[bad])).contains(&"SPF_TOO_MANY_LOOKUPS"));
    // ip4/ip6/all do not count as DNS lookups
    assert!(
        spf::audit(&["v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 ip4:198.51.100.1 -all"]).is_empty()
    );
    assert!(codes(&spf::audit(&["v=spf1 ptr -all"])).contains(&"SPF_PTR"));
}

#[test]
fn dmarc_policy_levels() {
    assert_eq!(codes(&dmarc::audit(&[])), ["DMARC_MISSING"]);
    let good = "v=DMARC1; p=reject; rua=mailto:r@example.com; adkim=s; aspf=s";
    assert!(dmarc::audit(&[good]).is_empty());
    assert!(codes(&dmarc::audit(&[
        "v=DMARC1; p=none; rua=mailto:r@example.com; adkim=s; aspf=s"
    ]))
    .contains(&"DMARC_MONITOR_ONLY"));
    assert!(codes(&dmarc::audit(&[
        "v=DMARC1; p=quarantine; rua=mailto:r@example.com; adkim=s; aspf=s"
    ]))
    .contains(&"DMARC_QUARANTINE"));
    assert!(
        codes(&dmarc::audit(&["v=DMARC1; rua=mailto:r@example.com"])).contains(&"DMARC_NO_POLICY")
    );
    assert!(codes(&dmarc::audit(&["v=DMARC1; p=banana"])).contains(&"DMARC_BAD_POLICY"));
}

#[test]
fn dmarc_pct_subdomain_and_reporting() {
    let f = dmarc::audit(&["v=DMARC1; p=reject; sp=none; pct=25"]);
    let c = codes(&f);
    assert!(
        c.contains(&"DMARC_WEAK_SUBDOMAIN")
            && c.contains(&"DMARC_PARTIAL")
            && c.contains(&"DMARC_NO_REPORTS")
    );
    assert!(codes(&dmarc::audit(&[
        "v=DMARC1; p=reject; rua=dmarc@example.com"
    ]))
    .contains(&"DMARC_BAD_RUA"));
    assert!(codes(&dmarc::audit(&[
        "v=DMARC1; p=reject; pct=abc; rua=mailto:a@b.c"
    ]))
    .contains(&"DMARC_BAD_PCT"));
    assert_eq!(
        codes(&dmarc::audit(&["v=DMARC1; p=none", "v=DMARC1; p=reject"])),
        ["DMARC_MULTIPLE"]
    );
}

#[test]
fn dmarc_tags_are_case_insensitive_and_first_wins() {
    let f = dmarc::audit(&["v=DMARC1; P=REJECT; p=none; RUA=mailto:a@b.c; ADKIM=s; ASPF=s"]);
    assert!(f.is_empty(), "{f:?}");
}

#[test]
fn base64_length_decoding() {
    assert_eq!(dkim::base64_len("TWFu"), Some(3));
    assert_eq!(dkim::base64_len("TWE="), Some(2));
    assert_eq!(dkim::base64_len("TQ=="), Some(1));
    assert_eq!(dkim::base64_len("TW Fu\n"), Some(3), "whitespace ignored");
    assert_eq!(dkim::base64_len("TW*u"), None);
    assert_eq!(dkim::base64_len(""), Some(0));
}

fn rsa_key_with_der_len(n: usize) -> String {
    // 4 base64 chars encode 3 bytes, so n bytes of 0x00 are 'AAAA' groups
    "A".repeat(n.div_ceil(3) * 4)
}

#[test]
fn dkim_key_strength_by_size() {
    let k1024 = format!("v=DKIM1; k=rsa; p={}", rsa_key_with_der_len(162));
    let k2048 = format!("v=DKIM1; k=rsa; p={}", rsa_key_with_der_len(294));
    let k512 = format!("v=DKIM1; k=rsa; p={}", rsa_key_with_der_len(94));
    assert_eq!(codes(&dkim::audit("s1", &k1024)), ["DKIM_KEY_WEAK"]);
    assert!(dkim::audit("s1", &k2048).is_empty());
    assert_eq!(dkim::audit("s1", &k512)[0].severity, Severity::Critical);
    assert!(dkim::audit(
        "s1",
        "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
    )
    .is_empty());
}

#[test]
fn dkim_states_and_flags() {
    assert_eq!(codes(&dkim::audit("old", "v=DKIM1; p=")), ["DKIM_REVOKED"]);
    assert_eq!(codes(&dkim::audit("x", "v=DKIM1; k=rsa")), ["DKIM_NO_KEY"]);
    assert_eq!(codes(&dkim::audit("x", "v=DKIM1; p=%%%")), ["DKIM_BAD_KEY"]);
    let ok = rsa_key_with_der_len(294);
    assert!(codes(&dkim::audit("t", &format!("v=DKIM1; t=y; p={ok}"))).contains(&"DKIM_TEST_MODE"));
    assert!(codes(&dkim::audit(
        "t",
        &format!("v=DKIM1; h=sha1:sha256; p={ok}")
    ))
    .contains(&"DKIM_SHA1"));
    assert!(codes(&dkim::audit("t", &format!("v=DKIM2; p={ok}"))).contains(&"DKIM_BAD_VERSION"));
    assert!(codes(&dkim::audit("t", &format!("v=DKIM1; k=dsa; p={ok}")))
        .contains(&"DKIM_UNKNOWN_KEY_TYPE"));
}

#[test]
fn severity_helpers() {
    assert!(Severity::Critical.rank() > Severity::High.rank());
    assert_eq!(Severity::parse("medium"), Some(Severity::Medium));
    assert_eq!(Severity::parse("nope"), None);
}
