//! Per-version Chrome browser fingerprint data and dispatch.
//!
//! Each entry maps a [`ChromeVersion`] variant to its (sec-ch-ua, User-Agent)
//! pair for every supported OS, plus the correct TLS and HTTP/2 preset.

use crate::header::{
    ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, HeaderMap, HeaderName, HeaderValue, USER_AGENT,
};
use crate::{Emulation, http2::Http2Options, tls::TlsOptions};

use super::http2::*;
use super::tls::*;
use super::{BrowserProfile, ChromeVersion, TargetOS};

const ACCEPT_HTML: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9";
const ACCEPT_LANG: &str = "en-US,en;q=0.9";

fn build_headers(
    sec_ch_ua: &'static str,
    user_agent: &'static str,
    os: TargetOS,
    include_priority: bool,
) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("sec-ch-ua", HeaderValue::from_static(sec_ch_ua));
    h.insert(
        "sec-ch-ua-mobile",
        HeaderValue::from_static(if os.is_mobile() { "?1" } else { "?0" }),
    );
    h.insert(
        "sec-ch-ua-platform",
        HeaderValue::from_static(os.platform()),
    );
    h.insert(USER_AGENT, HeaderValue::from_static(user_agent));
    h.insert("sec-fetch-dest", HeaderValue::from_static("document"));
    h.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    h.insert("sec-fetch-site", HeaderValue::from_static("none"));
    h.insert(ACCEPT, HeaderValue::from_static(ACCEPT_HTML));
    h.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br, zstd"),
    );
    h.insert(ACCEPT_LANGUAGE, HeaderValue::from_static(ACCEPT_LANG));

    if include_priority {
        h.insert(
            HeaderName::from_static("priority"),
            HeaderValue::from_static("u=0, i"),
        );
    }

    h
}

fn assemble(
    profile: BrowserProfile,
    tls: TlsOptions,
    h2: Http2Options,
    sec_ch_ua: &'static str,
    user_agent: &'static str,
    priority_header: bool,
) -> Emulation {
    let mut builder = Emulation::builder().tls_options(tls);

    if !profile.no_http2 {
        builder = builder.http2_options(h2);
    }

    if !profile.no_headers {
        let mut headers = build_headers(sec_ch_ua, user_agent, profile.target_os, priority_header);
        if let Some(extra) = profile.custom_headers {
            for (k, v) in extra {
                if let Some(name) = k {
                    headers.insert(name, v);
                }
            }
        }
        builder = builder.headers(headers);
    }

    builder.build()
}

fn ua_for(version: ChromeVersion, os: TargetOS) -> &'static str {
    match (version, os) {
        (ChromeVersion::V100, TargetOS::Windows) => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
        (ChromeVersion::V101, TargetOS::Windows) => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36",
        (ChromeVersion::V104, TargetOS::Windows) => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
        (ChromeVersion::V105, TargetOS::Windows) => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
        (v, TargetOS::MacOS) => match v.major() {
            m => Box::leak(format!("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36", m).into_boxed_str())
        },
        (v, TargetOS::Linux) => match v.major() {
            m => Box::leak(format!("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36", m).into_boxed_str())
        },
        (v, TargetOS::Android) => match v.major() {
            m => Box::leak(format!("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Mobile Safari/537.36", m).into_boxed_str())
        },
        (v, TargetOS::IOS) => match v.major() {
            m => Box::leak(format!("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/{}.0.0.0 Mobile/15E148 Safari/604.1", m).into_boxed_str())
        },
        (v, TargetOS::Windows) => match v.major() {
            m => Box::leak(format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36", m).into_boxed_str())
        },
    }
}

fn sec_ch_ua_for(version: ChromeVersion) -> &'static str {
    match version.major() {
        100..=101 => r#""Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100""#,
        104 => r#""Chromium";v="104", "Google Chrome";v="104", "Not A;Brand";v="99""#,
        105 => r#""Google Chrome";v="105", "Not)A;Brand";v="8", "Chromium";v="105""#,
        106..=116 => r#""Chromium";v="116", "Google Chrome";v="116", "Not;A=Brand";v="99""#,
        117 => r#""Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117""#,
        118..=120 => r#""Chromium";v="120", "Google Chrome";v="120", "Not?A_Brand";v="99""#,
        123 => r#""Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123""#,
        124..=128 => r#""Chromium";v="128", "Google Chrome";v="128", "Not?A_Brand";v="99""#,
        129..=131 => r#""Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24""#,
        132 => r#""Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132""#,
        133 => r#""Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133""#,
        134..=136 => r#""Chromium";v="136", "Not:A-Brand";v="24", "Google Chrome";v="136""#,
        137 => r#""Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24""#,
        _ => r#""Chromium";v="145", "Not=A?Brand";v="24", "Google Chrome";v="145""#,
    }
}

pub fn build_version_emulation(version: ChromeVersion, profile: BrowserProfile) -> Emulation {
    let (tls, h2, priority_header) = match version {
        ChromeVersion::V100 | ChromeVersion::V101 | ChromeVersion::V104 => {
            (tls_gen1(), h2_gen1(), false)
        }
        ChromeVersion::V105 => (tls_gen2(), h2_gen1(), false),
        ChromeVersion::V106
        | ChromeVersion::V107
        | ChromeVersion::V108
        | ChromeVersion::V109
        | ChromeVersion::V110
        | ChromeVersion::V114 => (tls_gen3(), h2_gen2(), false),
        ChromeVersion::V116 => (tls_gen4(), h2_gen2(), false),
        ChromeVersion::V117 => (tls_gen5(), h2_gen3(), false),
        ChromeVersion::V118 | ChromeVersion::V119 => (tls_gen4(), h2_gen3(), false),
        ChromeVersion::V120 | ChromeVersion::V123 => (tls_gen5(), h2_gen3(), false),
        ChromeVersion::V124 | ChromeVersion::V126 | ChromeVersion::V127 | ChromeVersion::V128 => {
            (tls_gen6_kyber(), h2_gen3(), false)
        }
        ChromeVersion::V129 | ChromeVersion::V130 => (tls_gen6_kyber(), h2_gen3(), true),
        ChromeVersion::V131 => (tls_gen7_mlkem(), h2_gen3(), true),
        ChromeVersion::V132
        | ChromeVersion::V133
        | ChromeVersion::V134
        | ChromeVersion::V135
        | ChromeVersion::V136
        | ChromeVersion::V137
        | ChromeVersion::V138
        | ChromeVersion::V139
        | ChromeVersion::V140
        | ChromeVersion::V141
        | ChromeVersion::V142
        | ChromeVersion::V143
        | ChromeVersion::V144
        | ChromeVersion::V145 => (tls_gen8_mlkem_alps(), h2_gen3(), true),
    };

    let sec_ch_ua = sec_ch_ua_for(version);
    let ua = ua_for(version, profile.target_os);
    assemble(profile, tls, h2, sec_ch_ua, ua, priority_header)
}
