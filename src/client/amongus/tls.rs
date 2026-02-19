//! Chrome TLS configuration constants and builder.

use crate::tls::{
    AlpnProtocol, AlpsProtocol, CertificateCompressionAlgorithm, TlsOptions, TlsVersion,
};

macro_rules! join {
    ($sep:expr, $first:expr $(, $rest:expr)*) => {
        concat!($first $(, $sep, $rest)*)
    };
}

pub const CURVES_CLASSIC: &str = join!(":", "X25519", "P-256", "P-384");

pub const CURVES_KYBER: &str = join!(":", "X25519Kyber768Draft00", "X25519", "P-256", "P-384");

pub const CURVES_MLKEM: &str = join!(":", "X25519MLKEM768", "X25519", "P-256", "P-384");

pub const CIPHER_SUITE: &str = join!(
    ":",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA"
);

pub const SIG_ALGOS: &str = join!(
    ":",
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
);

pub const CERT_COMPRESSION: &[CertificateCompressionAlgorithm] =
    &[CertificateCompressionAlgorithm::BROTLI];

#[derive(Debug, Clone)]
pub struct ChromeTlsProfile {
    pub curves: &'static str,
    pub sig_algos: &'static str,
    pub cipher_suite: &'static str,
    pub alps_proto: AlpsProtocol,
    pub alps_new_codepoint: bool,
    pub ech_grease: bool,
    pub permute_extensions: bool,
    pub pre_shared_key: bool,
}

#[derive(Debug, Clone)]
pub struct ChromeTlsProfileBuilder {
    curves: &'static str,
    sig_algos: &'static str,
    cipher_suite: &'static str,
    alps_proto: AlpsProtocol,
    alps_new_codepoint: bool,
    ech_grease: bool,
    permute_extensions: bool,
    pre_shared_key: bool,
}

impl Default for ChromeTlsProfileBuilder {
    fn default() -> Self {
        Self {
            curves: CURVES_CLASSIC,
            sig_algos: SIG_ALGOS,
            cipher_suite: CIPHER_SUITE,
            alps_proto: AlpsProtocol::HTTP2,
            alps_new_codepoint: false,
            ech_grease: false,
            permute_extensions: false,
            pre_shared_key: false,
        }
    }
}

impl ChromeTlsProfile {
    pub fn builder() -> ChromeTlsProfileBuilder {
        ChromeTlsProfileBuilder::default()
    }
}

impl ChromeTlsProfileBuilder {
    pub fn curves(mut self, curves: &'static str) -> Self {
        self.curves = curves;
        self
    }

    pub fn sig_algos(mut self, sig_algos: &'static str) -> Self {
        self.sig_algos = sig_algos;
        self
    }

    pub fn cipher_suite(mut self, cipher_suite: &'static str) -> Self {
        self.cipher_suite = cipher_suite;
        self
    }

    pub fn alps_proto(mut self, alps_proto: AlpsProtocol) -> Self {
        self.alps_proto = alps_proto;
        self
    }

    pub fn alps_new_codepoint(mut self, alps_new_codepoint: bool) -> Self {
        self.alps_new_codepoint = alps_new_codepoint;
        self
    }

    pub fn ech_grease(mut self, ech_grease: bool) -> Self {
        self.ech_grease = ech_grease;
        self
    }

    pub fn permute_extensions(mut self, permute_extensions: bool) -> Self {
        self.permute_extensions = permute_extensions;
        self
    }

    pub fn pre_shared_key(mut self, pre_shared_key: bool) -> Self {
        self.pre_shared_key = pre_shared_key;
        self
    }

    pub fn build(self) -> ChromeTlsProfile {
        ChromeTlsProfile {
            curves: self.curves,
            sig_algos: self.sig_algos,
            cipher_suite: self.cipher_suite,
            alps_proto: self.alps_proto,
            alps_new_codepoint: self.alps_new_codepoint,
            ech_grease: self.ech_grease,
            permute_extensions: self.permute_extensions,
            pre_shared_key: self.pre_shared_key,
        }
    }
}

impl From<ChromeTlsProfile> for TlsOptions {
    fn from(p: ChromeTlsProfile) -> Self {
        TlsOptions::builder()
            .grease_enabled(true)
            .enable_ocsp_stapling(true)
            .enable_signed_cert_timestamps(true)
            .curves_list(p.curves)
            .sigalgs_list(p.sig_algos)
            .cipher_list(p.cipher_suite)
            .min_tls_version(TlsVersion::TLS_1_2)
            .max_tls_version(TlsVersion::TLS_1_3)
            .permute_extensions(p.permute_extensions)
            .pre_shared_key(p.pre_shared_key)
            .enable_ech_grease(p.ech_grease)
            .alps_protocols([p.alps_proto])
            .alps_use_new_codepoint(p.alps_new_codepoint)
            .aes_hw_override(true)
            .certificate_compression_algorithms(CERT_COMPRESSION)
            .alpn_protocols([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
            .build()
    }
}

#[inline]
pub fn tls_gen1() -> TlsOptions {
    ChromeTlsProfile::builder().build().into()
}

#[inline]
pub fn tls_gen2() -> TlsOptions {
    ChromeTlsProfile::builder().ech_grease(true).build().into()
}

#[inline]
pub fn tls_gen3() -> TlsOptions {
    ChromeTlsProfile::builder()
        .permute_extensions(true)
        .build()
        .into()
}

#[inline]
pub fn tls_gen4() -> TlsOptions {
    ChromeTlsProfile::builder()
        .permute_extensions(true)
        .ech_grease(true)
        .build()
        .into()
}

#[inline]
pub fn tls_gen5() -> TlsOptions {
    ChromeTlsProfile::builder()
        .permute_extensions(true)
        .ech_grease(true)
        .pre_shared_key(true)
        .build()
        .into()
}

#[inline]
pub fn tls_gen6_kyber() -> TlsOptions {
    ChromeTlsProfile::builder()
        .permute_extensions(true)
        .ech_grease(true)
        .pre_shared_key(true)
        .curves(CURVES_KYBER)
        .build()
        .into()
}

#[inline]
pub fn tls_gen7_mlkem() -> TlsOptions {
    ChromeTlsProfile::builder()
        .permute_extensions(true)
        .ech_grease(true)
        .pre_shared_key(true)
        .curves(CURVES_MLKEM)
        .build()
        .into()
}

#[inline]
pub fn tls_gen8_mlkem_alps() -> TlsOptions {
    ChromeTlsProfile::builder()
        .permute_extensions(true)
        .ech_grease(true)
        .pre_shared_key(true)
        .curves(CURVES_MLKEM)
        .alps_new_codepoint(true)
        .build()
        .into()
}
