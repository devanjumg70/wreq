use http::HeaderMap;

use crate::{Emulation, EmulationFactory};

mod http2;
mod tls;
mod versions;

pub use http2::{h2_gen1, h2_gen2, h2_gen3};
pub use tls::{
    CERT_COMPRESSION, CIPHER_SUITE, CURVES_CLASSIC, CURVES_KYBER, CURVES_MLKEM, ChromeTlsProfile,
    SIG_ALGOS, tls_gen1, tls_gen2, tls_gen3, tls_gen4, tls_gen5, tls_gen6_kyber, tls_gen7_mlkem,
    tls_gen8_mlkem_alps,
};

use versions::build_version_emulation;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum TargetOS {
    #[default]
    Windows,
    MacOS,
    Linux,
    Android,
    IOS,
}

impl TargetOS {
    #[inline]
    pub(crate) const fn platform(self) -> &'static str {
        match self {
            Self::Windows => "\"Windows\"",
            Self::MacOS => "\"macOS\"",
            Self::Linux => "\"Linux\"",
            Self::Android => "\"Android\"",
            Self::IOS => "\"iOS\"",
        }
    }

    #[inline]
    pub(crate) const fn is_mobile(self) -> bool {
        matches!(self, Self::Android | Self::IOS)
    }
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum ChromeVersion {
    V100,
    V101,
    V104,
    V105,
    V106,
    V107,
    V108,
    V109,
    V110,
    V114,
    V116,
    V117,
    V118,
    V119,
    V120,
    V123,
    V124,
    V126,
    V127,
    V128,
    V129,
    V130,
    V131,
    V132,
    V133,
    V134,
    V135,
    V136,
    V137,
    V138,
    V139,
    V140,
    V141,
    V142,
    V143,
    V144,
    #[default]
    V145,
}

impl ChromeVersion {
    #[inline]
    pub const fn major(self) -> u16 {
        match self {
            Self::V100 => 100,
            Self::V101 => 101,
            Self::V104 => 104,
            Self::V105 => 105,
            Self::V106 => 106,
            Self::V107 => 107,
            Self::V108 => 108,
            Self::V109 => 109,
            Self::V110 => 110,
            Self::V114 => 114,
            Self::V116 => 116,
            Self::V117 => 117,
            Self::V118 => 118,
            Self::V119 => 119,
            Self::V120 => 120,
            Self::V123 => 123,
            Self::V124 => 124,
            Self::V126 => 126,
            Self::V127 => 127,
            Self::V128 => 128,
            Self::V129 => 129,
            Self::V130 => 130,
            Self::V131 => 131,
            Self::V132 => 132,
            Self::V133 => 133,
            Self::V134 => 134,
            Self::V135 => 135,
            Self::V136 => 136,
            Self::V137 => 137,
            Self::V138 => 138,
            Self::V139 => 139,
            Self::V140 => 140,
            Self::V141 => 141,
            Self::V142 => 142,
            Self::V143 => 143,
            Self::V144 => 144,
            Self::V145 => 145,
        }
    }
}

impl EmulationFactory for ChromeVersion {
    fn emulation(self) -> Emulation {
        BrowserProfile::builder().version(self).build().emulation()
    }
}

#[derive(Clone, Debug)]
pub struct BrowserProfile {
    pub version: ChromeVersion,
    pub target_os: TargetOS,
    pub no_http2: bool,
    pub no_headers: bool,
    pub custom_headers: Option<HeaderMap>,
}

#[derive(Clone, Debug, Default)]
pub struct BrowserProfileBuilder {
    version: ChromeVersion,
    target_os: TargetOS,
    no_http2: bool,
    no_headers: bool,
    custom_headers: Option<HeaderMap>,
}

impl BrowserProfile {
    #[inline]
    pub fn builder() -> BrowserProfileBuilder {
        BrowserProfileBuilder::default()
    }
}

impl BrowserProfileBuilder {
    pub fn version(mut self, version: ChromeVersion) -> Self {
        self.version = version;
        self
    }

    pub fn target_os(mut self, target_os: TargetOS) -> Self {
        self.target_os = target_os;
        self
    }

    pub fn no_http2(mut self, no_http2: bool) -> Self {
        self.no_http2 = no_http2;
        self
    }

    pub fn no_headers(mut self, no_headers: bool) -> Self {
        self.no_headers = no_headers;
        self
    }

    pub fn custom_headers(mut self, custom_headers: HeaderMap) -> Self {
        self.custom_headers = Some(custom_headers);
        self
    }

    pub fn build(self) -> BrowserProfile {
        BrowserProfile {
            version: self.version,
            target_os: self.target_os,
            no_http2: self.no_http2,
            no_headers: self.no_headers,
            custom_headers: self.custom_headers,
        }
    }
}

impl EmulationFactory for BrowserProfile {
    fn emulation(self) -> Emulation {
        build_version_emulation(self.version, self)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub enum AmongUs {
    #[default]
    Imposter,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AmongUsBuilder {
    profile: AmongUs,
}

impl AmongUs {
    #[inline]
    pub fn builder() -> AmongUsBuilder {
        AmongUsBuilder {
            profile: AmongUs::Imposter,
        }
    }
}

impl AmongUsBuilder {
    #[inline]
    pub fn imposter(mut self) -> Self {
        self.profile = AmongUs::Imposter;
        self
    }

    #[inline]
    pub fn build(self) -> AmongUs {
        self.profile
    }
}

impl EmulationFactory for AmongUs {
    fn emulation(self) -> Emulation {
        match self {
            AmongUs::Imposter => ChromeVersion::V145.emulation(),
        }
    }
}
