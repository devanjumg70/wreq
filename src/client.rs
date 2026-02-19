#[allow(missing_docs)]
mod amongus;
mod body;
mod conn;
mod core;
mod emulation;
mod http;
mod request;
mod response;

pub mod layer;
#[cfg(feature = "multipart")]
pub mod multipart;
#[cfg(feature = "ws")]
pub mod ws;

pub use self::{
    amongus::{
        AmongUs, AmongUsBuilder, BrowserProfile, BrowserProfileBuilder, CERT_COMPRESSION,
        CIPHER_SUITE, CURVES_CLASSIC, CURVES_KYBER, CURVES_MLKEM, ChromeTlsProfile, ChromeVersion,
        SIG_ALGOS, TargetOS, h2_gen1, h2_gen2, h2_gen3, tls_gen1, tls_gen2, tls_gen3, tls_gen4,
        tls_gen5, tls_gen6_kyber, tls_gen7_mlkem, tls_gen8_mlkem_alps,
    },
    body::Body,
    core::{http1, http2, upgrade::Upgraded},
    emulation::{Emulation, EmulationBuilder, EmulationFactory},
    http::{Client, ClientBuilder},
    request::{Request, RequestBuilder},
    response::Response,
};
pub(crate) use self::{
    conn::{Connected, Connection},
    core::Error as CoreError,
    http::{ConnectIdentity, ConnectRequest, client::error::Error},
};
