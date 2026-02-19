use crate::http2::{Http2Options, PseudoId, PseudoOrder};

pub fn h2_gen1() -> Http2Options {
    Http2Options::builder()
        .initial_stream_id(3)
        .initial_window_size(16_777_216)
        .initial_connection_window_size(16_711_681 + 65_535)
        .headers_pseudo_order(
            PseudoOrder::builder()
                .extend([
                    PseudoId::Method,
                    PseudoId::Path,
                    PseudoId::Authority,
                    PseudoId::Scheme,
                ])
                .build(),
        )
        .build()
}

#[inline]
pub fn h2_gen2() -> Http2Options {
    h2_gen1()
}

#[inline]
pub fn h2_gen3() -> Http2Options {
    h2_gen1()
}
