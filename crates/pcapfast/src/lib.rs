//! pcapfast: zero-copy, multithreaded pcap / pcapng parser with flow
//! extraction.
//!
//! The capture is mmapped read-only (it is *input*; database files are never
//! mmapped anywhere in LumenDB), cut into record-aligned chunks and decoded on
//! scoped threads. Packets are never copied: link / IP / L4 headers are read
//! in place from the mapping, and each thread aggregates into its own
//! [`FlowTable`] and timeline which are merged at the end.

pub mod error;
pub mod flow;
pub mod packet;
pub mod pcap;
pub mod pcapng;
pub mod reader;
pub mod synth;

pub use error::{Error, Result};
pub use flow::{FlowKey, FlowStats, FlowTable};
pub use reader::{parse_bytes, parse_file, parse_reader, parse_reader_parallel, Format, ParseOptions, ParseStats};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reexports_are_usable() {
        let mut v = Vec::new();
        let o = synth::SynthOptions {
            packets: 10,
            ..Default::default()
        };
        synth::generate(&o, &mut v).unwrap();
        let s = parse_bytes(&v, &ParseOptions::default()).unwrap();
        assert_eq!(s.packets, 10);
        let r: Result<FlowTable> = Ok(s.flows);
        assert!(r.is_ok());
    }
}
