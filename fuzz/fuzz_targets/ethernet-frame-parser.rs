#![no_main]

use libfuzzer_sys::fuzz_target;

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::*;

fuzz_target!(|data: &[u8]| {
    let Ok(frame) = EthernetFrame::new_checked(data) else {
        return;
    };

    match frame.ethertype() {
        EthernetProtocol::Arp => {
            let Ok(arp_packet) = ArpPacket::new_checked(frame.payload()) else {
                return;
            };

            let Ok(repr) = ArpRepr::parse(&arp_packet) else {
                return;
            };

            let mut buffer = vec![0; repr.buffer_len()];
            let mut arp_packet = ArpPacket::new_unchecked(&mut buffer[..]);
            repr.emit(&mut arp_packet);
        }
        EthernetProtocol::Ipv4 => {
            let Ok(ipv4_packet) = Ipv4Packet::new_checked(frame.payload()) else {
                return;
            };

            let Ok(repr) = Ipv4Repr::parse(&ipv4_packet, &ChecksumCapabilities::default()) else {
                return;
            };

            let mut buffer = vec![0; repr.buffer_len()];
            let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut buffer[..]);
            repr.emit(&mut ipv4_packet, &ChecksumCapabilities::default());
        }
        EthernetProtocol::Ipv6 => {
            let Ok(ipv6_packet) = Ipv6Packet::new_checked(frame.payload()) else {
                return;
            };

            let Ok(repr) = Ipv6Repr::parse(&ipv6_packet) else {
                return;
            };

            let mut buffer = vec![0; repr.buffer_len()];
            let mut ipv6_packet = Ipv6Packet::new_unchecked(&mut buffer[..]);
            repr.emit(&mut ipv6_packet);
        }
        _ => {}
    }
});
