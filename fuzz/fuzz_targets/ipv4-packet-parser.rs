#![no_main]

use libfuzzer_sys::fuzz_target;

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::*;

fuzz_target!(|data: &[u8]| {
    let Ok(packet) = Ipv4Packet::new_checked(data) else {
        return;
    };

    let payload = packet.payload();

    match packet.next_header() {
        IpProtocol::Icmp => {
            let Ok(packet) = Icmpv4Packet::new_checked(payload) else {
                return;
            };

            let Ok(repr) = Icmpv4Repr::parse(&packet, &ChecksumCapabilities::default()) else {
                return;
            };

            let mut buffer = vec![0; repr.buffer_len()];
            let mut packet = Icmpv4Packet::new_unchecked(&mut buffer[..]);
            repr.emit(&mut packet, &ChecksumCapabilities::default());
        }
        IpProtocol::Igmp => {
            let Ok(packet) = IgmpPacket::new_checked(payload) else {
                return;
            };

            let Ok(repr) = IgmpRepr::parse(&packet) else {
                return;
            };

            let mut buffer = vec![0; repr.buffer_len()];
            let mut packet = IgmpPacket::new_unchecked(&mut buffer[..]);
            repr.emit(&mut packet);
        }
        IpProtocol::Tcp => {
            let Ok(tcp_packet) = TcpPacket::new_checked(payload) else {
                return;
            };

            let Ok(repr) = TcpRepr::parse(
                &tcp_packet,
                &packet.src_addr().into_address(),
                &packet.dst_addr().into_address(),
                &ChecksumCapabilities::default(),
            ) else {
                return;
            };

            let mut buffer = vec![0; repr.buffer_len()];
            let mut frame = TcpPacket::new_unchecked(&mut buffer[..]);
            repr.emit(
                &mut frame,
                &packet.src_addr().into_address(),
                &packet.dst_addr().into_address(),
                &ChecksumCapabilities::default(),
            );
        }
        IpProtocol::Udp => {
            let Ok(udp_packet) = UdpPacket::new_checked(payload) else {
                return;
            };

            let Ok(repr) = UdpRepr::parse(
                &udp_packet,
                &packet.src_addr().into_address(),
                &packet.dst_addr().into_address(),
                &ChecksumCapabilities::default(),
            ) else {
                return;
            };

            let mut buffer = vec![0; repr.header_len() + udp_packet.payload().len()];
            let mut p = UdpPacket::new_unchecked(&mut buffer[..]);
            repr.emit(
                &mut p,
                &packet.src_addr().into_address(),
                &packet.dst_addr().into_address(),
                udp_packet.payload().len(),
                |b| b.copy_from_slice(udp_packet.payload()),
                &ChecksumCapabilities::default(),
            );
        }
        _ => {}
    }
});
