#![no_main]

use libfuzzer_sys::fuzz_target;

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::*;

fuzz_target!(|data: &[u8]| {
    let Ok(packet) = Ipv6Packet::new_checked(data) else {
        return;
    };

    let payload = packet.payload();
    match packet.next_header() {
        IpProtocol::HopByHop => {
            let Ok(frame) = Ipv6HopByHopHeader::new_checked(payload) else {
                return;
            };
            let Ok(repr) = Ipv6HopByHopRepr::parse(&frame) else {
                return;
            };
            let mut buffer = vec![0; repr.buffer_len()];
            let mut hop_by_hop_frame = Ipv6HopByHopHeader::new_unchecked(&mut buffer[..]);
            repr.emit(&mut hop_by_hop_frame);
        }
        IpProtocol::Icmpv6 => {
            let Ok(p) = Icmpv6Packet::new_checked(payload) else {
                return;
            };
            let Ok(repr) = Icmpv6Repr::parse(
                &packet.src_addr(),
                &packet.dst_addr(),
                &p,
                &ChecksumCapabilities::default(),
            ) else {
                return;
            };
            let mut buffer = vec![0; repr.buffer_len()];
            let mut p = Icmpv6Packet::new_unchecked(&mut buffer[..]);
            repr.emit(
                &packet.src_addr(),
                &packet.dst_addr(),
                &mut p,
                &ChecksumCapabilities::default(),
            );
        }
        IpProtocol::Ipv6Route => {
            let Ok(frame) = Ipv6RoutingHeader::new_checked(payload) else {
                return;
            };
            let Ok(repr) = Ipv6RoutingRepr::parse(&frame) else {
                return;
            };
            let mut buffer = vec![0; repr.buffer_len()];
            let mut packet = Ipv6RoutingHeader::new_unchecked(&mut buffer[..]);
            repr.emit(&mut packet);
        }
        IpProtocol::Ipv6Frag => {
            let Ok(frame) = Ipv6FragmentHeader::new_checked(payload) else {
                return;
            };
            let Ok(repr) = Ipv6FragmentRepr::parse(&frame) else {
                return;
            };
            let mut buffer = vec![0; repr.buffer_len()];
            let mut frame = Ipv6FragmentHeader::new_unchecked(&mut buffer[..]);
            repr.emit(&mut frame);
        }
        IpProtocol::Ipv6Opts => {
            let Ok(packet) = Ipv6Option::new_checked(payload) else {
                return;
            };
            let Ok(repr) = Ipv6OptionRepr::parse(&packet) else {
                return;
            };
            let mut buffer = vec![0; repr.buffer_len()];
            let mut packet = Ipv6Option::new_unchecked(&mut buffer[..]);
            repr.emit(&mut packet);
        }
        // TODO: enable fuzzing once panics are fixed.
        #[cfg(any())]
        IpProtocol::IpSecEsp => {
            let Ok(packet) = IpSecAuthHeaderPacket::new_checked(payload) else {
                return;
            };
            let Ok(repr) = IpSecAuthHeaderRepr::parse(&packet) else {
                return;
            };
            let mut buffer = vec![0; repr.buffer_len()];
            let mut packet = IpSecAuthHeaderPacket::new_unchecked(&mut buffer[..]);
            repr.emit(&mut packet);
        }
        // TODO: enable fuzzing once panics are fixed.
        #[cfg(any())]
        IpProtocol::IpSecAh => {
            let Ok(packet) = IpSecEspPacket::new_checked(payload) else {
                return;
            };
            let Ok(repr) = IpSecEspRepr::parse(&packet) else {
                return;
            };
            let mut buffer = vec![0; repr.buffer_len()];
            let mut packet = IpSecEspPacket::new_unchecked(&mut buffer[..]);
            repr.emit(&mut packet);
        }
        IpProtocol::Ipv6NoNxt => (),
        IpProtocol::Tcp => {
            let Ok(frame) = TcpPacket::new_checked(payload) else {
                return;
            };
            let Ok(repr) = TcpRepr::parse(
                &frame,
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
            let Ok(frame) = UdpPacket::new_checked(payload) else {
                return;
            };
            let Ok(repr) = UdpRepr::parse(
                &frame,
                &packet.src_addr().into_address(),
                &packet.dst_addr().into_address(),
                &ChecksumCapabilities::default(),
            ) else {
                return;
            };
            let mut buffer = vec![0; repr.header_len() + frame.payload().len()];
            let mut p = UdpPacket::new_unchecked(&mut buffer[..]);
            repr.emit(
                &mut p,
                &packet.src_addr().into_address(),
                &packet.dst_addr().into_address(),
                frame.payload().len(),
                |b| b.copy_from_slice(frame.payload()),
                &ChecksumCapabilities::default(),
            );
        }
        _ => {}
    }
});
