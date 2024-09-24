#![no_main]

use libfuzzer_sys::fuzz_target;

use smoltcp::wire::*;

fuzz_target!(|data: &[u8]| {
    if data.len() > 127 {
        return;
    }

    let Ok(frame) = Ieee802154Frame::new_checked(data) else {
        return;
    };

    let Ok(repr) = Ieee802154Repr::parse(&frame) else {
        return;
    };

    let Some(payload) = frame.payload() else {
        return;
    };

    match SixlowpanPacket::dispatch(payload) {
        Ok(SixlowpanPacket::FragmentHeader) => {
            let Ok(fragment) = SixlowpanFragPacket::new_checked(payload) else {
                return;
            };
            let Ok(repr) = SixlowpanFragRepr::parse(&fragment) else {
                return;
            };

            let mut buffer = vec![0; repr.buffer_len()];
            let mut fragment = SixlowpanFragPacket::new_unchecked(&mut buffer[..]);
            repr.emit(&mut fragment);
        }
        Ok(SixlowpanPacket::IphcHeader) => {
            let Ok(iphc_packet) = SixlowpanIphcPacket::new_checked(payload) else {
                return;
            };

            let Ok(iphc_repr) =
                SixlowpanIphcRepr::parse(&iphc_packet, repr.src_addr, repr.dst_addr, &[])
            else {
                return;
            };

            let mut buffer = vec![0; iphc_repr.buffer_len()];
            let mut iphc = SixlowpanIphcPacket::new_unchecked(&mut buffer[..]);
            iphc_repr.emit(&mut iphc);

            let payload = iphc_packet.payload();
            match iphc_repr.next_header {
                SixlowpanNextHeader::Compressed => {
                    let Ok(p) = SixlowpanNhcPacket::dispatch(payload) else {
                        return;
                    };

                    match p {
                        SixlowpanNhcPacket::ExtHeader => {
                            let Ok(ext_header) = SixlowpanExtHeaderPacket::new_checked(payload)
                            else {
                                return;
                            };

                            let Ok(repr) = SixlowpanExtHeaderRepr::parse(&ext_header) else {
                                return;
                            };

                            let mut buffer = vec![0; repr.buffer_len()];
                            let mut ext_header =
                                SixlowpanExtHeaderPacket::new_unchecked(&mut buffer[..]);
                            repr.emit(&mut ext_header);
                        }
                        SixlowpanNhcPacket::UdpHeader => {
                            let Ok(udp) = SixlowpanUdpNhcPacket::new_checked(payload) else {
                                return;
                            };

                            let Ok(repr) = SixlowpanUdpNhcRepr::parse(
                                &udp,
                                &iphc_repr.src_addr,
                                &iphc_repr.dst_addr,
                                &Default::default(),
                            ) else {
                                return;
                            };

                            let mut buffer = vec![0; repr.header_len() + udp.payload().len()];
                            let mut udp_packet =
                                SixlowpanUdpNhcPacket::new_unchecked(&mut buffer[..]);
                            repr.emit(
                                &mut udp_packet,
                                &iphc_repr.src_addr,
                                &iphc_repr.dst_addr,
                                udp.payload().len(),
                                |b| b.copy_from_slice(udp.payload()),
                                &Default::default(),
                            );
                        }
                    }
                }
                // NOTE: we already fuzz this case in ipv6-packet-parser.rs
                SixlowpanNextHeader::Uncompressed(_) => {}
            }
        }
        _ => {}
    }
});
