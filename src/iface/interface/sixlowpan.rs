use super::*;

use crate::phy::ChecksumCapabilities;
use crate::wire::*;

// Max len of non-fragmented packets after decompression (including ipv6 header and payload)
// TODO: lower. Should be (6lowpan mtu) - (min 6lowpan header size) + (max ipv6 header size)
pub(crate) const MAX_DECOMPRESSED_LEN: usize = 1500;

impl InterfaceInner {
    pub(super) fn process_sixlowpan<'output, 'payload: 'output, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        sockets: &mut SocketSet,
        ieee802154_repr: &Ieee802154Repr,
        payload: &'payload T,
        f: &'output mut FragmentsBuffer,
    ) -> Option<IpPacket<'output>> {
        let payload = match check!(SixlowpanPacket::dispatch(payload)) {
            #[cfg(not(feature = "proto-sixlowpan-fragmentation"))]
            SixlowpanPacket::FragmentHeader => {
                net_debug!(
                    "Fragmentation is not supported, \
                    use the `proto-sixlowpan-fragmentation` feature to add support."
                );
                return None;
            }
            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            SixlowpanPacket::FragmentHeader => {
                match self.process_sixlowpan_fragment(ieee802154_repr, payload, f) {
                    Some(payload) => payload,
                    None => return None,
                }
            }
            SixlowpanPacket::IphcHeader => {
                match self.decompress_sixlowpan(
                    ieee802154_repr,
                    payload.as_ref(),
                    None,
                    &mut f.decompress_buf,
                ) {
                    Ok(len) => &f.decompress_buf[..len],
                    Err(e) => {
                        net_debug!("sixlowpan decompress failed: {:?}", e);
                        return None;
                    }
                }
            }
        };

        self.process_ipv6(sockets, &check!(Ipv6Packet::new_checked(payload)))
    }

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    fn process_sixlowpan_fragment<'output, 'payload: 'output, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        ieee802154_repr: &Ieee802154Repr,
        payload: &'payload T,
        f: &'output mut FragmentsBuffer,
    ) -> Option<&'output [u8]> {
        use crate::iface::fragmentation::{AssemblerError, AssemblerFullError};

        // We have a fragment header, which means we cannot process the 6LoWPAN packet,
        // unless we have a complete one after processing this fragment.
        let frag = check!(SixlowpanFragPacket::new_checked(payload));

        // The key specifies to which 6LoWPAN fragment it belongs too.
        // It is based on the link layer addresses, the tag and the size.
        let key = FragKey::Sixlowpan(frag.get_key(ieee802154_repr));

        // The offset of this fragment in increments of 8 octets.
        let offset = frag.datagram_offset() as usize * 8;

        // We reserve a spot in the packet assembler set and add the required
        // information to the packet assembler.
        // This information is the total size of the packet when it is fully assmbled.
        // We also pass the header size, since this is needed when other fragments
        // (other than the first one) are added.
        let frag_slot = match f.assembler.get(&key, self.now + f.reassembly_timeout) {
            Ok(frag) => frag,
            Err(AssemblerFullError) => {
                net_debug!("No available packet assembler for fragmented packet");
                return None;
            }
        };

        if frag.is_first_fragment() {
            // The first fragment contains the total size of the IPv6 packet.
            // However, we received a packet that is compressed following the 6LoWPAN
            // standard. This means we need to convert the IPv6 packet size to a 6LoWPAN
            // packet size. The packet size can be different because of first the
            // compression of the IP header and when UDP is used (because the UDP header
            // can also be compressed). Other headers are not compressed by 6LoWPAN.

            // First segment tells us the total size.
            let total_size = frag.datagram_size() as usize;
            if frag_slot.set_total_size(total_size).is_err() {
                net_debug!("No available packet assembler for fragmented packet");
                return None;
            }

            // Decompress headers+payload into the assembler.
            if let Err(e) = frag_slot.add_with(0, |buffer| {
                self.decompress_sixlowpan(ieee802154_repr, frag.payload(), Some(total_size), buffer)
                    .map_err(|_| AssemblerError)
            }) {
                net_debug!("fragmentation error: {:?}", e);
                return None;
            }
        } else {
            // Add the fragment to the packet assembler.
            if let Err(e) = frag_slot.add(frag.payload(), offset) {
                net_debug!("fragmentation error: {:?}", e);
                return None;
            }
        }

        match frag_slot.assemble() {
            Some(payload) => {
                net_trace!("6LoWPAN: fragmented packet now complete");
                Some(payload)
            }
            None => None,
        }
    }

    fn decompress_sixlowpan(
        &self,
        ieee802154_repr: &Ieee802154Repr,
        iphc_payload: &[u8],
        total_size: Option<usize>,
        buffer: &mut [u8],
    ) -> core::result::Result<usize, crate::wire::Error> {
        let iphc = SixlowpanIphcPacket::new_checked(iphc_payload)?;
        let iphc_repr = SixlowpanIphcRepr::parse(
            &iphc,
            ieee802154_repr.src_addr,
            ieee802154_repr.dst_addr,
            &self.sixlowpan_address_context,
        )?;

        let mut decompressed_size = 40 + iphc.payload().len();

        let next_header = match iphc_repr.next_header {
            SixlowpanNextHeader::Compressed => {
                match SixlowpanNhcPacket::dispatch(iphc.payload())? {
                    SixlowpanNhcPacket::ExtHeader => {
                        net_debug!("Extension headers are currently not supported for 6LoWPAN");
                        IpProtocol::Unknown(0)
                    }
                    SixlowpanNhcPacket::UdpHeader => {
                        let udp_packet = SixlowpanUdpNhcPacket::new_checked(iphc.payload())?;
                        let udp_repr = SixlowpanUdpNhcRepr::parse(
                            &udp_packet,
                            &iphc_repr.src_addr,
                            &iphc_repr.dst_addr,
                            &crate::phy::ChecksumCapabilities::ignored(),
                        )?;

                        decompressed_size += 8;
                        decompressed_size -= udp_repr.header_len();
                        IpProtocol::Udp
                    }
                }
            }
            SixlowpanNextHeader::Uncompressed(proto) => proto,
        };

        if buffer.len() < decompressed_size {
            net_debug!("sixlowpan decompress: buffer too short");
            return Err(crate::wire::Error);
        }
        let buffer = &mut buffer[..decompressed_size];

        let total_size = if let Some(size) = total_size {
            size
        } else {
            decompressed_size
        };

        let ipv6_repr = Ipv6Repr {
            src_addr: iphc_repr.src_addr,
            dst_addr: iphc_repr.dst_addr,
            next_header,
            payload_len: total_size - 40,
            hop_limit: iphc_repr.hop_limit,
        };

        // Emit the decompressed IPHC header (decompressed to an IPv6 header).
        let mut ipv6_packet = Ipv6Packet::new_unchecked(&mut buffer[..ipv6_repr.buffer_len()]);
        ipv6_repr.emit(&mut ipv6_packet);
        let buffer = &mut buffer[ipv6_repr.buffer_len()..];

        match iphc_repr.next_header {
            SixlowpanNextHeader::Compressed => {
                match SixlowpanNhcPacket::dispatch(iphc.payload())? {
                    SixlowpanNhcPacket::ExtHeader => todo!(),
                    SixlowpanNhcPacket::UdpHeader => {
                        // We need to uncompress the UDP packet and emit it to the
                        // buffer.
                        let udp_packet = SixlowpanUdpNhcPacket::new_checked(iphc.payload())?;
                        let udp_repr = SixlowpanUdpNhcRepr::parse(
                            &udp_packet,
                            &iphc_repr.src_addr,
                            &iphc_repr.dst_addr,
                            &ChecksumCapabilities::ignored(),
                        )?;

                        let mut udp = UdpPacket::new_unchecked(
                            &mut buffer[..udp_repr.0.header_len() + iphc.payload().len()
                                - udp_repr.header_len()],
                        );
                        udp_repr.0.emit_header(&mut udp, ipv6_repr.payload_len - 8);

                        buffer[8..].copy_from_slice(&iphc.payload()[udp_repr.header_len()..]);
                    }
                }
            }
            SixlowpanNextHeader::Uncompressed(_) => {
                // For uncompressed headers we just copy the slice.
                let len = iphc.payload().len();
                buffer[..len].copy_from_slice(iphc.payload());
            }
        };

        Ok(decompressed_size)
    }

    fn emit_iphc_into_buffer(
        &mut self,
        mut buffer: &mut [u8],
        packet: &IpPacket,
        ieee_repr: &Ieee802154Repr,
    ) {
        // Create the IPHC representation.
        let ip_repr = match packet.ip_repr() {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(_) => unreachable!(),
            IpRepr::Ipv6(repr) => repr,
        };

        let next_header = match packet {
            #[cfg(feature = "proto-ipv6")]
            IpPacket::Icmpv6(_) => SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6),
            #[cfg(feature = "socket-raw")]
            IpPacket::Raw(_) => todo!(),
            #[cfg(feature = "socket-udp")]
            IpPacket::Udp(_) => SixlowpanNextHeader::Compressed,
            #[cfg(feature = "socket-tcp")]
            IpPacket::Tcp(_) => SixlowpanNextHeader::Uncompressed(IpProtocol::Tcp),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        };

        let iphc_repr = SixlowpanIphcRepr {
            src_addr: ip_repr.src_addr,
            ll_src_addr: ieee_repr.src_addr,
            dst_addr: ip_repr.dst_addr,
            ll_dst_addr: ieee_repr.dst_addr,
            next_header,
            hop_limit: ip_repr.hop_limit,
            ecn: None,
            dscp: None,
            flow_label: None,
        };

        iphc_repr.emit(&mut SixlowpanIphcPacket::new_unchecked(
            &mut buffer[..iphc_repr.buffer_len()],
        ));

        buffer = &mut buffer[iphc_repr.buffer_len()..];

        match packet {
            IpPacket::Icmpv6((_, icmp_repr)) => {
                icmp_repr.emit(
                    &ip_repr.src_addr.into(),
                    &ip_repr.dst_addr.into(),
                    &mut Icmpv6Packet::new_unchecked(&mut buffer[..icmp_repr.buffer_len()]),
                    &self.checksum_caps(),
                );
            }
            #[cfg(feature = "socket-udp")]
            IpPacket::Udp((_, udp_repr, payload)) => {
                let udp_repr = SixlowpanUdpNhcRepr(*udp_repr);
                udp_repr.emit(
                    &mut SixlowpanUdpNhcPacket::new_unchecked(
                        &mut buffer[..udp_repr.header_len() + payload.len()],
                    ),
                    &iphc_repr.src_addr,
                    &iphc_repr.dst_addr,
                    &self.checksum_caps(),
                    payload.len(),
                    |buf| buf.copy_from_slice(payload),
                );
            }
            #[cfg(feature = "socket-tcp")]
            IpPacket::Tcp((_, tcp_repr)) => {
                tcp_repr.emit(
                    &mut TcpPacket::new_unchecked(&mut buffer[..tcp_repr.buffer_len()]),
                    &ip_repr.src_addr.into(),
                    &ip_repr.dst_addr.into(),
                    &self.checksum_caps(),
                );
            }
            #[cfg(feature = "socket-raw")]
            IpPacket::Raw((_, _raw)) => todo!(),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }

    pub(super) fn dispatch_sixlowpan<Tx: TxToken>(
        &mut self,
        tx_token: Tx,
        packet: IpPacket,
        ieee_repr: Ieee802154Repr,
        frag: &mut Fragmenter,
    ) {
        // First we calculate the size we are going to need. If the size is bigger than the MTU,
        // then we use fragmentation.
        let (total_size, compressed_size, uncompressed_size) =
            self.calculate_compressed_packet_size(&packet, &ieee_repr);
        let ieee_len = ieee_repr.buffer_len();

        // TODO(thvdveld): use the MTU of the device.
        if total_size + ieee_len > 125 {
            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            {
                // The packet does not fit in one Ieee802154 frame, so we need fragmentation.
                // We do this by emitting everything in the `frag.buffer` from the interface.
                // After emitting everything into that buffer, we send the first fragment heere.
                // When `poll` is called again, we check if frag was fully sent, otherwise we
                // call `dispatch_ieee802154_frag`, which will transmit the other fragments.

                // `dispatch_ieee802154_frag` requires some information about the total packet size,
                // the link local source and destination address...

                let pkt = frag;
                if pkt.buffer.len() < total_size {
                    net_debug!(
                        "dispatch_ieee802154: dropping, \
                        fragmentation buffer is too small, at least {} needed",
                        total_size
                    );
                    return;
                }

                self.emit_iphc_into_buffer(&mut pkt.buffer[..], &packet, &ieee_repr);

                pkt.sixlowpan.ll_dst_addr = ieee_repr.dst_addr.unwrap();
                pkt.sixlowpan.ll_src_addr = ieee_repr.src_addr.unwrap();
                pkt.packet_len = total_size;

                // The datagram size that we need to set in the first fragment header is equal to the
                // IPv6 payload length + 40.
                pkt.sixlowpan.datagram_size = (packet.ip_repr().payload_len() + 40) as u16;

                let tag = self.get_sixlowpan_fragment_tag();
                // We save the tag for the other fragments that will be created when calling `poll`
                // multiple times.
                pkt.sixlowpan.datagram_tag = tag;

                let frag1 = SixlowpanFragRepr::FirstFragment {
                    size: pkt.sixlowpan.datagram_size,
                    tag,
                };
                let fragn = SixlowpanFragRepr::Fragment {
                    size: pkt.sixlowpan.datagram_size,
                    tag,
                    offset: 0,
                };

                // We calculate how much data we can send in the first fragment and the other
                // fragments. The eventual IPv6 sizes of these fragments need to be a multiple of eight
                // (except for the last fragment) since the offset field in the fragment is an offset
                // in multiples of 8 octets. This is explained in [RFC 4944 § 5.3].
                //
                // [RFC 4944 § 5.3]: https://datatracker.ietf.org/doc/html/rfc4944#section-5.3

                let header_diff = uncompressed_size - compressed_size;
                let frag1_size =
                    (125 - ieee_len - frag1.buffer_len() + header_diff) / 8 * 8 - header_diff;

                pkt.sixlowpan.fragn_size = (125 - ieee_len - fragn.buffer_len()) / 8 * 8;
                pkt.sent_bytes = frag1_size;
                pkt.sixlowpan.datagram_offset = frag1_size + header_diff;

                tx_token.consume(ieee_len + frag1.buffer_len() + frag1_size, |mut tx_buf| {
                    // Add the IEEE header.
                    let mut ieee_packet = Ieee802154Frame::new_unchecked(&mut tx_buf[..ieee_len]);
                    ieee_repr.emit(&mut ieee_packet);
                    tx_buf = &mut tx_buf[ieee_len..];

                    // Add the first fragment header
                    let mut frag1_packet = SixlowpanFragPacket::new_unchecked(&mut tx_buf);
                    frag1.emit(&mut frag1_packet);
                    tx_buf = &mut tx_buf[frag1.buffer_len()..];

                    // Add the buffer part.
                    tx_buf[..frag1_size].copy_from_slice(&pkt.buffer[..frag1_size]);
                });
            }

            #[cfg(not(feature = "proto-sixlowpan-fragmentation"))]
            {
                net_debug!(
                    "Enable the `proto-sixlowpan-fragmentation` feature for fragmentation support."
                );
                return;
            }
        } else {
            // We don't need fragmentation, so we emit everything to the TX token.
            tx_token.consume(total_size + ieee_len, |mut tx_buf| {
                let mut ieee_packet = Ieee802154Frame::new_unchecked(&mut tx_buf[..ieee_len]);
                ieee_repr.emit(&mut ieee_packet);
                tx_buf = &mut tx_buf[ieee_len..];

                self.emit_iphc_into_buffer(tx_buf, &packet, &ieee_repr);
            });
        }
    }

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    pub(super) fn dispatch_sixlowpan_frag<Tx: TxToken>(
        &mut self,
        tx_token: Tx,
        ieee_repr: Ieee802154Repr,
        frag: &mut Fragmenter,
    ) {
        // Create the FRAG_N header.
        let fragn = SixlowpanFragRepr::Fragment {
            size: frag.sixlowpan.datagram_size,
            tag: frag.sixlowpan.datagram_tag,
            offset: (frag.sixlowpan.datagram_offset / 8) as u8,
        };

        let ieee_len = ieee_repr.buffer_len();
        let frag_size = (frag.packet_len - frag.sent_bytes).min(frag.sixlowpan.fragn_size);

        tx_token.consume(
            ieee_repr.buffer_len() + fragn.buffer_len() + frag_size,
            |mut tx_buf| {
                let mut ieee_packet = Ieee802154Frame::new_unchecked(&mut tx_buf[..ieee_len]);
                ieee_repr.emit(&mut ieee_packet);
                tx_buf = &mut tx_buf[ieee_len..];

                let mut frag_packet =
                    SixlowpanFragPacket::new_unchecked(&mut tx_buf[..fragn.buffer_len()]);
                fragn.emit(&mut frag_packet);
                tx_buf = &mut tx_buf[fragn.buffer_len()..];

                // Add the buffer part
                tx_buf[..frag_size].copy_from_slice(&frag.buffer[frag.sent_bytes..][..frag_size]);

                frag.sent_bytes += frag_size;
                frag.sixlowpan.datagram_offset += frag_size;
            },
        );
    }

    fn calculate_compressed_packet_size(
        &self,
        packet: &IpPacket,
        ieee_repr: &Ieee802154Repr,
    ) -> (usize, usize, usize) {
        let mut total_size = 0;
        let mut compressed_hdr_size = 0;
        let mut uncompressed_hdr_size = 0;

        let ip_repr = match packet.ip_repr() {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(_) => unreachable!(),
            IpRepr::Ipv6(repr) => repr,
        };

        let next_header = match packet {
            #[cfg(feature = "proto-ipv6")]
            IpPacket::Icmpv6(_) => SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6),
            #[cfg(feature = "socket-raw")]
            IpPacket::Raw(_) => todo!(),
            #[cfg(feature = "socket-udp")]
            IpPacket::Udp(_) => SixlowpanNextHeader::Compressed,
            #[cfg(feature = "socket-tcp")]
            IpPacket::Tcp(_) => SixlowpanNextHeader::Uncompressed(IpProtocol::Tcp),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        };

        let iphc = SixlowpanIphcRepr {
            src_addr: ip_repr.src_addr,
            ll_src_addr: ieee_repr.src_addr,
            dst_addr: ip_repr.dst_addr,
            ll_dst_addr: ieee_repr.dst_addr,
            next_header,
            hop_limit: ip_repr.hop_limit,
            ecn: None,
            dscp: None,
            flow_label: None,
        };

        total_size += iphc.buffer_len();
        compressed_hdr_size += iphc.buffer_len();
        uncompressed_hdr_size += ip_repr.buffer_len();

        match packet {
            #[cfg(feature = "socket-udp")]
            IpPacket::Udp((_, udp_hdr, payload)) => {
                uncompressed_hdr_size += udp_hdr.header_len();

                let udp_hdr = SixlowpanUdpNhcRepr(*udp_hdr);
                compressed_hdr_size += udp_hdr.header_len();

                total_size += udp_hdr.header_len() + payload.len();
            }
            _ => {
                total_size += ip_repr.payload_len;
            }
        }

        (total_size, compressed_hdr_size, uncompressed_hdr_size)
    }
}
