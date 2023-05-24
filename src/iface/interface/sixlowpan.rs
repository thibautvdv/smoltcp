use super::*;

#[cfg(feature = "proto-rpl")]
use crate::iface::rpl::lollipop;

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
                match self.sixlowpan_to_ipv6(
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

        self.process_ipv6(
            sockets,
            ieee802154_repr.src_addr.map(HardwareAddress::from),
            &check!(Ipv6Packet::new_checked(payload)),
        )
    }

    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    pub(super) fn process_sixlowpan_fragment<
        'output,
        'payload: 'output,
        T: AsRef<[u8]> + ?Sized,
    >(
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
                self.sixlowpan_to_ipv6(ieee802154_repr, frag.payload(), Some(total_size), buffer)
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

    pub(super) fn dispatch_sixlowpan<Tx: TxToken>(
        &mut self,
        tx_token: Tx,
        mut ip_packet: IpPacket,
        ieee_repr: Ieee802154Repr,
        frag: &mut Fragmenter,
    ) {
        // First we calculate the size we are going to need. If the size is bigger than the MTU,
        // then we use fragmentation.
        let (total_size, compressed_size, uncompressed_size) =
            self.calculate_compressed_packet_size(&mut ip_packet, &ieee_repr);

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

                let mut payload_length = ip_packet.ip_repr().payload_len();

                if ip_packet.repr.dst_addr().is_unicast() {
                    payload_length += 8;
                }

                self.ipv6_to_sixlowpan(&mut pkt.buffer[..], ip_packet, &ieee_repr);

                pkt.sixlowpan.ll_dst_addr = ieee_repr.dst_addr.unwrap();
                pkt.sixlowpan.ll_src_addr = ieee_repr.src_addr.unwrap();
                pkt.packet_len = total_size;

                // The datagram size that we need to set in the first fragment header is equal to the
                // IPv6 payload length + 40.
                pkt.sixlowpan.datagram_size = (payload_length + 40) as u16;

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

                self.ipv6_to_sixlowpan(tx_buf, ip_packet, &ieee_repr);
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
        packet: &mut IpPacket,
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

        let mut payload_len = ip_repr.payload_len;

        #[cfg(feature = "proto-rpl")]
        let hop_by_hop = if packet.routing.is_none() {
            packet.hbh.map(Ipv6OptionRepr::Rpl)
        } else {
            None
        };

        #[cfg(not(feature = "proto-rpl"))]
        let hop_by_hop: Option<Ipv6OptionRepr> = None;

        let next_header = packet.as_sixlowpan_next_header();

        let iphc = SixlowpanIphcRepr {
            src_addr: ip_repr.src_addr,
            ll_src_addr: ieee_repr.src_addr,
            dst_addr: ip_repr.dst_addr,
            ll_dst_addr: ieee_repr.dst_addr,
            next_header: if packet.routing.is_some() || hop_by_hop.is_some() {
                SixlowpanNextHeader::Compressed
            } else {
                next_header
            },
            hop_limit: ip_repr.hop_limit,
            ecn: None,
            dscp: None,
            flow_label: None,
        };

        total_size += iphc.buffer_len();
        compressed_hdr_size += iphc.buffer_len();
        uncompressed_hdr_size += ip_repr.buffer_len();

        if let Some(routing) = &packet.routing {
            let ext_hdr = SixlowpanExtHeaderRepr {
                ext_header_id: SixlowpanExtHeaderId::RoutingHeader,
                next_header,
                length: routing.buffer_len() as u8,
            };
            total_size += ext_hdr.buffer_len() + routing.buffer_len();
            compressed_hdr_size += ext_hdr.buffer_len() + routing.buffer_len();
            uncompressed_hdr_size += Ipv6ExtHeaderRepr {
                next_header: ip_repr.next_header,
                length: ext_hdr.length / 8,
                data: &[],
            }
            .buffer_len()
                + routing.buffer_len();
        }

        // Add the hop-by-hop to the sizes.
        if let Some(hbh) = hop_by_hop {
            let ext_hdr = SixlowpanExtHeaderRepr {
                ext_header_id: SixlowpanExtHeaderId::HopByHopHeader,
                next_header,
                length: hbh.buffer_len() as u8,
            };
            total_size += ext_hdr.buffer_len() + hbh.buffer_len();
            compressed_hdr_size += ext_hdr.buffer_len() + hbh.buffer_len();
            uncompressed_hdr_size += Ipv6ExtHeaderRepr {
                next_header: ip_repr.next_header,
                length: ext_hdr.length / 8,
                data: &[],
            }
            .buffer_len()
                + hbh.buffer_len();
        }

        match packet.payload {
            #[cfg(feature = "socket-udp")]
            IpPayload::Udp(udp_hdr, payload) => {
                uncompressed_hdr_size += udp_hdr.header_len();

                let udp_hdr = SixlowpanUdpNhcRepr(udp_hdr);
                compressed_hdr_size += udp_hdr.header_len();

                total_size += udp_hdr.header_len() + payload.len();
            }
            _ => {
                total_size += payload_len;
            }
        }

        (total_size, compressed_hdr_size, uncompressed_hdr_size)
    }

    fn ipv6_to_sixlowpan(
        &self,
        mut buffer: &mut [u8],
        mut packet: IpPacket,
        ieee_repr: &Ieee802154Repr,
    ) {
        // Create the IPHC representation.
        let ip_repr = match packet.ip_repr() {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(_) => unreachable!(),
            IpRepr::Ipv6(repr) => repr.clone(),
        };

        #[cfg(feature = "proto-rpl")]
        let hop_by_hop = if packet.routing.is_none() {
            packet.hbh.map(Ipv6OptionRepr::Rpl)
        } else {
            None
        };

        #[cfg(not(feature = "proto-rpl"))]
        let hop_by_hop: Option<Ipv6OptionRepr> = None;

        let next_header = packet.as_sixlowpan_next_header();

        let iphc_repr = SixlowpanIphcRepr {
            src_addr: ip_repr.src_addr,
            ll_src_addr: ieee_repr.src_addr,
            dst_addr: ip_repr.dst_addr,
            ll_dst_addr: ieee_repr.dst_addr,
            next_header: if packet.routing.is_some() || hop_by_hop.is_some() {
                SixlowpanNextHeader::Compressed
            } else {
                next_header
            },
            hop_limit: ip_repr.hop_limit,
            ecn: None,
            dscp: None,
            flow_label: None,
        };

        iphc_repr.emit(&mut SixlowpanIphcPacket::new_unchecked(
            &mut buffer[..iphc_repr.buffer_len()],
        ));
        buffer = &mut buffer[iphc_repr.buffer_len()..];

        // Emit the Hop-by-Hop header, required for RPL
        if let Some(routing) = &packet.routing {
            let ext_hdr = SixlowpanExtHeaderRepr {
                ext_header_id: SixlowpanExtHeaderId::RoutingHeader,
                next_header,
                length: routing.buffer_len() as u8,
            };
            ext_hdr.emit(&mut SixlowpanExtHeaderPacket::new_unchecked(
                &mut buffer[..ext_hdr.buffer_len()],
            ));
            buffer = &mut buffer[ext_hdr.buffer_len()..];

            routing.emit(&mut Ipv6RoutingHeader::new_unchecked(
                &mut buffer[..routing.buffer_len()],
            ));
            buffer = &mut buffer[routing.buffer_len()..];
        }

        // Emit the Hop-by-Hop header, required for RPL
        if let Some(hbh) = hop_by_hop {
            let ext_hdr = SixlowpanExtHeaderRepr {
                ext_header_id: SixlowpanExtHeaderId::HopByHopHeader,
                next_header,
                length: hbh.buffer_len() as u8,
            };
            ext_hdr.emit(&mut SixlowpanExtHeaderPacket::new_unchecked(
                &mut buffer[..ext_hdr.buffer_len()],
            ));
            buffer = &mut buffer[ext_hdr.buffer_len()..];

            hbh.emit(&mut Ipv6Option::new_unchecked(
                &mut buffer[..hbh.buffer_len()],
            ));
            buffer = &mut buffer[hbh.buffer_len()..];
        }

        match &mut packet.payload {
            IpPayload::Icmpv6(icmp_repr) => {
                icmp_repr.emit(
                    &ip_repr.src_addr.into(),
                    &ip_repr.dst_addr.into(),
                    &mut Icmpv6Packet::new_unchecked(&mut buffer[..icmp_repr.buffer_len()]),
                    &self.checksum_caps(),
                );
            }
            #[cfg(feature = "socket-udp")]
            IpPayload::Udp(udp_repr, payload) => {
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
            IpPayload::Tcp(tcp_repr) => {
                tcp_repr.emit(
                    &mut TcpPacket::new_unchecked(&mut buffer[..tcp_repr.buffer_len()]),
                    &ip_repr.src_addr.into(),
                    &ip_repr.dst_addr.into(),
                    &self.checksum_caps(),
                );
            }
            #[cfg(feature = "socket-raw")]
            IpPayload::Raw(_raw) => todo!(),

            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }

    fn sixlowpan_to_ipv6(
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

        let first_next_header = match iphc_repr.next_header {
            SixlowpanNextHeader::Compressed => {
                match SixlowpanNhcPacket::dispatch(iphc.payload())? {
                    SixlowpanNhcPacket::ExtHeader => {
                        SixlowpanExtHeaderPacket::new_checked(iphc.payload())?
                            .extension_header_id()
                            .into()
                    }
                    SixlowpanNhcPacket::UdpHeader => IpProtocol::Udp,
                }
            }
            SixlowpanNextHeader::Uncompressed(proto) => proto,
        };

        let mut decompressed_size = 40 + iphc.payload().len();
        let mut next_header = Some(iphc_repr.next_header);
        let mut data = iphc.payload();

        while let Some(nh) = next_header {
            match nh {
                SixlowpanNextHeader::Compressed => match SixlowpanNhcPacket::dispatch(data)? {
                    SixlowpanNhcPacket::ExtHeader => {
                        let ext_hdr = SixlowpanExtHeaderPacket::new_checked(data)?;
                        let ext_repr = SixlowpanExtHeaderRepr::parse(&ext_hdr)?;
                        decompressed_size += 2;
                        decompressed_size -= ext_repr.buffer_len();
                        next_header = Some(ext_repr.next_header);
                        data = &data[ext_repr.buffer_len() + ext_repr.length as usize..];
                    }
                    SixlowpanNhcPacket::UdpHeader => {
                        let udp_packet = SixlowpanUdpNhcPacket::new_checked(data)?;
                        let udp_repr = SixlowpanUdpNhcRepr::parse(
                            &udp_packet,
                            &iphc_repr.src_addr,
                            &iphc_repr.dst_addr,
                            &crate::phy::ChecksumCapabilities::ignored(),
                        )?;

                        decompressed_size += 8;
                        decompressed_size -= udp_repr.header_len();
                        break;
                    }
                },
                SixlowpanNextHeader::Uncompressed(proto) => match proto {
                    IpProtocol::HopByHop => todo!(),
                    IpProtocol::Tcp => break,
                    IpProtocol::Udp => break,
                    IpProtocol::Icmpv6 => break,
                    _ => unreachable!(),
                },
            }
        }

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

        let mut rest_size = total_size;

        let ipv6_repr = Ipv6Repr {
            src_addr: iphc_repr.src_addr,
            dst_addr: iphc_repr.dst_addr,
            next_header: first_next_header,
            payload_len: total_size - 40,
            hop_limit: iphc_repr.hop_limit,
        };
        rest_size -= 40;

        // Emit the decompressed IPHC header (decompressed to an IPv6 header).
        let mut ipv6_packet = Ipv6Packet::new_unchecked(&mut buffer[..ipv6_repr.buffer_len()]);
        ipv6_repr.emit(&mut ipv6_packet);
        let mut buffer = &mut buffer[ipv6_repr.buffer_len()..];

        let mut next_header = Some(iphc_repr.next_header);
        let mut data = iphc.payload();

        while let Some(nh) = next_header {
            match nh {
                SixlowpanNextHeader::Compressed => match SixlowpanNhcPacket::dispatch(data)? {
                    SixlowpanNhcPacket::ExtHeader => {
                        let ext_hdr = SixlowpanExtHeaderPacket::new_checked(data)?;
                        let ext_repr = SixlowpanExtHeaderRepr::parse(&ext_hdr)?;

                        let nh = match ext_repr.next_header {
                            SixlowpanNextHeader::Compressed => {
                                let d = &data[ext_repr.length as usize + ext_repr.buffer_len()..];
                                //let d = &ext_hdr.payload()[ext_repr.length as usize..];
                                match SixlowpanNhcPacket::dispatch(d)? {
                                    SixlowpanNhcPacket::ExtHeader => {
                                        SixlowpanExtHeaderPacket::new_checked(d)?
                                            .extension_header_id()
                                            .into()
                                    }
                                    SixlowpanNhcPacket::UdpHeader => IpProtocol::Udp,
                                }
                            }
                            SixlowpanNextHeader::Uncompressed(proto) => proto,
                        };
                        next_header = Some(ext_repr.next_header);

                        let ipv6_ext_rpr = Ipv6ExtHeaderRepr {
                            next_header: nh,
                            length: ext_repr.length / 8,
                            data: &ext_hdr.payload()[..ext_repr.length as usize],
                        };
                        ipv6_ext_rpr.emit(&mut Ipv6ExtHeader::new_unchecked(
                            &mut buffer[..ipv6_ext_rpr.buffer_len()],
                        ));

                        buffer[ipv6_ext_rpr.buffer_len()..][..ext_hdr.payload().len()]
                            .copy_from_slice(ext_hdr.payload());
                        buffer = &mut buffer[ipv6_ext_rpr.buffer_len() + ext_hdr.payload().len()..];

                        rest_size -= ipv6_ext_rpr.buffer_len() + ext_hdr.payload().len();
                        data = &data[ext_repr.buffer_len() + ext_repr.length as usize..];
                    }
                    SixlowpanNhcPacket::UdpHeader => {
                        let udp_packet = SixlowpanUdpNhcPacket::new_checked(data)?;
                        let payload = udp_packet.payload();
                        let udp_repr = SixlowpanUdpNhcRepr::parse(
                            &udp_packet,
                            &iphc_repr.src_addr,
                            &iphc_repr.dst_addr,
                            &ChecksumCapabilities::ignored(),
                        )?;

                        let mut udp = UdpPacket::new_unchecked(&mut buffer[..payload.len() + 8]);
                        udp_repr
                            .0
                            .emit_header(&mut udp, rest_size - udp_repr.0.header_len()); // TODO
                        buffer[8..][..payload.len()].copy_from_slice(payload);

                        break;
                    }
                },
                SixlowpanNextHeader::Uncompressed(proto) => match proto {
                    IpProtocol::HopByHop => todo!(),
                    IpProtocol::Tcp => {
                        buffer.copy_from_slice(data);
                        break;
                    }
                    IpProtocol::Udp => {
                        buffer.copy_from_slice(data);
                        break;
                    }
                    IpProtocol::Icmpv6 => {
                        buffer.copy_from_slice(data);
                        break;
                    }
                    _ => unreachable!(),
                },
            }
        }

        Ok(decompressed_size)
    }
}

#[cfg(test)]
#[cfg(feature = "proto-rpl")]
mod tests {
    use super::*;

    static SIXLOWPAN_COMPRESSED_RPL_DAO: [u8; 99] = [
        0x61, 0xdc, 0x45, 0xcd, 0xab, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x03, 0x00,
        0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x7e, 0xf7, 0x00, 0xe0, 0x3a, 0x06, 0x63, 0x04, 0x00,
        0x1e, 0x08, 0x00, 0x9b, 0x02, 0x3e, 0x63, 0x1e, 0x40, 0x00, 0xf1, 0xfd, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x05, 0x12, 0x00,
        0x80, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x03, 0x00, 0x03,
        0x00, 0x03, 0x06, 0x14, 0x00, 0x00, 0x00, 0x1e, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
    ];

    static SIXLOWPAN_UNCOMPRESSED_RPL_DAO: [u8; 114] = [
        0x60, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x40, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x3a, 0x00, 0x63, 0x04, 0x00,
        0x1e, 0x08, 0x00, 0x9b, 0x02, 0x3e, 0x63, 0x1e, 0x40, 0x00, 0xf1, 0xfd, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x05, 0x12, 0x00,
        0x80, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x03, 0x00, 0x03,
        0x00, 0x03, 0x06, 0x14, 0x00, 0x00, 0x00, 0x1e, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
    ];

    #[test]
    fn test_sixlowpan_decompress_hop_by_hop_with_icmpv6() {
        let (mut iface, _, _) = crate::iface::interface::tests::create(Medium::Ieee802154);

        iface
            .inner
            .sixlowpan_address_context
            .push(SixlowpanAddressContext([
                0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            ]))
            .unwrap();

        let ieee_frame = Ieee802154Frame::new_checked(&SIXLOWPAN_COMPRESSED_RPL_DAO).unwrap();
        let ieee_repr = Ieee802154Repr::parse(&ieee_frame).unwrap();

        let mut buffer = [0u8; 256];
        let len = iface
            .inner
            .sixlowpan_to_ipv6(
                &ieee_repr,
                ieee_frame.payload().unwrap(),
                None,
                &mut buffer[..],
            )
            .unwrap();

        assert_eq!(&buffer[..len], &SIXLOWPAN_UNCOMPRESSED_RPL_DAO);
    }

    #[test]
    fn test_sixlowpan_compress_hop_by_hop_with_icmpv6() {
        let (iface, _, _) = crate::iface::interface::tests::create(Medium::Ieee802154);

        let ieee_repr = Ieee802154Repr {
            frame_type: Ieee802154FrameType::Data,
            security_enabled: false,
            frame_pending: false,
            ack_request: true,
            sequence_number: Some(69),
            pan_id_compression: true,
            frame_version: Ieee802154FrameVersion::Ieee802154_2006,
            dst_pan_id: Some(Ieee802154Pan(43981)),
            dst_addr: Some(Ieee802154Address::Extended([0, 1, 0, 1, 0, 1, 0, 1])),
            src_pan_id: None,
            src_addr: Some(Ieee802154Address::Extended([0, 3, 0, 3, 0, 3, 0, 3])),
        };

        let mut ip_packet = IpPacket::new(
            Ipv6Repr {
                src_addr: Ipv6Address::from_bytes(&[
                    253, 0, 0, 0, 0, 0, 0, 0, 2, 3, 0, 3, 0, 3, 0, 3,
                ]),
                dst_addr: Ipv6Address::from_bytes(&[
                    253, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 1, 0, 1, 0, 1,
                ]),
                next_header: IpProtocol::Icmpv6,
                payload_len: 66,
                hop_limit: 64,
            },
            Icmpv6Repr::Rpl(RplRepr::DestinationAdvertisementObject {
                rpl_instance_id: RplInstanceId::Global(30),
                expect_ack: false,
                sequence: 241,
                dodag_id: Some(Ipv6Address::from_bytes(&[
                    253, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 1, 0, 1, 0, 1,
                ])),
                //options: &[
                //5, 18, 0, 128, 253, 0, 0, 0, 0, 0, 0, 0, 2, 3, 0, 3, 0, 3, 0, 3, 6, 20, 0, 0,
                //0, 30, 253, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 1, 0, 1, 0, 1,
                //],
                options: heapless::Vec::new(),
            }),
        );

        let (total_size, _, _) = iface
            .inner
            .calculate_compressed_packet_size(&mut ip_packet, &ieee_repr);
        let mut buffer = vec![0u8; total_size];

        iface
            .inner
            .ipv6_to_sixlowpan(&mut buffer[..total_size], ip_packet, &ieee_repr);

        let result = [
            0x7e, 0x0, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x3, 0x0, 0x3, 0x0, 0x3, 0x0,
            0x3, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1,
            0xe0, 0x3a, 0x6, 0x63, 0x4, 0x0, 0x1e, 0x3, 0x0, 0x9b, 0x2, 0x3e, 0x63, 0x1e, 0x40,
            0x0, 0xf1, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0,
            0x1, 0x5, 0x12, 0x0, 0x80, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x3, 0x0, 0x3,
            0x0, 0x3, 0x0, 0x3, 0x6, 0x14, 0x0, 0x0, 0x0, 0x1e, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x2, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1,
        ];

        assert_eq!(&result, &result);
    }

    #[test]
    fn test_sixlowpan_compress_hop_by_hop_with_udp() {
        let (iface, _, _) = crate::iface::interface::tests::create(Medium::Ieee802154);

        let ieee_repr = Ieee802154Repr {
            frame_type: Ieee802154FrameType::Data,
            security_enabled: false,
            frame_pending: false,
            ack_request: true,
            sequence_number: Some(69),
            pan_id_compression: true,
            frame_version: Ieee802154FrameVersion::Ieee802154_2006,
            dst_pan_id: Some(Ieee802154Pan(43981)),
            dst_addr: Some(Ieee802154Address::Extended([0, 1, 0, 1, 0, 1, 0, 1])),
            src_pan_id: None,
            src_addr: Some(Ieee802154Address::Extended([0, 3, 0, 3, 0, 3, 0, 3])),
        };

        let addr = Ipv6Address::from_bytes(&[253, 0, 0, 0, 0, 0, 0, 0, 2, 3, 0, 3, 0, 3, 0, 3]);
        let parent_address =
            Ipv6Address::from_bytes(&[253, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 1, 0, 1, 0, 1]);

        let mut options = heapless::Vec::new();
        options
            .push(RplOptionRepr::RplTarget {
                prefix_length: 128,
                prefix: addr,
            })
            .unwrap();
        options
            .push(RplOptionRepr::TransitInformation {
                external: false,
                path_control: 0,
                path_sequence: 0,
                path_lifetime: 30,
                parent_address: Some(parent_address),
            })
            .unwrap();

        let mut ip_packet = IpPacket::new(
            Ipv6Repr {
                src_addr: addr,
                dst_addr: parent_address,
                next_header: IpProtocol::Icmpv6,
                payload_len: 66,
                hop_limit: 64,
            },
            Icmpv6Repr::Rpl(RplRepr::DestinationAdvertisementObject {
                rpl_instance_id: RplInstanceId::Global(30),
                expect_ack: false,
                sequence: 241,
                dodag_id: Some(Ipv6Address::from_bytes(&[
                    253, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 1, 0, 1, 0, 1,
                ])),

                options,
            }),
        );

        let (total_size, _, _) = iface
            .inner
            .calculate_compressed_packet_size(&mut ip_packet, &ieee_repr);
        let mut buffer = vec![0u8; total_size];

        iface
            .inner
            .ipv6_to_sixlowpan(&mut buffer[..total_size], ip_packet, &ieee_repr);

        let result = [
            0x7e, 0x0, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x3, 0x0, 0x3, 0x0, 0x3, 0x0,
            0x3, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1,
            0xe0, 0x3a, 0x6, 0x63, 0x4, 0x0, 0x1e, 0x3, 0x0, 0x9b, 0x2, 0x3e, 0x63, 0x1e, 0x40,
            0x0, 0xf1, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0,
            0x1, 0x5, 0x12, 0x0, 0x80, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x3, 0x0, 0x3,
            0x0, 0x3, 0x0, 0x3, 0x6, 0x14, 0x0, 0x0, 0x0, 0x1e, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x2, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1,
        ];

        assert_eq!(&result, &result);
    }
}
