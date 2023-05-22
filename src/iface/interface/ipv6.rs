use super::check;
use super::icmp_reply_payload_len;
use super::InterfaceInner;
use super::IpPacket;
use super::SocketSet;

#[cfg(feature = "socket-icmp")]
use crate::socket::icmp;
use crate::socket::AnySocket;

use crate::wire::*;

impl InterfaceInner {
    #[cfg(feature = "proto-ipv6")]
    pub(super) fn process_ipv6<'frame, T: AsRef<[u8]> + ?Sized>(
        &mut self,
        sockets: &mut SocketSet,
        src_ll_addr: Option<HardwareAddress>,
        ipv6_packet: &Ipv6Packet<&'frame T>,
    ) -> Option<IpPacket<'frame>> {
        let ipv6_repr = check!(Ipv6Repr::parse(ipv6_packet));

        if !ipv6_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return None;
        }

        let ip_payload = ipv6_packet.payload();

        #[cfg(feature = "socket-raw")]
        let handled_by_raw_socket = self.raw_socket_filter(sockets, &ipv6_repr.into(), ip_payload);
        #[cfg(not(feature = "socket-raw"))]
        let handled_by_raw_socket = false;

        self.process_nxt_hdr(
            sockets,
            src_ll_addr,
            ipv6_repr,
            ipv6_repr.next_header,
            handled_by_raw_socket,
            ip_payload,
        )
    }

    /// Given the next header value forward the payload onto the correct process
    /// function.
    #[cfg(feature = "proto-ipv6")]
    pub(super) fn process_nxt_hdr<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        src_ll_addr: Option<HardwareAddress>,
        ipv6_repr: Ipv6Repr,
        nxt_hdr: IpProtocol,
        handled_by_raw_socket: bool,
        ip_payload: &'frame [u8],
    ) -> Option<IpPacket<'frame>> {
        match nxt_hdr {
            IpProtocol::Icmpv6 => {
                self.process_icmpv6(sockets, src_ll_addr, ipv6_repr.into(), ip_payload)
            }

            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            IpProtocol::Udp => {
                let udp_packet = check!(UdpPacket::new_checked(ip_payload));
                let udp_repr = check!(UdpRepr::parse(
                    &udp_packet,
                    &ipv6_repr.src_addr.into(),
                    &ipv6_repr.dst_addr.into(),
                    &self.checksum_caps(),
                ));

                self.process_udp(
                    sockets,
                    ipv6_repr.into(),
                    udp_repr,
                    handled_by_raw_socket,
                    udp_packet.payload(),
                    ip_payload,
                )
            }

            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp => self.process_tcp(sockets, ipv6_repr.into(), ip_payload),

            IpProtocol::HopByHop => {
                self.process_hopbyhop(sockets, src_ll_addr, ipv6_repr, ip_payload)
            }

            IpProtocol::Ipv6Route => {
                self.process_routing(sockets, src_ll_addr, ipv6_repr, ip_payload)
            }

            #[cfg(feature = "socket-raw")]
            _ if handled_by_raw_socket => None,

            _ => {
                // Send back as much of the original payload as we can.
                let payload_len =
                    icmp_reply_payload_len(ip_payload.len(), IPV6_MIN_MTU, ipv6_repr.buffer_len());
                let icmp_reply_repr = Icmpv6Repr::ParamProblem {
                    reason: Icmpv6ParamProblem::UnrecognizedNxtHdr,
                    // The offending packet is after the IPv6 header.
                    pointer: ipv6_repr.buffer_len() as u32,
                    header: ipv6_repr,
                    data: &ip_payload[0..payload_len],
                };
                self.icmpv6_reply(ipv6_repr, icmp_reply_repr)
            }
        }
    }

    #[cfg(feature = "proto-ipv6")]
    pub(super) fn process_icmpv6<'frame>(
        &mut self,
        _sockets: &mut SocketSet,
        src_ll_addr: Option<HardwareAddress>,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Option<IpPacket<'frame>> {
        let icmp_packet = check!(Icmpv6Packet::new_checked(ip_payload));
        let icmp_repr = check!(Icmpv6Repr::parse(
            &ip_repr.src_addr(),
            &ip_repr.dst_addr(),
            &icmp_packet,
            &self.caps.checksum,
        ));

        #[cfg(feature = "socket-icmp")]
        let mut handled_by_icmp_socket = false;

        #[cfg(all(feature = "socket-icmp", feature = "proto-ipv6"))]
        for icmp_socket in _sockets
            .items_mut()
            .filter_map(|i| icmp::Socket::downcast_mut(&mut i.socket))
        {
            if icmp_socket.accepts(self, &ip_repr, &icmp_repr.clone().into()) {
                icmp_socket.process(self, &ip_repr, &icmp_repr.clone().into());
                handled_by_icmp_socket = true;
            }
        }

        match icmp_repr {
            // Respond to echo requests.
            Icmpv6Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } => match ip_repr {
                IpRepr::Ipv6(ipv6_repr) => {
                    let icmp_reply_repr = Icmpv6Repr::EchoReply {
                        ident,
                        seq_no,
                        data,
                    };
                    self.icmpv6_reply(ipv6_repr, icmp_reply_repr)
                }
                #[allow(unreachable_patterns)]
                _ => unreachable!(),
            },

            // Ignore any echo replies.
            Icmpv6Repr::EchoReply { .. } => None,

            // Forward any NDISC packets to the ndisc packet handler
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            Icmpv6Repr::Ndisc(repr) if ip_repr.hop_limit() == 0xff => match ip_repr {
                IpRepr::Ipv6(ipv6_repr) => self.process_ndisc(ipv6_repr, repr),
                #[allow(unreachable_patterns)]
                _ => unreachable!(),
            },

            // Don't report an error if a packet with unknown type
            // has been handled by an ICMP socket
            #[cfg(feature = "socket-icmp")]
            _ if handled_by_icmp_socket => None,

            #[cfg(feature = "proto-rpl")]
            // Only process RPL packets when we actually are using RPL.
            Icmpv6Repr::Rpl(rpl) => self.process_rpl(
                src_ll_addr,
                match ip_repr {
                    IpRepr::Ipv6(ip_repr) => ip_repr,
                    IpRepr::Ipv4(_) => unreachable!(),
                },
                rpl,
            ),

            // FIXME: do something correct here?
            _ => None,
        }
    }

    #[cfg(all(
        any(feature = "medium-ethernet", feature = "medium-ieee802154"),
        feature = "proto-ipv6"
    ))]
    pub(super) fn process_ndisc<'frame>(
        &mut self,
        ip_repr: Ipv6Repr,
        repr: NdiscRepr<'frame>,
    ) -> Option<IpPacket<'frame>> {
        match repr {
            NdiscRepr::NeighborAdvert {
                lladdr,
                target_addr,
                flags,
            } => {
                let ip_addr = ip_repr.src_addr.into();
                if let Some(lladdr) = lladdr {
                    let lladdr = check!(lladdr.parse(self.caps.medium));
                    if !lladdr.is_unicast() || !target_addr.is_unicast() {
                        return None;
                    }
                    if flags.contains(NdiscNeighborFlags::OVERRIDE)
                        || !self.neighbor_cache.lookup(&ip_addr, self.now).found()
                    {
                        self.neighbor_cache.fill(ip_addr, lladdr, self.now)
                    }
                }
                None
            }
            NdiscRepr::NeighborSolicit {
                target_addr,
                lladdr,
                ..
            } => {
                if let Some(lladdr) = lladdr {
                    let lladdr = check!(lladdr.parse(self.caps.medium));
                    if !lladdr.is_unicast() || !target_addr.is_unicast() {
                        return None;
                    }
                    self.neighbor_cache
                        .fill(ip_repr.src_addr.into(), lladdr, self.now);
                }

                if self.has_solicited_node(ip_repr.dst_addr) && self.has_ip_addr(target_addr) {
                    let advert = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                        flags: NdiscNeighborFlags::SOLICITED,
                        target_addr,
                        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                        lladdr: Some(self.hardware_addr.into()),
                    });
                    let ip_repr = Ipv6Repr {
                        src_addr: target_addr,
                        dst_addr: ip_repr.src_addr,
                        next_header: IpProtocol::Icmpv6,
                        hop_limit: 0xff,
                        payload_len: advert.buffer_len(),
                    };
                    Some(IpPacket::new(ip_repr, advert))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub(super) fn process_hopbyhop<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ll_src_addr: Option<HardwareAddress>,
        ipv6_repr: Ipv6Repr,
        ip_payload: &'frame [u8],
    ) -> Option<IpPacket<'frame>> {
        let ext_hdr = check!(Ipv6ExtHeader::new_checked(ip_payload));

        let hbh_repr = check!(Ipv6ExtHeaderRepr::parse(&ext_hdr));
        let hbh_options = Ipv6OptionsIterator::new(hbh_repr.data);

        for opt_repr in hbh_options {
            let opt_repr = check!(opt_repr);
            match opt_repr {
                Ipv6OptionRepr::Pad1 | Ipv6OptionRepr::PadN(_) => (),
                #[cfg(feature = "proto-rpl")]
                Ipv6OptionRepr::Rpl(rpl_hop_by_hop) => {
                    return self.process_rpl_hopbyhop(
                        sockets,
                        ll_src_addr,
                        ipv6_repr,
                        hbh_repr,
                        rpl_hop_by_hop,
                        ip_payload,
                    );
                }

                Ipv6OptionRepr::Unknown { type_, .. } => {
                    match Ipv6OptionFailureType::from(type_) {
                        Ipv6OptionFailureType::Skip => (),
                        Ipv6OptionFailureType::Discard => {
                            return None;
                        }
                        _ => {
                            // FIXME(dlrobertson): Send an ICMPv6 parameter problem message
                            // here.
                            return None;
                        }
                    }
                }
            }
        }
        self.process_nxt_hdr(
            sockets,
            ll_src_addr,
            ipv6_repr,
            ext_hdr.next_header(),
            false,
            &ip_payload[ext_hdr.payload().len() + 2..],
        )
    }

    pub(super) fn process_routing<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ll_src_addr: Option<HardwareAddress>,
        mut ipv6_repr: Ipv6Repr,
        ip_payload: &'frame [u8],
    ) -> Option<IpPacket<'frame>> {
        let ext_hdr = check!(Ipv6ExtHeader::new_checked(ip_payload));

        let routing_header = check!(Ipv6RoutingHeader::new_checked(ext_hdr.payload()));
        let mut routing_repr = check!(Ipv6RoutingRepr::parse(&routing_header));

        match &mut routing_repr {
            Ipv6RoutingRepr::Type2 { .. } => {
                net_debug!("IPv6 Type2 routing header not supported yet, dropping packet.");
                todo!("We should respond with a ICMPv6 unkown protocol.");
                return None;
            }
            Ipv6RoutingRepr::Rpl {
                segments_left,
                cmpr_i,
                cmpr_e,
                pad,
                addresses,
            } => {
                // Calculate the number of addresses left to visit.
                let n = (((ext_hdr.header_len() as usize * 8)
                    - *pad as usize
                    - (16 - *cmpr_e as usize))
                    / (16 - *cmpr_i as usize))
                    + 1;

                if *segments_left == 0 {
                    // We can process the next header.
                } else if *segments_left as usize > n {
                    dbg!(&routing_repr);
                    todo!(
                        "We should send an ICMP Parameter Problem, Code 0, \
                            to the source address, pointing to the segments left \
                            field, and discard the packet."
                    );
                } else {
                    // Decrement the segments left by 1.
                    *segments_left -= 1;

                    // Compute i, the index of the next address to be visited in the address
                    // vector, by substracting segments left from n.
                    let i = addresses.len() - *segments_left as usize;

                    let address = addresses[i - 1];
                    net_debug!("The next address: {address}");

                    // If Addresses[i] or the Destination address is mutlicast, we discard the
                    // packet.

                    if address.is_multicast() || ipv6_repr.dst_addr.is_multicast() {
                        dbg!(&routing_repr);
                        net_trace!("Dropping packet, destination address is multicast");
                        return None;
                    }

                    let tmp_addr = ipv6_repr.dst_addr;
                    ipv6_repr.dst_addr = address;
                    addresses[i - 1] = tmp_addr;

                    if ipv6_repr.hop_limit <= 1 {
                        dbg!(&routing_repr);
                        todo!(
                            "Send an ICMP Time Exceeded -- Hop Limit Exceeded in \
                            Transit message to the Source Address and discard the packet."
                        );
                    } else {
                        ipv6_repr.hop_limit -= 1;
                        ipv6_repr.next_header = ext_hdr.next_header();
                        let payload = &ip_payload[ext_hdr.payload().len() + 2..];
                        ipv6_repr.payload_len = payload.len();

                        return self.forward(ipv6_repr, payload, Some(routing_repr), None);
                    }
                }
            }
        }

        self.process_nxt_hdr(
            sockets,
            ll_src_addr,
            ipv6_repr,
            ext_hdr.next_header(),
            false,
            &ip_payload[ext_hdr.payload().len() + 2..],
        )
    }

    pub(super) fn icmpv6_reply<'frame, 'icmp: 'frame>(
        &self,
        ipv6_repr: Ipv6Repr,
        icmp_repr: Icmpv6Repr<'icmp>,
    ) -> Option<IpPacket<'frame>> {
        if ipv6_repr.dst_addr.is_unicast() {
            let ipv6_reply_repr = Ipv6Repr {
                src_addr: ipv6_repr.dst_addr,
                dst_addr: ipv6_repr.src_addr,
                next_header: IpProtocol::Icmpv6,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64,
            };
            Some(IpPacket::new(ipv6_reply_repr, icmp_repr))
        } else {
            // Do not send any ICMP replies to a broadcast destination address.
            None
        }
    }

    // NOTE: This function is currently only used for RPL.
    pub(super) fn forward<'frame>(
        &self,
        mut ip_repr: Ipv6Repr,
        payload: &'frame [u8],
        mut routing: Option<Ipv6RoutingRepr>,
        mut hbh: Option<RplHopByHopRepr>,
    ) -> Option<IpPacket<'frame>> {
        use crate::iface::RplModeOfOperation;

        let InterfaceInner { rpl, .. } = self;

        // Change the sender rank to our own rank.
        if let Some(hbh) = &mut hbh {
            hbh.sender_rank = self.rpl.rank.raw_value();
        }

        let forward_to = match self.rpl.mode_of_operation {
            RplModeOfOperation::NoDownwardRoutesMaintained if rpl.has_parent() => {
                net_trace!("[FORWARDING] forwarding to parent");
                rpl.parent_address.unwrap()
            }

            RplModeOfOperation::NoDownwardRoutesMaintained => {
                net_trace!("[FORWARDING] cannot forward, no parent");
                return None;
            }

            #[cfg(feature = "rpl-mop-1")]
            RplModeOfOperation::NonStoringMode if self.rpl.is_root => {
                if self.has_neighbor(&ip_repr.dst_addr.into()) {
                    net_trace!("[FORWARDING] forwarding to neighbor");
                    ip_repr.dst_addr
                } else {
                    net_trace!("[FORWARDING] forwarding, creating source routing header");

                    let our_ip = self.ipv6_addr().unwrap();

                    let mut nh = ip_repr.dst_addr;

                    // Create the source routing header
                    let mut route = heapless::Vec::<Ipv6Address, 32>::new();
                    route.push(nh).unwrap();

                    loop {
                        let next_hop = self.relations.find_next_hop(&nh);
                        if let Some(next_hop) = next_hop {
                            if next_hop == our_ip {
                                break;
                            }

                            route.push(next_hop).unwrap();
                            nh = next_hop;
                        } else {
                            todo!("unreachable");
                        }
                    }

                    let segments_left = route.len() - 1;
                    ip_repr.dst_addr = route[segments_left];

                    // Create the route list for the source routing header
                    let mut addresses = heapless::Vec::new();
                    for addr in route[..segments_left].iter().rev() {
                        addresses.push(*addr).unwrap();
                    }

                    // Add the source routing option to the packet.
                    routing = Some(Ipv6RoutingRepr::Rpl {
                        segments_left: segments_left as u8,
                        cmpr_i: 0,
                        cmpr_e: 0,
                        pad: 0,
                        addresses,
                    });

                    ip_repr.dst_addr
                }
            }

            RplModeOfOperation::NonStoringMode if routing.is_some() => {
                net_trace!("[FORWARDING] forwarding using source routing header");
                ip_repr.dst_addr
            }
            RplModeOfOperation::NonStoringMode if rpl.parent_address.is_some() => {
                rpl.parent_address.unwrap()
            }
            RplModeOfOperation::NonStoringMode => {
                net_trace!("[FORWARDING] cannot forward, no parent");
                return None;
            }

            #[cfg(feature = "rpl-mop-2")]
            RplModeOfOperation::StoringModeWithoutMulticast
                if self.relations.find_next_hop(&ip_repr.dst_addr).is_some() =>
            {
                // First look if we know that the destination is in our sub-tree.
                // Otherwise, try to send it up to our parent.
                if let Some(hbh) = &mut hbh {
                    hbh.down = true;
                }

                let nh = self.relations.find_next_hop(&ip_repr.dst_addr).unwrap();
                let nh = if nh == self.ipv6_addr().unwrap() {
                    ip_repr.dst_addr
                } else {
                    nh
                };

                net_trace!(
                    "[FORWARDING] destination in sub-tree, forwarding to: {}",
                    nh
                );

                nh
            }
            #[cfg(feature = "rpl-mop-2")]
            RplModeOfOperation::StoringModeWithoutMulticast if rpl.has_parent() => {
                net_trace!("[FORWARDING] forwarding to parent");
                if let Some(hbh) = &mut hbh {
                    hbh.down = false;
                }
                rpl.parent_address.unwrap()
            }
            #[cfg(feature = "rpl-mop-2")]
            RplModeOfOperation::StoringModeWithoutMulticast => {
                net_trace!("[FORWARDING] cannot forward, no parent");
                return None;
            }
        };

        match ip_repr.next_header {
            IpProtocol::Tcp => todo!(),
            IpProtocol::Udp => {
                let udp = UdpPacket::new_checked(payload).unwrap();
                let udp_repr = UdpRepr::parse(
                    &udp,
                    &ip_repr.src_addr.into(),
                    &ip_repr.dst_addr.into(),
                    &self.checksum_caps(),
                )
                .unwrap();

                ip_repr.payload_len = udp_repr.header_len() + udp.payload().len();
                let mut packet =
                    IpPacket::forward(ip_repr, (udp_repr, udp.payload()), Some(forward_to), hbh);
                packet.routing = routing;
                Some(packet)
            }
            IpProtocol::Icmpv6 => {
                let icmp = Icmpv6Packet::new_checked(payload).unwrap();
                let icmp_repr = Icmpv6Repr::parse(
                    &ip_repr.src_addr.into(),
                    &ip_repr.dst_addr.into(),
                    &icmp,
                    &self.checksum_caps(),
                )
                .unwrap();
                ip_repr.payload_len = icmp_repr.buffer_len();

                let mut packet = IpPacket::forward(ip_repr, icmp_repr, Some(forward_to), hbh);
                packet.routing = routing;

                Some(packet)
            }
            _ => todo!(),
        }
    }
}
