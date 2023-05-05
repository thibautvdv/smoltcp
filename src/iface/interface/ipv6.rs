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

            IpProtocol::HopByHop => self.process_hopbyhop(
                sockets,
                src_ll_addr,
                ipv6_repr,
                handled_by_raw_socket,
                ip_payload,
            ),

            IpProtocol::Ipv6Route => self.process_routing(
                sockets,
                src_ll_addr,
                ipv6_repr,
                handled_by_raw_socket,
                ip_payload,
            ),

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
            Icmpv6Repr::Rpl(rpl) if self.rpl.is_some() => self.process_rpl(
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

    #[cfg(feature = "proto-ipv6")]
    pub(super) fn process_hopbyhop<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ll_src_addr: Option<HardwareAddress>,
        mut ipv6_repr: Ipv6Repr,
        handled_by_raw_socket: bool,
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
                    if let Some(rpl) = self.rpl.as_ref() {
                        let dst = ipv6_repr.dst_addr;

                        if dst.is_unicast() && !self.has_ip_addr(dst) {
                            match rpl.mode_of_operation {
                                crate::iface::RplModeOfOperation::NoDownwardRoutesMaintained => {
                                    if let Some(default_route) = rpl.parent_address {
                                        todo!();
                                    }
                                }
                                #[cfg(feature = "rpl-mop-1")]
                                crate::iface::RplModeOfOperation::NonStoringMode => {
                                    ipv6_repr.next_header = hbh_repr.next_header;
                                    return self.forward(
                                        ipv6_repr,
                                        &ip_payload[ext_hdr.payload().len() + 2..],
                                        None,
                                        Some(rpl_hop_by_hop),
                                    );
                                }
                                #[cfg(feature = "rpl-mop-2")]
                                crate::iface::RplModeOfOperation::StoringModeWithoutMulticast => {
                                    ipv6_repr.next_header = hbh_repr.next_header;
                                    return self.forward(
                                        ipv6_repr,
                                        &ip_payload[ext_hdr.payload().len() + 2..],
                                        None,
                                        Some(rpl_hop_by_hop),
                                    );
                                }
                            }
                        }
                    }
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
            handled_by_raw_socket,
            &ip_payload[ext_hdr.payload().len() + 2..],
        )
    }

    pub(super) fn process_routing<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ll_src_addr: Option<HardwareAddress>,
        mut ipv6_repr: Ipv6Repr,
        handled_by_raw_socket: bool,
        ip_payload: &'frame [u8],
    ) -> Option<IpPacket<'frame>> {
        let ext_hdr = check!(Ipv6ExtHeader::new_checked(ip_payload));

        let routing_header = check!(Ipv6RoutingHeader::new_checked(ext_hdr.payload()));

        let mut routing_repr = check!(Ipv6RoutingRepr::parse(&routing_header));

        net_trace!("Processing");
        dbg!(&routing_repr);

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
            handled_by_raw_socket,
            &ip_payload[ext_hdr.payload().len() + 2..],
        )
    }

    #[cfg(feature = "proto-ipv6")]
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
    fn forward<'frame>(
        &self,
        mut ip_repr: Ipv6Repr,
        payload: &'frame [u8],
        mut routing: Option<Ipv6RoutingRepr>,
        mut hbh: Option<RplHopByHopRepr>,
    ) -> Option<IpPacket<'frame>> {
        let mut to = ip_repr.dst_addr;

        if let Some(rpl) = &self.rpl {
            // Change the sender rank to our own rank.

            if let Some(hbh) = &mut hbh {
                hbh.sender_rank = rpl.rank.raw_value();
            }

            match rpl.mode_of_operation {
                #[cfg(feature = "rpl-mop-0")]
                crate::iface::RplModeOfOperation::NoDownwardRoutesMaintained => {
                    if let Some(parent) = rpl.parent_address {
                        if let Some(hbh) = &mut hbh {
                            hbh.down = false;
                        }
                        to = parent
                    } else {
                        net_debug!("Unable to forward, no parent yet.");
                        return None;
                    }
                }

                #[cfg(feature = "rpl-mop-1")]
                crate::iface::RplModeOfOperation::NonStoringMode => {
                    if rpl.is_root {
                        // Look the route to be used in the source routing header.
                        let mut route = heapless::Vec::<Ipv6Address, 32>::new();

                        // The destination should be reachable in 32 hops, otherwise, we'll have an
                        // infenite loop here.
                        let mut next_hop = ip_repr.dst_addr;
                        route.push(next_hop).unwrap();

                        loop {
                            next_hop = rpl.relations.find_next_hop(&next_hop).unwrap();
                            if next_hop == self.ipv6_addr().unwrap() {
                                break;
                            } else {
                                route.push(next_hop).unwrap();
                            }
                        }

                        net_trace!("Creating the source routes");
                        dbg!(&route);

                        if route.is_empty() {
                            // Don't use source routing header, but just transmit to the neighbor.
                            if let Some(hbh) = &mut hbh {
                                hbh.down = true;
                            }
                            to = ip_repr.dst_addr;
                        } else {
                            let len = route.len();
                            to = route[len - 1];

                            let mut addresses = heapless::Vec::new();
                            for addr in route[..len - 1].iter().rev() {
                                addresses.push(*addr).unwrap();
                            }

                            net_trace!("Routing header routes:");
                            dbg!(&addresses);

                            ip_repr.dst_addr = to;
                            // Add the source routing option to the packet.
                            routing = Some(Ipv6RoutingRepr::Rpl {
                                segments_left: route.len() as u8 - 1,
                                cmpr_i: 0,
                                cmpr_e: 0,
                                pad: 0,
                                addresses,
                            });

                            net_trace!("Routing header created");
                            dbg!(&routing);
                        }
                    } else if routing.is_some() {
                    } else if let Some(parent) = rpl.parent_address {
                        if let Some(hbh) = &mut hbh {
                            hbh.down = false;
                        }
                        to = parent
                    } else {
                        net_debug!("Unable to forward, no parent yet.");
                        return None;
                    }
                }

                #[cfg(feature = "rpl-mop-2")]
                crate::iface::RplModeOfOperation::StoringModeWithoutMulticast => {
                    // First look if we know that the destination is in our sub-tree.
                    // Otherwise, try to send it up to our parent.
                    if let Some(nh) = rpl.relations.find_next_hop(&to) {
                        if let Some(hbh) = &mut hbh {
                            hbh.down = true;
                        }
                        to = nh;
                    } else if let Some(parent) = rpl.parent_address {
                        if let Some(hbh) = &mut hbh {
                            hbh.down = false;
                        }
                        to = parent;
                    } else {
                        net_debug!("Destination not in sub-tree, and we don't have a parent yet.");
                        return None;
                    }
                }
            }
        }

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
                    IpPacket::forward(ip_repr, (udp_repr, udp.payload()), Some(to), hbh);
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

                let mut packet = IpPacket::forward(ip_repr, icmp_repr, Some(to), hbh);
                packet.routing = routing;

                Some(packet)
            }
            _ => todo!(),
        }
    }
}
