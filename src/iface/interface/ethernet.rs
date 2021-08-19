use crate::iface::interface::IpPacket;
use crate::iface::NeighborAnswer;
use crate::iface::NeighborCache;
use crate::phy::Device;
use crate::phy::Medium;
use crate::phy::TxToken;
use crate::socket::Context;
use crate::socket::SocketSet;
use crate::time::Instant;
use crate::wire::*;
use crate::{Error, Result};

use super::Interface;
use super::InterfaceBuilder;
use super::InterfaceInner;

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(feature = "medium-ethernet")]
pub(super) enum EthernetPacket<'a> {
    #[cfg(feature = "proto-ipv4")]
    Arp(ArpRepr),
    Ip(IpPacket<'a>),
}

impl<'a, DeviceT> InterfaceBuilder<'a, DeviceT>
where
    DeviceT: for<'d> Device<'d>,
{
    /// Set the Ethernet address the interface will use. See also
    /// [ethernet_addr].
    ///
    /// # Panics
    /// This function panics if the address is not unicast.
    ///
    /// [ethernet_addr]: struct.Interface.html#method.ethernet_addr
    #[cfg(feature = "medium-ethernet")]
    pub fn ethernet_addr(mut self, addr: EthernetAddress) -> Self {
        InterfaceInner::check_ethernet_addr(&addr);
        self.ethernet_addr = Some(addr);
        self
    }

    /// Set the Neighbor Cache the interface will use.
    #[cfg(feature = "medium-ethernet")]
    pub fn neighbor_cache(mut self, neighbor_cache: NeighborCache<'a>) -> Self {
        self.neighbor_cache = Some(neighbor_cache);
        self
    }
}

impl<'a, DeviceT> Interface<'a, DeviceT>
where
    DeviceT: for<'d> Device<'d>,
{
    /// Get the Ethernet address of the interface.
    ///
    /// # Panics
    /// This function panics if if the interface's medium is not Ethernet.
    #[cfg(feature = "medium-ethernet")]
    pub fn ethernet_addr(&self) -> EthernetAddress {
        self.inner.ethernet_addr.unwrap()
    }

    /// Set the Ethernet address of the interface.
    ///
    /// # Panics
    /// This function panics if the address is not unicast, or if the
    /// interface's medium is not Ethernet.
    #[cfg(feature = "medium-ethernet")]
    pub fn set_ethernet_addr(&mut self, addr: EthernetAddress) {
        assert!(self.device.capabilities().medium == Medium::Ethernet);
        InterfaceInner::check_ethernet_addr(&addr);
        self.inner.ethernet_addr = Some(addr);
    }
}

impl<'a> InterfaceInner<'a> {
    #[cfg(feature = "medium-ethernet")]
    pub(super) fn process_ethernet<'frame, T: AsRef<[u8]>>(
        &mut self,
        cx: &Context,
        sockets: &mut SocketSet,
        frame: &'frame T,
    ) -> Result<Option<EthernetPacket<'frame>>> {
        let eth_frame = EthernetFrame::new_checked(frame)?;

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !eth_frame.dst_addr().is_broadcast()
            && !eth_frame.dst_addr().is_multicast()
            && eth_frame.dst_addr() != self.ethernet_addr.unwrap()
        {
            return Ok(None);
        }

        match eth_frame.ethertype() {
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Arp => self.process_arp(cx.now, &eth_frame),
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload())?;
                if eth_frame.src_addr().is_unicast() && ipv4_packet.src_addr().is_unicast() {
                    // Fill the neighbor cache from IP header of unicast frames.
                    let ip_addr = IpAddress::Ipv4(ipv4_packet.src_addr());
                    if self.in_same_network(&ip_addr) {
                        self.neighbor_cache.as_mut().unwrap().fill(
                            ip_addr,
                            eth_frame.src_addr(),
                            cx.now,
                        );
                    }
                }

                self.process_ipv4(cx, sockets, &ipv4_packet)
                    .map(|o| o.map(EthernetPacket::Ip))
            }
            #[cfg(feature = "proto-ipv6")]
            EthernetProtocol::Ipv6 => {
                let ipv6_packet = Ipv6Packet::new_checked(eth_frame.payload())?;
                if eth_frame.src_addr().is_unicast() && ipv6_packet.src_addr().is_unicast() {
                    // Fill the neighbor cache from IP header of unicast frames.
                    let ip_addr = IpAddress::Ipv6(ipv6_packet.src_addr());
                    if self.in_same_network(&ip_addr)
                        && self
                            .neighbor_cache
                            .as_mut()
                            .unwrap()
                            .lookup(&ip_addr, cx.now)
                            .found()
                    {
                        self.neighbor_cache.as_mut().unwrap().fill(
                            ip_addr,
                            eth_frame.src_addr(),
                            cx.now,
                        );
                    }
                }

                self.process_ipv6(cx, sockets, &ipv6_packet)
                    .map(|o| o.map(EthernetPacket::Ip))
            }
            // Drop all other traffic.
            _ => Err(Error::Unrecognized),
        }
    }

    #[cfg(feature = "medium-ethernet")]
    pub(super) fn check_ethernet_addr(addr: &EthernetAddress) {
        if addr.is_multicast() {
            panic!("Ethernet address {} is not unicast", addr)
        }
    }

    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
    pub(super) fn process_arp<'frame, T: AsRef<[u8]>>(
        &mut self,
        timestamp: Instant,
        eth_frame: &EthernetFrame<&'frame T>,
    ) -> Result<Option<EthernetPacket<'frame>>> {
        let arp_packet = ArpPacket::new_checked(eth_frame.payload())?;
        let arp_repr = ArpRepr::parse(&arp_packet)?;

        match arp_repr {
            // Respond to ARP requests aimed at us, and fill the ARP cache from all ARP
            // requests and replies, to minimize the chance that we have to perform
            // an explicit ARP request.
            ArpRepr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                target_protocol_addr,
                ..
            } => {
                if source_protocol_addr.is_unicast() && source_hardware_addr.is_unicast() {
                    self.neighbor_cache.as_mut().unwrap().fill(
                        source_protocol_addr.into(),
                        source_hardware_addr,
                        timestamp,
                    );
                } else {
                    // Discard packets with non-unicast source addresses.
                    net_debug!("non-unicast source address");
                    return Err(Error::Malformed);
                }

                if operation == ArpOperation::Request && self.has_ip_addr(target_protocol_addr) {
                    Ok(Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Reply,
                        source_hardware_addr: self.ethernet_addr.unwrap(),
                        source_protocol_addr: target_protocol_addr,
                        target_hardware_addr: source_hardware_addr,
                        target_protocol_addr: source_protocol_addr,
                    })))
                } else {
                    Ok(None)
                }
            }
        }
    }

    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv6"))]
    pub(super) fn process_ndisc<'frame>(
        &mut self,
        timestamp: Instant,
        ip_repr: Ipv6Repr,
        repr: NdiscRepr<'frame>,
    ) -> Result<Option<IpPacket<'frame>>> {
        match repr {
            NdiscRepr::NeighborAdvert {
                lladdr,
                target_addr,
                flags,
            } => {
                let ip_addr = ip_repr.src_addr.into();
                match lladdr {
                    Some(lladdr) if lladdr.is_unicast() && target_addr.is_unicast() => {
                        if flags.contains(NdiscNeighborFlags::OVERRIDE)
                            || !self
                                .neighbor_cache
                                .as_mut()
                                .unwrap()
                                .lookup(&ip_addr, timestamp)
                                .found()
                        {
                            self.neighbor_cache
                                .as_mut()
                                .unwrap()
                                .fill(ip_addr, lladdr, timestamp)
                        }
                    }
                    _ => (),
                }
                Ok(None)
            }
            NdiscRepr::NeighborSolicit {
                target_addr,
                lladdr,
                ..
            } => {
                match lladdr {
                    Some(lladdr) if lladdr.is_unicast() && target_addr.is_unicast() => self
                        .neighbor_cache
                        .as_mut()
                        .unwrap()
                        .fill(ip_repr.src_addr.into(), lladdr, timestamp),
                    _ => (),
                }
                if self.has_solicited_node(ip_repr.dst_addr) && self.has_ip_addr(target_addr) {
                    let advert = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
                        flags: NdiscNeighborFlags::SOLICITED,
                        target_addr: target_addr,
                        lladdr: Some(self.ethernet_addr.unwrap()),
                    });
                    let ip_repr = Ipv6Repr {
                        src_addr: target_addr,
                        dst_addr: ip_repr.src_addr,
                        next_header: IpProtocol::Icmpv6,
                        hop_limit: 0xff,
                        payload_len: advert.buffer_len(),
                    };
                    Ok(Some(IpPacket::Icmpv6((ip_repr, advert))))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    #[cfg(feature = "medium-ethernet")]
    pub(super) fn dispatch<Tx>(
        &mut self,
        cx: &Context,
        tx_token: Tx,
        packet: EthernetPacket,
    ) -> Result<()>
    where
        Tx: TxToken,
    {
        match packet {
            #[cfg(feature = "proto-ipv4")]
            EthernetPacket::Arp(arp_repr) => {
                let dst_hardware_addr = match arp_repr {
                    ArpRepr::EthernetIpv4 {
                        target_hardware_addr,
                        ..
                    } => target_hardware_addr,
                };

                self.dispatch_ethernet(cx, tx_token, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(dst_hardware_addr);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
                    arp_repr.emit(&mut packet);
                })
            }
            EthernetPacket::Ip(packet) => self.dispatch_ip(cx, tx_token, packet),
        }
    }

    #[cfg(feature = "medium-ethernet")]
    pub(super) fn dispatch_ethernet<Tx, F>(
        &mut self,
        cx: &Context,
        tx_token: Tx,
        buffer_len: usize,
        f: F,
    ) -> Result<()>
    where
        Tx: TxToken,
        F: FnOnce(EthernetFrame<&mut [u8]>),
    {
        let tx_len = EthernetFrame::<&[u8]>::buffer_len(buffer_len);
        tx_token.consume(cx.now, tx_len, |tx_buffer| {
            debug_assert!(tx_buffer.as_ref().len() == tx_len);
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);
            frame.set_src_addr(self.ethernet_addr.unwrap());

            f(frame);

            Ok(())
        })
    }

    #[cfg(feature = "medium-ethernet")]
    pub(super) fn lookup_hardware_addr<Tx>(
        &mut self,
        cx: &Context,
        tx_token: Tx,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
    ) -> Result<(EthernetAddress, Tx)>
    where
        Tx: TxToken,
    {
        if dst_addr.is_multicast() {
            let b = dst_addr.as_bytes();
            let hardware_addr = match *dst_addr {
                IpAddress::Unspecified => None,
                #[cfg(feature = "proto-ipv4")]
                IpAddress::Ipv4(_addr) => Some(EthernetAddress::from_bytes(&[
                    0x01,
                    0x00,
                    0x5e,
                    b[1] & 0x7F,
                    b[2],
                    b[3],
                ])),
                #[cfg(feature = "proto-ipv6")]
                IpAddress::Ipv6(_addr) => Some(EthernetAddress::from_bytes(&[
                    0x33, 0x33, b[12], b[13], b[14], b[15],
                ])),
            };
            if let Some(hardware_addr) = hardware_addr {
                return Ok((hardware_addr, tx_token));
            }
        }

        let dst_addr = self.route(dst_addr, cx.now)?;

        match self
            .neighbor_cache
            .as_mut()
            .unwrap()
            .lookup(&dst_addr, cx.now)
        {
            NeighborAnswer::Found(hardware_addr) => return Ok((hardware_addr, tx_token)),
            NeighborAnswer::RateLimited => return Err(Error::Unaddressable),
            NeighborAnswer::NotFound => (),
        }

        match (src_addr, dst_addr) {
            #[cfg(feature = "proto-ipv4")]
            (&IpAddress::Ipv4(src_addr), IpAddress::Ipv4(dst_addr)) => {
                net_debug!(
                    "address {} not in neighbor cache, sending ARP request",
                    dst_addr
                );

                let arp_repr = ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Request,
                    source_hardware_addr: self.ethernet_addr.unwrap(),
                    source_protocol_addr: src_addr,
                    target_hardware_addr: EthernetAddress::BROADCAST,
                    target_protocol_addr: dst_addr,
                };

                self.dispatch_ethernet(cx, tx_token, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(EthernetAddress::BROADCAST);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    arp_repr.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()))
                })?;
            }

            #[cfg(feature = "proto-ipv6")]
            (&IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr)) => {
                net_debug!(
                    "address {} not in neighbor cache, sending Neighbor Solicitation",
                    dst_addr
                );

                let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
                    target_addr: dst_addr,
                    lladdr: Some(self.ethernet_addr.unwrap()),
                });

                let packet = IpPacket::Icmpv6((
                    Ipv6Repr {
                        src_addr: src_addr,
                        dst_addr: dst_addr.solicited_node(),
                        next_header: IpProtocol::Icmpv6,
                        payload_len: solicit.buffer_len(),
                        hop_limit: 0xff,
                    },
                    solicit,
                ));

                self.dispatch_ip(cx, tx_token, packet)?;
            }

            _ => (),
        }
        // The request got dispatched, limit the rate on the cache.
        self.neighbor_cache.as_mut().unwrap().limit_rate(cx.now);
        Err(Error::Unaddressable)
    }
}
