use super::*;

use super::super::rpl::*;
use crate::wire::*;

impl InterfaceInner {
    /// Return a reference to the RPL information.
    pub fn rpl(&self) -> &RplInstance {
        &self.rpl
    }

    /// Return a mutable reference to the RPL information.
    pub fn rpl_mut(&mut self) -> &mut RplInstance {
        &mut self.rpl
    }

    /// Process an incoming RPL packet.
    pub(super) fn process_rpl<'output, 'payload: 'output>(
        &mut self,
        src_ll_addr: Option<HardwareAddress>,
        ip_repr: Ipv6Repr,
        repr: RplRepr<'payload>,
    ) -> Option<IpPacket<'output>> {
        match repr {
            RplRepr::DodagInformationSolicitation { .. } => self.process_rpl_dis(ip_repr, repr),
            RplRepr::DodagInformationObject { .. } => {
                self.process_rpl_dio(src_ll_addr, ip_repr, repr)
            }
            RplRepr::DestinationAdvertisementObject { .. } => self.process_rpl_dao(ip_repr, repr),
            RplRepr::DestinationAdvertisementObjectAck { .. } => {
                net_trace!("[DAO-ACK] received DAO-ACK, which is not supported yet");
                None
            }
        }
    }

    /// Process an incoming RPL DIS packet.
    ///
    /// When processing a DIS packet, we first check if the Solicited Information is present. This
    /// option has predicates that we need to match on, if the option is present. It is used as a
    /// filtering mechanism.
    ///
    /// When receiving and validating a DIS message, we need to reset our Trickle timer. More
    /// information can be found in RFC6550 8.3.
    ///
    /// When receiving a unicast DIS message, we should respond with a unicast DIO message, instead
    /// of a multicast message.
    pub(super) fn process_rpl_dis<'output, 'payload: 'output>(
        &mut self,
        ip_repr: Ipv6Repr,
        repr: RplRepr<'payload>,
    ) -> Option<IpPacket<'output>> {
        match repr {
            RplRepr::DodagInformationSolicitation { options } => {
                let src_addr = self.ipv6_addr().unwrap();

                for opt in &options {
                    match opt {
                        // Skip padding
                        RplOptionRepr::Pad1 | RplOptionRepr::PadN(_) => (),

                        // The solicited information option is used for filtering incoming DIS
                        // packets. This option will contain predicates, which we need to match on.
                        // When we match all to requested predicates, then we answer with a DIO,
                        // otherwise we just drop the packet. See section 8.3 for more information.
                        RplOptionRepr::SolicitedInformation {
                            rpl_instance_id,
                            version_predicate,
                            instance_id_predicate,
                            dodag_id_predicate,
                            dodag_id,
                            version_number,
                        } => {
                            let InterfaceInner { rpl, .. } = self;

                            if (*version_predicate
                                && rpl.version_number
                                    != lollipop::SequenceCounter::new(*version_number))
                                || (*instance_id_predicate && rpl.instance_id != *rpl_instance_id)
                                || (*dodag_id_predicate && rpl.dodag_id != Some(*dodag_id))
                            {
                                net_trace!("[RPL DIS] predicates did not match, dropping packet");
                                return None;
                            }
                        }
                        _ => net_trace!("[RPL DIS] received invalid option"),
                    }
                }

                // When receiving a unicast DIS message, we should respond we a unicast DIO
                // message, containing the DODAG Information option, without resetting the Trickle
                // timer.
                if ip_repr.dst_addr.is_unicast() {
                    net_trace!("[RPL DIS] sending unicast DIO");

                    let InterfaceInner { rpl, .. } = self;

                    let mut options = heapless::Vec::new();
                    options.push(rpl.dodag_configuration()).unwrap();

                    let icmp = Icmpv6Repr::Rpl(rpl.dodag_information_object(options));

                    Some(IpPacket::new(
                        Ipv6Repr {
                            src_addr,
                            dst_addr: ip_repr.dst_addr,
                            next_header: IpProtocol::Icmpv6,
                            payload_len: icmp.buffer_len(),
                            hop_limit: 64,
                        },
                        icmp,
                    ))
                } else {
                    net_trace!("[RPL DIS] resetting trickle timer");

                    // Resest the trickle timer (section 8.3)
                    let InterfaceInner { now, rand, rpl, .. } = self;
                    rpl.dio_timer.hear_inconsistency(*now, rand);
                    None
                }
            }
            _ => unreachable!(),
        }
    }

    /// Process an incoming RPL DIO packet.
    pub(super) fn process_rpl_dio<'output, 'payload: 'output>(
        &mut self,
        src_ll_addr: Option<HardwareAddress>,
        ip_repr: Ipv6Repr,
        repr: RplRepr<'payload>,
    ) -> Option<IpPacket<'output>> {
        match repr {
            RplRepr::DodagInformationObject {
                rpl_instance_id,
                version_number,
                rank,
                grounded,
                mode_of_operation,
                dodag_preference,
                dtsn,
                dodag_id,
                options,
            } => {
                let InterfaceInner { rpl, .. } = self;
                let sender_rank = Rank::new(rank, rpl.minimum_hop_rank_increase);

                // Process the options.
                for opt in &options {
                    match opt {
                        // Skip padding
                        RplOptionRepr::Pad1 | RplOptionRepr::PadN(_) => (),

                        RplOptionRepr::DagMetricContainer => {
                            // NOTE(thvdveld): We don't support DAG Metric containers yet. They contain
                            // information about node, link or path metrics specified in RFC6551. The
                            net_trace!("[RPL DIO] Dag Metric Container Option not yet supported");
                        }
                        RplOptionRepr::RouteInformation { .. } => {
                            // The root of a DODAG is responsible for setting the option values.

                            // NOTE: RIOT and Contiki-NG don't implement the handling of the route
                            // information option. smoltcp does not handle prefic information
                            // packets, neither does it handle the route information packets from
                            // RFC4191. Therefore, the infrastructure is not in place for handling
                            // this option in RPL. This is considered future work!
                            net_trace!("[RPL DIO] Route Information Option not yet supported");
                        }
                        RplOptionRepr::DodagConfiguration {
                            objective_code_point,
                            ..
                        } => {
                            // If we are not part of a network, and the OCP is not the same as
                            // ours, then we don't accept the DIO packet.
                            if rpl.parent_address.is_none()
                                && *objective_code_point != rpl.objective_code_point
                            {
                                net_trace!("[RPL DIO] dropping packet, OCP is not compatible");
                                return None;
                            }

                            // The dodag configuration option contains information about how the DODAG
                            // operates.
                            //
                            // *NOTE*: The RFC states that nobody can modify this information, unless
                            // it's the root. However, upon receiving this information, we don't know
                            // if it's coming from the root. We can choose to always accept this
                            // information. In this case we assume that link layer communication is
                            // secured. When the communication is not secure, then this information
                            // can be changed by an attacker.
                            rpl.update_dodag_configuration(opt);
                        }
                        // The root of a DODAG is responsible for setting the option values.
                        // This information is propagated down the DODAG unchanged.
                        RplOptionRepr::PrefixInformation { .. } => {
                            // FIXME(thvdveld): handle a prefix information option.
                            net_trace!("[RPL DIO] Prefix Information Option not yet supported");
                        }
                        _ => net_trace!("[RPL DIO] Received invalid option"),
                    }
                }

                // If we don't have a parent yet, then we didn't join a RPL network. So we just
                // accept the first one, if the mode of operation is the same and the rank of the
                // sender is not INFINITE.
                if !rpl.is_root
                    && rpl.parent_address.is_none()
                    && ModeOfOperation::from(mode_of_operation) == rpl.mode_of_operation
                    && sender_rank != Rank::INFINITE
                {
                    net_trace!("[RPL DIO] accepting new RPL network settings");
                    net_trace!("  - Grounded: {grounded}");
                    net_trace!("  - Preference: {dodag_preference}");
                    net_trace!("  - Version: {version_number}");
                    net_trace!("  - Instance ID: {rpl_instance_id:?}");
                    net_trace!("  - DODAG ID: {dodag_id}");

                    rpl.grounded = grounded;
                    rpl.mode_of_operation = mode_of_operation.into();
                    rpl.preference = dodag_preference;
                    rpl.version_number = SequenceCounter::new(version_number);
                    rpl.instance_id = rpl_instance_id;
                    rpl.dodag_id = Some(dodag_id);
                }

                // We check if we can accept the DIO message:
                // 1. The RPL instance is the same as our RPL instance.
                // 2. The DODAG ID must be the same as our DODAG ID.
                // 3. The version number must be the same or higher than ours.
                // 4. The Mode of Operation must be the same as our Mode of Operation.
                // 5. The Objective Function must be the same as our Ojbective ObjectiveFunction,
                //    which we already checked.
                if rpl_instance_id != rpl.instance_id
                    || rpl.dodag_id != Some(dodag_id)
                    || ModeOfOperation::from(mode_of_operation) != rpl.mode_of_operation
                    || version_number < rpl.version_number.value()
                {
                    net_trace!("[RPL DIO] dropping DIO packet");
                    return None;
                }

                // If the Version number is higher than ours, we need to clear our parent set,
                // remove our parent and reset our rank.
                //
                // When we are the root, we change the version number to one higher than the
                // received one. Then we reset the Trickle timer, such that the information is
                // propagated in the network.
                if SequenceCounter::new(version_number) > rpl.version_number {
                    net_trace!("[RPL DIO] version number higher than ours");

                    if rpl.is_root {
                        net_trace!("[RPL DIO] (root) using new version number + 1");

                        rpl.version_number = SequenceCounter::new(version_number);
                        rpl.version_number.increment();

                        net_trace!("[RPL DIO] resetting Trickle timer");
                        // Reset the trickle timer.
                        rpl.dio_timer.hear_inconsistency(self.now, &mut self.rand);
                    } else {
                        net_trace!(
                            "[RPL DIO] resetting parent set, resetting rank, \
                                removing parent"
                        );

                        // Clear the parent set, .
                        self.rpl_parent_set.clear();

                        // Remove our parent.
                        rpl.parent_address = None;
                        rpl.parent_rank = None;
                        rpl.parent_preference = None;
                        rpl.parent_last_heard = None;

                        rpl.rank = Rank::INFINITE;
                    }
                }

                // If the rank is smaller than ours, the instance id and the mode of operation is
                // the same as ours,, we can add the sender to our parent set.
                if sender_rank < rpl.rank && !rpl.is_root {
                    net_trace!("[RPL DIO] adding {} to parent set", ip_repr.src_addr);

                    self.rpl_parent_set.add_parent(
                        Parent::new(
                            ip_repr.src_addr,
                            sender_rank,
                            dodag_preference.into(),
                            SequenceCounter::new(version_number),
                        ),
                        self.now,
                    );
                }

                // Add the sender to our neighbor cache.
                self.neighbor_cache.fill_with_expiration(
                    ip_repr.src_addr.into(),
                    src_ll_addr.unwrap(),
                    self.now + rpl.dio_timer.max_expiration(),
                );

                // If our parent transmits a DIO with an infinite rank, than it means that our
                // parent is leaving the network. Thus we should deselect it as our parent.
                // If there is no parent in the parent set, we also detach from the network by
                // sending a DIO with an infinite rank.
                if Some(ip_repr.src_addr) == rpl.parent_address {
                    if Rank::new(rank, rpl.rank.min_hop_rank_increase) == Rank::INFINITE {
                        net_trace!("[RPL DIO] parent leaving, removing parent");

                        // Remove the parent from our parent set.
                        self.rpl_parent_set.remove_parent(&ip_repr.src_addr);

                        if self.rpl_parent_set.is_empty() {
                            net_trace!("[RPL DIO] no potential parents, leaving network");

                            // Since our parent is detaching, we are also detaching (since we don't
                            // have multiple parents).
                            let src_addr = self.ipv6_addr().unwrap();
                            let icmp = Icmpv6Repr::Rpl(self.remove_parent());

                            return Some(IpPacket::new(
                                Ipv6Repr {
                                    src_addr,
                                    dst_addr: Ipv6Address::LINK_LOCAL_ALL_RPL_NODES,
                                    next_header: IpProtocol::Icmpv6,
                                    payload_len: icmp.buffer_len(),
                                    hop_limit: 64,
                                },
                                icmp,
                            ));
                        }
                    } else {
                        net_trace!("[RPL DIO] information from parent, updating ours");
                        // Update our information when the information is coming from our parent, and
                        // its rank is not infinite.
                        rpl.grounded = grounded;
                        rpl.mode_of_operation = mode_of_operation.into();
                        rpl.preference = dodag_preference;
                        rpl.version_number = SequenceCounter::new(version_number);
                        rpl.instance_id = rpl_instance_id;
                        rpl.dodag_id = Some(dodag_id);

                        rpl.parent_last_heard = Some(self.now);
                    }
                }

                // Check if the DIO message is coming from a neighbor that could be our new
                // parent. For this, the DIO rank must be smaller than ours.
                if sender_rank < rpl.rank {
                    // Check for a preferred parent:
                    if let Some(preferred_parent) =
                        of0::ObjectiveFunction0::preferred_parent(&self.rpl_parent_set)
                    {
                        // Accept the preferred parent as new parent when we don't have a
                        // parent yet, or when we have a parent, but its rank is lower than
                        // the preferred parent, or when the rank is the same but the preference is
                        // higher.
                        if !rpl.has_parent()
                            || preferred_parent.rank.dag_rank()
                                < rpl.parent_rank.unwrap().dag_rank()
                            || (preferred_parent.rank.dag_rank()
                                == rpl.parent_rank.unwrap().dag_rank()
                                && preferred_parent.preference > rpl.parent_preference.unwrap())
                        {
                            net_trace!(
                                "[RPL DIO] selecting {} as new parent",
                                preferred_parent.ip_addr
                            );
                            rpl.parent_last_heard = Some(self.now);

                            // In case of MOP1, MOP2 and (maybe) MOP3, a DAO packet needs to be
                            // transmitted with this information.
                            return self.select_parent(&preferred_parent);
                        }
                    }
                }

                // We should increment the Trickle timer counter for a valid DIO message,
                // when we are the root, and the rank that is advertised in the DIO message is
                // not infinite (so we received a valid DIO from a child).
                //
                // When we are not the root, we hear a consistency, when the DIO message is from
                // our parent and is valid. The validity of the message should be checked when we
                // reach this line.
                if rpl.is_root && sender_rank != rank::Rank::INFINITE
                    || rpl.parent_address == Some(ip_repr.src_addr)
                {
                    net_trace!("[RPL DIO] hearing consistency");
                    self.rpl.dio_timer.hear_consistency();
                }

                None
            }
            _ => unreachable!(),
        }
    }

    pub(super) fn process_rpl_dao<'output, 'payload: 'output>(
        &mut self,
        ip_repr: Ipv6Repr,
        repr: RplRepr<'payload>,
    ) -> Option<IpPacket<'output>> {
        let our_addr = self.ipv6_addr().unwrap();
        match repr {
            RplRepr::DestinationAdvertisementObject {
                rpl_instance_id,
                dodag_id,
                ref options,
                ..
            } => {
                let InterfaceInner { rpl, .. } = self;

                if rpl.instance_id != rpl_instance_id && rpl.dodag_id != dodag_id {
                    net_trace!("[RPL DAO] dropping packet");
                    return None;
                }

                if matches!(
                    rpl.mode_of_operation,
                    ModeOfOperation::NoDownwardRoutesMaintained
                ) {
                    net_trace!("[RPL DAO] received DAO message, which is not supported in MOP0");
                    return None;
                }

                #[cfg(feature = "rpl-mop-1")]
                if matches!(rpl.mode_of_operation, ModeOfOperation::NonStoringMode) && !rpl.is_root
                {
                    net_trace!("[RPL DAO] forwarding DAO to root");
                    // Forward the DAO to the root, via our parent.
                    return Some(IpPacket::forward(
                        ip_repr,
                        Icmpv6Repr::Rpl(repr),
                        rpl.parent_address,
                        Some(RplHopByHopRepr {
                            down: false,
                            rank_error: false,
                            forwarding_error: false,
                            instance_id: rpl.instance_id,
                            sender_rank: rpl.rank.raw_value(),
                        }),
                    ));
                }

                let mut child = None;
                let mut lifetime = None;
                let mut sequence = None;
                let mut prefix_length = None;
                let mut parent = None;

                for opt in options {
                    match opt {
                        //skip padding
                        RplOptionRepr::Pad1 | RplOptionRepr::PadN(_) => (),
                        RplOptionRepr::RplTarget {
                            prefix_length: pl,
                            prefix,
                        } => {
                            prefix_length = Some(*pl);
                            child = Some(*prefix);
                        }
                        RplOptionRepr::TransitInformation {
                            path_sequence,
                            path_lifetime,
                            parent_address,
                            ..
                        } => {
                            lifetime = Some(*path_lifetime);
                            sequence = Some(*path_sequence);
                            parent = if let Some(parent) = *parent_address {
                                Some(parent)
                            } else {
                                match rpl.mode_of_operation {
                                    ModeOfOperation::NoDownwardRoutesMaintained => todo!(),
                                    #[cfg(feature = "rpl-mop-1")]
                                    ModeOfOperation::NonStoringMode => {
                                        net_debug!(
                                            "[RPL DAO] Parent Address required for MOP1, dropping packet"
                                        );
                                        return None;
                                    }
                                    #[cfg(feature = "rpl-mop-2")]
                                    ModeOfOperation::StoringModeWithoutMulticast => {
                                        Some(ip_repr.src_addr)
                                    }
                                }
                            };
                        }
                        RplOptionRepr::RplTargetDescriptor { .. } => {
                            net_trace!("[RPL DAO] Target Descriptor Option not yet supported");
                        }
                        _ => net_trace!("[RPL DAO] received invalid option"),
                    }
                }

                // Remove stale relations.
                self.relations.purge(self.now);

                if let (
                    Some(child),
                    Some(lifetime),
                    Some(sequence),
                    Some(_prefix_length),
                    Some(parent),
                ) = (child, lifetime, sequence, prefix_length, parent)
                {
                    net_trace!("[RPL DAO] Adding {} => {} relation", child, parent);

                    //Create the relation with the child and parent addresses extracted from the options
                    self.relations.add_relation_checked(
                        &child,
                        RelationInfo {
                            next_hop: parent,
                            expires_at: self.now + Duration::from_secs(lifetime as u64),
                            dao_sequence: SequenceCounter::new(sequence),
                        },
                    );

                    #[cfg(feature = "rpl-mop-2")]
                    if matches!(
                        rpl.mode_of_operation,
                        ModeOfOperation::StoringModeWithoutMulticast
                    ) && !rpl.is_root
                    {
                        net_trace!("[RPL DAO] forwarding relation information to parent");

                        // Send message upward.
                        let mut options = heapless::Vec::new();
                        options
                            .push(RplOptionRepr::RplTarget {
                                prefix_length: 128,
                                prefix: child,
                            })
                            .unwrap();
                        options
                            .push(RplOptionRepr::TransitInformation {
                                external: false,
                                path_control: 0,
                                path_sequence: 0,
                                path_lifetime: 30,
                                parent_address: None,
                            })
                            .unwrap();

                        let icmp = Icmpv6Repr::Rpl(
                            rpl.destination_advertisement_object(Default::default(), options),
                        );

                        // Selecting new parent (so new information).
                        rpl.dao_seq_number.increment();

                        return Some(IpPacket::new(
                            Ipv6Repr {
                                src_addr: our_addr,
                                dst_addr: rpl.parent_address.unwrap(),
                                next_header: IpProtocol::Icmpv6,
                                payload_len: icmp.buffer_len(),
                                hop_limit: 64,
                            },
                            icmp,
                        ));
                    }
                } else {
                    net_trace!("[RPL DAO] not all required info received for adding relation");
                }

                None
            }
            _ => unreachable!(),
        }
    }

    pub(super) fn process_rpl_hopbyhop<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ll_src_addr: Option<HardwareAddress>,
        mut ipv6_repr: Ipv6Repr,
        ext_hdr: Ipv6ExtHeaderRepr,
        mut hbh: RplHopByHopRepr,
        ip_payload: &'frame [u8],
    ) -> Option<IpPacket<'frame>> {
        let sender_rank = Rank::new(hbh.sender_rank, self.rpl.minimum_hop_rank_increase);

        if hbh.rank_error {
            net_trace!("[RPL HBH] contains rank error, resetting trickle timer, dropping packet");

            let InterfaceInner { rpl, now, rand, .. } = self;
            rpl.dio_timer.hear_inconsistency(*now, rand);
            return None;
        }

        // Check for inconsistencies (see 11.2.2.2), which are:
        //  - If the packet is going down, and the sender rank is higher or equal as ours.
        //  - If the packet is going up, and the sender rank is lower or equal as ours.
        if (hbh.down && self.rpl.rank <= sender_rank) || (!hbh.down && self.rpl.rank >= sender_rank)
        {
            net_trace!("[RPL HBH] inconsistency detected, setting Rank-Error");
            hbh.rank_error = true;
        }

        // If the packet is not for us, we forward the packet.
        if ipv6_repr.dst_addr.is_unicast() && !self.has_ip_addr(ipv6_repr.dst_addr) {
            // Replace the next header field in the IPv6 header by the next header of the
            // hop-by-hop header.
            ipv6_repr.next_header = ext_hdr.next_header;

            return self.forward(
                ipv6_repr,
                &ip_payload[ext_hdr.data.len() + 2..],
                None,
                Some(hbh),
            );
        }

        self.process_nxt_hdr(
            sockets,
            ll_src_addr,
            ipv6_repr,
            ext_hdr.next_header,
            false,
            &ip_payload[ext_hdr.data.len() + 2..],
        )
    }

    fn remove_parent<'options>(&mut self) -> RplRepr<'options> {
        let InterfaceInner { rpl, .. } = self;

        rpl.parent_address = None;
        rpl.parent_rank = None;
        rpl.parent_preference = None;
        rpl.parent_last_heard = None;
        rpl.rank = Rank::INFINITE;

        rpl.dodag_information_object(heapless::Vec::new())
    }

    fn select_parent<'options>(&mut self, parent: &Parent) -> Option<IpPacket<'options>> {
        let src_addr = self.ipv6_addr().unwrap();

        let InterfaceInner { rpl, rand, now, .. } = self;

        rpl.parent_address = Some(parent.ip_addr);
        rpl.parent_rank = Some(parent.rank);
        rpl.parent_preference = Some(parent.preference);

        // Recalculate our rank when updating our parent.
        rpl.rank = of0::ObjectiveFunction0::new_rank(rpl.rank, parent.rank);

        // Reset the trickle timer.
        let min = rpl.dio_timer.min_expiration();
        rpl.dio_timer.reset(min, *now, rand);

        // Set our parent as the default route.
        self.routes.add_default_ipv6_route(parent.ip_addr).unwrap();

        // We select a new parent, so we transmit a DAO (for MOP1, MOP2 and
        // MOP3). For MOP2, the Transit Information does not need the parent address.
        if let Some((parent_address, dst_addr)) = match rpl.mode_of_operation {
            ModeOfOperation::NoDownwardRoutesMaintained => None,
            #[cfg(feature = "rpl-mop-1")]
            ModeOfOperation::NonStoringMode => Some((Some(parent.ip_addr), rpl.dodag_id.unwrap())),
            #[cfg(feature = "rpl-mop-2")]
            ModeOfOperation::StoringModeWithoutMulticast => {
                Some((None, rpl.parent_address.unwrap()))
            }
            #[cfg(feature = "rpl-mop-3")]
            ModeOfOperation::StoringModeWithMulticast => todo!(),
        } {
            let mut options = heapless::Vec::new();
            options
                .push(RplOptionRepr::RplTarget {
                    prefix_length: 64,
                    prefix: src_addr,
                })
                .unwrap();
            options
                .push(RplOptionRepr::TransitInformation {
                    external: false,
                    path_control: 0,
                    path_sequence: 0,
                    path_lifetime: 0xff, // Should be 30
                    parent_address,
                })
                .unwrap();

            let icmp =
                Icmpv6Repr::Rpl(rpl.destination_advertisement_object(Default::default(), options));

            // Selecting new parent (so new information).
            rpl.dao_seq_number.increment();

            Some(IpPacket::new(
                Ipv6Repr {
                    src_addr,
                    dst_addr,
                    next_header: IpProtocol::Icmpv6,
                    payload_len: icmp.buffer_len(),
                    hop_limit: 64,
                },
                icmp,
            ))
        } else {
            None
        }
    }
}
