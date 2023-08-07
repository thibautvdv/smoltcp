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
            RplRepr::DestinationAdvertisementObject { .. } => {
                self.process_rpl_dao(src_ll_addr, ip_repr, repr)
            }
            RplRepr::DestinationAdvertisementObjectAck { .. } => {
                self.process_rpl_dao_ack(ip_repr, repr)
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
        // If we are not the root and we don't have a parent,
        // then we cannot transmit a DIO and thus should drop the DIS.
        if !self.rpl.is_root && !self.rpl.has_parent() {
            return None;
        }

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
                            if (*version_predicate
                                && self.rpl.version_number
                                    != lollipop::SequenceCounter::new(*version_number))
                                || (*instance_id_predicate
                                    && self.rpl.instance_id != *rpl_instance_id)
                                || (*dodag_id_predicate && self.rpl.dodag_id != Some(*dodag_id))
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

                    let mut options = heapless::Vec::new();
                    options.push(self.rpl.dodag_configuration()).unwrap();

                    let icmp = Icmpv6Repr::Rpl(self.rpl.dodag_information_object(options));

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
                    self.rpl
                        .dio_timer
                        .hear_inconsistency(self.now, &mut self.rand);
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
                let src_addr = self.ipv6_addr().unwrap();
                let sender_rank = Rank::new(rank, self.rpl.minimum_hop_rank_increase);

                let mut dodag_configuration = None;

                // Process options
                // ===============
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
                            if self.rpl.parent_address.is_none()
                                && *objective_code_point != self.rpl.objective_code_point
                            {
                                net_trace!("[RPL DIO] dropping packet, OCP is not compatible");
                                return None;
                            }

                            dodag_configuration = Some(opt);
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

                // Accept DIO if not part of DODAG
                // ===============================
                // If we are not part of a DODAG, check the MOP and OCP. If they are the same as
                // ours, we copy the fields of the DIO and the DODAG Configuration. If we cannot
                // check the OCP (because the DODAG Configuration option is missing), then we
                // transmit a unicast DIS to the sender of the DIO we received. The sender MUST
                // respond with a unicast DIO with the option present.
                if !self.rpl.is_root
                    && !self.rpl.has_parent() // not part of a DODAG
                    && ModeOfOperation::from(mode_of_operation) == self.rpl.mode_of_operation
                    && sender_rank != Rank::INFINITE
                {
                    if let Some(
                        opt @ RplOptionRepr::DodagConfiguration {
                            objective_code_point,
                            ..
                        },
                    ) = dodag_configuration
                    {
                        if *objective_code_point == self.rpl.objective_code_point {
                            net_trace!("[RPL DIO] accepting new RPL network settings");
                            net_trace!("  - Grounded: {}", grounded);
                            net_trace!("  - Preference: {}", dodag_preference);
                            net_trace!("  - Version: {}", version_number);
                            net_trace!("  - Instance ID: {:?}", rpl_instance_id);
                            net_trace!("  - DODAG ID: {}", dodag_id);

                            self.rpl.grounded = grounded;
                            self.rpl.mode_of_operation = mode_of_operation.into();
                            self.rpl.preference = dodag_preference;
                            self.rpl.version_number = SequenceCounter::new(version_number);
                            self.rpl.instance_id = rpl_instance_id;
                            self.rpl.dodag_id = Some(dodag_id);

                            // Update our DODAG configuration.
                            self.rpl.update_dodag_configuration(opt);
                        } else {
                            return None;
                        }
                    } else {
                        // Send a unicast DIS.
                        net_trace!("[RPL DIO] sending unicast DIS (to ask for DODAG Conf. option)");

                        let icmp = Icmpv6Repr::Rpl(RplRepr::DodagInformationSolicitation {
                            options: Default::default(),
                        });

                        return Some(IpPacket::new(
                            Ipv6Repr {
                                src_addr,
                                dst_addr: ip_repr.dst_addr,
                                next_header: IpProtocol::Icmpv6,
                                payload_len: icmp.buffer_len(),
                                hop_limit: 64,
                            },
                            icmp,
                        ));
                    }
                }

                // Check DIO validity
                // ==================
                // We check if we can accept the DIO message:
                // 1. The RPL instance is the same as our RPL instance.
                // 2. The DODAG ID must be the same as our DODAG ID.
                // 3. The version number must be the same or higher than ours.
                // 4. The Mode of Operation must be the same as our Mode of Operation.
                // 5. The Objective Function must be the same as our Ojbective ObjectiveFunction,
                //    which we already checked.
                if rpl_instance_id != self.rpl.instance_id
                    || self.rpl.dodag_id != Some(dodag_id)
                    || version_number < self.rpl.version_number.value()
                    || ModeOfOperation::from(mode_of_operation) != self.rpl.mode_of_operation
                {
                    net_trace!("[RPL DIO] dropping DIO packet");
                    return None;
                }

                // Global repair
                // =============
                // If the Version number is higher than ours, we need to clear our parent set,
                // remove our parent and reset our rank.
                //
                // When we are the root, we change the version number to one higher than the
                // received one. Then we reset the Trickle timer, such that the information is
                // propagated in the network.
                if SequenceCounter::new(version_number) > self.rpl.version_number {
                    net_trace!("[RPL DIO] version number higher than ours");

                    if self.rpl.is_root {
                        net_trace!("[RPL DIO] (root) using new version number + 1");

                        self.rpl.version_number = SequenceCounter::new(version_number);
                        self.rpl.version_number.increment();

                        net_trace!("[RPL DIO] resetting Trickle timer");
                        // Reset the trickle timer.
                        self.rpl
                            .dio_timer
                            .hear_inconsistency(self.now, &mut self.rand);
                        return None;
                    } else {
                        self.rpl.version_number = SequenceCounter::new(version_number);
                        self.rpl.rank = Rank::INFINITE;

                        let dio =
                            Icmpv6Repr::Rpl(self.rpl.dodag_information_object(Default::default()));

                        net_trace!(
                            "[RPL DIO] resetting parent set, resetting rank, \
                                removing parent"
                        );

                        // Clear the parent set, .
                        self.rpl_parent_set.clear();

                        // Remove our parent.
                        self.rpl.parent_address = None;
                        self.rpl.parent_rank = None;
                        self.rpl.parent_preference = None;
                        self.rpl.parent_last_heard = None;

                        // Transmit a DIO with INFINITE rank, but with an updated Version number.
                        // Everyone knows they have to leave the network and form a new one.
                        return Some(IpPacket::new(
                            Ipv6Repr {
                                src_addr,
                                dst_addr: Ipv6Address::LINK_LOCAL_ALL_RPL_NODES,
                                next_header: IpProtocol::Icmpv6,
                                payload_len: dio.buffer_len(),
                                hop_limit: 64,
                            },
                            dio,
                        ));
                    }
                }

                // Add the sender to our neighbor cache.
                self.neighbor_cache.fill_with_expiration(
                    ip_repr.src_addr.into(),
                    src_ll_addr.unwrap(),
                    self.now + self.rpl.dio_timer.max_expiration(),
                );

                // Remove parent if parent has INFINITE rank
                // =========================================
                // If our parent transmits a DIO with an infinite rank, than it means that our
                // parent is leaving the network. Thus we should deselect it as our parent.
                // If there is no parent in the parent set, we also detach from the network by
                // sending a DIO with an infinite rank.
                if Some(ip_repr.src_addr) == self.rpl.parent_address {
                    if Rank::new(rank, self.rpl.rank.min_hop_rank_increase) == Rank::INFINITE {
                        net_trace!("[RPL DIO] parent leaving, removing parent");

                        // Remove the parent from our parent set.
                        self.rpl_parent_set.remove_parent(&ip_repr.src_addr);

                        // If the parent set is not empty, we can still select a new parent, which
                        // we do lower.
                        if self.rpl_parent_set.is_empty() {
                            net_trace!("[RPL DIO] no potential parents, leaving network");

                            // DIO with INFINITE rank.
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
                        } else {
                            // Select and schedule DAO to new parent.
                            // We don't need to send a no-path DAO, since the parent detatched from
                            // the network.
                            return self.select_preferred_parent();
                        }
                    } else {
                        // DTSN increased, so we need to transmit a DAO.
                        if SequenceCounter::new(dtsn) > self.rpl.dtsn {
                            net_trace!("[RPL DIO] DTSN increased, scheduling DAO.");
                            self.rpl.dao_expiration = self.now;
                        }

                        self.rpl.parent_last_heard = Some(self.now);

                        // Trickle Consistency
                        // ===================
                        // When we are not the root, we hear a consistency when the DIO message is from
                        // our parent and is valid. The validity of the message should be checked when we
                        // reach this line.
                        net_trace!("[RPL DIO] hearing consistency");
                        self.rpl.dio_timer.hear_consistency();

                        return None;
                    }
                }

                // Add node to parent set
                // ======================
                // If the rank is smaller than ours, the instance id and the mode of operation is
                // the same as ours,, we can add the sender to our parent set.
                let no_path_dao = if sender_rank < self.rpl.rank && !self.rpl.is_root {
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

                    // Select parent
                    // =============
                    // Send a no-path DAO to our old parent.
                    // Select and schedule DAO to new parent.
                    self.select_preferred_parent()
                } else {
                    None
                };

                // Trickle Consistency
                // ===================
                // We should increment the Trickle timer counter for a valid DIO message,
                // when we are the root, and the rank that is advertised in the DIO message is
                // not infinite (so we received a valid DIO from a child).
                if self.rpl.is_root && sender_rank != rank::Rank::INFINITE {
                    net_trace!("[RPL DIO] hearing consistency");
                    self.rpl.dio_timer.hear_consistency();
                }

                no_path_dao
            }
            _ => unreachable!(),
        }
    }

    pub(super) fn process_rpl_dao<'output, 'payload: 'output>(
        &mut self,
        src_ll_addr: Option<HardwareAddress>,
        ip_repr: Ipv6Repr,
        repr: RplRepr<'payload>,
    ) -> Option<IpPacket<'output>> {
        let our_addr = self.ipv6_addr().unwrap();
        match repr {
            RplRepr::DestinationAdvertisementObject {
                rpl_instance_id,
                dodag_id,
                expect_ack,
                sequence,
                ref options,
            } => {
                // Check validity of the DAO
                // =========================
                if self.rpl.instance_id != rpl_instance_id && self.rpl.dodag_id != dodag_id {
                    net_trace!("[RPL DAO] dropping packet");
                    return None;
                }

                if matches!(
                    self.rpl.mode_of_operation,
                    ModeOfOperation::NoDownwardRoutesMaintained
                ) {
                    net_trace!("[RPL DAO] received DAO message, which is not supported in MOP0");
                    return None;
                }

                // Add the sender to our neighbor cache.
                self.neighbor_cache.fill_with_expiration(
                    ip_repr.src_addr.into(),
                    src_ll_addr.unwrap(),
                    self.now + self.rpl.dio_timer.max_expiration(),
                );

                #[cfg(feature = "rpl-mop-1")]
                if matches!(self.rpl.mode_of_operation, ModeOfOperation::NonStoringMode)
                    && !self.rpl.is_root
                {
                    net_trace!("[RPL DAO] forwarding DAO to root");
                    let mut options = heapless::Vec::new();
                    options
                        .push(Ipv6OptionRepr::Rpl(RplHopByHopRepr {
                            down: false,
                            rank_error: false,
                            forwarding_error: false,
                            instance_id: self.rpl.instance_id,
                            sender_rank: self.rpl.rank.raw_value(),
                        }))
                        .unwrap();

                    // Forward the DAO to the root, via our parent.
                    return Some(IpPacket::forward(
                        ip_repr,
                        Icmpv6Repr::Rpl(repr),
                        self.rpl.parent_address,
                        Some(Ipv6ExtHeaderRepr {
                            next_header: todo!(),
                            length: todo!(),
                            options,
                        }),
                    ));
                }

                let mut child = None;
                let mut lifetime = None;
                let mut p_sequence = None;
                let mut prefix_length = None;
                let mut parent = None;

                // Process options
                // ===============
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
                            p_sequence = Some(*path_sequence);
                            parent = match self.rpl.mode_of_operation {
                                ModeOfOperation::NoDownwardRoutesMaintained => unreachable!(),

                                #[cfg(feature = "rpl-mop-1")]
                                ModeOfOperation::NonStoringMode => {
                                    if let Some(parent_address) = parent_address {
                                        Some(*parent_address)
                                    } else {
                                        net_debug!(
                                            "[RPL DAO] Parent Address required for MOP1, dropping packet"
                                        );
                                        return None;
                                    }
                                }

                                #[cfg(feature = "rpl-mop-2")]
                                ModeOfOperation::StoringModeWithoutMulticast => {
                                    Some(ip_repr.src_addr)
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
                    Some(_path_sequence),
                    Some(_prefix_length),
                    Some(parent),
                ) = (child, lifetime, p_sequence, prefix_length, parent)
                {
                    net_trace!("[RPL DAO] Adding {} => {} relation", child, parent);

                    //Create the relation with the child and parent addresses extracted from the options
                    self.relations.add_relation_checked(
                        &child,
                        RelationInfo {
                            next_hop: parent,
                            expires_at: self.now
                                + Duration::from_secs(
                                    lifetime as u64 * self.rpl.lifetime_unit as u64,
                                ),
                            dao_sequence: SequenceCounter::new(sequence),
                        },
                    );

                    // Schedule an ACK if requested and the DAO was for us.
                    if expect_ack && ip_repr.dst_addr == our_addr {
                        self.rpl
                            .dao_ack
                            .push((ip_repr.src_addr, SequenceCounter::new(sequence)))
                            .unwrap();
                    }

                    #[cfg(feature = "rpl-mop-2")]
                    if matches!(
                        self.rpl.mode_of_operation,
                        ModeOfOperation::StoringModeWithoutMulticast
                    ) && !self.rpl.is_root
                    {
                        net_trace!("[RPL DAO] forwarding relation information to parent");

                        // Send message upward.
                        let mut options = heapless::Vec::new();
                        options
                            .push(RplOptionRepr::RplTarget {
                                prefix_length: _prefix_length,
                                prefix: child,
                            })
                            .unwrap();
                        options
                            .push(RplOptionRepr::TransitInformation {
                                external: false,
                                path_control: 0,
                                path_sequence: _path_sequence,
                                path_lifetime: lifetime,
                                parent_address: None,
                            })
                            .unwrap();

                        let icmp = Icmpv6Repr::Rpl(
                            self.rpl
                                .destination_advertisement_object(self.rpl.dao_seq_number, options),
                        );

                        // Selecting new parent (so new information).
                        self.rpl.dao_seq_number.increment();

                        return Some(IpPacket::new(
                            Ipv6Repr {
                                src_addr: our_addr,
                                dst_addr: self.rpl.parent_address.unwrap(),
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

    pub(super) fn process_rpl_dao_ack<'output, 'payload: 'output>(
        &mut self,
        ip_repr: Ipv6Repr,
        repr: RplRepr<'payload>,
    ) -> Option<IpPacket<'output>> {
        match repr {
            RplRepr::DestinationAdvertisementObjectAck {
                rpl_instance_id,
                sequence,
                status,
                dodag_id,
            } => {
                if rpl_instance_id == self.rpl.instance_id && dodag_id == self.rpl.dodag_id {
                    if status == 0 {
                        self.rpl.daos.retain(|dao| {
                            !(dao.to == ip_repr.src_addr
                                && dao.sequence == Some(SequenceCounter::new(sequence)))
                        });

                        net_trace!("[RPL DAO-ACK] DAO {} acknowledged", sequence);
                    } else {
                        // FIXME: the node should do something correct here.
                        net_trace!("[RPL DAO-ACK] ACK status was {}", status);
                    }
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

            self.rpl
                .dio_timer
                .hear_inconsistency(self.now, &mut self.rand);
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

        // Set the sender rank to our own now.
        hbh.sender_rank = self.rpl.rank.raw_value();

        self.process_nxt_hdr(
            sockets,
            ll_src_addr,
            ipv6_repr,
            ext_hdr.next_header,
            false,
            &ip_payload[ext_hdr
                .options
                .iter()
                .map(|o| o.buffer_len())
                .sum::<usize>()
                + 2..],
        )
    }

    fn remove_parent<'options>(&mut self) -> RplRepr<'options> {
        self.rpl.parent_address = None;
        self.rpl.parent_rank = None;
        self.rpl.parent_preference = None;
        self.rpl.parent_last_heard = None;
        self.rpl.rank = Rank::INFINITE;

        self.rpl.dodag_information_object(heapless::Vec::new())
    }

    fn select_preferred_parent<'options>(&mut self) -> Option<IpPacket<'options>> {
        if let Some(preferred_parent) =
            of0::ObjectiveFunction0::preferred_parent(&self.rpl_parent_set)
        {
            // Accept the preferred parent as new parent when we don't have a
            // parent yet, or when we have a parent, but its rank is lower than
            // the preferred parent, or when the rank is the same but the preference is
            // higher.
            if !self.rpl.has_parent()
                || preferred_parent.rank.dag_rank() < self.rpl.parent_rank.unwrap().dag_rank()
            {
                net_trace!(
                    "[RPL DIO] selecting {} as new parent",
                    preferred_parent.ip_addr
                );
                self.rpl.parent_last_heard = Some(self.now);

                // Schedule a DAO after we send a no-path dao.
                net_trace!("[RPL DIO] scheduling DAO");
                self.rpl.dao_expiration = self.now;

                // In case of MOP1, MOP2 and (maybe) MOP3, a DAO packet needs to be
                // transmitted with this information.
                return self.select_parent(self.rpl.parent_address, &preferred_parent);
            }
        }

        None
    }

    fn select_parent<'options>(
        &mut self,
        old_parent: Option<Ipv6Address>,
        parent: &Parent,
    ) -> Option<IpPacket<'options>> {
        let no_path = if let Some(old_parent) = old_parent {
            self.no_path_dao(old_parent)
        } else {
            // If there was no old parent, then we don't need to transmit a no-path DAO.
            None
        };

        self.rpl.parent_address = Some(parent.ip_addr);
        self.rpl.parent_rank = Some(parent.rank);

        // Recalculate our rank when updating our parent.
        self.rpl.rank = of0::ObjectiveFunction0::new_rank(self.rpl.rank, parent.rank);

        // Reset the trickle timer.
        let min = self.rpl.dio_timer.min_expiration();
        self.rpl.dio_timer.reset(min, self.now, &mut self.rand);

        no_path
    }

    fn no_path_dao<'options>(&mut self, old_parent: Ipv6Address) -> Option<IpPacket<'options>> {
        let src_addr = self.ipv6_addr().unwrap();

        if self.rpl.mode_of_operation == ModeOfOperation::NoDownwardRoutesMaintained {
            return None;
        }

        #[cfg(feature = "rpl-mop-1")]
        if self.rpl.mode_of_operation == ModeOfOperation::NonStoringMode {
            return None;
        }

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
                path_lifetime: 0, // no-path lifetime
                parent_address: None,
            })
            .unwrap();

        let icmp = Icmpv6Repr::Rpl(
            self.rpl
                .destination_advertisement_object(self.rpl.dao_seq_number, options),
        );

        self.rpl
            .daos
            .push(Dao {
                needs_sending: false,
                sent_at: Some(self.now),
                sent_count: 1,
                to: old_parent,
                child: src_addr,
                parent: None,
                sequence: Some(self.rpl.dao_seq_number),
            })
            .unwrap();

        self.rpl.dao_seq_number.increment();

        Some(IpPacket::new(
            Ipv6Repr {
                src_addr,
                dst_addr: old_parent,
                next_header: IpProtocol::Icmpv6,
                payload_len: icmp.buffer_len(),
                hop_limit: 64,
            },
            icmp,
        ))
    }
}
