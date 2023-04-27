use super::*;

use super::super::rpl::*;
use crate::wire::*;

impl InterfaceInner {
    pub(super) fn process_rpl<'frame>(
        &mut self,
        src_ll_addr: Option<HardwareAddress>,
        ip_repr: Ipv6Repr,
        repr: RplRepr<'frame>,
    ) -> Option<IpPacket<'frame>> {
        match repr {
            RplRepr::DodagInformationSolicitation { .. } => self.process_rpl_dis(ip_repr, repr),
            RplRepr::DodagInformationObject { .. } => {
                self.process_rpl_dio(src_ll_addr, ip_repr, repr)
            }
            RplRepr::DestinationAdvertisementObject { .. } => {
                net_trace!("Received DAO, which is not supported yet.");
                None
            }
            RplRepr::DestinationAdvertisementObjectAck { .. } => {
                net_trace!("Received DAO-ACK, which is not supported yet.");
                None
            }
        }
    }

    pub(super) fn process_rpl_dis<'frame>(
        &mut self,
        ip_repr: Ipv6Repr,
        repr: RplRepr<'frame>,
    ) -> Option<IpPacket<'frame>> {
        match repr {
            RplRepr::DodagInformationSolicitation { options } => {
                let InterfaceInner { rand, rpl, now, .. } = self;
                let rpl = rpl.as_mut().unwrap();

                let options = RplOptionsIterator::new(options);
                for opt in options {
                    let opt = check!(opt);
                    match opt {
                        // Skip padding
                        RplOptionRepr::Pad1 | RplOptionRepr::PadN(_) => (),
                        // This option is used for filtering.
                        RplOptionRepr::SolicitedInformation {
                            rpl_instance_id,
                            version_predicate,
                            instance_id_predicate,
                            dodag_id_predicate,
                            dodag_id,
                            version_number,
                        } => {
                            // Section 8.3:
                            //    o  When a node receives a multicast DIS with a Solicited Information
                            //       option and the node matches all of the predicates in the Solicited
                            //       Information option, unless a DIS flag restricts this behavior.
                            // We check if the predicates are matched. I they don't match we do not
                            // reset the Trickle timer.

                            if (version_predicate
                                && rpl.version_number
                                    != lollipop::SequenceCounter::new(version_number))
                                || (instance_id_predicate && rpl.instance_id != rpl_instance_id)
                                || (dodag_id_predicate && rpl.dodag_id != Some(dodag_id))
                            {
                                return None;
                            }
                        }
                        _ => net_trace!("Received invalid option"),
                    }
                }

                if ip_repr.dst_addr.is_unicast() {
                    // TODO(diana): we should respond to source with a unicast DIO message.
                    // It is used for probiing purposes.
                    return None;
                }

                // Section 8.3:
                //    o  When a node receives a multicast DIS message without a Solicited
                //       Information option, unless a DIS flag restricts this behavior.
                // We reset the Trickle timer.
                rpl.dio_timer.hear_inconsistency(*now, rand);

                None
            }
            _ => unreachable!(),
        }
    }

    pub(super) fn process_rpl_dio<'frame>(
        &mut self,
        src_ll_addr: Option<HardwareAddress>,
        ip_repr: Ipv6Repr,
        repr: RplRepr<'frame>,
    ) -> Option<IpPacket<'frame>> {
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
                let rpl = self.rpl.as_mut().unwrap();
                let mut dio_rank = rank::Rank::new(rank, consts::DEFAULT_MIN_HOP_RANK_INCREASE);
                let mut ocp = None;

                let options = RplOptionsIterator::new(options);
                for opt in options {
                    let opt = check!(opt);
                    match opt {
                        // Skip padding
                        RplOptionRepr::Pad1 | RplOptionRepr::PadN(_) => (),
                        RplOptionRepr::DagMetricContainer => {
                            // NOTE(thvdveld): We don't support DAG Metric containers yet. They contain
                            // information about node, link or path metrics specified in RFC6551. The
                            net_trace!("Dag Metric Container Option not yet supported");
                        }
                        RplOptionRepr::RouteInformation { .. } => {
                            // The root of a DODAG is responsible for setting the option values.

                            // NOTE: RIOT and Contiki-NG don't implement the handling of the route
                            // information option. smoltcp does not handle prefic information
                            // packets, neither does it handle the route information packets from
                            // RFC4191. Therefore, the infrastructure is not in place for handling
                            // this option in RPL. This is considered future work!
                            net_trace!("Route Information Option not yet supported");
                        }
                        RplOptionRepr::DodagConfiguration {
                            minimum_hop_rank_increase,
                            objective_code_point,
                            ..
                        } => {
                            // The dodag configuration option contains information about how the DODAG
                            // operates.

                            // TODO(thvdveld): we should not just accept a dodag configuration.
                            dio_rank.min_hop_rank_increase = minimum_hop_rank_increase;
                            ocp = Some(objective_code_point);
                            rpl.update_dodag_configuration(&opt);
                        }
                        // The root of a DODAG is responsible for setting the option values.
                        // This information is propagated down the DODAG unchanged.
                        RplOptionRepr::PrefixInformation { .. } => {
                            // FIXME(thvdveld): handle a prefix information option.
                            net_trace!("Prefix Information Option not yet supported");
                        }
                        _ => net_trace!("Received invalid option."),
                    }
                }

                // We check if we can accept the DIO message:
                // 1. The RPL instance is the same as our RPL instance.
                // 2. The DODAG ID must be the same as our DODAG ID, unless we haven't selected
                //    one.
                // 3. The version number must be the same as our version number.
                // 4. The Mode of Operation must be the same as our Mode of Operation.
                // 5. The Objective Function must be the same as our Ojbective Function.
                if rpl_instance_id == rpl.instance_id
                    && match rpl.dodag_id {
                        Some(our_dodag_id) if our_dodag_id == dodag_id => true,
                        None => true,
                        _ => false,
                    }
                {
                    if version_number != rpl.version_number.value() {
                        if rpl.is_root {
                            // Reset the DIO trickle timer.
                            let InterfaceInner { rand, now, .. } = self;
                            rpl.dio_timer.hear_inconsistency(*now, rand);
                        } else {
                            // TODO(thvdveld): if a node that is not the root receives a DIO packet with
                            // a different Version Number, then global repair should be triggered
                            // somehow.

                            // For now we ignore the packet when we are a leaf node when the
                            // version number does not matches ours.
                        }
                        return None;
                    }

                    if (ModeOfOperation::from(mode_of_operation) != rpl.mode_of_operation)
                        || (ocp != Some(rpl.objective_code_point))
                    {
                        // We ignore the packet if the Mode of Operation is not the same as ours.
                        // We also ignore the packet if the objective function is different.
                        return None;
                    }

                    // NOTE(thvdveld): this won't work when a custom MinHopRankIncrease value is
                    // used, since the INFINITE rank is constructued with the default value from
                    // the RFC.
                    if Some(ip_repr.src_addr) == rpl.parent_address
                        && rank::Rank::new(rank, rpl.rank.min_hop_rank_increase)
                            == rank::Rank::INFINITE
                    {
                        // Reset the DIO trickle timer.
                        let InterfaceInner { rand, now, .. } = self;
                        rpl.dio_timer.hear_inconsistency(*now, rand);

                        rpl.parent_address = None;
                        rpl.parent_rank = None;
                        rpl.parent_preference = None;
                        rpl.parent_last_heard = None;
                        rpl.rank = rank::Rank::INFINITE;

                        let icmp = Icmpv6Repr::Rpl(RplRepr::DodagInformationObject {
                            rpl_instance_id: rpl.instance_id,
                            version_number: rpl.version_number.value(),
                            rank: rank::Rank::INFINITE.raw_value(),
                            grounded: rpl.grounded,
                            mode_of_operation: rpl.mode_of_operation.into(),
                            dodag_preference: rpl.preference,
                            dtsn: rpl.dtsn.value(),
                            dodag_id: rpl.dodag_id.unwrap(),
                            options: &[],
                        });

                        return Some(IpPacket::Icmpv6((
                            Ipv6Repr {
                                src_addr: self.ipv6_addr().unwrap(),
                                dst_addr: Ipv6Address::LINK_LOCAL_ALL_RPL_NODES,
                                next_header: IpProtocol::Icmpv6,
                                payload_len: icmp.buffer_len(),
                                hop_limit: 64,
                            },
                            icmp,
                        )));
                    }

                    // Update our RPL values from the DIO message:
                    rpl.grounded = grounded;
                    rpl.mode_of_operation = mode_of_operation.into();
                    rpl.preference = dodag_preference;
                    rpl.version_number = lollipop::SequenceCounter::new(version_number);
                    rpl.instance_id = rpl_instance_id;
                    rpl.dodag_id = Some(dodag_id);

                    // Add the Neighbor to our RPL neighbor table.
                    // TODO(thvdveld): check if this is the right place for adding a node to the
                    // neighbour table.
                    rpl.neighbors.add_neighbor(
                        neighbor_table::RplNeighbor::new(
                            src_ll_addr.unwrap(),
                            ip_repr.src_addr,
                            dio_rank.into(),
                            dodag_preference.into(),
                        ),
                        self.now,
                    );

                    // NOTE: we take twice the maximum value the DIO timer can be. This is because
                    // Contiki's Trickle timer can have a maximum value of 1.5 times of the
                    // theoretical maximum value. We didn't look into why this is in Contiki.
                    //
                    // TODO(thvdveld): with the trickle counter timer, DIO messages may not be sent
                    // anymore by neighbours. Thus, the following would not work:
                    rpl.neighbors
                        .purge(self.now, rpl.dio_timer.max_expiration() * 2);

                    // We should increment the Trickle timer counter for a valid DIO message,
                    // when we are the root, and the rank that is advertised in the DIO message is
                    // not infinite.
                    // We also increment it when we hear a valid DIO message from our parent (when
                    // we are not the root, obviously).
                    // At this point, the DIO message should be valid.
                    let mut may_hear_inconsistency =
                        rpl.is_root && dio_rank != rank::Rank::INFINITE;

                    // Check if the DIO message is comming from a neighbor that could be our new
                    // parent. For this, the DIO rank must be smaller than ours.
                    if dio_rank < rpl.rank {
                        if rpl.parent_address == Some(ip_repr.src_addr) {
                            may_hear_inconsistency = true;
                        }

                        let current_parent = rpl.parent_address;

                        // Check for a preferred parent:
                        if let Some(preferred_parent) =
                            of0::ObjectiveFunction0::preferred_parent(&rpl.neighbors)
                        {
                            if Some(preferred_parent.ip_addr()) != current_parent {
                                may_hear_inconsistency = false;
                            }

                            // Accept the preferred parent as new parent when we don't have a
                            // parent yet, or when we have a parent, but its rank is higher than
                            // the preferred parent.
                            if !rpl.has_parent()
                                || preferred_parent.rank().dag_rank()
                                    < rpl.parent_rank.unwrap().dag_rank()
                                || (preferred_parent.rank().dag_rank()
                                    == rpl.parent_rank.unwrap().dag_rank()
                                    && preferred_parent.preference()
                                        > rpl.parent_preference.unwrap())
                            {
                                rpl.parent_address = Some(preferred_parent.ip_addr());
                                rpl.parent_rank = Some(preferred_parent.rank());
                                rpl.parent_preference = Some(preferred_parent.preference());

                                // Recalculate our rank when updating our parent.
                                let new_rank = of0::ObjectiveFunction0::new_rank(
                                    rpl.rank,
                                    // NOTE: we can unwrap, because we just have set it to a value.
                                    rpl.parent_rank.unwrap(),
                                );
                                rpl.rank = new_rank;

                                // Reset the DIO trickle timer.
                                let InterfaceInner { rand, now, .. } = self;

                                let min = rpl.dio_timer.min_expiration();
                                rpl.dio_timer.reset(min, *now, rand);
                            }
                        }

                        if rpl.parent_address == Some(ip_repr.src_addr) {
                            rpl.parent_last_heard = Some(self.now);
                        }
                    }

                    if may_hear_inconsistency {
                        rpl.dio_timer.hear_consistent();
                    }
                }

                None
            }
            _ => unreachable!(),
        }
    }
}
