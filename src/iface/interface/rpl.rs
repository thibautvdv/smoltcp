use super::{InterfaceInner, IpPacket};

use crate::iface::rpl::*;
use crate::wire::*;

impl<'a> InterfaceInner<'a> {
    #[cfg(feature = "proto-rpl")]
    pub(super) fn process_rpl<'frame>(
        &mut self,
        ll_addr: HardwareAddress,
        ip_repr: Ipv6Repr,
        repr: RplRepr,
    ) -> Option<IpPacket<'frame>> {
        let now = self.now();

        net_trace!("RPL message:\n{repr}");

        match repr {
            RplRepr::DodagInformationSolicitation { options } => {
                // FIXME: we should check if the message is unicast or multicast.
                // FIXME: we should also see if the packet contains options (these are used for
                // filtering stuff).

                // We reset our DIO trickle timer because a node is joining our network.
                let InterfaceInner { rand, rpl, now, .. } = self;
                rpl.dio_timer.reset(*now, rand);

                None
            }

            RplRepr::DodagInformationObject {
                rank,
                rpl_instance_id,
                version_number,
                grounded,
                mode_of_operation,
                dodag_preference,
                dtsn,
                dodag_id,
                mut options,
            } => {
                let mut dio_rank = Rank::new(rank, DEFAULT_MIN_HOP_RANK_INCREASE);
                let mut ocp = None;

                while let Ok(opt_packet) = RplOptionPacket::new_checked(options) {
                    let opt = RplOptionRepr::parse(&opt_packet).unwrap();

                    match opt {
                        RplOptionRepr::DodagConfiguration {
                            minimum_hop_rank_increase,
                            objective_code_point,
                            ..
                        } => {
                            dio_rank.min_hop_rank_increase = minimum_hop_rank_increase;
                            ocp = Some(objective_code_point);
                            self.rpl.update_dodag_conf(&opt);
                        }
                        _ => (),
                    }

                    options = &options[opt.buffer_len()..];
                }

                // We check if we can accept the DIO message:
                // 1. The RPL instance is the same as our RPL instance.
                // 2. The DODAG ID must be the same as our DODAG ID, unless we haven't selected
                //    one.
                // 3. The version number must be the same as our version number.
                // 4. The Mode of Operation must be the same as our Mode of Operation.
                // 5. The Objective Function must be the same as our Ojbective Function.

                if rpl_instance_id == self.rpl.instance_id
                    && match self.rpl.dodag_id {
                        Some(our_dodag_id) if our_dodag_id == dodag_id => true,
                        None => true,
                        _ => false,
                    }
                    && SequenceCounter::new(version_number) == self.rpl.version_number
                    && mode_of_operation == self.rpl.mode_of_operation
                    && (ocp == Some(self.rpl.ocp) || ocp.is_none())
                {
                    // Update our RPL values from the DIO message:
                    self.rpl.grounded = grounded;
                    self.rpl.mode_of_operation = mode_of_operation;
                    self.rpl.dodag_preference = dodag_preference;
                    self.rpl.version_number = SequenceCounter::new(version_number);
                    self.rpl.instance_id = rpl_instance_id;
                    self.rpl.dodag_id = Some(dodag_id);

                    // Add the Neighbor to our RPL neighbor table.
                    self.rpl.neighbor_table.add_neighbor(
                        RplNeighbor::new(
                            ll_addr,
                            ip_repr.src_addr,
                            dio_rank.into(),
                            dodag_preference.into(),
                        ),
                        now,
                    );

                    // NOTE: we take twice the maximum value the DIO timer can be. This is because
                    // Contiki's Trickle timer can have a maximum value of 1.5 times of the
                    // theoretical maximum value. We didn't look into why this is in Contiki.
                    self.rpl
                        .neighbor_table
                        .purge(self.now, self.rpl.dio_timer.max_expiration() * 2);

                    // Check if the DIO message is comming from a neighbor that could be our new
                    // parent. For this, the DIO rank must be smaller than ours.
                    if dio_rank < self.rpl.rank {
                        // Check for a preferred parent:
                        if let Some(preferred_parent) =
                            ObjectiveFunction0::preferred_parent(&self.rpl.neighbor_table)
                        {
                            // Accept the preferred parent as new parent when we don't have a
                            // parent yet, or when we have a parent, but its rank is higher than
                            // the preferred parent.
                            if !self.rpl.has_parent()
                                || preferred_parent.rank().dag_rank()
                                    < self.rpl.parent_rank.unwrap().dag_rank()
                            {
                                self.rpl.parent_address = Some(preferred_parent.ip_addr());
                                self.rpl.parent_rank = Some(preferred_parent.rank());
                                self.rpl.parent_preference = Some(preferred_parent.preference());

                                // Recalculate our rank when updating our parent.
                                let new_rank = ObjectiveFunction0::new_rank(
                                    self.rpl.rank,
                                    self.rpl.parent_rank.unwrap(),
                                );
                                self.rpl.rank = new_rank;

                                let src_addr = self.ipv6_address().unwrap();
                                // Reset the DIO trickle timer.
                                let InterfaceInner { rand, rpl, now, .. } = self;
                                rpl.dio_timer.reset(*now, rand);
                            }
                        }

                        if self.rpl.parent_address.unwrap() == ip_repr.src_addr {
                            self.rpl.parent_last_heard = Some(now);
                        }
                    }
                }

                None
            }
            _ => unimplemented!(),
        }
    }
}
