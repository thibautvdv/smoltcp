use super::*;

use super::super::rpl::*;
use crate::wire::*;

impl InterfaceInner {
    pub(super) fn process_rpl<'frame>(
        &mut self,
        ip_repr: IpRepr,
        repr: RplRepr<'frame>,
    ) -> Option<IpPacket<'frame>> {
        match repr {
            RplRepr::DodagInformationSolicitation { .. } => self.process_rpl_dis(ip_repr, repr),
            RplRepr::DodagInformationObject { .. } => self.process_rpl_dio(ip_repr, repr),
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
        ip_repr: IpRepr,
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

                if ip_repr.dst_addr().is_unicast() {
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
        _ip_repr: IpRepr,
        _repr: RplRepr<'frame>,
    ) -> Option<IpPacket<'frame>> {
        todo!();
    }
}
