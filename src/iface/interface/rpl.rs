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
        // Add processing of RPL packets here.

        todo!();
    }
}
