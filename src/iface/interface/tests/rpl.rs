use core::option;

use crate::iface::interface::tests::*;
use crate::iface::interface::*;
use crate::iface::rpl::*;
use crate::iface::{RplConfig, RplRootConfig};

use alloc::{collections::VecDeque, vec::Vec};

const ROOT_ADDRESS: Ieee802154Address = Ieee802154Address::Extended([1u8; 8]);
const NODE_1_ADDRESS: Ieee802154Address = Ieee802154Address::Extended([2u8; 8]);
const NODE_2_ADDRESS: Ieee802154Address = Ieee802154Address::Extended([3u8; 8]);

fn ip_addr(addr: Ieee802154Address) -> Ipv6Address {
    addr.as_link_local_address().unwrap()
}

/// A loopback device.
#[derive(Debug)]
pub struct TestDevice {
    pub(crate) rx_queue: VecDeque<Vec<u8>>,
    pub(crate) tx_queue: VecDeque<Vec<u8>>,
    medium: Medium,
}

#[allow(clippy::new_without_default)]
impl TestDevice {
    pub fn new(medium: Medium) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            medium,
        }
    }
}

impl Device for TestDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: 65535,
            medium: self.medium,
            ..DeviceCapabilities::default()
        }
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_queue.pop_front().map(move |buffer| {
            let rx = RxToken { buffer };
            let tx = TxToken {
                queue: &mut self.tx_queue,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            queue: &mut self.tx_queue,
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl crate::phy::RxToken for RxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer)
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct TxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> crate::phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = Vec::new();
        buffer.resize(len, 0);
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}

fn create_rpl_packet(
    ll_src_addr: Ieee802154Address,
    ll_src_pan_id: Ieee802154Pan,
    ll_dst_addr: Ieee802154Address,
    ll_dst_pan_id: Ieee802154Pan,
    dst_addr: Option<Ipv6Address>,
    rpl_repr: RplRepr,
) -> Vec<u8> {
    let ieee_repr = Ieee802154Repr {
        frame_type: Ieee802154FrameType::Data,
        security_enabled: false,
        frame_pending: false,
        ack_request: false,
        sequence_number: Some(1),
        pan_id_compression: true,
        frame_version: Ieee802154FrameVersion::Ieee802154_2003,
        dst_pan_id: Some(ll_dst_pan_id),
        dst_addr: Some(ll_dst_addr),
        src_pan_id: Some(ll_src_pan_id),
        src_addr: Some(ll_src_addr),
    };

    let iphc_repr = SixlowpanIphcRepr {
        src_addr: ll_src_addr.as_link_local_address().unwrap(),
        ll_src_addr: Some(ll_src_addr),
        dst_addr: if let Some(addr) = dst_addr {
            addr
        } else {
            ll_dst_addr.as_link_local_address().unwrap()
        },
        ll_dst_addr: Some(ll_dst_addr),
        next_header: SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6),
        hop_limit: 64,
        ecn: None,
        dscp: None,
        flow_label: None,
    };

    let icmpv6_repr = Icmpv6Repr::Rpl(rpl_repr);

    let size = ieee_repr.buffer_len() + iphc_repr.buffer_len() + icmpv6_repr.buffer_len();

    let mut data = vec![0; size];
    let mut buffer = &mut data[..];

    let mut ieee_packet = Ieee802154Frame::new_unchecked(&mut buffer[..ieee_repr.buffer_len()]);
    ieee_repr.emit(&mut ieee_packet);
    buffer = &mut buffer[ieee_repr.buffer_len()..];

    let mut iphc_packet = SixlowpanIphcPacket::new_unchecked(&mut buffer[..iphc_repr.buffer_len()]);
    iphc_repr.emit(&mut iphc_packet);
    buffer = &mut buffer[iphc_repr.buffer_len()..];

    let mut icmpv6_packet = Icmpv6Packet::new_unchecked(&mut buffer[..icmpv6_repr.buffer_len()]);
    icmpv6_repr.emit(
        &ll_src_addr.as_link_local_address().unwrap().into(),
        &if let Some(addr) = dst_addr {
            addr.into()
        } else {
            ll_dst_addr.as_link_local_address().unwrap().into()
        },
        &mut icmpv6_packet,
        &ChecksumCapabilities::default(),
    );

    data
}

/// Generate a random IEEE802.15.4 addres.
fn random_ieee802154_address(rand: &mut Rand) -> Ieee802154Address {
    let mut address = [0u8; 8];

    for i in &mut address {
        *i = (rand.rand_u16() & 0xff) as u8;
    }

    Ieee802154Address::Extended(address)
}

fn rpl_root_node(mop: ModeOfOperation) -> (Interface, SocketSet<'static>, TestDevice) {
    let (mut iface, sockets, _) = create(Medium::Ieee802154);

    let mut rpl_config = RplConfig::default();
    rpl_config.mode_of_operation = mop;
    let rpl_config = rpl_config.into_root(RplRootConfig {
        preference: 0,
        dodag_id: ip_addr(ROOT_ADDRESS),
    });
    iface.context_mut().rpl = Some(Rpl::new(rpl_config));

    if let Some(rpl) = iface.context_mut().rpl_mut() {
        rpl.mode_of_operation = mop;
    }

    iface.set_hardware_addr(HardwareAddress::Ieee802154(ROOT_ADDRESS));
    iface.update_ip_addrs(|a| a[0] = IpCidr::Ipv6(Ipv6Cidr::new(ip_addr(ROOT_ADDRESS), 128)));

    (iface, sockets, TestDevice::new(Medium::Ieee802154))
}

fn rpl_connected_node(
    addr: Ieee802154Address,
    mop: ModeOfOperation,
) -> (Interface, SocketSet<'static>, TestDevice) {
    let (mut iface, sockets, _) = create(Medium::Ieee802154);

    let mut rpl_config = RplConfig::default();
    rpl_config.mode_of_operation = mop;
    iface.context_mut().rpl = Some(Rpl::new(rpl_config));

    iface.set_hardware_addr(HardwareAddress::Ieee802154(addr));
    iface.update_ip_addrs(|a| a[0] = IpCidr::Ipv6(Ipv6Cidr::new(ip_addr(addr), 128)));

    iface.context_mut().neighbor_cache.fill_with_expiration(
        ip_addr(ROOT_ADDRESS).into(),
        ROOT_ADDRESS.into(),
        Instant::now() + Duration::from_secs(2_000),
    );

    if let Some(rpl) = iface.context_mut().rpl_mut() {
        rpl.parent_address = Some(ip_addr(ROOT_ADDRESS));
        rpl.parent_rank = Some(Rank::ROOT);
        rpl.parent_preference = Some(0);
        rpl.parent_last_heard = Some(Instant::now());
        rpl.rank = Rank::new(256 * 2, 256);
        rpl.dodag_id = Some(ip_addr(ROOT_ADDRESS));
    }

    (iface, sockets, TestDevice::new(Medium::Ieee802154))
}

fn rpl_unconnected_node(
    addr: Ieee802154Address,
    mop: ModeOfOperation,
) -> (Interface, SocketSet<'static>, TestDevice) {
    let (mut iface, sockets, _) = create(Medium::Ieee802154);

    let mut rpl_config = RplConfig::default();
    rpl_config.mode_of_operation = mop;
    iface.context_mut().rpl = Some(Rpl::new(rpl_config));

    iface.set_hardware_addr(HardwareAddress::Ieee802154(addr));
    iface.update_ip_addrs(|a| a[0] = IpCidr::Ipv6(Ipv6Cidr::new(ip_addr(addr), 128)));

    (iface, sockets, TestDevice::new(Medium::Ieee802154))
}

#[test]
fn trickle_timer_intervals() {
    let (mut iface, mut sockets, mut device) =
        rpl_root_node(ModeOfOperation::NoDownwardRoutesMaintained);

    let now = Instant::now();

    iface.poll(now, &mut device, &mut sockets);

    let mut i = iface.context().rpl().unwrap().dio_timer.get_i();

    // Poll the interface and simulate 2.000 seconds.
    for t in 0..100_000 {
        // We set the counter to 1 to check that when a new interval is selected, the counter
        // is set to 0.
        iface
            .context_mut()
            .rpl_mut()
            .unwrap()
            .dio_timer
            .set_counter(1);

        iface.poll(
            now + Duration::from_millis(t * 10),
            &mut device,
            &mut sockets,
        );

        let trickle = &iface.context().rpl().unwrap().dio_timer;

        // t should always be in between I/2 and I.
        assert!(trickle.get_i() / 2 < trickle.get_t());
        assert!(trickle.get_i() > trickle.get_t());

        // The new interval I should be double the previous one.
        if i != trickle.get_i() {
            assert_eq!(i * 2, trickle.get_i());
            i = trickle.get_i();
            assert_eq!(trickle.get_counter(), 0);
        }
    }
}

#[test]
fn reset_trickle_timer_on_dis_multicast() {
    let (mut iface, mut sockets, mut device) =
        rpl_connected_node(NODE_1_ADDRESS, ModeOfOperation::NoDownwardRoutesMaintained);

    // Poll the interface and simulate 100 seconds.
    for i in 0..100 {
        iface.poll(
            Instant::now() + Duration::from_secs(i),
            &mut device,
            &mut sockets,
        );
    }

    // Check that the interval of the DIO trickle timer is not equal to the minimum value.
    let rpl = iface.context().rpl().unwrap();
    assert_ne!(rpl.dio_timer.get_i(), rpl.dio_timer.min_expiration());

    // Create a DIS multicast message.
    let rpl_repr = RplRepr::DodagInformationSolicitation {
        options: Default::default(),
    };
    let packet = create_rpl_packet(
        ROOT_ADDRESS,
        Ieee802154Pan(0xbeef),
        Ieee802154Address::BROADCAST,
        Ieee802154Pan(0xbeef),
        Some(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES),
        rpl_repr,
    );

    device.rx_queue.push_back(packet);

    // Poll the interface such that the DIS message is processed and thus the trickle timer is
    // reset.
    iface.poll(
        Instant::now() + Duration::from_secs(100) + Duration::from_millis(100),
        &mut device,
        &mut sockets,
    );

    let rpl = iface.context().rpl().unwrap();
    assert_eq!(rpl.dio_timer.get_i(), rpl.dio_timer.min_expiration());
    assert_eq!(rpl.dio_timer.get_counter(), 0);
}

#[test]
fn ignore_dis_with_solicited_information_option_mismatch() {
    let (mut iface, mut sockets, mut device) =
        rpl_connected_node(NODE_1_ADDRESS, ModeOfOperation::NoDownwardRoutesMaintained);

    // Poll the interface and simulate 100 seconds.
    for i in 0..100 {
        iface.poll(
            Instant::now() + Duration::from_secs(i),
            &mut device,
            &mut sockets,
        );
    }

    // Check that the interval of the DIO trickle timer is not equal to the minimum value.
    let rpl = iface.context().rpl().unwrap();
    assert_ne!(rpl.dio_timer.get_i(), rpl.dio_timer.min_expiration());

    // Create a DIS multicast message.
    let dis_option = RplOptionRepr::SolicitedInformation {
        instance_id_predicate: true,
        rpl_instance_id: RplInstanceId::from(30),
        dodag_id_predicate: true,
        dodag_id: random_ieee802154_address(&mut Rand::new(1234))
            .as_link_local_address()
            .unwrap(),
        version_predicate: true,
        version_number: 240,
    };
    let mut options = heapless::Vec::new();
    options.push(dis_option).unwrap();
    let rpl_repr = RplRepr::DodagInformationSolicitation { options };
    let packet = create_rpl_packet(
        ROOT_ADDRESS,
        Ieee802154Pan(0xbeef),
        Ieee802154Address::BROADCAST,
        Ieee802154Pan(0xbeef),
        Some(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES),
        rpl_repr,
    );

    device.rx_queue.push_back(packet);

    iface.poll(
        Instant::now() + Duration::from_secs(100) + Duration::from_millis(100),
        &mut device,
        &mut sockets,
    );

    let rpl = iface.context().rpl().unwrap();
    assert_ne!(rpl.dio_timer.get_i(), rpl.dio_timer.min_expiration());
    assert_eq!(rpl.dio_timer.get_counter(), 0);
}

#[test]
fn trickle_timer_is_running_by_default_when_node_is_root() {
    let (mut iface, mut sockets, mut device) =
        rpl_root_node(ModeOfOperation::NoDownwardRoutesMaintained);

    // Poll the interface and simulate 100 seconds.
    for i in 0..100 {
        iface.poll(
            Instant::now() + Duration::from_secs(i),
            &mut device,
            &mut sockets,
        );
    }

    // Check that the interval of the DIO trickle timer is 0, because it was never set.
    let rpl = iface.context().rpl().unwrap();
    assert_ne!(rpl.dio_timer.get_i(), Duration::from_secs(0));
    assert_eq!(rpl.dio_timer.get_counter(), 0);
}

#[test]
fn reset_trickle_timer_on_global_repair() {}

#[test]
fn reset_trickle_timer_on_local_repair() {}

#[test]
fn reset_trickle_timer_on_selecting_parent() {
    let (mut iface, mut sockets, mut device) =
        rpl_unconnected_node(NODE_1_ADDRESS, ModeOfOperation::NoDownwardRoutesMaintained);

    // Poll the interface and simulate 100 seconds.
    for i in 0..100 {
        iface.poll(
            Instant::now() + Duration::from_secs(i),
            &mut device,
            &mut sockets,
        );
    }

    let mut options = heapless::Vec::new();
    options
        .push(iface.context().rpl().unwrap().dodag_configuration())
        .unwrap();

    // Create a DIO message from a root node.
    let rpl_repr = RplRepr::DodagInformationObject {
        rpl_instance_id: RplInstanceId::from(30),
        version_number: SequenceCounter::default().value(),
        rank: Rank::ROOT.raw_value(),
        grounded: false,
        mode_of_operation: ModeOfOperation::NoDownwardRoutesMaintained.into(),
        dodag_preference: 0,
        dtsn: SequenceCounter::default().value(),
        dodag_id: ip_addr(ROOT_ADDRESS),
        options,
    };
    let packet = create_rpl_packet(
        ROOT_ADDRESS,
        Ieee802154Pan(0xbeef),
        Ieee802154Address::BROADCAST,
        Ieee802154Pan(0xbeef),
        Some(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES),
        rpl_repr,
    );

    device.rx_queue.push_back(packet);

    iface.poll(
        Instant::now() + Duration::from_secs(101),
        &mut device,
        &mut sockets,
    );

    let rpl = iface.context().rpl().unwrap();
    assert_eq!(rpl.parent_address, Some(ip_addr(ROOT_ADDRESS)));
    assert_eq!(rpl.parent_rank, Some(Rank::ROOT));
    assert_eq!(rpl.parent_preference, Some(0));
    assert_eq!(rpl.dodag_id, Some(ip_addr(ROOT_ADDRESS)));
    assert_eq!(rpl.dio_timer.get_counter(), 0);
}

#[test]
fn increment_trickle_counter_on_hearing_consistent_dio() {
    let (mut iface, mut sockets, mut device) =
        rpl_connected_node(NODE_1_ADDRESS, ModeOfOperation::NoDownwardRoutesMaintained);

    iface.poll(
        Instant::now() + Duration::from_millis(1),
        &mut device,
        &mut sockets,
    );

    let mut options = heapless::Vec::new();
    options
        .push(iface.context().rpl().unwrap().dodag_configuration())
        .unwrap();

    // Create a DIO message from a root node.
    let rpl_repr = RplRepr::DodagInformationObject {
        rpl_instance_id: RplInstanceId::from(30),
        version_number: SequenceCounter::default().value(),
        rank: Rank::ROOT.raw_value(),
        grounded: false,
        mode_of_operation: ModeOfOperation::NoDownwardRoutesMaintained.into(),
        dodag_preference: 0,
        dtsn: SequenceCounter::default().value(),
        dodag_id: ip_addr(ROOT_ADDRESS),
        options,
    };
    let packet = create_rpl_packet(
        ROOT_ADDRESS,
        Ieee802154Pan(0xbeef),
        Ieee802154Address::BROADCAST,
        Ieee802154Pan(0xbeef),
        Some(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES),
        rpl_repr,
    );

    device.rx_queue.push_back(packet);

    iface.poll(
        Instant::now() + Duration::from_secs(1),
        &mut device,
        &mut sockets,
    );

    let rpl = iface.context().rpl().unwrap();
    assert_eq!(rpl.dio_timer.get_counter(), 1);
}

#[test]
fn reset_trickle_timer_on_root_receiving_dio_with_wrong_version_number() {
    let (mut iface, mut sockets, mut device) =
        rpl_root_node(ModeOfOperation::NoDownwardRoutesMaintained);

    // Poll the interface and simulate 100 seconds.
    for i in 0..100 {
        iface.poll(
            Instant::now() + Duration::from_secs(i),
            &mut device,
            &mut sockets,
        );
    }

    let rpl = iface.context().rpl().unwrap();
    assert_ne!(rpl.dio_timer.get_i(), rpl.dio_timer.min_expiration());

    let mut options = heapless::Vec::new();
    options
        .push(iface.context().rpl().unwrap().dodag_configuration())
        .unwrap();

    let mut version_number = SequenceCounter::default();
    version_number.increment();

    // Create a DIO message from a node, with a wrong version number.
    let rpl_repr = RplRepr::DodagInformationObject {
        rpl_instance_id: RplInstanceId::from(30),
        version_number: version_number.value(),
        rank: Rank::ROOT.raw_value(),
        grounded: false,
        mode_of_operation: ModeOfOperation::NoDownwardRoutesMaintained.into(),
        dodag_preference: 0,
        dtsn: SequenceCounter::default().value(),
        dodag_id: ip_addr(ROOT_ADDRESS),
        options,
    };

    let packet = create_rpl_packet(
        NODE_1_ADDRESS,
        Ieee802154Pan(0xbeef),
        Ieee802154Address::BROADCAST,
        Ieee802154Pan(0xbeef),
        Some(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES),
        rpl_repr,
    );

    device.rx_queue.push_back(packet);

    // Poll the interface such that the DIO message is processed and thus the node selects a
    // parent (and resets the trickle timer).
    iface.poll(
        Instant::now() + Duration::from_secs(100) + Duration::from_millis(100),
        &mut device,
        &mut sockets,
    );

    // Check that the node selected a parent and dodag_id, and that the trickle timer is started.
    let rpl = iface.context().rpl().unwrap();
    assert_eq!(rpl.dio_timer.get_counter(), 0);
    assert_eq!(rpl.dio_timer.get_i(), rpl.dio_timer.min_expiration());
}

#[test]
fn reset_trickle_timer_on_parent_advertising_() {
    let (mut iface, mut sockets, mut device) =
        rpl_connected_node(NODE_1_ADDRESS, ModeOfOperation::NoDownwardRoutesMaintained);

    // Poll the interface and simulate 100 seconds.
    for i in 0..100 {
        iface.poll(
            Instant::now() + Duration::from_secs(i),
            &mut device,
            &mut sockets,
        );
    }

    let mut options = heapless::Vec::new();
    options
        .push(iface.context().rpl().unwrap().dodag_configuration())
        .unwrap();

    // Create a DIO message from a node, with an infinite Rank.
    let rpl_repr = RplRepr::DodagInformationObject {
        rpl_instance_id: RplInstanceId::from(30),
        version_number: SequenceCounter::default().value(),
        rank: Rank::INFINITE.raw_value(),
        grounded: false,
        mode_of_operation: ModeOfOperation::NoDownwardRoutesMaintained.into(),
        dodag_preference: 0,
        dtsn: SequenceCounter::default().value(),
        dodag_id: ip_addr(ROOT_ADDRESS),
        options,
    };

    let packet = create_rpl_packet(
        ROOT_ADDRESS,
        Ieee802154Pan(0xbeef),
        Ieee802154Address::BROADCAST,
        Ieee802154Pan(0xbeef),
        Some(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES),
        rpl_repr,
    );

    device.rx_queue.push_back(packet);

    // Poll the interface such that the DIO message is processed and thus the node selects a
    // parent (and resets the trickle timer).
    iface.poll(
        Instant::now() + Duration::from_secs(100) + Duration::from_millis(100),
        &mut device,
        &mut sockets,
    );

    let rpl = iface.context().rpl().unwrap();
    // TODO(thdveld): local repair
    //assert!(!rpl.has_parent());
    assert_eq!(rpl.dio_timer.get_i(), rpl.dio_timer.min_expiration());
    assert_eq!(rpl.dio_timer.get_counter(), 0);
}

#[test]
fn trickle_timer_counter_increment_for_root_dio_from_child_rank_not_infinite() {
    let (mut iface, mut sockets, mut device) =
        rpl_root_node(ModeOfOperation::NoDownwardRoutesMaintained);

    // Poll the interface and simulate 100 seconds.
    for i in 0..100 {
        iface.poll(
            Instant::now() + Duration::from_secs(i),
            &mut device,
            &mut sockets,
        );
    }

    let mut options = heapless::Vec::new();
    options
        .push(iface.context().rpl().unwrap().dodag_configuration())
        .unwrap();

    let packet = create_rpl_packet(
        NODE_1_ADDRESS,
        Ieee802154Pan(0xbeef),
        Ieee802154Address::BROADCAST,
        Ieee802154Pan(0xbeef),
        Some(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES),
        RplRepr::DodagInformationObject {
            rpl_instance_id: RplInstanceId::from(30),
            version_number: SequenceCounter::default().value(),
            rank: 256 * 2,
            grounded: false,
            mode_of_operation: ModeOfOperation::NoDownwardRoutesMaintained.into(),
            dodag_preference: 0,
            dtsn: SequenceCounter::default().value(),
            dodag_id: ip_addr(ROOT_ADDRESS),
            options,
        },
    );

    device.rx_queue.push_back(packet);

    iface.poll(
        Instant::now() + Duration::from_secs(100) + Duration::from_millis(100),
        &mut device,
        &mut sockets,
    );

    let rpl = iface.context().rpl().unwrap();
    assert_eq!(rpl.dio_timer.get_counter(), 1);
}
