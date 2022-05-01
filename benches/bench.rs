#![feature(test)]

mod wire {
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{IpAddress, IpProtocol};
    #[cfg(feature = "proto-ipv4")]
    use smoltcp::wire::{Ipv4Address, Ipv4Packet, Ipv4Repr};
    #[cfg(feature = "proto-ipv6")]
    use smoltcp::wire::{Ipv6Address, Ipv6Packet, Ipv6Repr};
    use smoltcp::wire::{TcpControl, TcpPacket, TcpRepr, TcpSeqNumber};
    use smoltcp::wire::{UdpPacket, UdpRepr};

    use smoltcp::phy::{Medium, RawSocket};
    use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
    use smoltcp::storage::RingBuffer;
    use smoltcp::wire::{Ieee802154Pan, IpCidr};
    use std::os::unix::io::AsRawFd;
    extern crate test;

    #[cfg(feature = "proto-ipv6")]
    const SRC_ADDR: IpAddress = IpAddress::Ipv6(Ipv6Address([
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]));
    #[cfg(feature = "proto-ipv6")]
    const DST_ADDR: IpAddress = IpAddress::Ipv6(Ipv6Address([
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    ]));

    #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
    const SRC_ADDR: IpAddress = IpAddress::Ipv4(Ipv4Address([192, 168, 1, 1]));
    #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
    const DST_ADDR: IpAddress = IpAddress::Ipv4(Ipv4Address([192, 168, 1, 2]));

    #[bench]
    #[cfg(any(feature = "proto-ipv6", feature = "proto-ipv4"))]
    fn bench_emit_tcp(b: &mut test::Bencher) {
        static PAYLOAD_BYTES: [u8; 400] = [0x2a; 400];
        let repr = TcpRepr {
            src_port: 48896,
            dst_port: 80,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(0x01234567),
            ack_number: None,
            window_len: 0x0123,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            payload: &PAYLOAD_BYTES,
        };
        let mut bytes = vec![0xa5; repr.buffer_len()];

        b.iter(|| {
            let mut packet = TcpPacket::new_unchecked(&mut bytes);
            repr.emit(
                &mut packet,
                &SRC_ADDR,
                &DST_ADDR,
                &ChecksumCapabilities::default(),
            );
        });
    }

    #[bench]
    #[cfg(any(feature = "proto-ipv6", feature = "proto-ipv4"))]
    fn bench_emit_udp(b: &mut test::Bencher) {
        static PAYLOAD_BYTES: [u8; 400] = [0x2a; 400];
        let repr = UdpRepr {
            src_port: 48896,
            dst_port: 80,
        };
        let mut bytes = vec![0xa5; repr.header_len() + PAYLOAD_BYTES.len()];

        b.iter(|| {
            let mut packet = UdpPacket::new_unchecked(&mut bytes);
            repr.emit(
                &mut packet,
                &SRC_ADDR,
                &DST_ADDR,
                PAYLOAD_BYTES.len(),
                |buf| buf.copy_from_slice(&PAYLOAD_BYTES),
                &ChecksumCapabilities::default(),
            );
        });
    }

    #[bench]
    #[cfg(feature = "proto-ipv4")]
    fn bench_emit_ipv4(b: &mut test::Bencher) {
        let repr = Ipv4Repr {
            src_addr: Ipv4Address([192, 168, 1, 1]),
            dst_addr: Ipv4Address([192, 168, 1, 2]),
            next_header: IpProtocol::Tcp,
            payload_len: 100,
            hop_limit: 64,
        };
        let mut bytes = vec![0xa5; repr.buffer_len()];

        b.iter(|| {
            let mut packet = Ipv4Packet::new_unchecked(&mut bytes);
            repr.emit(&mut packet, &ChecksumCapabilities::default());
        });
    }

    #[bench]
    #[cfg(feature = "proto-ipv6")]
    fn bench_emit_ipv6(b: &mut test::Bencher) {
        let repr = Ipv6Repr {
            src_addr: Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            dst_addr: Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            next_header: IpProtocol::Tcp,
            payload_len: 100,
            hop_limit: 64,
        };
        let mut bytes = vec![0xa5; repr.buffer_len()];

        b.iter(|| {
            let mut packet = Ipv6Packet::new_unchecked(&mut bytes);
            repr.emit(&mut packet);
        });
    }
    #[bench]
    fn bench_emit_6lowpan(b: &mut test::Bencher) {
        let device = RawSocket::new("wpan1", Medium::Ieee802154).unwrap();
        let fd = device.as_raw_fd();

        let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; 4096]);
        let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; 4096]);
        let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

        let ieee802154_addr = smoltcp::wire::Ieee802154Address::Extended([
            0x1a, 0x0b, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        ]);
        let ip_addrs = [IpCidr::new(
            IpAddress::v6(0xfe80, 0, 0, 0, 0x180b, 0x4242, 0x4242, 0x4242),
            64,
        )];

        let cache = FragmentsCache::new(vec![], BTreeMap::new());

        let buffer: Vec<(usize, managed::ManagedSlice<'_, u8>)> = (0..12)
            .into_iter()
            .map(|_| (0_usize, managed::ManagedSlice::from(vec![0; 127])))
            .collect();

        let out_fragments_cache = RingBuffer::new(buffer);

        let mut builder = InterfaceBuilder::new(device, vec![])
            .ip_addrs(ip_addrs)
            .pan_id(Ieee802154Pan(0xbeef));
        builder = builder
            .hardware_addr(ieee802154_addr.into())
            .neighbor_cache(neighbor_cache)
            .sixlowpan_fragments_cache(cache)
            .out_fragments_cache(out_fragments_cache);
        let mut iface = builder.finalize();

        let tcp_handle = iface.add_socket(tcp_socket);

        let socket = iface.get_socket::<TcpSocket>(tcp_handle);
        socket.listen(50000).unwrap();
        let mut tcp_active = false;
        b.iter(|| {
            
        });
    }

}
