//! 6lowpan benchmark exmaple
//!
//! This example is designed to run using the Linux ieee802154/6lowpan support,
//! using mac802154_hwsim.
//!
//! mac802154_hwsim allows you to create multiple "virtual" radios and specify
//! which is in range with which. This is very useful for testing without
//! needing real hardware. By default it creates two interfaces `wpan0` and
//! `wpan1` that are in range with each other. You can customize this with
//! the `wpan-hwsim` tool.
//!
//! We'll configure Linux to speak 6lowpan on `wpan0`, and leave `wpan1`
//! unconfigured so smoltcp can use it with a raw socket.
//!
//! # Setup
//!
//!     modprobe mac802154_hwsim
//!
//!     ip link set wpan0 down
//!     ip link set wpan1 down
//!     iwpan dev wpan0 set pan_id 0xbeef
//!     iwpan dev wpan1 set pan_id 0xbeef
//!     ip link add link wpan0 name lowpan0 type lowpan
//!     ip link set wpan0 up
//!     ip link set wpan1 up
//!     ip link set lowpan0 up
//!
//! # Running
//!
//! Run it with `sudo ./target/debug/examples/sixlowpan`.
//!
//! You can set wireshark to sniff on interface `wpan0` to see the packets.
//!
//! Ping it with `ping fe80::180b:4242:4242:4242%lowpan0`.
//!
//! Speak UDP with `nc -uv fe80::180b:4242:4242:4242%lowpan0 6969`.
//!
//! # Teardown
//!
//!     rmmod mac802154_hwsim
//!

mod utils;

use log::debug;
use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use std::str;

use smoltcp::iface::{FragmentsCache, InterfaceBuilder, NeighborCache};
use smoltcp::phy::{wait as phy_wait, Medium, RawSocket};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
use smoltcp::storage::RingBuffer;
use smoltcp::wire::{Ieee802154Pan, IpAddress, IpCidr};



//For benchmark
use smoltcp::time::{Duration, Instant};
use std::thread;
use std::cmp;
use std::net::TcpStream;
use std::net::{SocketAddrV6};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};



use std::fs;


fn if_nametoindex(ifname: &str) -> u32 {
    let contents = fs::read_to_string(format!("/sys/devices/virtual/net/{}/ifindex",ifname))
        .expect(format!("Something went wrong trying to get IF-index of lowpan0, does \"/sys/devices/virtual/net/{}/ifindex\" exist?", ifname).as_str())
        .replace("\n", "");
    contents.parse::<u32>().unwrap()

}

const AMOUNT: usize = 100_000_000;

enum Client {
    Reader,
    Writer,
}


fn client(kind: Client){
    let port: u16 = match kind {
        Client::Reader => 1234,
        Client::Writer => 1235,
    };

    let scope_id = if_nametoindex("lowpan0");

    let socket_addr = SocketAddrV6::new("fe80:0:0:0:180b:4242:4242:4242".parse().unwrap(), port, 0, scope_id);
    
    //let socket_addr: SocketAddrV6 = "[fe80:0:0:0:180b:4242:4242:4242]:1234".parse().unwrap();


    let mut stream = TcpStream::connect(socket_addr).expect("failed to connect TLKAGMKA");
    let mut buffer = vec![0; 1_000_000];

    let start = Instant::now();

    let mut processed = 0;
    while processed < AMOUNT {
        let length = cmp::min(buffer.len(), AMOUNT - processed);
        let result = match kind {
            Client::Reader => stream.read(&mut buffer[..length]),
            Client::Writer => stream.write(&buffer[..length]),
        };
        match result {
            Ok(0) => break,
            Ok(result) => {
                // print!("(P:{})", result);
                processed += result
            }
            Err(err) => panic!("cannot process: {}", err),
        }
    }

    let end = Instant::now();

    let elapsed = (end - start).total_millis() as f64 / 1000.0;

    println!("throughput: {:.3} Gbps", AMOUNT as f64 / elapsed / 0.125e9);

    CLIENT_DONE.store(true, Ordering::SeqCst);
}


static CLIENT_DONE: AtomicBool = AtomicBool::new(false);

fn main(){
    #[cfg(feature = "log")]
    utils::setup_logging("info");

    let (mut opts, mut free) = utils::create_options();
    utils::add_middleware_options(&mut opts, &mut free);
    free.push("MODE");


    let mut matches = utils::parse_options(&opts, free);

    let device = RawSocket::new("wpan1", Medium::Ieee802154).unwrap();

    let fd = device.as_raw_fd();
    let device = utils::parse_middleware_options(&mut matches, device, /*loopback=*/ false);


    let mode = match matches.free[0].as_ref() {
        "reader" => Client::Reader,
        "writer" => Client::Writer,
        _ => panic!("invalid mode"),
    };

    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let tcp1_rx_buffer = TcpSocketBuffer::new(vec![0; 4096]);
    let tcp1_tx_buffer = TcpSocketBuffer::new(vec![0; 4096]);
    let tcp1_socket = TcpSocket::new(tcp1_rx_buffer, tcp1_tx_buffer);

    let tcp2_rx_buffer = TcpSocketBuffer::new(vec![0; 4096]);
    let tcp2_tx_buffer = TcpSocketBuffer::new(vec![0; 4096]);
    let tcp2_socket = TcpSocket::new(tcp2_rx_buffer, tcp2_tx_buffer);

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
        .map(|_| (0_usize, managed::ManagedSlice::from(vec![0; 1_000_000_000])))
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

    let tcp1_handle = iface.add_socket(tcp1_socket);
    let tcp2_handle = iface.add_socket(tcp2_socket);



    let default_timeout = Some(Duration::from_millis(1000));
    

    thread::spawn(move || client(mode));
    let mut processed = 0;

    while !CLIENT_DONE.load(Ordering::SeqCst) {
        let timestamp = Instant::now();
        match iface.poll(timestamp) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        // tcp:1234: emit data
        let socket = iface.get_socket::<TcpSocket>(tcp1_handle);
        if !socket.is_open() {
            socket.listen(1234).unwrap();
        }

        if socket.can_send() {
            if processed < AMOUNT {
                let length = socket
                    .send(|buffer| {
                        let length = cmp::min(buffer.len(), AMOUNT - processed);
                        (length, length)
                    })
                    .unwrap();
                processed += length;
            }
        }

        // tcp:1235: sink data
        let socket = iface.get_socket::<TcpSocket>(tcp2_handle);
        if !socket.is_open() {
            socket.listen(1235).unwrap();
        }

        if socket.can_recv() {
            if processed < AMOUNT {
                let length = socket
                    .recv(|buffer| {
                        let length = cmp::min(buffer.len(), AMOUNT - processed);
                        (length, length)
                    })
                    .unwrap();
                processed += length;
            }
        }

        match iface.poll_at(timestamp) {
            Some(poll_at) if timestamp < poll_at => {
                phy_wait(fd, Some(poll_at - timestamp)).expect("wait error");
            }
            Some(_) => (),
            None => {
                phy_wait(fd, default_timeout).expect("wait error");
            }
        }
    }
}