/*
 * Cli admin tools
 * By Stéphane Bressani
 * www.stephane-bressani.ch
 *
 * To do: Bot telegram notification or mail
 *        Unit tests
 */
extern crate dns_lookup;
extern crate futures;
extern crate hex;
extern crate tokio;

use pnet::packet::*;
use pnet::transport::*;
use std::collections;
use std::i64;
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::sync;
use std::sync::atomic;
use std::thread;
use std::time;
// const MAX: u16 = 65535;

/*struct Arguments {
    flag: String,
    ipaddr_begin: IpAddr,
    ipaddr_end: IpAddr,
    thread: u16,
}*/
/*
extern crate hyper;
use hyper::Client;
use hyper::body::HttpBody as _;
use tokio::io::{stdout, AsyncWriteExt as _};
use hyper_tls::HttpsConnector;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Check health of https

    // http only
    // let client = Client::new();

    // http or https connections
    let client = Client::builder().build::<_, hyper::Body>(HttpsConnector::new());

    let mut resp = client.get("https://www.stephane-bressani.ch".parse()?).await?;

    println!("Response: {}", resp.status());

    while let Some(chunk) = resp.body_mut().data().await {
        stdout().write_all(&chunk?).await?;
    }

    Ok(())
}
*/

/// Scan private intranet
///
/// The private address ranges are defined in IETF RFC 1918 and include:
///
/// 10.0.0.0/8
/// 172.16.0.0/12
/// 192.168.0.0/16
///
/// https://doc.rust-lang.org/std/net/struct.Ipv4Addr.html#method.is_private
fn check_private_range() {
    let mut range: Vec<[Ipv4Addr; 2]> = Vec::new();
    /*
    range.push([Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 255, 255, 255)]);
    range.push([
        Ipv4Addr::new(172, 16, 0, 0),
        Ipv4Addr::new(172, 31, 255, 255),
    ]);
    range.push([
        Ipv4Addr::new(192, 168, 0, 0),
        Ipv4Addr::new(192, 168, 255, 255),
    ]);
    */
    range.push([
        Ipv4Addr::new(192, 168, 0, 0),
        Ipv4Addr::new(192, 168, 0, 255),
    ]);
    let mut ip: Vec<IpAddr> = Vec::new();
    for r in range {
        let mut pos: [u8; 4] = r[0].octets();
        let pos_final: [u8; 4] = r[1].octets();
        loop {
            let current_addr = Ipv4Addr::new(pos[0], pos[1], pos[2], pos[3]);
            ip.push(IpAddr::V4(current_addr));
            let compare_1 = i64::from_str_radix(
                hex::encode(vec![pos[0], pos[1], pos[2], pos[3]]).as_str(),
                16,
            )
            .unwrap();
            let compare_2 = i64::from_str_radix(
                hex::encode(vec![pos_final[0], pos_final[1], pos_final[2], pos_final[3]]).as_str(),
                16,
            )
            .unwrap();
            if compare_1 >= compare_2 {
                break;
            };
            // Algo for Ipv4Addr
            if pos[3] == 255 {
                pos[3] = 0;
                if pos[2] == 255 {
                    pos[2] = 0;
                    if pos[1] == 255 {
                        pos[1] = 0;
                        pos[0] = pos[0] + 1;
                    //if pos[0] == 255 {
                    // }
                    } else {
                        pos[1] = pos[1] + 1;
                    }
                } else {
                    pos[2] = pos[2] + 1;
                }
            } else {
                pos[3] = pos[3] + 1;
            }
        }
    }
    host_check(ip);
}

/// Work with my home_web_addr
/// ip = Vec::new();
/// let home_web_addr = Ipv4Addr::new(164, 132, 99, 183);
/// ip.push(IpAddr::V4(home_web_addr));
/// host_check(ip);

fn host_check(ip: Vec<IpAddr>) {
    for current_ip in ip {
        let mut sw_print: bool = false;
        let addr_name = match dns_lookup::lookup_addr(&current_ip) {
            Ok(name) => {
                sw_print = true;
                name
            }
            Err(_) => current_ip.to_string(),
        };
        if sw_print {
            println!("{}", addr_name);
        }

        // https://github.com/Daniel-Liu-c0deb0t/9S/blob/master/src/main.rs

        // use process id to identify ICMP packets that were sent from this
        // process future work: handle process IDs larger than u16::max_value()
        let identifier = std::process::id() as u16;

        let (mut sender, receiver) = match current_ip {
            IpAddr::V4(_) => {
                // note: must use Layer4 since pnet does not support
                // IPv6 Layer3 it will take care of creating sockets and
                // wrapping our ICMP packets with IPv4/IPv6 packets before
                // sending the biggest limitation of this is that we cannot
                // obtain the ttl of received packets
                transport_channel(
                    1024,
                    TransportChannelType::Layer4(TransportProtocol::Ipv4(
                        ip::IpNextHeaderProtocols::Icmp,
                    )),
                )
                .expect("Unable to open transport channel!")
            }
            IpAddr::V6(_) => transport_channel(
                1024,
                TransportChannelType::Layer4(TransportProtocol::Ipv6(
                    ip::IpNextHeaderProtocols::Icmpv6,
                )),
            )
            .expect("Unable to open transport channel!"),
        };

        // this will set the ttl for all packets
        // unfortunately, pnet does not support setting the ttl on IPv6
        const TTL: u8 = 64;
        if current_ip.is_ipv4() {
            sender.set_ttl(TTL).unwrap();
        }
    }
}

fn main() {
    // Ip range private
    check_private_range();
    // 29.07 OK work but only with sudo
    /*
    let addr = std::env::args().nth(1).unwrap().parse().unwrap();

    let pinger = tokio_ping::Pinger::new();
    let stream = pinger.and_then(move |pinger| Ok(pinger.chain(addr).stream()));
    let future = stream.and_then(|stream| {
        stream.take(3).for_each(|mb_time| {
            match mb_time {
                Some(time) => println!("time={:?}", time),
                None => println!("timeout"),
            }
            Ok(())
        })
    });

    tokio::run(future.map_err(|err| eprintln!("Error: {}", err)))
    */
}

/// Creates a separate to concurrently receive ICMP packets that are sent, and returns a JoinHandle that
/// allows the received packets count and lost packets count to be accessed.
///
/// # Arguments
/// * `not_done` - Whether this process is exiting.
/// * `receiver` - TransportReceiver for receiving packets.
/// * `total_packets` - Number of packets sent so far.
/// * `iterations` - Maximum number of packets to send.
/// * `identifier` - A number uniquely identifying this process.
/// * `timeout` - How long to wait for an echo reply when an echo request is sent.
/// * `addr` - Address of where to send packets. This is mainly used for printing to stdout.
fn make_icmp_receiver_thread(
    not_done: sync::Arc<atomic::AtomicBool>,
    mut receiver: TransportReceiver,
    total_packets: sync::Arc<sync::Mutex<usize>>,
    iterations: usize,
    identifier: u16,
    timeout: time::Duration,
    addr: String,
) -> thread::JoinHandle<(usize, usize)> {
    thread::spawn(move || {
        let mut receiver_iter = icmp_packet_iter(&mut receiver);
        let mut total_rtt = 0;
        let mut received_packets = 0;
        let mut lost_packets = 0;
        let mut timed_out_packets = 0;
        // HashSet to keep track of duplicate packets
        let mut received = collections::HashSet::new();
        let receiver_delay = time::Duration::from_millis(100);

        while not_done.load(atomic::Ordering::SeqCst) {
            // receiver_delay should be low to keep this thread responsive to not_done changes
            let next_res = receiver_iter
                .next_with_timeout(receiver_delay)
                .expect("Error receiving packet! 9S unhappy :( ");

            let (res_packet, res_ip) = match next_res {
                Some(res) => res,
                None => continue,
            };

            let curr_time = time::SystemTime::now()
                .duration_since(time::UNIX_EPOCH)
                .unwrap()
                .as_millis();
            // we don't care if this is changed by the main thread (we want consistency in the
            // printed results), so just read it once
            let total_packets_sent = { *total_packets.lock().unwrap() };

            match res_packet.get_icmp_type() {
                icmp::IcmpTypes::EchoReply => {
                    let (res_identifier, res_seq_num, res_send_time) =
                        read_payload(res_packet.payload());

                    if res_identifier == identifier && (res_seq_num as usize) <= total_packets_sent
                    {
                        // at this point we double checked that the received packet is definitely a packet
                        // sent by this specific process (and not some other process doing a ping)

                        if received.contains(&res_seq_num) {
                            println!(
                                "9S received a duplicate packet (seq num: {}) from {}!",
                                res_seq_num, addr
                            );
                        } else {
                            let elapsed_ms = curr_time - res_send_time;

                            // a packet is timed out even if we receive it after the timeout
                            if elapsed_ms > timeout.as_millis() {
                                timed_out_packets += 1;
                                println!("9S received timed out packet (seq num: {}) from {} in {} ms!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                res_seq_num, addr, elapsed_ms, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);
                            } else {
                                total_rtt += elapsed_ms;
                                received_packets += 1;
                                println!("9S received packet (seq num: {}) from {} in {} ms (avg rtt: {:.1} ms)!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                    res_seq_num, addr, elapsed_ms, total_rtt as f64 / received_packets as f64, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);
                            }

                            received.insert(res_seq_num);
                        }
                    }
                    // not our packet, not our problem
                }
                icmp::IcmpTypes::DestinationUnreachable => {
                    // only part of the original packet is returned
                    // payload bytes 0..4 is unused, 4..24 is the IPv4 header,
                    // 24..28 is the ICMP header, and 28..32 is the identifier and sequence number
                    let (res_identifier, res_seq_num) =
                        read_payload_id(&res_packet.payload()[28..32]);

                    if res_identifier == identifier && (res_seq_num as usize) <= total_packets_sent
                    {
                        if received.contains(&res_seq_num) {
                            println!(
                                "9S received a duplicate packet (seq num: {}) from {}!",
                                res_seq_num, addr
                            );
                        } else {
                            lost_packets += 1;
                            println!("9S received a destination unreachable packet (seq num: {}) from {} (code: {})!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                res_seq_num, addr, res_packet.get_icmp_code().0, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);

                            received.insert(res_seq_num);
                        }
                    }
                    // not our packet, not our problem
                }
                icmp::IcmpTypes::TimeExceeded => {
                    // only part of the original packet is returned
                    // payload bytes 0..4 is unused, 4..24 is the IPv4 header,
                    // 24..28 is the ICMP header, and 28..32 is the identifier and sequence number
                    let (res_identifier, res_seq_num) =
                        read_payload_id(&res_packet.payload()[28..32]);

                    if res_identifier == identifier && (res_seq_num as usize) <= total_packets_sent
                    {
                        if received.contains(&res_seq_num) {
                            println!(
                                "9S received a duplicate packet (seq num: {}) from {}!",
                                res_seq_num, addr
                            );
                        } else {
                            lost_packets += 1;
                            println!("9S received a time exceeded packet (seq num: {}) before reaching {} (last host: {}, code: {})!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                res_seq_num, addr, res_ip, res_packet.get_icmp_code().0, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);

                            received.insert(res_seq_num);
                        }
                    }
                    // not our packet, not our problem
                }
                _ => (), // quietly skip this received packet if it is not what we were expecting
            }

            // future work: also count timed out packets that were never received
            if received_packets + lost_packets + timed_out_packets >= iterations {
                not_done.store(false, atomic::Ordering::SeqCst);
                break;
            }
        }

        (received_packets, lost_packets)
    })
}

/// Creates a separate to concurrently receive ICMPv6 packets that are sent, and returns a JoinHandle that
/// allows the received packets count and lost packets count to be accessed.
///
/// # Arguments
/// * `not_done` - Whether this process is exiting.
/// * `receiver` - TransportReceiver for receiving packets.
/// * `total_packets` - Number of packets sent so far.
/// * `iterations` - Maximum number of packets to send.
/// * `identifier` - A number uniquely identifying this process.
/// * `timeout` - How long to wait for an echo reply when an echo request is sent.
/// * `addr` - Address of where to send packets. This is mainly used for printing to stdout.
fn make_icmpv6_receiver_thread(
    not_done: sync::Arc<atomic::AtomicBool>,
    mut receiver: TransportReceiver,
    total_packets: sync::Arc<sync::Mutex<usize>>,
    iterations: usize,
    identifier: u16,
    timeout: time::Duration,
    addr: String,
) -> thread::JoinHandle<(usize, usize)> {
    thread::spawn(move || {
        let mut receiver_iter = icmpv6_packet_iter(&mut receiver);
        let mut total_rtt = 0;
        let mut received_packets = 0;
        let mut lost_packets = 0;
        let mut timed_out_packets = 0;
        // HashSet to keep track of duplicate packets
        let mut received = collections::HashSet::new();
        let receiver_delay = time::Duration::from_millis(100);

        while not_done.load(atomic::Ordering::SeqCst) {
            // receiver_delay should be low to keep this thread responsive to not_done changes
            let next_res = receiver_iter
                .next_with_timeout(receiver_delay)
                .expect("Error receiving packet! 9S unhappy :( ");

            let (res_packet, res_ip) = match next_res {
                Some(res) => res,
                None => continue,
            };

            let curr_time = time::SystemTime::now()
                .duration_since(time::UNIX_EPOCH)
                .unwrap()
                .as_millis();
            // we don't care if this is changed by the main thread (we want consistency in the
            // printed results), so just read it once
            let total_packets_sent = { *total_packets.lock().unwrap() };

            match res_packet.get_icmpv6_type() {
                icmpv6::Icmpv6Types::EchoReply => {
                    let (res_identifier, res_seq_num, res_send_time) =
                        read_payload(res_packet.payload());

                    if res_identifier == identifier && (res_seq_num as usize) <= total_packets_sent
                    {
                        // at this point we double checked that the received packet is definitely a packet
                        // sent by this specific process (and not some other process doing a ping)

                        if received.contains(&res_seq_num) {
                            println!(
                                "9S received a duplicate packet (seq num: {}) from {}!",
                                res_seq_num, addr
                            );
                        } else {
                            let elapsed_ms = curr_time - res_send_time;
                            total_rtt += elapsed_ms;

                            // a packet is timed out even if we receive it after the timeout
                            if elapsed_ms > timeout.as_millis() {
                                timed_out_packets += 1;
                                println!("9S received timed out packet (seq num: {}) from {} in {} ms (avg rtt: {:.1} ms)!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                res_seq_num, addr, elapsed_ms, total_rtt as f64 / received_packets as f64, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);
                            } else {
                                received_packets += 1;
                                println!("9S received packet (seq num: {}) from {} in {} ms (avg rtt: {:.1} ms)!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                    res_seq_num, addr, elapsed_ms, total_rtt as f64 / received_packets as f64, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);
                            }

                            received.insert(res_seq_num);
                        }
                    }
                    // not our packet, not our problem
                }
                icmpv6::Icmpv6Types::DestinationUnreachable => {
                    // only part of the original packet is returned
                    // payload bytes 0..4 is unused, 4..44 is the IPv6 header,
                    // 44..48 is the ICMPv6 header, and 48..52 is the identifier and sequence number
                    let (res_identifier, res_seq_num) =
                        read_payload_id(&res_packet.payload()[48..52]);

                    if res_identifier == identifier && (res_seq_num as usize) <= total_packets_sent
                    {
                        if received.contains(&res_seq_num) {
                            println!(
                                "9S received a duplicate packet (seq num: {}) from {}!",
                                res_seq_num, addr
                            );
                        } else {
                            lost_packets += 1;
                            println!("9S received a destination unreachable packet (seq num: {}) from {} (code: {})!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                res_seq_num, addr, res_packet.get_icmpv6_code().0, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);

                            received.insert(res_seq_num);
                        }
                    }
                    // not our packet, not our problem
                }
                icmpv6::Icmpv6Types::TimeExceeded => {
                    // only part of the original packet is returned
                    // payload bytes 0..4 is unused, 4..44 is the IPv6 header,
                    // 44..48 is the ICMPv6 header, and 48..52 is the identifier and sequence number
                    let (res_identifier, res_seq_num) =
                        read_payload_id(&res_packet.payload()[48..52]);

                    if res_identifier == identifier && (res_seq_num as usize) <= total_packets_sent
                    {
                        if received.contains(&res_seq_num) {
                            println!(
                                "9S received a duplicate packet (seq num: {}) from {}!",
                                res_seq_num, addr
                            );
                        } else {
                            lost_packets += 1;
                            println!("9S received a time exceeded packet (seq num: {}) before reaching {} (last host: {}, code: {})!\n\tSent {}, with {} ({:.1}%) lost so far.",
                                res_seq_num, addr, res_ip, res_packet.get_icmpv6_code().0, total_packets_sent, lost_packets, lost_packets as f64 / total_packets_sent as f64 * 100f64);

                            received.insert(res_seq_num);
                        }
                    }
                    // not our packet, not our problem
                }
                _ => (), // quietly skip this received packet if it is not what we were expecting
            }

            // future work: also count timed out packets that were never received
            if received_packets + lost_packets + timed_out_packets >= iterations {
                not_done.store(false, atomic::Ordering::SeqCst);
                break;
            }
        }

        (received_packets, lost_packets)
    })
}
/// Returns a tuple containing the identifier, sequence number,
/// and send time (in milliseconds) for a packet's payload.
///
/// # Arguments
/// * `payload` - Payload of a packet.
fn read_payload(payload: &[u8]) -> (u16, u16, u128) {
    let send_time = unsafe {
        let num = 0u128;
        let mut arr = mem::transmute::<u128, [u8; 16]>(num);
        arr.copy_from_slice(&payload[4..20]);
        mem::transmute::<[u8; 16], u128>(arr)
    };

    (
        payload[0] as u16 + ((payload[1] as u16) << 8), // identifier
        payload[2] as u16 + ((payload[3] as u16) << 8), // sequence number
        send_time,
    )
}

/// Returns a tuple containing the identifier and sequence number for a packet's payload.
///
/// # Arguments
/// * `payload` - Payload of a packet.
fn read_payload_id(payload: &[u8]) -> (u16, u16) {
    (
        payload[0] as u16 + ((payload[1] as u16) << 8), // identifier
        payload[2] as u16 + ((payload[3] as u16) << 8),
    ) // sequence number
}
