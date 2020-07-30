/*
 * Cli admin tools
 * By Stéphane Bressani
 * www.stephane-bressani.ch
 *
 * To do: Bot telegram notification or mail
 *        Unit tests
 */
// extern crate futures;
// extern crate tokio;

// extern crate tokio_ping;

// use futures::{Future, Stream};
// use std::net::IpAddr;

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
extern crate hex;

use std::i64;
use std::net::Ipv4Addr;

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
    range.push([Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 255, 255, 255)]);
    range.push([
        Ipv4Addr::new(172, 16, 0, 0),
        Ipv4Addr::new(172, 31, 255, 255),
    ]);
    range.push([
        Ipv4Addr::new(192, 168, 0, 0),
        Ipv4Addr::new(192, 168, 255, 255),
    ]);
    for r in range {
        let mut pos: [u8; 4] = r[0].octets();
        let pos_final: [u8; 4] = r[1].octets();
        loop {
            let current_addr = Ipv4Addr::new(pos[0], pos[1], pos[2], pos[3]);
            println!("{:?}", current_addr);
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
