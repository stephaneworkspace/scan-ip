/*
 * Cli for scan with multi-thread ip range
 * By Stéphane Bressani
 * www.stephane-bressani.ch
 *
 * To do: Bot telegram notification or mail
 */
extern crate futures;
extern crate tokio;

extern crate tokio_ping;

use futures::{Future, Stream};
// use std::net::IpAddr;

// const MAX: u16 = 65535;

/*struct Arguments {
    flag: String,
    ipaddr_begin: IpAddr,
    ipaddr_end: IpAddr,
    thread: u16,
}*/

fn main() {
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
}
