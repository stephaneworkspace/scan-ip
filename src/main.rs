/*
 * Cli for scan with multi-thread ip range
 * By Stéphane Bressani
 * www.stephane-bressani.ch
 */
use std::net::IpAddr;

struct Arguments {
    flag: String,
    ipaddr_begin: IpAddr,
    ipaddr_end: IpAddr,
    thread: u16,
}

fn main() {
    println!("Hello, world!");
}
