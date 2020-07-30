extern crate rawsock;
use rawsock::open_best_library;

const ICMP_PACKET: [u8; 84] = [
    0x45, 0x00, 0x00, 0x54, 0xee, 0x96, 0x40, 0x00, 0x40, 0x01, 0x79, 0xf0, 0xc0, 0xa8, 0x01, 0x6a,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x00, 0x2f, 0x08, 0x66, 0xc2, 0x00, 0x12, 0x82, 0xaa, 0xcc, 0x5c,
    0x00, 0x00, 0x00, 0x00, 0x51, 0x49, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37,
];
/// This example shows automatic choosing of the best underlying library
/// available on your system and dynamic dispatch of calls to the right
/// implementation.
///
/// For most applications this is the recommended approach.

pub fn ping() {
    /*
     */
    println!("Opening packet capturing library");
    let lib = open_best_library().expect("Could not open any packet capturing library");
    println!("Library opened, version is {}", lib.version());
    let interf_name = "eth0"; //replace with whatever is available on your platform
    println!("Opening the {} interface", interf_name);
    let mut interf = lib
        .open_interface(&interf_name)
        .expect("Could not open network interface");
    println!("Interface opened, data link: {}", interf.data_link());

    //send some packets
    println!("Sending 5 packets:");
    for i in 0..5 {
        println!("Sending ICMP ping packet no {}", i);
        interf.send(&ICMP_PACKET).expect("Could not send packet");
    }

    //receive some packets.
    println!("Receiving 5 packets:");
    for _ in 0..5 {
        let packet = interf.receive().expect("Could not receive packet");
        println!("Received packet: {}", packet);
    }
}
