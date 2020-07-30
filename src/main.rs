/*
 * Cli for scan with multi-thread ip range
 * By Stéphane Bressani
 * www.stephane-bressani.ch
 *
 * To do: Bot telegram notification or mail
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
fn main() {
    // Ip range with arg
    // -> Todo

    // Ping fn
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
