use std::net::Ipv4Addr;

use pcap::{Capture, Packet};

struct EthernetHeader {
    dest_mac: [u8; 6],
    src_mac: [u8; 6],
    ethertype: u16,
}

struct Ipv4Header {
    version: u8,
    header_length: u8,
    total_length: u16,
    protocol: u8,
    src_ip: [u8; 4],
    dest_ip: [u8; 4],
}

fn main() {
    let devices = get_devices().expect("Failed to get devices...");
    println!("Select the device.");
    for device in &devices {
        println!("{}", device.name);
    }

    let mut sniffer = Capture::from_device("wlp0s20f3").unwrap().open().unwrap();

    while let Ok(packet) = sniffer.next_packet() {
        let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
        let ethernet = EthernetHeader {
            src_mac: packet[0..6].try_into().unwrap(),
            dest_mac: packet[6..12].try_into().unwrap(),
            ethertype,
        };
        match ethertype {
            0x0800 => {
                println!("IPv4 Packet");
                let ipv4 = sniff_ipv4(&packet);
                println!(
                    "{}: {} -> {}",
                    ipv4.protocol,
                    Ipv4Addr::new(
                        ipv4.src_ip[0],
                        ipv4.src_ip[1],
                        ipv4.src_ip[2],
                        ipv4.src_ip[3]
                    ),
                    Ipv4Addr::new(
                        ipv4.dest_ip[0],
                        ipv4.dest_ip[1],
                        ipv4.dest_ip[2],
                        ipv4.dest_ip[3]
                    )
                );
            }
            0x86dd => println!("IPv6 Packet"),
            0x0806 => println!("ARP Packet"),
            _ => println!("Unknown Ethertype: 0x{:x}", ethertype),
        }
    }
}

fn get_devices() -> Result<Vec<pcap::Device>, pcap::Error> {
    let devices = pcap::Device::list()?;
    Ok(devices)
}

fn sniff_ipv4(packet: &Packet<'_>) -> Ipv4Header {
    let version = packet[14] >> 4;
    let header_length = packet[14] & 0x0F;

    Ipv4Header {
        version: version,
        header_length: header_length * 4,
        total_length: u16::from_be_bytes([packet[16], packet[17]]),
        protocol: packet[23],
        src_ip: packet[26..30].try_into().unwrap(),
        dest_ip: packet[30..34].try_into().unwrap(),
    }
}
