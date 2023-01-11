use std::net::IpAddr;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use pnet::packet::{tcp::TcpPacket, udp::UdpPacket};

fn get_interface() -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .filter(|x| x.is_up() && x.is_running() && !x.is_loopback())
        .next()
}

fn handle_dns_packet(
    protocol: IpNextHeaderProtocol,
    source: IpAddr,
    packet: Vec<u8>,
) -> (Option<dns_message_parser::Dns>, Option<IpAddr>) {
    let payload = match protocol {
        IpNextHeaderProtocols::Tcp => {
            TcpPacket::new(&packet).and_then(|pct| Some(pct.payload().to_vec()))
        }
        IpNextHeaderProtocols::Udp => {
            UdpPacket::new(&packet).and_then(|pct| Some(pct.payload().to_vec()))
        }
        _ => None,
    };
    if let Some(payload) = payload {
        return (
            dns_message_parser::Dns::decode(bytes::Bytes::copy_from_slice(&payload)).ok(),
            Some(source),
        );
    }
    (None, None)
}

fn handle_ipv4_packet(
    ethernet: EthernetPacket,
) -> (Option<dns_message_parser::Dns>, Option<IpAddr>) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        return match header.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => handle_dns_packet(
                IpNextHeaderProtocols::Tcp,
                IpAddr::V4(header.get_destination()),
                header.payload().to_vec(),
            ),
            IpNextHeaderProtocols::Udp => handle_dns_packet(
                IpNextHeaderProtocols::Udp,
                IpAddr::V4(header.get_destination()),
                header.payload().to_vec(),
            ),
            _ => (None, None),
        };
    }
    (None, None)
}

fn handle_ipv6_packet(
    ethernet: EthernetPacket,
) -> (Option<dns_message_parser::Dns>, Option<IpAddr>) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        return match header.get_next_header() {
            IpNextHeaderProtocols::Tcp => handle_dns_packet(
                IpNextHeaderProtocols::Tcp,
                IpAddr::V6(header.get_destination()),
                header.payload().to_vec(),
            ),
            IpNextHeaderProtocols::Udp => handle_dns_packet(
                IpNextHeaderProtocols::Udp,
                IpAddr::V6(header.get_destination()),
                header.payload().to_vec(),
            ),
            _ => (None, None),
        };
    }
    (None, None)
}

fn main() {
    let iface = match get_interface() {
        Some(iface) => iface,
        None => {
            println!("No suitable interface was found");
            return;
        }
    };

    println!("Listening on {} interface", iface.name);

    let mut rx = match datalink::channel(&iface, Default::default()) {
        Ok(Ethernet(_, rx)) => rx,
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => {
            println!(
                "An error occurred when creating the datalink channel: {}",
                e
            );
            return;
        }
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(packet) = EthernetPacket::new(packet) {
                    let (dns_packet, source_address) = match packet.get_ethertype() {
                        EtherTypes::Ipv4 => handle_ipv4_packet(packet),
                        EtherTypes::Ipv6 => handle_ipv6_packet(packet),
                        _ => (None, None),
                    };
                    if let Some(dns_packet) = dns_packet {
                        if dns_packet.is_response() {
                            for answer in dns_packet.answers {
                                println!("{} asked: {}", source_address.unwrap(), answer);
                            }
                        }
                    }
                } else {
                    println!("Not Ethernet packet was received");
                }
            }
            Err(e) => {
                println!("An error occured while reading {}", e);
                return;
            }
        }
    }
}
