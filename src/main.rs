use etherparse::{Ethernet2Header, PacketHeaders};
use ifstructs::ifreq;
use libc;
use libc::{c_char, c_void};
use std::mem;

extern "C" {
    fn htons(hostshort: i32) -> i32;
}

fn init_socket(eth_device: &str, promisc: bool, ip_only: bool) -> i32 {
    unsafe {
        let sock: i32 = match libc::socket(
            libc::PF_PACKET,
            libc::SOCK_RAW,
            libc::ETH_P_ALL.to_be() as i32,
        ) {
            -1 => panic!("Failed to create socket"),
            fd => fd,
        };

        let mut ifreq: ifreq = mem::zeroed();
        let mut addr: libc::sockaddr_ll = mem::zeroed();

        let mut device_name: [u8; 16] = [0; 16];

        for (i, ch) in eth_device.as_bytes().iter().enumerate() {
            if i >= device_name.len() {
                break;
            }
            device_name[i] = ch.clone();
        }
        ifreq.ifr_name = device_name;

        addr.sll_family = libc::PF_PACKET as u16;
        addr.sll_protocol = if ip_only {
            htons(libc::ETH_P_IP) as u16
        } else {
            htons(libc::ETH_P_ALL) as u16
        };
        addr.sll_ifindex = ifreq.ifr_ifru.ifr_ifindex;

        if libc::bind(
            sock,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of_val(&addr) as u32,
        ) < 0
        {
            libc::close(sock);
            panic!("Failed to bind socket")
        }

        if promisc {
            if libc::ioctl(sock, libc::SIOCGIFFLAGS, &ifreq) < 0 {
                libc::close(sock);
                panic!("Failed to set device info into specified socket");
            }

            ifreq.ifr_ifru.ifr_flags |= libc::IFF_PROMISC as i16;

            if libc::ioctl(sock, libc::SIOCSIFFLAGS, &ifreq) < 0 {
                libc::close(sock);
                panic!("Failed to set device info into specified socket");
            }
        }

        sock
    }
}

fn mac_to_str(mac: [u8; 6]) -> String {
    format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn ipv4_to_str(ip: [u8; 4]) -> String {
    format!("{:?}:{:?}:{:?}:{:?}", ip[0], ip[1], ip[2], ip[3])
}

static ARP_OPERATION_REQUEST: &'static str = "request";
static ARP_OPERATION_REPLY: &'static str = "reply";
static ARP_OPERATION_UNKNOWN: &'static str = "unknown";

fn arp_op_to_str(op: u16) -> &'static str {
    if op == 1 {
        ARP_OPERATION_REQUEST
    } else if op == 2 {
        ARP_OPERATION_REPLY
    } else {
        ARP_OPERATION_UNKNOWN
    }
}

// Derived from https://gist.github.com/thombles/16736c9c656e6dad9a08c81b30a974ac
#[repr(C)]
#[derive(Debug)]
struct RawArpFrame {
    // ARP Payload
    hardware_type: u16, // expect 0x0001 for ethernet
    protocol_type: u16, // expect 0x0800 for IPv4
    hw_addr_len: u8,    // expect 6 [octets] for MAC addresses
    proto_addr_len: u8, // expect 4 [octets] for IPv4 addresses
    operation: u16,     // 1 for request, 2 for reply
    sender_hw_addr: [u8; 6],
    sender_proto_addr: [u8; 4],
    target_hw_addr: [u8; 6],
    target_proto_addr: [u8; 4],
}

static ARP_HARDWARE: &'static [&str] = &[
    "From KA9Q: NET/ROM pseudo.",
    "Ethernet 10/100Mbps.",
    "Experimental Ethernet.",
    "AX.25 Level 2.",
    "PROnet token ring.",
    "Chaosnet.",
    "IEEE 802.2 Ethernet/TR/TB.",
    "ARCnet.",
    "APPLEtalk.",
    "undefine",
    "undefine",
    "undefine",
    "undefine",
    "undefine",
    "undefine",
    "Frame Relay DLCI.",
    "undefine",
    "undefine",
    "undefine",
    "ATM.",
    "undefine",
    "undefine",
    "undefine",
    "Metricom STRIP (new IANA id).",
];

static ETHERTYPE_IP: u16 = 0x0800;
static ETHERTYPE_ARP: u16 = 0x0806;
static ETHERTYPE_REVARP: u16 = 0x8035;
static ETHERTYPE_IPV6: u16 = 0x86dd;

fn analyze_arp(packet: &[u8]) {
    let arp_hdr_len = mem::size_of::<RawArpFrame>();

    if packet.len() < arp_hdr_len {
        return;
    }
    let arp_hdr: RawArpFrame = unsafe { std::ptr::read(packet.as_ptr() as *const _) };

    println!("---- arp ----");

    if arp_hdr.hardware_type.to_be() < 24 {
        println!(
            "  Hardware: {:?}",
            ARP_HARDWARE[arp_hdr.hardware_type.to_be() as usize]
        );
    }

    if arp_hdr.protocol_type.to_be() == ETHERTYPE_IP {
        println!("  Protocol: IPv4");
    } else if arp_hdr.protocol_type.to_be() == ETHERTYPE_ARP {
        println!("  Protocol: Address Resolution");
    } else if arp_hdr.protocol_type.to_be() == ETHERTYPE_REVARP {
        println!("  Protocol: Reverse ARP");
    } else if arp_hdr.protocol_type.to_be() == ETHERTYPE_IPV6 {
        println!("  Protocol: IPv6");
    } else {
        println!("  Protocol: unknown");
    }

    println!("  proto addr len: {:?}", arp_hdr.proto_addr_len);
    println!(
        "  operation: {:?}",
        arp_op_to_str(arp_hdr.operation.to_be())
    );
    println!(
        "  src MAC address: {:?}",
        mac_to_str(arp_hdr.sender_hw_addr)
    );
    println!(
        "  src IP address: {:?}",
        ipv4_to_str(arp_hdr.sender_proto_addr)
    );
    println!(
        "  dst MAC address: {:?}",
        mac_to_str(arp_hdr.target_hw_addr)
    );
    println!(
        "  dst IP address: {:?}",
        ipv4_to_str(arp_hdr.target_proto_addr)
    );
}

fn analyze_ether(buf: &[c_char; 1024]) {
    let buf_cp: Vec<u8> = buf.iter().map(|&c| c as u8).collect();
    if let Ok(value) = PacketHeaders::from_ethernet_slice(&buf_cp) {
        let eth_type = value.link.unwrap().ether_type;

        if eth_type == libc::ETH_P_ARP as u16 {
            analyze_arp(value.payload);
        }
    }
}

fn main() {
    let mut buf: [c_char; 1024] = [0; 1024];
    let sock = init_socket("enp6s0", false, false);

    loop {
        unsafe {
            libc::read(
                sock,
                buf.as_mut_ptr() as *mut c_void,
                mem::size_of_val(&buf),
            );
            analyze_ether(&buf);
        }
    }
}
