use etherparse::PacketHeaders;
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

        println!("{:?}", sock);
        if sock < 0 {
            panic!("Failed to create socket");
        }

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

fn print_ether_hdr(buf: &[c_char; 1024]) {
    let mut buf_cp: Vec<u8> = Vec::new();
    for ch in buf {
        buf_cp.push(ch.clone() as u8);
    }

    match PacketHeaders::from_ethernet_slice(&buf_cp[..]) {
        Err(value) => println!("error"),
        Ok(value) => println!("ok"),
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
            print_ether_hdr(&buf);
        }
    }
}
