use std::net::{IpAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use std::mem;

const ICMP_ECHO: u8 = 8;
const ICMPV6_ECHO_REQUEST: u8 = 128;

pub fn main(args: &str) {
    let parts: Vec<&str> = args.trim().split_whitespace().collect();

    if parts.is_empty() {
        eprintln!("Usage: ping <destination> [count]");
        return;
    }

    let destination = parts[0];
    let count = if parts.len() > 1 {
        parts[1].parse::<usize>().unwrap_or(4)
    } else {
        4
    };

    // Resolve the destination address
    let addr = match resolve_address(destination) {
        Some(addr) => addr,
        None => {
            eprintln!("Failed to resolve address: {}", destination);
            return;
        }
    };

    println!("PING {} ({}) with {} packets", destination, addr, count);

    match addr {
        IpAddr::V4(ipv4) => ping_ipv4(ipv4, count),
        IpAddr::V6(ipv6) => ping_ipv6(ipv6, count),
    }
}

fn resolve_address(dest: &str) -> Option<IpAddr> {
    // Try parsing as IP address first
    if let Ok(addr) = dest.parse::<IpAddr>() {
        return Some(addr);
    }

    // Try DNS resolution (add dummy port for ToSocketAddrs)
    let dest_with_port = format!("{}:0", dest);
    if let Ok(mut addrs) = dest_with_port.to_socket_addrs() {
        if let Some(socket_addr) = addrs.next() {
            return Some(socket_addr.ip());
        }
    }

    None
}

fn ping_ipv4(dest: std::net::Ipv4Addr, count: usize) {
    let sock = unsafe {
        libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP)
    };

    if sock < 0 {
        eprintln!("Failed to create raw socket (need root/CAP_NET_RAW)");
        return;
    }

    // Set receive timeout
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const _ as *const libc::c_void,
            mem::size_of::<libc::timeval>() as u32,
        );
    }

    let mut sent = 0;
    let mut received = 0;

    for seq in 0..count {
        let start = Instant::now();

        if send_icmp_echo(sock, dest, seq as u16) {
            sent += 1;

            if let Some(rtt) = recv_icmp_reply(sock, seq as u16) {
                received += 1;
                println!("64 bytes from {}: icmp_seq={} ttl=64 time={:.1} ms",
                    dest, seq, rtt * 1000.0);
            } else {
                println!("Request timeout for icmp_seq {}", seq);
            }
        }

        // Wait for 1 second between pings
        let elapsed = start.elapsed();
        if elapsed < Duration::from_secs(1) && seq < count - 1 {
            std::thread::sleep(Duration::from_secs(1) - elapsed);
        }
    }

    unsafe { libc::close(sock); }

    println!("\n--- {} ping statistics ---", dest);
    println!("{} packets transmitted, {} received, {:.1}% packet loss",
        sent, received,
        if sent > 0 { (sent - received) as f64 / sent as f64 * 100.0 } else { 0.0 });
}

fn send_icmp_echo(sock: i32, dest: std::net::Ipv4Addr, seq: u16) -> bool {
    let mut packet = vec![0u8; 64];

    // ICMP header
    packet[0] = ICMP_ECHO;  // Type
    packet[1] = 0;           // Code
    packet[2] = 0;           // Checksum (will calculate)
    packet[3] = 0;
    packet[4] = 0;           // Identifier
    packet[5] = 0;
    packet[6] = (seq >> 8) as u8;    // Sequence number
    packet[7] = (seq & 0xff) as u8;

    // Payload (fill with pattern)
    for i in 8..packet.len() {
        packet[i] = (i & 0xff) as u8;
    }

    // Calculate checksum
    let checksum = calculate_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xff) as u8;

    // Send packet
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(dest.octets()),
        },
        sin_zero: [0; 8],
    };

    let result = unsafe {
        libc::sendto(
            sock,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };

    result >= 0
}

fn recv_icmp_reply(sock: i32, expected_seq: u16) -> Option<f64> {
    let start = Instant::now();
    let mut buf = vec![0u8; 1024];

    loop {
        let result = unsafe {
            libc::recv(
                sock,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };

        if result < 0 {
            return None; // Timeout or error
        }

        let len = result as usize;
        if len < 28 { // Min: 20 (IP header) + 8 (ICMP header)
            continue;
        }

        // Skip IP header (typically 20 bytes, but check IHL)
        let ip_header_len = ((buf[0] & 0x0f) * 4) as usize;
        if len < ip_header_len + 8 {
            continue;
        }

        let icmp_type = buf[ip_header_len];
        let icmp_seq = u16::from_be_bytes([
            buf[ip_header_len + 6],
            buf[ip_header_len + 7],
        ]);

        // Check if this is an echo reply for our sequence number
        if icmp_type == 0 && icmp_seq == expected_seq {
            let rtt = start.elapsed().as_secs_f64();
            return Some(rtt);
        }

        // Check for timeout (2 seconds)
        if start.elapsed() > Duration::from_secs(2) {
            return None;
        }
    }
}

fn ping_ipv6(dest: std::net::Ipv6Addr, count: usize) {
    let sock = unsafe {
        libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6)
    };

    if sock < 0 {
        eprintln!("Failed to create raw socket (need root/CAP_NET_RAW)");
        return;
    }

    // Set receive timeout
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const _ as *const libc::c_void,
            mem::size_of::<libc::timeval>() as u32,
        );
    }

    let mut sent = 0;
    let mut received = 0;

    for seq in 0..count {
        let start = Instant::now();

        if send_icmpv6_echo(sock, dest, seq as u16) {
            sent += 1;

            if let Some(rtt) = recv_icmpv6_reply(sock, seq as u16) {
                received += 1;
                println!("64 bytes from {}: icmp_seq={} hlim=64 time={:.1} ms",
                    dest, seq, rtt * 1000.0);
            } else {
                println!("Request timeout for icmp_seq {}", seq);
            }
        }

        // Wait for 1 second between pings
        let elapsed = start.elapsed();
        if elapsed < Duration::from_secs(1) && seq < count - 1 {
            std::thread::sleep(Duration::from_secs(1) - elapsed);
        }
    }

    unsafe { libc::close(sock); }

    println!("\n--- {} ping statistics ---", dest);
    println!("{} packets transmitted, {} received, {:.1}% packet loss",
        sent, received,
        if sent > 0 { (sent - received) as f64 / sent as f64 * 100.0 } else { 0.0 });
}

fn send_icmpv6_echo(sock: i32, dest: std::net::Ipv6Addr, seq: u16) -> bool {
    let mut packet = vec![0u8; 64];

    // ICMPv6 header (kernel will calculate checksum for ICMPv6)
    packet[0] = ICMPV6_ECHO_REQUEST;  // Type
    packet[1] = 0;                     // Code
    packet[2] = 0;                     // Checksum (kernel calculates)
    packet[3] = 0;
    packet[4] = 0;                     // Identifier
    packet[5] = 0;
    packet[6] = (seq >> 8) as u8;      // Sequence number
    packet[7] = (seq & 0xff) as u8;

    // Payload
    for i in 8..packet.len() {
        packet[i] = (i & 0xff) as u8;
    }

    // Send packet
    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as u16,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: dest.octets(),
        },
        sin6_scope_id: 0,
    };

    let result = unsafe {
        libc::sendto(
            sock,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in6>() as u32,
        )
    };

    result >= 0
}

fn recv_icmpv6_reply(sock: i32, expected_seq: u16) -> Option<f64> {
    let start = Instant::now();
    let mut buf = vec![0u8; 1024];

    loop {
        let result = unsafe {
            libc::recv(
                sock,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };

        if result < 0 {
            return None; // Timeout or error
        }

        let len = result as usize;
        if len < 8 { // ICMPv6 header only (no IP header in raw socket)
            continue;
        }

        let icmp_type = buf[0];
        let icmp_seq = u16::from_be_bytes([buf[6], buf[7]]);

        // Check if this is an echo reply (type 129) for our sequence number
        if icmp_type == 129 && icmp_seq == expected_seq {
            let rtt = start.elapsed().as_secs_f64();
            return Some(rtt);
        }

        // Check for timeout (2 seconds)
        if start.elapsed() > Duration::from_secs(2) {
            return None;
        }
    }
}

fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum up 16-bit words
    while i < data.len() - 1 {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }

    // Add remaining byte if odd length
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}

pub fn help_text() -> &'static str {
    "ping <dest> [count]               - Send ICMP echo requests (IPv4/IPv6)"
}
