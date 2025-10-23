use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem;
use std::net::Ipv4Addr;

pub fn main(args: &str) {
    let parts: Vec<&str> = args.split_whitespace().collect();

    if parts.is_empty() {
        // No arguments - list all interfaces
        list_network_interfaces();
        return;
    }

    let iface = parts[0];

    if parts.len() == 1 {
        // Just interface name - show that interface
        println!("\n{}:", iface);
        print_interface_info(iface);
        return;
    }

    // Parse commands for the interface
    let mut i = 1;
    while i < parts.len() {
        match parts[i] {
            "up" => {
                if let Err(e) = bring_interface_up(iface) {
                    eprintln!("{}", e);
                }
            }
            "down" => {
                if let Err(e) = bring_interface_down(iface) {
                    eprintln!("{}", e);
                }
            }
            _ => {
                // Check if it looks like an IP address (contains dots)
                if parts[i].contains('.') {
                    let ip = parts[i];
                    // Check for netmask
                    let netmask = if i + 1 < parts.len() && parts[i + 1] == "netmask" && i + 2 < parts.len() {
                        i += 2;
                        parts[i]
                    } else {
                        "255.255.255.0" // Default netmask
                    };

                    if let Err(e) = set_interface_ipv4(iface, ip, netmask) {
                        eprintln!("{}", e);
                    }
                } else if parts[i].contains(':') {
                    // IPv6 address
                    let ipv6 = parts[i];
                    // Parse prefix length (e.g., 2001:db8::1/64)
                    let (addr, prefix) = if let Some(pos) = ipv6.find('/') {
                        let addr = &ipv6[..pos];
                        let prefix = ipv6[pos + 1..].parse::<u8>().unwrap_or(64);
                        (addr, prefix)
                    } else {
                        (ipv6, 64)
                    };

                    if let Err(e) = set_interface_ipv6(iface, addr, prefix) {
                        eprintln!("{}", e);
                    }
                } else {
                    eprintln!("Unknown option: {}", parts[i]);
                }
            }
        }
        i += 1;
    }
}

fn list_network_interfaces() {
    println!("\nNetwork interfaces:");

    // Read from /proc/net/dev which lists all network interfaces
    match File::open("/proc/net/dev") {
        Ok(file) => {
            let reader = BufReader::new(file);
            for (i, line) in reader.lines().enumerate() {
                if let Ok(line) = line {
                    // Skip the first two header lines
                    if i < 2 {
                        continue;
                    }

                    // Parse interface name (everything before the colon)
                    if let Some(iface_name) = line.split(':').next() {
                        let iface_name = iface_name.trim();
                        if !iface_name.is_empty() {
                            // Get interface flags and details using ioctl
                            print_interface_info(iface_name);
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read /proc/net/dev: {}", e);
        }
    }
}

fn print_interface_info(iface_name: &str) {
    println!("\n{}:", iface_name);

    // Create a socket for ioctl calls
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        eprintln!("  Failed to create socket for ioctl");
        return;
    }

    // Prepare interface request structure
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let iface_bytes = iface_name.as_bytes();
    let copy_len = iface_bytes.len().min(libc::IFNAMSIZ - 1);

    // Copy interface name byte by byte
    for i in 0..copy_len {
        ifr.ifr_name[i] = iface_bytes[i] as i8;
    }

    // Get interface flags
    let flags = unsafe {
        if libc::ioctl(sock, libc::SIOCGIFFLAGS as i32, &mut ifr) == 0 {
            ifr.ifr_ifru.ifru_flags
        } else {
            0
        }
    };

    // Print flags
    print!("  Flags: ");
    if flags & libc::IFF_UP as i16 != 0 { print!("UP "); }
    if flags & libc::IFF_BROADCAST as i16 != 0 { print!("BROADCAST "); }
    if flags & libc::IFF_LOOPBACK as i16 != 0 { print!("LOOPBACK "); }
    if flags & libc::IFF_RUNNING as i16 != 0 { print!("RUNNING "); }
    if flags & libc::IFF_MULTICAST as i16 != 0 { print!("MULTICAST "); }
    println!();

    // Get IP address
    unsafe {
        let mut ifr_addr: libc::ifreq = mem::zeroed();

        // Copy interface name byte by byte
        for i in 0..copy_len {
            ifr_addr.ifr_name[i] = iface_bytes[i] as i8;
        }

        if libc::ioctl(sock, libc::SIOCGIFADDR as i32, &mut ifr_addr) == 0 {
            let sin = &*((&ifr_addr.ifr_ifru.ifru_addr) as *const libc::sockaddr as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            println!("  inet addr: {}", ip);
        }

        // Get netmask
        let mut ifr_netmask: libc::ifreq = mem::zeroed();
        for i in 0..copy_len {
            ifr_netmask.ifr_name[i] = iface_bytes[i] as i8;
        }
        if libc::ioctl(sock, libc::SIOCGIFNETMASK as i32, &mut ifr_netmask) == 0 {
            let sin = &*((&ifr_netmask.ifr_ifru.ifru_netmask) as *const libc::sockaddr as *const libc::sockaddr_in);
            let netmask = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            println!("  Mask: {}", netmask);
        }

        // Get MTU
        let mut ifr_mtu: libc::ifreq = mem::zeroed();
        for i in 0..copy_len {
            ifr_mtu.ifr_name[i] = iface_bytes[i] as i8;
        }
        if libc::ioctl(sock, libc::SIOCGIFMTU as i32, &mut ifr_mtu) == 0 {
            println!("  MTU: {}", ifr_mtu.ifr_ifru.ifru_mtu);
        }

        libc::close(sock);
    }

    // Get IPv6 addresses by reading /proc/net/if_inet6
    print_ipv6_addresses(iface_name);

    // Print interface statistics from /proc/net/dev
    print_interface_stats(iface_name);
}

fn print_ipv6_addresses(iface_name: &str) {
    // Read /proc/net/if_inet6 which contains all IPv6 addresses
    // Format: address index prefix_len scope flags interface_name
    // Example: fe80000000000000a2cec8fffe2ea722 02 40 20 80 eth0

    if let Ok(file) = File::open("/proc/net/if_inet6") {
        let reader = BufReader::new(file);

        for line in reader.lines() {
            if let Ok(line) = line {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    let iface = parts[5];

                    // Check if this line is for our interface
                    if iface == iface_name {
                        let addr_hex = parts[0];
                        let prefix_len = parts[2];

                        // Parse the hex address into IPv6 format
                        if addr_hex.len() == 32 {
                            let mut ipv6_parts = Vec::new();
                            for i in 0..8 {
                                let start = i * 4;
                                let end = start + 4;
                                if let Ok(part) = u16::from_str_radix(&addr_hex[start..end], 16) {
                                    ipv6_parts.push(format!("{:x}", part));
                                }
                            }

                            // Format as IPv6 address
                            let ipv6_addr = ipv6_parts.join(":");
                            println!("  inet6 addr: {}/{}", ipv6_addr, prefix_len);
                        }
                    }
                }
            }
        }
    }
}

fn print_interface_stats(iface_name: &str) {
    // Read /proc/net/dev for interface statistics
    // Format (after 2 header lines):
    // interface: RX bytes packets errs drop fifo frame compressed multicast TX bytes packets errs drop fifo colls carrier compressed

    if let Ok(file) = File::open("/proc/net/dev") {
        let reader = BufReader::new(file);

        for (i, line) in reader.lines().enumerate() {
            if let Ok(line) = line {
                // Skip the first two header lines
                if i < 2 {
                    continue;
                }

                // Parse interface name and statistics
                if let Some(colon_pos) = line.find(':') {
                    let iface = line[..colon_pos].trim();

                    if iface == iface_name {
                        let stats_str = line[colon_pos + 1..].trim();
                        let stats: Vec<&str> = stats_str.split_whitespace().collect();

                        if stats.len() >= 16 {
                            // RX statistics
                            let rx_bytes = stats[0].parse::<u64>().unwrap_or(0);
                            let rx_packets = stats[1].parse::<u64>().unwrap_or(0);
                            let rx_errs = stats[2].parse::<u64>().unwrap_or(0);
                            let rx_drop = stats[3].parse::<u64>().unwrap_or(0);
                            let rx_fifo = stats[4].parse::<u64>().unwrap_or(0);
                            let rx_frame = stats[5].parse::<u64>().unwrap_or(0);
                            let rx_compressed = stats[6].parse::<u64>().unwrap_or(0);
                            let rx_multicast = stats[7].parse::<u64>().unwrap_or(0);

                            // TX statistics
                            let tx_bytes = stats[8].parse::<u64>().unwrap_or(0);
                            let tx_packets = stats[9].parse::<u64>().unwrap_or(0);
                            let tx_errs = stats[10].parse::<u64>().unwrap_or(0);
                            let tx_drop = stats[11].parse::<u64>().unwrap_or(0);
                            let tx_fifo = stats[12].parse::<u64>().unwrap_or(0);
                            let tx_colls = stats[13].parse::<u64>().unwrap_or(0);
                            let tx_carrier = stats[14].parse::<u64>().unwrap_or(0);
                            let tx_compressed = stats[15].parse::<u64>().unwrap_or(0);

                            // Print RX statistics
                            println!("  RX packets:{} bytes:{} errors:{} dropped:{} fifo:{} frame:{} compressed:{} multicast:{}",
                                rx_packets, rx_bytes, rx_errs, rx_drop, rx_fifo, rx_frame, rx_compressed, rx_multicast);

                            // Print TX statistics
                            println!("  TX packets:{} bytes:{} errors:{} dropped:{} fifo:{} collisions:{} carrier:{} compressed:{}",
                                tx_packets, tx_bytes, tx_errs, tx_drop, tx_fifo, tx_colls, tx_carrier, tx_compressed);
                        }
                        break;
                    }
                }
            }
        }
    }
}

fn set_interface_ipv4(iface_name: &str, ip: &str, netmask: &str) -> Result<(), String> {
    println!("Setting IPv4 address {} with netmask {} on {}", ip, netmask, iface_name);

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err("Failed to create socket".to_string());
    }

    // Parse IP address
    let ip_addr: Ipv4Addr = ip.parse()
        .map_err(|e| format!("Invalid IP address: {}", e))?;
    let netmask_addr: Ipv4Addr = netmask.parse()
        .map_err(|e| format!("Invalid netmask: {}", e))?;

    // Set IP address
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let iface_bytes = iface_name.as_bytes();
    let copy_len = iface_bytes.len().min(libc::IFNAMSIZ - 1);
    for i in 0..copy_len {
        ifr.ifr_name[i] = iface_bytes[i] as i8;
    }

    unsafe {
        let sin = &mut *((&mut ifr.ifr_ifru.ifru_addr) as *mut libc::sockaddr as *mut libc::sockaddr_in);
        sin.sin_family = libc::AF_INET as u16;
        sin.sin_addr.s_addr = u32::from(ip_addr).to_be();

        if libc::ioctl(sock, libc::SIOCSIFADDR as i32, &mut ifr) < 0 {
            let errno = *libc::__errno_location();
            libc::close(sock);
            return Err(format!("Failed to set IP address: errno {}", errno));
        }

        // Set netmask
        let sin_mask = &mut *((&mut ifr.ifr_ifru.ifru_netmask) as *mut libc::sockaddr as *mut libc::sockaddr_in);
        sin_mask.sin_family = libc::AF_INET as u16;
        sin_mask.sin_addr.s_addr = u32::from(netmask_addr).to_be();

        if libc::ioctl(sock, libc::SIOCSIFNETMASK as i32, &mut ifr) < 0 {
            let errno = *libc::__errno_location();
            libc::close(sock);
            return Err(format!("Failed to set netmask: errno {}", errno));
        }

        libc::close(sock);
    }

    println!("Successfully set IPv4 address on {}", iface_name);

    // Add connected route for the network
    // Calculate network address from IP and netmask
    let network = Ipv4Addr::from(u32::from(ip_addr) & u32::from(netmask_addr));
    let prefix_len = netmask_to_prefix_len(netmask_addr);

    // Add the route using netlink
    if let Err(e) = add_connected_route_v4(network, prefix_len, iface_name) {
        eprintln!("Warning: Failed to add connected route: {}", e);
    }

    Ok(())
}

fn netmask_to_prefix_len(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

fn add_connected_route_v4(network: Ipv4Addr, prefix: u8, iface: &str) -> Result<(), String> {
    // Use the ip route add functionality to add the connected route
    // This is similar to what happens in ip.rs but we need to call it from here
    use crate::cmd::ip::add_route_internal_v4;

    // Add route without gateway (direct/connected route)
    add_route_internal_v4(network, prefix, None, Some(iface))
}

fn set_interface_ipv6(iface_name: &str, ip: &str, prefix_len: u8) -> Result<(), String> {
    println!("Setting IPv6 address {}/{} on {}", ip, prefix_len, iface_name);

    // Parse IPv6 address
    let parts: Vec<&str> = ip.split(':').collect();
    let mut addr_parts = [0u16; 8];

    // Simple IPv6 parser (handles :: notation)
    let mut i = 0;
    let mut double_colon_pos = None;

    for (_idx, part) in parts.iter().enumerate() {
        if part.is_empty() {
            if double_colon_pos.is_none() {
                double_colon_pos = Some(i);
            }
        } else {
            let val = u16::from_str_radix(part, 16)
                .map_err(|e| format!("Invalid IPv6 address part: {}", e))?;
            addr_parts[i] = val;
            i += 1;
        }
    }

    // If we had ::, fill the gap with zeros
    if let Some(pos) = double_colon_pos {
        let remaining = 8 - i;
        for j in (0..i).rev() {
            if j >= pos {
                addr_parts[j + remaining] = addr_parts[j];
                addr_parts[j] = 0;
            }
        }
    }

    // Use the in6_ifreq structure for IPv6 address configuration
    // The structure layout is: addr(16) + prefixlen(4) + ifindex(4) = 24 bytes
    #[repr(C)]
    struct in6_ifreq {
        ifr6_addr: libc::in6_addr,
        ifr6_prefixlen: u32,
        ifr6_ifindex: i32,
    }

    // First, get interface index using AF_INET socket
    let sock_v4 = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock_v4 < 0 {
        return Err("Failed to create socket for interface index".to_string());
    }

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let iface_bytes = iface_name.as_bytes();
    let copy_len = iface_bytes.len().min(libc::IFNAMSIZ - 1);
    for i in 0..copy_len {
        ifr.ifr_name[i] = iface_bytes[i] as i8;
    }

    let if_index = unsafe {
        if libc::ioctl(sock_v4, libc::SIOCGIFINDEX as i32, &mut ifr) < 0 {
            let errno = *libc::__errno_location();
            libc::close(sock_v4);
            return Err(format!("Failed to get interface index: errno {}", errno));
        }
        let idx = ifr.ifr_ifru.ifru_ifindex;
        libc::close(sock_v4);
        idx
    };

    // Now create IPv6 socket for setting address
    let sock = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err("Failed to create IPv6 socket".to_string());
    }

    // Set IPv6 address
    let mut ifr6: in6_ifreq = unsafe { mem::zeroed() };

    // Convert addr_parts to in6_addr
    for i in 0..8 {
        let bytes = addr_parts[i].to_be_bytes();
        ifr6.ifr6_addr.s6_addr[i * 2] = bytes[0];
        ifr6.ifr6_addr.s6_addr[i * 2 + 1] = bytes[1];
    }

    ifr6.ifr6_prefixlen = prefix_len as u32;
    ifr6.ifr6_ifindex = if_index;

    // SIOCSIFADDR is 0x8916, but for IPv6 we need SIOCSIFADDR (add address)
    // The correct ioctl for adding IPv6 address is SIOCSIFADDR = 0x8916
    const SIOCSIFADDR: u64 = 0x8916;

    unsafe {
        if libc::ioctl(sock, SIOCSIFADDR as i32, &mut ifr6) < 0 {
            let errno = *libc::__errno_location();
            libc::close(sock);

            // Provide more helpful error message
            let err_str = libc::strerror(errno);
            let msg = std::ffi::CStr::from_ptr(err_str)
                .to_string_lossy()
                .into_owned();
            let error_msg = format!("errno {} - {}", errno, msg);

            eprintln!("Debug: ifindex={}, prefixlen={}", if_index, prefix_len);
            eprintln!("Debug: Trying ioctl SIOCSIFADDR (0x{:x})", SIOCSIFADDR);

            return Err(format!("Failed to set IPv6 address: {}", error_msg));
        }
        libc::close(sock);
    }

    println!("Successfully set IPv6 address on {}", iface_name);
    Ok(())
}

pub fn bring_interface_up(iface_name: &str) -> Result<(), String> {
    println!("Bringing interface {} up...", iface_name);

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err("Failed to create socket".to_string());
    }

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let iface_bytes = iface_name.as_bytes();
    let copy_len = iface_bytes.len().min(libc::IFNAMSIZ - 1);
    for i in 0..copy_len {
        ifr.ifr_name[i] = iface_bytes[i] as i8;
    }

    unsafe {
        // Get current flags
        if libc::ioctl(sock, libc::SIOCGIFFLAGS as i32, &mut ifr) < 0 {
            let errno = *libc::__errno_location();
            libc::close(sock);
            return Err(format!("Failed to get interface flags: errno {}", errno));
        }

        // Set UP flag
        ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;

        if libc::ioctl(sock, libc::SIOCSIFFLAGS as i32, &mut ifr) < 0 {
            let errno = *libc::__errno_location();
            libc::close(sock);
            return Err(format!("Failed to bring interface up: errno {}", errno));
        }

        libc::close(sock);
    }

    println!("Successfully brought interface {} up", iface_name);
    Ok(())
}

pub fn bring_interface_down(iface_name: &str) -> Result<(), String> {
    println!("Bringing interface {} down...", iface_name);

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err("Failed to create socket".to_string());
    }

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let iface_bytes = iface_name.as_bytes();
    let copy_len = iface_bytes.len().min(libc::IFNAMSIZ - 1);
    for i in 0..copy_len {
        ifr.ifr_name[i] = iface_bytes[i] as i8;
    }

    unsafe {
        // Get current flags
        if libc::ioctl(sock, libc::SIOCGIFFLAGS as i32, &mut ifr) < 0 {
            let errno = *libc::__errno_location();
            libc::close(sock);
            return Err(format!("Failed to get interface flags: errno {}", errno));
        }

        // Clear UP flag
        ifr.ifr_ifru.ifru_flags &= !(libc::IFF_UP as i16);

        if libc::ioctl(sock, libc::SIOCSIFFLAGS as i32, &mut ifr) < 0 {
            let errno = *libc::__errno_location();
            libc::close(sock);
            return Err(format!("Failed to bring interface down: errno {}", errno));
        }

        libc::close(sock);
    }

    println!("Successfully brought interface {} down", iface_name);
    Ok(())
}

pub fn help_text() -> &'static str {
    "ifconfig [iface] [config]         - Configure network interfaces"
}
