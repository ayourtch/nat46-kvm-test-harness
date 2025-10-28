use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use oside::protocols::icmpv6::icmpv6NeighborSolicitation;

// Global state for fake hosts
lazy_static::lazy_static! {
    static ref FAKE_HOSTS: Arc<Mutex<HashMap<String, InterfaceHosts>>> = Arc::new(Mutex::new(HashMap::new()));
}

#[derive(Clone)]
struct FakeHost {
    ip: IpAddr,
    mac: [u8; 6],
    respond_icmp: bool,
    is_router: bool,
}

struct InterfaceHosts {
    hosts: Vec<FakeHost>,
    default_mac: [u8; 6],  // Interface MAC as default
    stop_flag: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<()>>,
}

pub fn main(args: &str) {
    let parts: Vec<&str> = args.trim().split_whitespace().collect();

    if parts.is_empty() {
        eprintln!("Usage:");
        eprintln!("  fakehost add <interface> <ip-address> [mac <mac>] [icmp] [router]");
        eprintln!("           - Add fake host responding to ARP/NS");
        eprintln!("           - mac: Set MAC address (default: interface MAC)");
        eprintln!("           - icmp: Respond to ICMP Echo (ping)");
        eprintln!("           - router: Set Router flag in IPv6 NA");
        eprintln!("  fakehost del <interface> <ip-address>  - Remove fake host");
        eprintln!("  fakehost show                          - Show all fake hosts");
        eprintln!("");
        return;
    }

    match parts[0] {
        "add" => {
            if parts.len() < 3 {
                eprintln!("Usage: fakehost add <interface> <ip-address> [mac <mac>] [icmp] [router]");
                return;
            }
            add_fakehost(parts[1], &parts[2..]);
        }
        "del" => {
            if parts.len() < 3 {
                eprintln!("Usage: fakehost del <interface> <ip-address>");
                return;
            }
            del_fakehost(parts[1], parts[2]);
        }
        "show" => {
            show_fakehosts();
        }
        _ => {
            eprintln!("Unknown command: {}", parts[0]);
            eprintln!("Use: add, del, or show");
        }
    }
}

fn parse_mac(mac_str: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = mac_str.split(|c| c == ':' || c == '-').collect();
    if parts.len() != 6 {
        return None;
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

fn add_fakehost(iface: &str, args: &[&str]) {
    if args.is_empty() {
        eprintln!("Usage: fakehost add <interface> <ip-address> [mac <mac>] [icmp] [router]");
        return;
    }

    let ip_str = args[0];
    let mut custom_mac: Option<[u8; 6]> = None;
    let mut respond_icmp = false;
    let mut is_router = false;

    // Parse optional arguments
    let mut i = 1;
    while i < args.len() {
        match args[i] {
            "mac" => {
                if i + 1 < args.len() {
                    custom_mac = parse_mac(args[i + 1]);
                    if custom_mac.is_none() {
                        eprintln!("Invalid MAC address: {}", args[i + 1]);
                        return;
                    }
                    i += 2;
                } else {
                    eprintln!("mac requires an address argument");
                    return;
                }
            }
            "icmp" => {
                respond_icmp = true;
                i += 1;
            }
            "router" => {
                is_router = true;
                i += 1;
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                return;
            }
        }
    }

    // Parse IP address
    let ip_addr = if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
        IpAddr::V4(ipv4)
    } else if let Ok(ipv6) = ip_str.parse::<Ipv6Addr>() {
        IpAddr::V6(ipv6)
    } else {
        eprintln!("Invalid IP address: {}", ip_str);
        return;
    };

    let mut hosts = FAKE_HOSTS.lock().unwrap();

    // Get or create interface entry
    if !hosts.contains_key(iface) {
        // Get interface MAC address as default
        let default_mac = match get_interface_mac(iface) {
            Some(m) => m,
            None => {
                eprintln!("Failed to get MAC address for interface {}", iface);
                return;
            }
        };

        // Start responder thread
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = Arc::clone(&stop_flag);
        let iface_owned = iface.to_string();

        let thread_handle = thread::spawn(move || {
            responder_thread(&iface_owned, stop_flag_clone);
        });

        hosts.insert(iface.to_string(), InterfaceHosts {
            hosts: Vec::new(),
            default_mac,
            stop_flag,
            thread_handle: Some(thread_handle),
        });

        println!("Started fake host responder on {}", iface);
    }

    let interface = hosts.get_mut(iface).unwrap();

    // Check if this IP already exists
    if interface.hosts.iter().any(|h| h.ip == ip_addr) {
        eprintln!("Fake host {} already exists on {}", ip_str, iface);
        return;
    }

    // Use custom MAC or default to interface MAC
    let mac = custom_mac.unwrap_or(interface.default_mac);

    // Create and add the fake host
    let fake_host = FakeHost {
        ip: ip_addr,
        mac,
        respond_icmp,
        is_router,
    };

    interface.hosts.push(fake_host);

    let proto = match ip_addr {
        IpAddr::V4(_) => "ARP",
        IpAddr::V6(_) => "NS",
    };

    println!("Added fake host {} on {} (will respond to {}{}{})",
        ip_str, iface, proto,
        if respond_icmp { ", ICMP" } else { "" },
        if is_router { ", Router flag" } else { "" });
}

fn del_fakehost(iface: &str, ip_str: &str) {
    let mut hosts = FAKE_HOSTS.lock().unwrap();

    if let Some(interface) = hosts.get_mut(iface) {
        // Parse IP address
        let ip_addr = if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
            IpAddr::V4(ipv4)
        } else if let Ok(ipv6) = ip_str.parse::<Ipv6Addr>() {
            IpAddr::V6(ipv6)
        } else {
            eprintln!("Invalid IP address: {}", ip_str);
            return;
        };

        // Find and remove the host
        if let Some(pos) = interface.hosts.iter().position(|h| h.ip == ip_addr) {
            interface.hosts.remove(pos);
            println!("Removed fake host {} from {}", ip_str, iface);

            // If no more hosts on this interface, stop the thread
            if interface.hosts.is_empty() {
                interface.stop_flag.store(true, Ordering::SeqCst);
                if let Some(handle) = interface.thread_handle.take() {
                    drop(hosts); // Release lock before joining
                    let _ = handle.join();
                    let mut hosts = FAKE_HOSTS.lock().unwrap();
                    hosts.remove(iface);
                    println!("Stopped fake host responder on {}", iface);
                }
            }
        } else {
            eprintln!("Fake host {} not found on {}", ip_str, iface);
        }
    } else {
        eprintln!("No fake hosts on interface {}", iface);
    }
}

fn show_fakehosts() {
    let hosts = FAKE_HOSTS.lock().unwrap();

    if hosts.is_empty() {
        println!("No fake hosts configured");
        return;
    }

    println!("\nFake hosts:");
    println!("{:<15} {:<40} {:<18} {:<6} {:<6} {}",
        "Interface", "IP Address", "MAC Address", "ICMP", "Router", "Type");
    println!("{}", "-".repeat(100));

    for (iface, interface) in hosts.iter() {
        for host in &interface.hosts {
            let mac_str = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                host.mac[0], host.mac[1], host.mac[2],
                host.mac[3], host.mac[4], host.mac[5]);

            let proto = match host.ip {
                IpAddr::V4(_) => "IPv4 (ARP)",
                IpAddr::V6(_) => "IPv6 (NDP)",
            };

            println!("{:<15} {:<40} {:<18} {:<6} {:<6} {}",
                iface,
                host.ip,
                mac_str,
                if host.respond_icmp { "yes" } else { "no" },
                if host.is_router { "yes" } else { "no" },
                proto);
        }
    }
}

fn get_interface_mac(iface: &str) -> Option<[u8; 6]> {
    use std::mem;

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return None;
    }

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let iface_bytes = iface.as_bytes();
    let copy_len = iface_bytes.len().min(libc::IFNAMSIZ - 1);

    for i in 0..copy_len {
        ifr.ifr_name[i] = iface_bytes[i] as i8;
    }

    let result = unsafe { libc::ioctl(sock, libc::SIOCGIFHWADDR as i32, &mut ifr) };
    unsafe { libc::close(sock); }

    if result == 0 {
        let hwaddr = unsafe { &ifr.ifr_ifru.ifru_hwaddr };
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = hwaddr.sa_data[i] as u8;
        }
        Some(mac)
    } else {
        None
    }
}

fn responder_thread(iface: &str, stop_flag: Arc<AtomicBool>) {
    // Get TAP file descriptor from registry
    let tap_fd = match super::tap::get_tap_fd(iface) {
        Some(fd) => fd,
        None => {
            eprintln!("Failed to get TAP FD for {}. Make sure it's a TAP interface created with 'tap add'.", iface);
            return;
        }
    };

    println!("Fake host responder running on {} (fd={})", iface, tap_fd);

    let mut buffer = vec![0u8; 2048];

    loop {
        if stop_flag.load(Ordering::SeqCst) {
            break;
        }

        // Set read timeout
        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 100_000, // 100ms
        };

        unsafe {
            libc::setsockopt(
                tap_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
        }

        // Read packet
        let result = unsafe {
            libc::read(
                tap_fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
            )
        };

        if result < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                continue;
            }
            eprintln!("Read error on {}: errno {}", iface, errno);
            thread::sleep(Duration::from_millis(100));
            continue;
        }

        if result == 0 {
            continue;
        }

        let packet_len = result as usize;

        // Process packet and generate response if needed
        if let Some(response) = process_packet(&buffer[..packet_len], iface) {
            // Send response
            unsafe {
                libc::write(
                    tap_fd,
                    response.as_ptr() as *const libc::c_void,
                    response.len(),
                );
            }
        }
    }

    println!("Fake host responder stopped on {}", iface);
}


fn process_packet(packet: &[u8], iface: &str) -> Option<Vec<u8>> {
    use oside::protocols::all::*;
    use oside::*;
    use oside::protocols::icmpv6::icmpv6EchoRequest;

    // Parse Ethernet frame
    let (stack, _) = Ether!().ldecode(packet)?;

    // Check for ARP
    if let Some(arp) = stack.get_layer(ARP!()) {
       return handle_arp(arp, iface);
    }

    // Check for IPv6 Neighbor Solicitation
    if stack.get_layer(Icmpv6NeighborSolicitation!()).is_some() {
       return handle_ns(&stack, iface);
    }

    // Check for ICMP Echo Request (IPv4)
    if let Some(icmp) = stack.get_layer(ICMP!()) {
        return handle_icmp(&stack, icmp, iface);
    }

    // Check for ICMPv6 Echo Request (IPv6)
    if stack.get_layer(oside::Icmpv6EchoRequest!()).is_some() {
        return handle_icmpv6_echo(&stack, iface);
    }

    None
}

use oside::protocols::all::Arp;

fn handle_arp(arp: &Arp, iface: &str) -> Option<Vec<u8>> {
    use oside::protocols::all::*;
    use oside::*;

    // FIXME: This is ... interesting, to say the least.
    // Does this mean I need better ergonomics for the oside,
    // such that Claude could figure it out ?
    let json = serde_json::to_value(arp).ok()?;

    // Check if it's an ARP request
    let op = json.get("op")?.as_u64()?;
    if op != 1 {
        // Not a request
        return None;
    }

    let target_ip_str = json.get("pdst")?.as_str()?;
    let target_ip: Ipv4Addr = target_ip_str.parse().ok()?;

    // Find the fake host with this IP
    let hosts = FAKE_HOSTS.lock().unwrap();
    let interface = hosts.get(iface)?;

    let fake_host = interface.hosts.iter()
        .find(|h| h.ip == IpAddr::V4(target_ip))?;

    let sender_ip_str = json.get("psrc")?.as_str()?;
    let sender_ip: Ipv4Addr = sender_ip_str.parse().ok()?;
    let sender_mac_str = json.get("hwsrc")?.as_str()?;

    println!("ARP: Who has {}? Tell {} - Responding with MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        target_ip, sender_ip,
        fake_host.mac[0], fake_host.mac[1], fake_host.mac[2],
        fake_host.mac[3], fake_host.mac[4], fake_host.mac[5]);

    // Build ARP reply with the fake host's MAC
    let mac_str = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        fake_host.mac[0], fake_host.mac[1], fake_host.mac[2],
        fake_host.mac[3], fake_host.mac[4], fake_host.mac[5]);

    let arp_reply = ARP!(
        op = 2,
        hwsrc = ArpHardwareAddress::from(mac_str.as_str()),
        psrc = ArpProtocolAddress::from(target_ip_str),
        hwdst = ArpHardwareAddress::from(sender_mac_str),
        pdst = ArpProtocolAddress::from(sender_ip_str)
    );

    let stack = Ether!(
        dst = MacAddr::from(sender_mac_str),
        src = MacAddr::from(mac_str.as_str()),
        etype = 0x0806
    ) / arp_reply;

    Some(stack.lencode())
}

fn handle_ns(stack: &oside::LayerStack, iface: &str) -> Option<Vec<u8>> {
    use oside::*;
    use oside::protocols::all::*;
    use oside::Icmpv6NeighborSolicitation;
    use oside::protocols::icmpv6::icmpv6NeighborAdvertisement;
    use oside::protocols::icmpv6::Icmpv6;
    use oside::protocols::icmpv6::NdpOption::TargetLinkLayerAddress;

    let rx_ns = &stack[Icmpv6NeighborSolicitation!()];

    let target_ip: Ipv6Addr = rx_ns.target_address.value().into();

    // Find the fake host with this IP
    let hosts = FAKE_HOSTS.lock().unwrap();
    let interface = hosts.get(iface)?;

    let fake_host = interface.hosts.iter()
        .find(|h| h.ip == IpAddr::V6(target_ip))?;

    // Build MAC address string from fake host's MAC
    let mac_str = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        fake_host.mac[0], fake_host.mac[1], fake_host.mac[2],
        fake_host.mac[3], fake_host.mac[4], fake_host.mac[5]);

    println!("NS: Who has {}? Tell {} - Responding with MAC {}{}",
        target_ip,
        stack[IPV6!()].src.value(),
        mac_str,
        if fake_host.is_router { " (Router)" } else { "" });

    // Neighbor Advertisement reply:
    // - Source IP: the target address (the IP we're claiming)
    // - Destination IP: the source of the NS
    // - Flags: Router (0x80000000 if router) + Solicited (0x40000000) + Override (0x20000000)
    // - Option: Target Link-Layer Address (type 2), not Source (type 1)
    let flags = if fake_host.is_router {
        0xe0000000  // Router + Solicited + Override
    } else {
        0x60000000  // Solicited + Override
    };

    let pkt = Ether!(dst = stack[Ether!()].src.clone(), src = mac_str.as_str())
            / IPV6!(hop_limit = 255,
                    src = rx_ns.target_address.value().clone(),  // Source is the target IP
                    dst = stack[IPV6!()].src.value().clone())
            / ICMPV6!()
            / Icmpv6NeighborAdvertisement!(
                target_address = rx_ns.target_address.value().clone(),
                flags = flags,
                options = vec![TargetLinkLayerAddress(mac_str.as_str().into())]
              );

    Some(pkt.lencode())
}

fn handle_icmp(stack: &oside::LayerStack, icmp: &oside::protocols::all::Icmp, iface: &str) -> Option<Vec<u8>> {
    use oside::*;
    use oside::protocols::all::*;

    let icmp_type = icmp.typ.value();

    if icmp_type != 8 {
        // Not an echo request
        return None;
    }

    // Get destination IP from the IP layer
    let ip_layer = &stack[IP!()];
    let echo_layer = &stack[Echo!()];
    let dst_ip: Ipv4Addr = ip_layer.dst.value().into();

    // Find the fake host with this IP
    let hosts = FAKE_HOSTS.lock().unwrap();
    let interface = hosts.get(iface)?;

    let fake_host = interface.hosts.iter()
        .find(|h| h.ip == IpAddr::V4(dst_ip) && h.respond_icmp)?;

    let src_ip: Ipv4Addr = ip_layer.src.value().into();

    // Build MAC address string
    let mac_str = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        fake_host.mac[0], fake_host.mac[1], fake_host.mac[2],
        fake_host.mac[3], fake_host.mac[4], fake_host.mac[5]);

    println!("ICMP Echo: {} -> {} - Responding", src_ip, dst_ip);

    let reply = Ether!(
        dst = stack[Ether!()].src.clone(),
        src = mac_str.as_str()
    ) / IP!(
        src = dst_ip.to_string().as_str(),
        dst = src_ip.to_string().as_str()
    ) / ICMP!(
    ) / EchoReply!(
        identifier = echo_layer.identifier.value().clone(),
        sequence = echo_layer.sequence.value().clone()
    ) / stack[Raw!()].clone();

    Some(reply.lencode())
}

fn handle_icmpv6_echo(stack: &oside::LayerStack, iface: &str) -> Option<Vec<u8>> {
    use oside::*;
    use oside::protocols::all::*;
    use oside::protocols::icmpv6::Icmpv6;
    // use oside::protocols::icmpv6::Icmpv6EchoReply;
    use oside::protocols::icmpv6::icmpv6EchoReply;
    use oside::protocols::icmpv6::icmpv6EchoRequest;

    let echo_req = &stack[Icmpv6EchoRequest!()];
    let echo_req_data = &stack[Raw!()];

    // Get destination IP from the IPv6 layer
    let ipv6_layer = &stack[IPV6!()];
    let dst_ip: Ipv6Addr = ipv6_layer.dst.value().into();

    // Find the fake host with this IP
    let hosts = FAKE_HOSTS.lock().unwrap();
    let interface = hosts.get(iface)?;

    let fake_host = interface.hosts.iter()
        .find(|h| h.ip == IpAddr::V6(dst_ip) && h.respond_icmp)?;

    let src_ip: Ipv6Addr = ipv6_layer.src.value().into();

    // Build MAC address string
    let mac_str = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        fake_host.mac[0], fake_host.mac[1], fake_host.mac[2],
        fake_host.mac[3], fake_host.mac[4], fake_host.mac[5]);

    println!("ICMPv6 Echo: {} -> {} - Responding", src_ip, dst_ip);

    // Build ICMPv6 Echo Reply
    let reply = Ether!(
        dst = stack[Ether!()].src.clone(),
        src = mac_str.as_str()
    ) / IPV6!(
        hop_limit = 64,
        src = dst_ip.to_string().as_str(),
        dst = src_ip.to_string().as_str()
    ) / ICMPV6!()
    / Icmpv6EchoReply!(
        identifier = echo_req.identifier.value().clone(),
        sequence = echo_req.sequence.value().clone()
    )
    / echo_req_data.clone();

    Some(reply.lencode())
}

pub fn help_text() -> &'static str {
    "fakehost <add|del|show>           - Manage fake hosts responding to ARP/NS/ICMP"
}
