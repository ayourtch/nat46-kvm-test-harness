use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

// Global state for fake hosts
lazy_static::lazy_static! {
    static ref FAKE_HOSTS: Arc<Mutex<HashMap<String, InterfaceHosts>>> = Arc::new(Mutex::new(HashMap::new()));
}

struct InterfaceHosts {
    ipv4_addrs: Vec<Ipv4Addr>,
    ipv6_addrs: Vec<Ipv6Addr>,
    mac_addr: [u8; 6],
    stop_flag: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<()>>,
}

pub fn main(args: &str) {
    let parts: Vec<&str> = args.trim().split_whitespace().collect();

    if parts.is_empty() {
        eprintln!("Usage:");
        eprintln!("  fakehost add <interface> <ipv4-address>  - Add fake host responding to ARP");
        eprintln!("  fakehost del <interface> <ipv4-address>  - Remove fake host");
        eprintln!("  fakehost show                            - Show all fake hosts");
        eprintln!("");
        eprintln!("Note: Only IPv4/ARP is currently supported. IPv6/NDP support coming soon.");
        return;
    }

    match parts[0] {
        "add" => {
            if parts.len() < 3 {
                eprintln!("Usage: fakehost add <interface> <ip-address>");
                return;
            }
            add_fakehost(parts[1], parts[2]);
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

fn add_fakehost(iface: &str, ip: &str) {
    let mut hosts = FAKE_HOSTS.lock().unwrap();

    // Parse IP address (IPv4 or IPv6)
    let is_ipv4 = ip.contains('.');
    let is_ipv6 = ip.contains(':');

    if !is_ipv4 && !is_ipv6 {
        eprintln!("Invalid IP address: {}", ip);
        return;
    }

    // Get or create interface entry
    if !hosts.contains_key(iface) {
        // Get interface MAC address
        let mac = match get_interface_mac(iface) {
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
            ipv4_addrs: Vec::new(),
            ipv6_addrs: Vec::new(),
            mac_addr: mac,
            stop_flag,
            thread_handle: Some(thread_handle),
        });

        println!("Started fake host responder on {}", iface);
    }

    let interface = hosts.get_mut(iface).unwrap();

    // Add IP address
    if is_ipv4 {
        if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
            if !interface.ipv4_addrs.contains(&ipv4) {
                interface.ipv4_addrs.push(ipv4);
                println!("Added fake host {} on {} (will respond to ARP)", ip, iface);
            } else {
                eprintln!("Fake host {} already exists on {}", ip, iface);
            }
        } else {
            eprintln!("Invalid IPv4 address: {}", ip);
        }
    } else {
        // IPv6 not yet supported
        eprintln!("IPv6 NDP support not yet implemented. Only IPv4 ARP is currently supported.");
        eprintln!("Try adding an IPv4 address instead.");
    }
}

fn del_fakehost(iface: &str, ip: &str) {
    let mut hosts = FAKE_HOSTS.lock().unwrap();

    if let Some(interface) = hosts.get_mut(iface) {
        let is_ipv4 = ip.contains('.');
        let mut removed = false;

        if is_ipv4 {
            if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
                if let Some(pos) = interface.ipv4_addrs.iter().position(|x| *x == ipv4) {
                    interface.ipv4_addrs.remove(pos);
                    removed = true;
                }
            }
        } else {
            if let Ok(ipv6) = ip.parse::<Ipv6Addr>() {
                if let Some(pos) = interface.ipv6_addrs.iter().position(|x| *x == ipv6) {
                    interface.ipv6_addrs.remove(pos);
                    removed = true;
                }
            }
        }

        if removed {
            println!("Removed fake host {} from {}", ip, iface);

            // If no more hosts on this interface, stop the thread
            if interface.ipv4_addrs.is_empty() && interface.ipv6_addrs.is_empty() {
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
            eprintln!("Fake host {} not found on {}", ip, iface);
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
    println!("{:<15} {:<40} {}", "Interface", "IP Address", "Type");
    println!("{}", "-".repeat(70));

    for (iface, interface) in hosts.iter() {
        for ipv4 in &interface.ipv4_addrs {
            println!("{:<15} {:<40} {}", iface, ipv4, "IPv4 (ARP)");
        }
        for ipv6 in &interface.ipv6_addrs {
            println!("{:<15} {:<40} {}", iface, ipv6, "IPv6 (NDP)");
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

    // Parse Ethernet frame
    let (stack, _) = Ether!().ldecode(packet)?;

    // Check if it's ARP
    for layer in &stack.layers {
        let type_name = layer.typetag_name();

        if type_name == "arp" {
            return handle_arp(layer, iface);
        }
        // TODO: Add IPv6 NDP support later
    }

    None
}

fn handle_arp(arp_layer: &Box<dyn oside::Layer>, iface: &str) -> Option<Vec<u8>> {
    use oside::protocols::all::*;
    use oside::*;

    let json = serde_json::to_value(arp_layer).ok()?;

    // Check if it's an ARP request
    let op = json.get("op")?.as_u64()?;
    if op != 1 {
        // Not a request
        return None;
    }

    let target_ip_str = json.get("pdst")?.as_str()?;
    let target_ip: Ipv4Addr = target_ip_str.parse().ok()?;

    // Check if we should respond to this IP
    let hosts = FAKE_HOSTS.lock().unwrap();
    let interface = hosts.get(iface)?;

    if !interface.ipv4_addrs.contains(&target_ip) {
        return None;
    }

    let sender_ip_str = json.get("psrc")?.as_str()?;
    let sender_ip: Ipv4Addr = sender_ip_str.parse().ok()?;
    let sender_mac_str = json.get("hwsrc")?.as_str()?;

    println!("ARP: Who has {}? Tell {} - Responding with MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        target_ip, sender_ip,
        interface.mac_addr[0], interface.mac_addr[1], interface.mac_addr[2],
        interface.mac_addr[3], interface.mac_addr[4], interface.mac_addr[5]);

    // Build ARP reply
    let mac_str = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        interface.mac_addr[0], interface.mac_addr[1], interface.mac_addr[2],
        interface.mac_addr[3], interface.mac_addr[4], interface.mac_addr[5]);

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

// TODO: IPv6 NDP support - disabled for now
// fn handle_ipv6_ndp(stack: &oside::LayerStack, iface: &str) -> Option<Vec<u8>> {
//     ...
// }

pub fn help_text() -> &'static str {
    "fakehost <add|del|show>           - Manage fake hosts responding to ARP (IPv4 only)"
}
