use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::collections::HashMap;

pub fn main(args: &str) {
    let parts: Vec<&str> = args.trim().split_whitespace().collect();

    if parts.is_empty() {
        print_usage();
        return;
    }

    // Check for -6 flag for IPv6
    let (is_ipv6, args_offset) = if parts[0] == "-6" {
        (true, 1)
    } else {
        (false, 0)
    };

    if parts.len() <= args_offset {
        print_usage();
        return;
    }

    match parts[args_offset] {
        "route" => {
            if parts.len() <= args_offset + 1 {
                // Default to "show"
                if is_ipv6 {
                    show_ipv6_routes();
                } else {
                    show_ipv4_routes();
                }
            } else {
                match parts[args_offset + 1] {
                    "show" | "list" => {
                        if is_ipv6 {
                            show_ipv6_routes();
                        } else {
                            show_ipv4_routes();
                        }
                    }
                    "add" => {
                        let route_args = &parts[args_offset + 2..];
                        if is_ipv6 {
                            add_ipv6_route(route_args);
                        } else {
                            add_ipv4_route(route_args);
                        }
                    }
                    "del" | "delete" => {
                        let route_args = &parts[args_offset + 2..];
                        if is_ipv6 {
                            del_ipv6_route(route_args);
                        } else {
                            del_ipv4_route(route_args);
                        }
                    }
                    _ => {
                        eprintln!("Unknown route command: {}", parts[args_offset + 1]);
                        print_usage();
                    }
                }
            }
        }
        "addr" | "address" => {
            if parts.len() <= args_offset + 1 {
                // Default to "show"
                show_addresses(is_ipv6, None);
            } else {
                match parts[args_offset + 1] {
                    "show" | "list" => {
                        // Check for "dev <interface>" argument
                        let device = if parts.len() > args_offset + 2 && parts[args_offset + 2] == "dev" {
                            if parts.len() > args_offset + 3 {
                                Some(parts[args_offset + 3])
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        show_addresses(is_ipv6, device);
                    }
                    "add" => {
                        let addr_args = &parts[args_offset + 2..];
                        if is_ipv6 {
                            add_address_v6(addr_args);
                        } else {
                            add_address_v4(addr_args);
                        }
                    }
                    "del" | "delete" => {
                        let addr_args = &parts[args_offset + 2..];
                        if is_ipv6 {
                            del_address_v6(addr_args);
                        } else {
                            del_address_v4(addr_args);
                        }
                    }
                    _ => {
                        eprintln!("Unknown address command: {}", parts[args_offset + 1]);
                        print_usage();
                    }
                }
            }
        }
        _ => {
            eprintln!("Unknown ip command: {}", parts[args_offset]);
            print_usage();
        }
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  Routes:");
    eprintln!("    ip route [show]                              - Show IPv4 routes");
    eprintln!("    ip route add <dest> via <gateway> [dev <if>] - Add IPv4 route");
    eprintln!("    ip route del <dest>                          - Delete IPv4 route");
    eprintln!("    ip -6 route [show]                           - Show IPv6 routes");
    eprintln!("    ip -6 route add <dest> via <gateway> [dev <if>] - Add IPv6 route");
    eprintln!("    ip -6 route del <dest>                       - Delete IPv6 route");
    eprintln!("  Addresses:");
    eprintln!("    ip addr [show] [dev <if>]                    - Show addresses");
    eprintln!("    ip addr add <addr/prefix> dev <if>           - Add IPv4 address");
    eprintln!("    ip addr del <addr/prefix> dev <if>           - Delete IPv4 address");
    eprintln!("    ip -6 addr add <addr/prefix> dev <if>        - Add IPv6 address");
    eprintln!("    ip -6 addr del <addr/prefix> dev <if>        - Delete IPv6 address");
}

fn show_ipv4_routes() {
    // Read /proc/net/route for IPv4 routes
    let file = match File::open("/proc/net/route") {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open /proc/net/route: {}", e);
            return;
        }
    };

    let reader = BufReader::new(file);
    let mut first = true;

    for line in reader.lines() {
        if let Ok(line) = line {
            if first {
                // Skip header
                first = false;
                continue;
            }

            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 8 {
                continue;
            }

            let iface = fields[0];
            let dest_hex = fields[1];
            let gateway_hex = fields[2];
            let flags = u32::from_str_radix(fields[3], 16).unwrap_or(0);
            let mask_hex = fields[7];

            // Parse destination
            let dest = parse_hex_ip(dest_hex);
            let gateway = parse_hex_ip(gateway_hex);
            let mask = parse_hex_ip(mask_hex);

            // Calculate prefix length from netmask
            let prefix_len = netmask_to_prefix(mask);

            // Format output similar to "ip route show"
            if dest == Ipv4Addr::new(0, 0, 0, 0) {
                // Default route
                if gateway != Ipv4Addr::new(0, 0, 0, 0) {
                    println!("default via {} dev {}", gateway, iface);
                }
            } else {
                if gateway != Ipv4Addr::new(0, 0, 0, 0) {
                    println!("{}/{} via {} dev {}", dest, prefix_len, gateway, iface);
                } else {
                    // Direct route
                    let scope = if (flags & 0x0001) != 0 { "link" } else { "" };
                    if !scope.is_empty() {
                        println!("{}/{} dev {} scope {}", dest, prefix_len, iface, scope);
                    } else {
                        println!("{}/{} dev {}", dest, prefix_len, iface);
                    }
                }
            }
        }
    }
}

fn show_ipv6_routes() {
    // Read /proc/net/ipv6_route for IPv6 routes
    let file = match File::open("/proc/net/ipv6_route") {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open /proc/net/ipv6_route: {}", e);
            return;
        }
    };

    let reader = BufReader::new(file);

    for line in reader.lines() {
        if let Ok(line) = line {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }

            let dest_hex = fields[0];
            let dest_prefix = u32::from_str_radix(fields[1], 16).unwrap_or(0);
            let _src_hex = fields[2];
            let _src_prefix = fields[3];
            let next_hop_hex = fields[4];
            let _metric = fields[5];
            let _refcnt = fields[6];
            let _use = fields[7];
            let _flags = fields[8];
            let iface = fields[9];

            // Parse IPv6 addresses
            let dest = parse_hex_ipv6(dest_hex);
            let next_hop = parse_hex_ipv6(next_hop_hex);

            // Format output
            if dest == Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0) && dest_prefix == 0 {
                // Default route
                if next_hop != Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0) {
                    println!("default via {} dev {}", next_hop, iface);
                }
            } else {
                if next_hop != Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0) {
                    println!("{}/{} via {} dev {}", dest, dest_prefix, next_hop, iface);
                } else {
                    println!("{}/{} dev {}", dest, dest_prefix, iface);
                }
            }
        }
    }
}

fn add_ipv4_route(args: &[&str]) {
    if args.is_empty() {
        eprintln!("Usage: ip route add <dest> via <gateway> [dev <if>]");
        eprintln!("   or: ip route add <dest> dev <if>");
        return;
    }

    // Parse arguments
    let dest = args[0];
    let (network, prefix) = parse_cidr_v4(dest);

    let mut gateway: Option<Ipv4Addr> = None;
    let mut device: Option<&str> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i] {
            "via" => {
                if i + 1 < args.len() {
                    gateway = args[i + 1].parse().ok();
                    i += 2;
                } else {
                    eprintln!("Missing gateway after 'via'");
                    return;
                }
            }
            "dev" => {
                if i + 1 < args.len() {
                    device = Some(args[i + 1]);
                    i += 2;
                } else {
                    eprintln!("Missing device after 'dev'");
                    return;
                }
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                return;
            }
        }
    }

    if let Err(e) = add_route_internal_v4(network, prefix, gateway, device) {
        eprintln!("Failed to add route: {}", e);
    } else {
        println!("Route added successfully");
    }
}

fn add_ipv6_route(args: &[&str]) {
    if args.is_empty() {
        eprintln!("Usage: ip -6 route add <dest> via <gateway> [dev <if>]");
        eprintln!("   or: ip -6 route add <dest> dev <if>");
        return;
    }

    // Parse arguments
    let dest = args[0];
    let (network, prefix) = parse_cidr_v6(dest);

    let mut gateway: Option<Ipv6Addr> = None;
    let mut device: Option<&str> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i] {
            "via" => {
                if i + 1 < args.len() {
                    gateway = args[i + 1].parse().ok();
                    i += 2;
                } else {
                    eprintln!("Missing gateway after 'via'");
                    return;
                }
            }
            "dev" => {
                if i + 1 < args.len() {
                    device = Some(args[i + 1]);
                    i += 2;
                } else {
                    eprintln!("Missing device after 'dev'");
                    return;
                }
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                return;
            }
        }
    }

    if let Err(e) = add_ipv6_route_internal(network, prefix, gateway, device) {
        eprintln!("Failed to add route: {}", e);
    } else {
        println!("Route added successfully");
    }
}

fn del_ipv4_route(args: &[&str]) {
    if args.is_empty() {
        eprintln!("Usage: ip route del <dest>");
        return;
    }

    let dest = args[0];
    let (network, prefix) = parse_cidr_v4(dest);

    if let Err(e) = del_ipv4_route_internal(network, prefix) {
        eprintln!("Failed to delete route: {}", e);
    } else {
        println!("Route deleted successfully");
    }
}

fn del_ipv6_route(args: &[&str]) {
    if args.is_empty() {
        eprintln!("Usage: ip -6 route del <dest>");
        return;
    }

    let dest = args[0];
    let (network, prefix) = parse_cidr_v6(dest);

    if let Err(e) = del_ipv6_route_internal(network, prefix) {
        eprintln!("Failed to delete route: {}", e);
    } else {
        println!("Route deleted successfully");
    }
}

// Helper functions

fn parse_hex_ip(hex: &str) -> Ipv4Addr {
    if hex.len() != 8 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }

    let val = u32::from_str_radix(hex, 16).unwrap_or(0);
    // Note: /proc/net/route uses little-endian hex format
    // So we need to convert: 0001A8C0 -> C0 A8 01 00 -> 192.168.1.0
    let bytes = val.to_le_bytes();
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

fn parse_hex_ipv6(hex: &str) -> Ipv6Addr {
    if hex.len() != 32 {
        return Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
    }

    let mut segments = [0u16; 8];
    for i in 0..8 {
        let start = i * 4;
        let end = start + 4;
        segments[i] = u16::from_str_radix(&hex[start..end], 16).unwrap_or(0);
    }

    Ipv6Addr::from(segments)
}

fn netmask_to_prefix(mask: Ipv4Addr) -> u8 {
    let mask_u32 = u32::from(mask);
    mask_u32.count_ones() as u8
}

fn parse_cidr_v4(cidr: &str) -> (Ipv4Addr, u8) {
    if let Some(pos) = cidr.find('/') {
        let addr = cidr[..pos].parse().unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
        let prefix = cidr[pos + 1..].parse().unwrap_or(32);
        (addr, prefix)
    } else {
        let addr = cidr.parse().unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
        (addr, 32)
    }
}

fn parse_cidr_v6(cidr: &str) -> (Ipv6Addr, u8) {
    if let Some(pos) = cidr.find('/') {
        let addr = cidr[..pos].parse().unwrap_or(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        let prefix = cidr[pos + 1..].parse().unwrap_or(128);
        (addr, prefix)
    } else {
        let addr = cidr.parse().unwrap_or(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        (addr, 128)
    }
}

// Route manipulation via rtnetlink (netlink sockets)
// These use NETLINK_ROUTE to manipulate the routing table

// Netlink constants
const NETLINK_ROUTE: i32 = 0;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_DUMP: u16 = 0x300;

const RTA_DST: u16 = 1;
const RTA_GATEWAY: u16 = 5;
const RTA_OIF: u16 = 4;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const RTN_UNICAST: u8 = 1;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RTPROT_BOOT: u8 = 3;
const RT_TABLE_MAIN: u8 = 254;

#[repr(C)]
struct nlmsghdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
struct rtmsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

#[repr(C)]
struct rtattr {
    rta_len: u16,
    rta_type: u16,
}

#[repr(C)]
struct ifaddrmsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

// Make this public so other modules (like ifconfig) can use it
pub fn add_route_internal_v4(
    dest: Ipv4Addr,
    prefix: u8,
    gateway: Option<Ipv4Addr>,
    device: Option<&str>,
) -> Result<(), String> {
    let sock = create_netlink_socket()?;

    // Get interface index if device specified
    let if_index = if let Some(dev) = device {
        match get_interface_index(dev) {
            Some(idx) => Some(idx as u32),
            None => return Err(format!("Interface {} not found", dev)),
        }
    } else {
        None
    };

    // Build netlink message
    let mut msg = Vec::new();

    // Netlink header
    let nlh = nlmsghdr {
        nlmsg_len: 0, // Will calculate later
        nlmsg_type: RTM_NEWROUTE,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    // Route message
    let rtm = rtmsg {
        rtm_family: libc::AF_INET as u8,
        rtm_dst_len: prefix,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RT_TABLE_MAIN,
        rtm_protocol: RTPROT_BOOT,
        rtm_scope: if gateway.is_some() { RT_SCOPE_UNIVERSE } else { RT_SCOPE_LINK },
        rtm_type: RTN_UNICAST,
        rtm_flags: 0,
    };

    // Add headers to message
    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &nlh as *const nlmsghdr as *const u8,
            std::mem::size_of::<nlmsghdr>(),
        )
    });
    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &rtm as *const rtmsg as *const u8,
            std::mem::size_of::<rtmsg>(),
        )
    });

    // Add RTA_DST attribute (destination network)
    // For IPv4, addresses should be in network byte order (big-endian)
    if dest != Ipv4Addr::new(0, 0, 0, 0) || prefix != 0 {
        add_rta_attr(&mut msg, RTA_DST, &dest.octets());
    }

    // Add RTA_GATEWAY attribute if specified
    if let Some(gw) = gateway {
        add_rta_attr(&mut msg, RTA_GATEWAY, &gw.octets());
    }

    // For direct routes without gateway, we need the device
    if gateway.is_none() && if_index.is_none() {
        unsafe { libc::close(sock); }
        return Err("Either gateway or device must be specified".to_string());
    }

    // Add RTA_OIF attribute (output interface) if specified
    if let Some(idx) = if_index {
        add_rta_attr(&mut msg, RTA_OIF, &idx.to_ne_bytes());
    }

    // Update message length
    let msg_len = msg.len() as u32;
    msg[0..4].copy_from_slice(&msg_len.to_ne_bytes());

    // Send message
    send_netlink_message(sock, &msg)?;

    // Receive ACK
    receive_netlink_ack(sock)?;

    unsafe { libc::close(sock); }
    Ok(())
}

fn add_ipv6_route_internal(
    dest: Ipv6Addr,
    prefix: u8,
    gateway: Option<Ipv6Addr>,
    device: Option<&str>,
) -> Result<(), String> {
    let sock = create_netlink_socket()?;

    // Get interface index if device specified
    let if_index = if let Some(dev) = device {
        match get_interface_index(dev) {
            Some(idx) => Some(idx as u32),
            None => return Err(format!("Interface {} not found", dev)),
        }
    } else {
        None
    };

    // Build netlink message
    let mut msg = Vec::new();

    // Netlink header
    let nlh = nlmsghdr {
        nlmsg_len: 0,
        nlmsg_type: RTM_NEWROUTE,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    // Route message
    let rtm = rtmsg {
        rtm_family: libc::AF_INET6 as u8,
        rtm_dst_len: prefix,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RT_TABLE_MAIN,
        rtm_protocol: RTPROT_BOOT,
        rtm_scope: if gateway.is_some() { RT_SCOPE_UNIVERSE } else { RT_SCOPE_LINK },
        rtm_type: RTN_UNICAST,
        rtm_flags: 0,
    };

    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &nlh as *const nlmsghdr as *const u8,
            std::mem::size_of::<nlmsghdr>(),
        )
    });
    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &rtm as *const rtmsg as *const u8,
            std::mem::size_of::<rtmsg>(),
        )
    });

    // Add RTA_DST attribute
    if dest != Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0) || prefix != 0 {
        add_rta_attr(&mut msg, RTA_DST, &dest.octets());
    }

    // Add RTA_GATEWAY attribute if specified
    if let Some(gw) = gateway {
        add_rta_attr(&mut msg, RTA_GATEWAY, &gw.octets());
    }

    // Add RTA_OIF attribute if specified
    if let Some(idx) = if_index {
        add_rta_attr(&mut msg, RTA_OIF, &idx.to_ne_bytes());
    }

    // Update message length
    let msg_len = msg.len() as u32;
    msg[0..4].copy_from_slice(&msg_len.to_ne_bytes());

    // Send message
    send_netlink_message(sock, &msg)?;

    // Receive ACK
    receive_netlink_ack(sock)?;

    unsafe { libc::close(sock); }
    Ok(())
}

fn del_ipv4_route_internal(dest: Ipv4Addr, prefix: u8) -> Result<(), String> {
    let sock = create_netlink_socket()?;

    // Build netlink message
    let mut msg = Vec::new();

    let nlh = nlmsghdr {
        nlmsg_len: 0,
        nlmsg_type: RTM_DELROUTE,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    let rtm = rtmsg {
        rtm_family: libc::AF_INET as u8,
        rtm_dst_len: prefix,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RT_TABLE_MAIN,
        rtm_protocol: RTPROT_BOOT,
        rtm_scope: RT_SCOPE_UNIVERSE,
        rtm_type: RTN_UNICAST,
        rtm_flags: 0,
    };

    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &nlh as *const nlmsghdr as *const u8,
            std::mem::size_of::<nlmsghdr>(),
        )
    });
    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &rtm as *const rtmsg as *const u8,
            std::mem::size_of::<rtmsg>(),
        )
    });

    // Add RTA_DST attribute
    if dest != Ipv4Addr::new(0, 0, 0, 0) || prefix != 0 {
        add_rta_attr(&mut msg, RTA_DST, &dest.octets());
    }

    // Update message length
    let msg_len = msg.len() as u32;
    msg[0..4].copy_from_slice(&msg_len.to_ne_bytes());

    // Send message
    send_netlink_message(sock, &msg)?;

    // Receive ACK
    receive_netlink_ack(sock)?;

    unsafe { libc::close(sock); }
    Ok(())
}

fn del_ipv6_route_internal(dest: Ipv6Addr, prefix: u8) -> Result<(), String> {
    let sock = create_netlink_socket()?;

    let mut msg = Vec::new();

    let nlh = nlmsghdr {
        nlmsg_len: 0,
        nlmsg_type: RTM_DELROUTE,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    let rtm = rtmsg {
        rtm_family: libc::AF_INET6 as u8,
        rtm_dst_len: prefix,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RT_TABLE_MAIN,
        rtm_protocol: RTPROT_BOOT,
        rtm_scope: RT_SCOPE_UNIVERSE,
        rtm_type: RTN_UNICAST,
        rtm_flags: 0,
    };

    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &nlh as *const nlmsghdr as *const u8,
            std::mem::size_of::<nlmsghdr>(),
        )
    });
    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &rtm as *const rtmsg as *const u8,
            std::mem::size_of::<rtmsg>(),
        )
    });

    // Add RTA_DST attribute
    if dest != Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0) || prefix != 0 {
        add_rta_attr(&mut msg, RTA_DST, &dest.octets());
    }

    // Update message length
    let msg_len = msg.len() as u32;
    msg[0..4].copy_from_slice(&msg_len.to_ne_bytes());

    // Send message
    send_netlink_message(sock, &msg)?;

    // Receive ACK
    receive_netlink_ack(sock)?;

    unsafe { libc::close(sock); }
    Ok(())
}

// Address manipulation functions

struct AddressInfo {
    family: u8,
    addr: String,
    prefix: u8,
}

fn show_addresses(_is_ipv6: bool, device: Option<&str>) {
    let filter_if_index = device.and_then(|dev| get_interface_index(dev));

    // Create netlink socket
    let sock = match create_netlink_socket() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create netlink socket: {}", e);
            return;
        }
    };

    // Build RTM_GETADDR request
    let mut msg = Vec::new();

    let nlh = nlmsghdr {
        nlmsg_len: (std::mem::size_of::<nlmsghdr>() + std::mem::size_of::<ifaddrmsg>()) as u32,
        nlmsg_type: RTM_GETADDR,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    let ifa = ifaddrmsg {
        ifa_family: libc::AF_UNSPEC as u8,
        ifa_prefixlen: 0,
        ifa_flags: 0,
        ifa_scope: 0,
        ifa_index: 0,
    };

    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &nlh as *const nlmsghdr as *const u8,
            std::mem::size_of::<nlmsghdr>(),
        )
    });
    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &ifa as *const ifaddrmsg as *const u8,
            std::mem::size_of::<ifaddrmsg>(),
        )
    });

    // Send message
    if let Err(e) = send_netlink_message(sock, &msg) {
        eprintln!("Failed to send netlink message: {}", e);
        unsafe { libc::close(sock); }
        return;
    }

    // Collect all addresses grouped by interface
    let mut interfaces: HashMap<u32, Vec<AddressInfo>> = HashMap::new();
    let mut buf = vec![0u8; 8192];
    let mut done = false;

    while !done {
        let len = unsafe {
            libc::recv(sock, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
        };

        if len <= 0 {
            break;
        }

        let mut offset = 0;
        while offset + std::mem::size_of::<nlmsghdr>() <= len as usize {
            let nlh = unsafe { &*(buf.as_ptr().add(offset) as *const nlmsghdr) };

            if nlh.nlmsg_type == NLMSG_DONE {
                done = true;
                break;
            }

            if nlh.nlmsg_type == NLMSG_ERROR {
                done = true;
                break;
            }

            if nlh.nlmsg_type == RTM_NEWADDR {
                let ifa = unsafe {
                    &*(buf.as_ptr().add(offset + std::mem::size_of::<nlmsghdr>()) as *const ifaddrmsg)
                };

                // Skip if filtering by device and doesn't match
                if let Some(filter_idx) = filter_if_index {
                    if ifa.ifa_index != filter_idx as u32 {
                        offset += nlh.nlmsg_len as usize;
                        continue;
                    }
                }

                // Parse attributes
                let attr_offset = offset + std::mem::size_of::<nlmsghdr>() + std::mem::size_of::<ifaddrmsg>();
                let attr_len = nlh.nlmsg_len as usize - std::mem::size_of::<nlmsghdr>() - std::mem::size_of::<ifaddrmsg>();

                let mut addr_str = String::new();
                let mut local_str = String::new();

                parse_address_attributes(&buf[attr_offset..attr_offset + attr_len], ifa.ifa_family, &mut addr_str, &mut local_str);

                // For IPv4, prefer IFA_LOCAL, for IPv6 use IFA_ADDRESS
                let display_addr = if ifa.ifa_family == libc::AF_INET as u8 {
                    if !local_str.is_empty() { local_str } else { addr_str }
                } else {
                    addr_str
                };

                if !display_addr.is_empty() {
                    interfaces.entry(ifa.ifa_index).or_insert_with(Vec::new).push(AddressInfo {
                        family: ifa.ifa_family,
                        addr: display_addr,
                        prefix: ifa.ifa_prefixlen,
                    });
                }
            }

            offset += nlh.nlmsg_len as usize;
        }
    }

    unsafe { libc::close(sock); }

    // Sort interfaces by index and display
    let mut if_indices: Vec<u32> = interfaces.keys().copied().collect();
    if_indices.sort();

    for if_index in if_indices {
        let if_name = get_interface_name(if_index as i32).unwrap_or_else(|| format!("if{}", if_index));
        println!("{}:", if_name);

        if let Some(addrs) = interfaces.get(&if_index) {
            for addr_info in addrs {
                let family = if addr_info.family == libc::AF_INET as u8 { "inet" } else { "inet6" };
                println!("    {} {}/{}", family, addr_info.addr, addr_info.prefix);
            }
        }
    }
}

fn parse_address_attributes(data: &[u8], family: u8, addr_str: &mut String, local_str: &mut String) {
    let mut offset = 0;

    while offset + std::mem::size_of::<rtattr>() <= data.len() {
        let rta = unsafe { &*(data.as_ptr().add(offset) as *const rtattr) };

        if rta.rta_len < std::mem::size_of::<rtattr>() as u16 {
            break;
        }

        let payload_offset = offset + std::mem::size_of::<rtattr>();
        let payload_len = rta.rta_len as usize - std::mem::size_of::<rtattr>();

        if payload_offset + payload_len > data.len() {
            break;
        }

        match rta.rta_type {
            IFA_ADDRESS => {
                if family == libc::AF_INET as u8 && payload_len == 4 {
                    let octets: [u8; 4] = data[payload_offset..payload_offset + 4].try_into().unwrap();
                    *addr_str = Ipv4Addr::from(octets).to_string();
                } else if family == libc::AF_INET6 as u8 && payload_len == 16 {
                    let octets: [u8; 16] = data[payload_offset..payload_offset + 16].try_into().unwrap();
                    *addr_str = Ipv6Addr::from(octets).to_string();
                }
            }
            IFA_LOCAL => {
                if family == libc::AF_INET as u8 && payload_len == 4 {
                    let octets: [u8; 4] = data[payload_offset..payload_offset + 4].try_into().unwrap();
                    *local_str = Ipv4Addr::from(octets).to_string();
                }
            }
            _ => {}
        }

        // Align to 4-byte boundary
        let aligned_len = (rta.rta_len as usize + 3) & !3;
        offset += aligned_len;
    }
}

fn add_address_v4(args: &[&str]) {
    if args.len() < 3 || args[1] != "dev" {
        eprintln!("Usage: ip addr add <addr/prefix> dev <interface>");
        return;
    }

    let addr_str = args[0];
    let device = args[2];

    let (addr, prefix) = parse_cidr_v4(addr_str);

    if let Err(e) = add_address_internal_v4(addr, prefix, device) {
        eprintln!("Failed to add address: {}", e);
    } else {
        println!("Address added successfully");
    }
}

fn add_address_v6(args: &[&str]) {
    if args.len() < 3 || args[1] != "dev" {
        eprintln!("Usage: ip -6 addr add <addr/prefix> dev <interface>");
        return;
    }

    let addr_str = args[0];
    let device = args[2];

    let (addr, prefix) = parse_cidr_v6(addr_str);

    if let Err(e) = add_address_internal_v6(addr, prefix, device) {
        eprintln!("Failed to add address: {}", e);
    } else {
        println!("Address added successfully");
    }
}

fn del_address_v4(args: &[&str]) {
    if args.len() < 3 || args[1] != "dev" {
        eprintln!("Usage: ip addr del <addr/prefix> dev <interface>");
        return;
    }

    let addr_str = args[0];
    let device = args[2];

    let (addr, prefix) = parse_cidr_v4(addr_str);

    if let Err(e) = del_address_internal_v4(addr, prefix, device) {
        eprintln!("Failed to delete address: {}", e);
    } else {
        println!("Address deleted successfully");
    }
}

fn del_address_v6(args: &[&str]) {
    if args.len() < 3 || args[1] != "dev" {
        eprintln!("Usage: ip -6 addr del <addr/prefix> dev <interface>");
        return;
    }

    let addr_str = args[0];
    let device = args[2];

    let (addr, prefix) = parse_cidr_v6(addr_str);

    if let Err(e) = del_address_internal_v6(addr, prefix, device) {
        eprintln!("Failed to delete address: {}", e);
    } else {
        println!("Address deleted successfully");
    }
}

fn add_address_internal_v4(addr: Ipv4Addr, prefix: u8, device: &str) -> Result<(), String> {
    let sock = create_netlink_socket()?;

    let if_index = match get_interface_index(device) {
        Some(idx) => idx as u32,
        None => return Err(format!("Interface {} not found", device)),
    };

    // Build netlink message
    let mut msg = Vec::new();

    let nlh = nlmsghdr {
        nlmsg_len: 0,
        nlmsg_type: RTM_NEWADDR,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    let ifa = ifaddrmsg {
        ifa_family: libc::AF_INET as u8,
        ifa_prefixlen: prefix,
        ifa_flags: 0,
        ifa_scope: RT_SCOPE_UNIVERSE,
        ifa_index: if_index,
    };

    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &nlh as *const nlmsghdr as *const u8,
            std::mem::size_of::<nlmsghdr>(),
        )
    });
    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &ifa as *const ifaddrmsg as *const u8,
            std::mem::size_of::<ifaddrmsg>(),
        )
    });

    // Add IFA_LOCAL and IFA_ADDRESS attributes
    add_rta_attr(&mut msg, IFA_LOCAL, &addr.octets());
    add_rta_attr(&mut msg, IFA_ADDRESS, &addr.octets());

    // Update message length
    let msg_len = msg.len() as u32;
    msg[0..4].copy_from_slice(&msg_len.to_ne_bytes());

    // Send message
    send_netlink_message(sock, &msg)?;

    // Receive ACK
    receive_netlink_ack(sock)?;

    unsafe { libc::close(sock); }
    Ok(())
}

fn add_address_internal_v6(addr: Ipv6Addr, prefix: u8, device: &str) -> Result<(), String> {
    let sock = create_netlink_socket()?;

    let if_index = match get_interface_index(device) {
        Some(idx) => idx as u32,
        None => return Err(format!("Interface {} not found", device)),
    };

    let mut msg = Vec::new();

    let nlh = nlmsghdr {
        nlmsg_len: 0,
        nlmsg_type: RTM_NEWADDR,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    let ifa = ifaddrmsg {
        ifa_family: libc::AF_INET6 as u8,
        ifa_prefixlen: prefix,
        ifa_flags: 0,
        ifa_scope: RT_SCOPE_UNIVERSE,
        ifa_index: if_index,
    };

    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &nlh as *const nlmsghdr as *const u8,
            std::mem::size_of::<nlmsghdr>(),
        )
    });
    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &ifa as *const ifaddrmsg as *const u8,
            std::mem::size_of::<ifaddrmsg>(),
        )
    });

    // Add IFA_ADDRESS attribute (for IPv6, we typically only need IFA_ADDRESS)
    add_rta_attr(&mut msg, IFA_ADDRESS, &addr.octets());

    // Update message length
    let msg_len = msg.len() as u32;
    msg[0..4].copy_from_slice(&msg_len.to_ne_bytes());

    // Send message
    send_netlink_message(sock, &msg)?;

    // Receive ACK
    receive_netlink_ack(sock)?;

    unsafe { libc::close(sock); }
    Ok(())
}

fn del_address_internal_v4(addr: Ipv4Addr, prefix: u8, device: &str) -> Result<(), String> {
    let sock = create_netlink_socket()?;

    let if_index = match get_interface_index(device) {
        Some(idx) => idx as u32,
        None => return Err(format!("Interface {} not found", device)),
    };

    let mut msg = Vec::new();

    let nlh = nlmsghdr {
        nlmsg_len: 0,
        nlmsg_type: RTM_DELADDR,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    let ifa = ifaddrmsg {
        ifa_family: libc::AF_INET as u8,
        ifa_prefixlen: prefix,
        ifa_flags: 0,
        ifa_scope: RT_SCOPE_UNIVERSE,
        ifa_index: if_index,
    };

    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &nlh as *const nlmsghdr as *const u8,
            std::mem::size_of::<nlmsghdr>(),
        )
    });
    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &ifa as *const ifaddrmsg as *const u8,
            std::mem::size_of::<ifaddrmsg>(),
        )
    });

    add_rta_attr(&mut msg, IFA_LOCAL, &addr.octets());
    add_rta_attr(&mut msg, IFA_ADDRESS, &addr.octets());

    let msg_len = msg.len() as u32;
    msg[0..4].copy_from_slice(&msg_len.to_ne_bytes());

    send_netlink_message(sock, &msg)?;
    receive_netlink_ack(sock)?;

    unsafe { libc::close(sock); }
    Ok(())
}

fn del_address_internal_v6(addr: Ipv6Addr, prefix: u8, device: &str) -> Result<(), String> {
    let sock = create_netlink_socket()?;

    let if_index = match get_interface_index(device) {
        Some(idx) => idx as u32,
        None => return Err(format!("Interface {} not found", device)),
    };

    let mut msg = Vec::new();

    let nlh = nlmsghdr {
        nlmsg_len: 0,
        nlmsg_type: RTM_DELADDR,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    let ifa = ifaddrmsg {
        ifa_family: libc::AF_INET6 as u8,
        ifa_prefixlen: prefix,
        ifa_flags: 0,
        ifa_scope: RT_SCOPE_UNIVERSE,
        ifa_index: if_index,
    };

    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &nlh as *const nlmsghdr as *const u8,
            std::mem::size_of::<nlmsghdr>(),
        )
    });
    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &ifa as *const ifaddrmsg as *const u8,
            std::mem::size_of::<ifaddrmsg>(),
        )
    });

    add_rta_attr(&mut msg, IFA_ADDRESS, &addr.octets());

    let msg_len = msg.len() as u32;
    msg[0..4].copy_from_slice(&msg_len.to_ne_bytes());

    send_netlink_message(sock, &msg)?;
    receive_netlink_ack(sock)?;

    unsafe { libc::close(sock); }
    Ok(())
}

// Netlink helper functions

fn create_netlink_socket() -> Result<i32, String> {
    let sock = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };

    if sock < 0 {
        return Err("Failed to create netlink socket".to_string());
    }

    // Bind socket
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0; // Kernel
    addr.nl_groups = 0;

    let bind_result = unsafe {
        libc::bind(
            sock,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };

    if bind_result < 0 {
        unsafe { libc::close(sock); }
        return Err("Failed to bind netlink socket".to_string());
    }

    Ok(sock)
}

fn add_rta_attr(msg: &mut Vec<u8>, rta_type: u16, data: &[u8]) {
    let rta_len = (std::mem::size_of::<rtattr>() + data.len()) as u16;
    let rta = rtattr {
        rta_len: rta_len,
        rta_type: rta_type,
    };

    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &rta as *const rtattr as *const u8,
            std::mem::size_of::<rtattr>(),
        )
    });
    msg.extend_from_slice(data);

    // Align to 4 bytes
    while msg.len() % 4 != 0 {
        msg.push(0);
    }
}

fn send_netlink_message(sock: i32, msg: &[u8]) -> Result<(), String> {
    let result = unsafe {
        libc::send(
            sock,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
            0,
        )
    };

    if result < 0 {
        return Err("Failed to send netlink message".to_string());
    }

    Ok(())
}

fn receive_netlink_ack(sock: i32) -> Result<(), String> {
    let mut buffer = vec![0u8; 4096];

    let result = unsafe {
        libc::recv(
            sock,
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
            0,
        )
    };

    if result < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(format!("Failed to receive netlink response (errno: {})", errno));
    }

    let len = result as usize;
    if len < std::mem::size_of::<nlmsghdr>() {
        return Err(format!("Invalid netlink response (too short: {} bytes)", len));
    }

    let nlh = unsafe { &*(buffer.as_ptr() as *const nlmsghdr) };

    // Debug: print message type
    eprintln!("DEBUG: Received netlink message type: {}", nlh.nlmsg_type);

    // Check for error message (NLMSG_ERROR = 2)
    if nlh.nlmsg_type == 2 {
        // Error message contains an error code after the header
        if len >= std::mem::size_of::<nlmsghdr>() + 4 {
            let error_code = unsafe {
                *(buffer.as_ptr().add(std::mem::size_of::<nlmsghdr>()) as *const i32)
            };

            eprintln!("DEBUG: Error code from kernel: {}", error_code);

            if error_code != 0 {
                let errno = -error_code;
                let error_msg = unsafe {
                    let err_str = libc::strerror(errno);
                    std::ffi::CStr::from_ptr(err_str)
                        .to_string_lossy()
                        .into_owned()
                };
                return Err(format!("Netlink error: {} (errno: {})", error_msg, errno));
            } else {
                eprintln!("DEBUG: Successful ACK (error_code == 0)");
            }
        }
    }

    Ok(())
}

fn get_interface_index(iface_name: &str) -> Option<i32> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return None;
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let iface_bytes = iface_name.as_bytes();
    let copy_len = iface_bytes.len().min(libc::IFNAMSIZ - 1);

    for i in 0..copy_len {
        ifr.ifr_name[i] = iface_bytes[i] as i8;
    }

    let result = unsafe { libc::ioctl(sock, libc::SIOCGIFINDEX as i32, &mut ifr) };
    unsafe { libc::close(sock); }

    if result == 0 {
        Some(unsafe { ifr.ifr_ifru.ifru_ifindex })
    } else {
        None
    }
}

fn get_interface_name(if_index: i32) -> Option<String> {
    let mut buf = [0u8; libc::IFNAMSIZ];
    let result = unsafe {
        libc::if_indextoname(if_index as u32, buf.as_mut_ptr() as *mut i8)
    };

    if result.is_null() {
        None
    } else {
        let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const i8) };
        Some(name.to_string_lossy().into_owned())
    }
}

pub fn help_text() -> &'static str {
    "ip [OPTIONS] <OBJECT> <COMMAND>   - Show/manipulate routing, addresses (iproute2 syntax)"
}
