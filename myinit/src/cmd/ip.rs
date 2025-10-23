use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr};

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
        _ => {
            eprintln!("Unknown ip command: {}", parts[args_offset]);
            print_usage();
        }
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  ip route [show]                              - Show IPv4 routes");
    eprintln!("  ip route add <dest> via <gateway> [dev <if>] - Add IPv4 route");
    eprintln!("  ip route del <dest>                          - Delete IPv4 route");
    eprintln!("  ip -6 route [show]                           - Show IPv6 routes");
    eprintln!("  ip -6 route add <dest> via <gateway> [dev <if>] - Add IPv6 route");
    eprintln!("  ip -6 route del <dest>                       - Delete IPv6 route");
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

    if let Err(e) = add_ipv4_route_internal(network, prefix, gateway, device) {
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
    // Note: /proc/net/route uses little-endian format
    Ipv4Addr::from(val.to_le())
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

fn add_ipv4_route_internal(
    dest: Ipv4Addr,
    prefix: u8,
    gateway: Option<Ipv4Addr>,
    device: Option<&str>,
) -> Result<(), String> {
    // This is a simplified implementation using /proc/sys/net manipulation
    // For a full implementation, we would use NETLINK_ROUTE sockets

    // Build route command string
    let mut cmd = format!("route add -net {} netmask {}",
        dest,
        prefix_to_netmask_v4(prefix));

    if let Some(gw) = gateway {
        cmd.push_str(&format!(" gw {}", gw));
    }

    if let Some(dev) = device {
        cmd.push_str(&format!(" dev {}", dev));
    }

    // Note: This requires the 'route' command which we don't have
    // Instead, we'll return an informational error
    Err(format!(
        "Route manipulation requires netlink support. Would execute: {}",
        cmd
    ))
}

fn add_ipv6_route_internal(
    dest: Ipv6Addr,
    prefix: u8,
    gateway: Option<Ipv6Addr>,
    device: Option<&str>,
) -> Result<(), String> {
    // Similar to IPv4, this would require NETLINK_ROUTE
    let mut cmd = format!("route -A inet6 add {}/{}", dest, prefix);

    if let Some(gw) = gateway {
        cmd.push_str(&format!(" gw {}", gw));
    }

    if let Some(dev) = device {
        cmd.push_str(&format!(" dev {}", dev));
    }

    Err(format!(
        "Route manipulation requires netlink support. Would execute: {}",
        cmd
    ))
}

fn del_ipv4_route_internal(dest: Ipv4Addr, prefix: u8) -> Result<(), String> {
    Err(format!(
        "Route deletion requires netlink support. Would delete: {}/{}",
        dest, prefix
    ))
}

fn del_ipv6_route_internal(dest: Ipv6Addr, prefix: u8) -> Result<(), String> {
    Err(format!(
        "Route deletion requires netlink support. Would delete: {}/{}",
        dest, prefix
    ))
}

fn prefix_to_netmask_v4(prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    Ipv4Addr::from(mask)
}

pub fn help_text() -> &'static str {
    "ip [OPTIONS] route <COMMAND>      - Show/manipulate routing tables"
}
