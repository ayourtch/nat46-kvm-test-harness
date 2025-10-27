use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::thread;
use std::time::Duration;

pub fn main(args: &str) {
    let parts: Vec<&str> = args.trim().split_whitespace().collect();

    if parts.len() != 2 {
        eprintln!("Usage: inject <file.pcap|file.jsonl> <interface>");
        eprintln!("  Replays packets from capture file to TUN/TAP interface");
        eprintln!("  File format is auto-detected from extension (.pcap or .jsonl)");
        return;
    }

    let filename = parts[0];
    let iface = parts[1];

    // Detect file format from extension
    let format = if filename.ends_with(".pcap") {
        FileFormat::Pcap
    } else if filename.ends_with(".jsonl") || filename.ends_with(".json") {
        FileFormat::Jsonl
    } else {
        eprintln!("Error: Unknown file format. Use .pcap or .jsonl extension");
        return;
    };

    // Open and parse the file
    let packets = match format {
        FileFormat::Pcap => parse_pcap_file(filename),
        FileFormat::Jsonl => parse_jsonl_file(filename),
    };

    let packets = match packets {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error parsing file: {}", e);
            return;
        }
    };

    if packets.is_empty() {
        eprintln!("No packets found in file");
        return;
    }

    println!("Loaded {} packets from {}", packets.len(), filename);

    // Try to get TAP FD from the global registry first
    let (inject_fd, use_tap_fd, needs_close) = if let Some(tap_fd) = super::tap::get_tap_fd(iface) {
        println!("Using TAP device file descriptor for {}", iface);
        (tap_fd, true, false)
    } else {
        // Fall back to raw socket
        match open_raw_socket(iface) {
            Ok(fd) => {
                println!("Using raw socket for {}", iface);
                (fd, false, true)
            }
            Err(e) => {
                eprintln!("Error: Could not inject to {}: {}", iface, e);
                eprintln!("Make sure the interface exists and is up");
                return;
            }
        }
    };

    println!("Injecting packets into {}...", iface);

    // Replay packets with original timing
    let mut prev_timestamp_us: Option<u128> = None;
    let mut injected = 0;

    for packet in packets {
        // Calculate delay based on timestamp difference
        if let Some(prev_ts) = prev_timestamp_us {
            let delay_us = packet.timestamp_us.saturating_sub(prev_ts);
            if delay_us > 0 && delay_us < 10_000_000 {  // Cap at 10 seconds
                thread::sleep(Duration::from_micros(delay_us as u64));
            }
        }

        // Send packet (use write for TAP, send for raw socket)
        let result = if use_tap_fd {
            unsafe {
                libc::write(
                    inject_fd,
                    packet.data.as_ptr() as *const libc::c_void,
                    packet.data.len(),
                )
            }
        } else {
            unsafe {
                libc::send(
                    inject_fd,
                    packet.data.as_ptr() as *const libc::c_void,
                    packet.data.len(),
                    0,
                )
            }
        };

        if result < 0 {
            eprintln!("Error sending packet {}: errno {}", injected,
                     unsafe { *libc::__errno_location() });
            break;
        }

        prev_timestamp_us = Some(packet.timestamp_us);
        injected += 1;

        if injected % 100 == 0 {
            println!("Injected {} packets...", injected);
        }
    }

    println!("Injection complete: {} packets sent", injected);

    // Close the socket only if we opened it (not if using TAP FD)
    if needs_close {
        unsafe {
            libc::close(inject_fd);
        }
    }
}

#[derive(Debug)]
enum FileFormat {
    Pcap,
    Jsonl,
}

#[derive(Debug)]
struct Packet {
    timestamp_us: u128,
    data: Vec<u8>,
}

fn open_raw_socket(iface: &str) -> Result<i32, String> {
    // Create raw packet socket (AF_PACKET) for sending
    let sock = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };

    if sock < 0 {
        return Err("Failed to create raw socket".to_string());
    }

    // Get interface index
    let if_index = match get_interface_index(iface) {
        Some(idx) => idx,
        None => {
            unsafe { libc::close(sock); }
            return Err(format!("Interface '{}' not found", iface));
        }
    };

    // Bind socket to specific interface
    let sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
        sll_ifindex: if_index,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    let bind_result = unsafe {
        libc::bind(
            sock,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };

    if bind_result < 0 {
        let errno = unsafe { *libc::__errno_location() };
        unsafe { libc::close(sock); }
        return Err(format!("Failed to bind socket to interface: errno {}", errno));
    }

    Ok(sock)
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

fn parse_jsonl_file(filename: &str) -> Result<Vec<Packet>, String> {
    let file = File::open(filename)
        .map_err(|e| format!("Failed to open file: {}", e))?;

    let reader = BufReader::new(file);
    let mut packets = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("Error reading line {}: {}", line_num + 1, e))?;

        if line.trim().is_empty() {
            continue;
        }

        let packet = parse_jsonl_line(&line)
            .map_err(|e| format!("Error parsing line {}: {}", line_num + 1, e))?;

        packets.push(packet);
    }

    Ok(packets)
}

fn parse_jsonl_line(line: &str) -> Result<Packet, String> {
    // Parse JSON manually (simple parsing for our known format)
    // Format: {"seq":N,"timestamp_us":T,"length":L,"data":"hexstring"}

    let timestamp_us = extract_json_number(line, "timestamp_us")?;
    let hex_data = extract_json_string(line, "data")?;

    // Convert hex string to bytes
    let data = hex_to_bytes(&hex_data)?;

    Ok(Packet {
        timestamp_us,
        data,
    })
}

fn extract_json_number(json: &str, key: &str) -> Result<u128, String> {
    let pattern = format!("\"{}\":", key);
    let start = json.find(&pattern)
        .ok_or_else(|| format!("Key '{}' not found", key))?;

    let value_start = start + pattern.len();
    let rest = &json[value_start..];

    // Find the end of the number (comma or closing brace)
    let value_end = rest.find(|c| c == ',' || c == '}')
        .ok_or_else(|| format!("Invalid JSON format for key '{}'", key))?;

    let value_str = rest[..value_end].trim();
    value_str.parse::<u128>()
        .map_err(|e| format!("Failed to parse number: {}", e))
}

fn extract_json_string(json: &str, key: &str) -> Result<String, String> {
    let pattern = format!("\"{}\":\"", key);
    let start = json.find(&pattern)
        .ok_or_else(|| format!("Key '{}' not found", key))?;

    let value_start = start + pattern.len();
    let rest = &json[value_start..];

    // Find closing quote
    let value_end = rest.find('"')
        .ok_or_else(|| format!("Invalid JSON string for key '{}'", key))?;

    Ok(rest[..value_end].to_string())
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string has odd length".to_string());
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);

    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|e| format!("Invalid hex byte '{}': {}", byte_str, e))?;
        bytes.push(byte);
    }

    Ok(bytes)
}

fn parse_pcap_file(filename: &str) -> Result<Vec<Packet>, String> {
    let mut file = File::open(filename)
        .map_err(|e| format!("Failed to open file: {}", e))?;

    // Read and validate PCAP global header (24 bytes)
    let mut header = [0u8; 24];
    file.read_exact(&mut header)
        .map_err(|e| format!("Failed to read PCAP header: {}", e))?;

    let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);

    if magic != 0xa1b2c3d4 && magic != 0xd4c3b2a1 {
        return Err(format!("Invalid PCAP magic number: 0x{:08x}", magic));
    }

    let is_little_endian = magic == 0xa1b2c3d4;

    println!("PCAP file format detected ({})",
             if is_little_endian { "little-endian" } else { "big-endian" });

    let mut packets = Vec::new();

    // Read packets
    loop {
        let packet = match read_pcap_packet(&mut file, is_little_endian) {
            Ok(p) => p,
            Err(e) => {
                if e.contains("EOF") {
                    break; // Normal end of file
                }
                return Err(e);
            }
        };

        packets.push(packet);
    }

    Ok(packets)
}

fn read_pcap_packet(file: &mut File, is_little_endian: bool) -> Result<Packet, String> {
    // Read packet header (16 bytes)
    let mut header = [0u8; 16];

    match file.read_exact(&mut header) {
        Ok(_) => {},
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err("EOF".to_string());
        }
        Err(e) => {
            return Err(format!("Failed to read packet header: {}", e));
        }
    }

    let (ts_sec, ts_usec, incl_len, _orig_len) = if is_little_endian {
        (
            u32::from_le_bytes([header[0], header[1], header[2], header[3]]),
            u32::from_le_bytes([header[4], header[5], header[6], header[7]]),
            u32::from_le_bytes([header[8], header[9], header[10], header[11]]),
            u32::from_le_bytes([header[12], header[13], header[14], header[15]]),
        )
    } else {
        (
            u32::from_be_bytes([header[0], header[1], header[2], header[3]]),
            u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
            u32::from_be_bytes([header[8], header[9], header[10], header[11]]),
            u32::from_be_bytes([header[12], header[13], header[14], header[15]]),
        )
    };

    // Calculate timestamp in microseconds
    let timestamp_us = (ts_sec as u128) * 1_000_000 + (ts_usec as u128);

    // Read packet data
    let mut data = vec![0u8; incl_len as usize];
    file.read_exact(&mut data)
        .map_err(|e| format!("Failed to read packet data: {}", e))?;

    Ok(Packet {
        timestamp_us,
        data,
    })
}

pub fn help_text() -> &'static str {
    "inject <file> <iface>            - Replay packets from PCAP/JSONL file to interface"
}
