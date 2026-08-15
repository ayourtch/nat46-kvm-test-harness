use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CAPTURE_STOP_IDLE: Duration = Duration::from_millis(50);
const CAPTURE_STOP_MAX: Duration = Duration::from_secs(1);

#[derive(Default)]
struct CaptureDrain {
    started_at: Option<Instant>,
    quiet_since: Option<Instant>,
}

impl CaptureDrain {
    fn observe_stop(&mut self, stop_requested: bool, now: Instant) {
        if stop_requested && self.started_at.is_none() {
            self.started_at = Some(now);
            self.quiet_since = Some(now);
        }
    }

    fn observe_packet(&mut self, now: Instant) {
        if self.started_at.is_some() {
            self.quiet_since = Some(now);
        }
    }

    fn is_complete(&self, now: Instant) -> bool {
        let Some(started_at) = self.started_at else {
            return false;
        };
        let quiet_since = self.quiet_since.unwrap_or(started_at);

        now.saturating_duration_since(quiet_since) >= CAPTURE_STOP_IDLE
            || now.saturating_duration_since(started_at) >= CAPTURE_STOP_MAX
    }
}

fn network_header(packet: &[u8], is_tap: bool) -> Option<(u16, usize)> {
    if !is_tap {
        return match packet.first().map(|byte| byte >> 4) {
            Some(4) => Some((0x0800, 0)),
            Some(6) => Some((0x86dd, 0)),
            _ => None,
        };
    }
    if packet.len() < 14 {
        return None;
    }

    let mut ether_type = u16::from_be_bytes([packet[12], packet[13]]);
    let mut offset = 14;
    while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
        if packet.len() < offset + 4 {
            return None;
        }
        ether_type = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        offset += 4;
    }
    Some((ether_type, offset))
}

fn ipv6_upper_layer(packet: &[u8], offset: usize) -> Option<(u8, usize)> {
    if packet.len() < offset + 40 || packet[offset] >> 4 != 6 {
        return None;
    }
    let mut next_header = packet[offset + 6];
    let mut cursor = offset + 40;

    loop {
        match next_header {
            // Hop-by-Hop Options, Routing, and Destination Options.
            0 | 43 | 60 => {
                if packet.len() < cursor + 2 {
                    return None;
                }
                next_header = packet[cursor];
                let length = (packet[cursor + 1] as usize + 1) * 8;
                if packet.len() < cursor + length {
                    return None;
                }
                cursor += length;
            }
            // Valid Neighbor Discovery messages are not fragmented. Keep
            // fragmented ICMPv6 visible rather than classifying it as ND.
            44 => return None,
            // Authentication Header length is measured in 32-bit words,
            // excluding the first two words.
            51 => {
                if packet.len() < cursor + 2 {
                    return None;
                }
                next_header = packet[cursor];
                let length = (packet[cursor + 1] as usize + 2) * 4;
                if packet.len() < cursor + length {
                    return None;
                }
                cursor += length;
            }
            _ => return Some((next_header, cursor)),
        }
    }
}

fn is_neighbor_discovery(packet: &[u8], is_tap: bool) -> bool {
    let Some((ether_type, offset)) = network_header(packet, is_tap) else {
        return false;
    };
    if ether_type != 0x86dd || packet.len() < offset + 40 {
        return false;
    }
    // RFC 4861 requires received ND packets to have IPv6 Hop Limit 255.
    if packet[offset + 7] != 255 {
        return false;
    }
    let Some((next_header, upper_offset)) = ipv6_upper_layer(packet, offset) else {
        return false;
    };
    next_header == 58
        && packet.len() >= upper_offset + 2
        && matches!(packet[upper_offset], 133..=137)
        && packet[upper_offset + 1] == 0
}

fn should_ignore_packet(packet: &[u8], is_tap: bool, ignored: &[CaptureIgnore]) -> bool {
    ignored.iter().any(|item| match item {
        CaptureIgnore::NeighborDiscovery => is_neighbor_discovery(packet, is_tap),
        CaptureIgnore::Arp => {
            matches!(network_header(packet, is_tap), Some((0x0806, _)))
        }
    })
}

// Global state for managing captures
lazy_static::lazy_static! {
    static ref CAPTURES: Arc<Mutex<HashMap<String, CaptureHandle>>> = Arc::new(Mutex::new(HashMap::new()));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureFormat {
    Jsonl,
    Pcap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureIgnore {
    NeighborDiscovery,
    Arp,
}

impl CaptureIgnore {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "nd" => Some(Self::NeighborDiscovery),
            "arp" => Some(Self::Arp),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::NeighborDiscovery => "nd",
            Self::Arp => "arp",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct CaptureOptions {
    format: CaptureFormat,
    max_packets: Option<u64>,
    ignored: Vec<CaptureIgnore>,
}

fn parse_start_options(parts: &[&str]) -> Result<CaptureOptions, String> {
    let mut options = CaptureOptions {
        format: CaptureFormat::Jsonl,
        max_packets: None,
        ignored: vec![CaptureIgnore::NeighborDiscovery],
    };

    for part in parts {
        match *part {
            "jsonl" => options.format = CaptureFormat::Jsonl,
            "pcap" => options.format = CaptureFormat::Pcap,
            _ => {
                if let Ok(count) = part.parse::<u64>() {
                    if options.max_packets.replace(count).is_some() {
                        return Err("packet count specified more than once".to_string());
                    }
                    continue;
                }

                let names = part
                    .strip_prefix("ignore=")
                    .or_else(|| part.strip_prefix("--ignore="));
                if let Some(names) = names {
                    if names.is_empty() {
                        return Err("ignore list must not be empty".to_string());
                    }
                    for name in names.split(',') {
                        let ignored = CaptureIgnore::parse(name)
                            .ok_or_else(|| format!("unknown capture ignore class {:?}", name))?;
                        if !options.ignored.contains(&ignored) {
                            options.ignored.push(ignored);
                        }
                    }
                    continue;
                }

                let names = part
                    .strip_prefix("include=")
                    .or_else(|| part.strip_prefix("--include="));
                if let Some(names) = names {
                    if names.is_empty() {
                        return Err("include list must not be empty".to_string());
                    }
                    for name in names.split(',') {
                        let included = CaptureIgnore::parse(name)
                            .ok_or_else(|| format!("unknown capture include class {:?}", name))?;
                        options.ignored.retain(|item| *item != included);
                    }
                    continue;
                }

                return Err(format!("unknown capture option {:?}", part));
            }
        }
    }

    Ok(options)
}

struct CaptureHandle {
    output_file: String,
    format: CaptureFormat,
    stop_flag: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<()>>,
    packets_captured: Arc<Mutex<u64>>,
    max_packets: Option<u64>,
    ignored: Vec<CaptureIgnore>,
}

pub fn main(args: &str) {
    let parts: Vec<&str> = args.trim().split_whitespace().collect();

    if parts.is_empty() {
        eprintln!("Usage:");
        eprintln!("  capture start <iface> <file> [jsonl|pcap] [count] [include=nd] [ignore=arp]");
        eprintln!(
            "  capture stop <iface>                                - Stop capture on interface"
        );
        eprintln!("  capture stop all                                    - Stop all captures");
        eprintln!("  capture show                                        - Show active captures");
        return;
    }

    match parts[0] {
        "start" => {
            if parts.len() < 3 {
                eprintln!("Usage: capture start <iface> <file> [jsonl|pcap] [count] [include=nd] [ignore=arp]");
                eprintln!("  Format defaults to jsonl if not specified");
                eprintln!("  Count is optional packet limit");
                eprintln!("  Neighbor Discovery is ignored by default; include=nd captures it");
                eprintln!("  Ignore/include classes apply before counting packets");
                return;
            }
            let iface = parts[1];
            let file = parts[2];
            let options = match parse_start_options(&parts[3..]) {
                Ok(options) => options,
                Err(error) => {
                    eprintln!("Invalid capture options: {}", error);
                    return;
                }
            };

            start_capture(iface, file, options);
        }
        "stop" => {
            if parts.len() < 2 {
                eprintln!("Usage: capture stop <iface|all>");
                return;
            }
            if parts[1] == "all" {
                stop_all_captures();
            } else {
                stop_capture(parts[1]);
            }
        }
        "show" => {
            show_captures();
        }
        _ => {
            eprintln!("Unknown capture command: {}", parts[0]);
            eprintln!("Use: start, stop, or show");
        }
    }
}

fn start_capture(iface: &str, output_file: &str, options: CaptureOptions) {
    let mut captures = CAPTURES.lock().unwrap();

    // Check if already capturing on this interface
    if captures.contains_key(iface) {
        eprintln!("Capture already running on interface {}", iface);
        eprintln!("Stop it first with: capture stop {}", iface);
        return;
    }

    let iface_owned = iface.to_string();
    let output_file_owned = output_file.to_string();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let packets_captured = Arc::new(Mutex::new(0u64));

    let stop_flag_clone = Arc::clone(&stop_flag);
    let packets_captured_clone = Arc::clone(&packets_captured);
    let iface_clone = iface_owned.clone();
    let output_clone = output_file_owned.clone();
    let (ready_sender, ready_receiver) = mpsc::channel();
    let format = options.format;
    let max_packets = options.max_packets;
    let ignored_for_thread = options.ignored.clone();

    // Spawn capture thread
    let thread_handle = thread::spawn(move || {
        capture_thread(
            &iface_clone,
            &output_clone,
            format,
            stop_flag_clone,
            packets_captured_clone,
            max_packets,
            ignored_for_thread,
            ready_sender,
        );
    });

    // Do not let the caller inject packets until the capture socket is bound.
    // This replaces timing delays in callers with an explicit readiness
    // handshake and closes the packet-loss race at capture startup.
    match ready_receiver.recv() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            eprintln!("Failed to start capture on {}: {}", iface, error);
            let _ = thread_handle.join();
            return;
        }
        Err(_) => {
            eprintln!(
                "Failed to start capture on {}: capture thread exited",
                iface
            );
            let _ = thread_handle.join();
            return;
        }
    }

    // Store capture handle
    captures.insert(
        iface_owned.clone(),
        CaptureHandle {
            output_file: output_file_owned,
            format,
            stop_flag,
            thread_handle: Some(thread_handle),
            packets_captured,
            max_packets,
            ignored: options.ignored.clone(),
        },
    );

    let format_str = match format {
        CaptureFormat::Jsonl => "jsonl",
        CaptureFormat::Pcap => "pcap",
    };

    let ignored = if options.ignored.is_empty() {
        String::new()
    } else {
        format!(
            " (ignoring: {})",
            options
                .ignored
                .iter()
                .map(|item| item.name())
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    println!(
        "Started capture on {} -> {} (format: {}) {}{}",
        iface,
        output_file,
        format_str,
        if let Some(count) = max_packets {
            format!("(max {} packets)", count)
        } else {
            "(unlimited)".to_string()
        },
        ignored,
    );
}

fn stop_capture(iface: &str) {
    let mut captures = CAPTURES.lock().unwrap();

    if let Some(mut handle) = captures.remove(iface) {
        // Signal thread to stop
        handle.stop_flag.store(true, Ordering::SeqCst);

        // Wait for thread to finish
        if let Some(thread) = handle.thread_handle.take() {
            let count_arc = Arc::clone(&handle.packets_captured);
            drop(captures); // Release lock before joining
            let _ = thread.join();

            let count = *count_arc.lock().unwrap();
            println!("Stopped capture on {} ({} packets captured)", iface, count);
        }
    } else {
        eprintln!("No capture running on interface {}", iface);
    }
}

fn stop_all_captures() {
    let captures = CAPTURES.lock().unwrap();
    let ifaces: Vec<String> = captures.keys().cloned().collect();
    drop(captures);

    if ifaces.is_empty() {
        println!("No captures running");
        return;
    }

    println!("Stopping {} capture(s)...", ifaces.len());
    for iface in ifaces {
        stop_capture(&iface);
    }
}

fn show_captures() {
    let captures = CAPTURES.lock().unwrap();

    if captures.is_empty() {
        println!("No active captures");
        return;
    }

    println!("\nActive captures:");
    println!(
        "{:<15} {:<30} {:<8} {:<12} {:<10} {}",
        "Interface", "Output File", "Format", "Packets", "Limit", "Ignoring"
    );
    println!("{}", "-".repeat(96));

    for (iface, handle) in captures.iter() {
        let count = *handle.packets_captured.lock().unwrap();
        let limit_str = if let Some(max) = handle.max_packets {
            format!("{}", max)
        } else {
            "unlimited".to_string()
        };
        let format_str = match handle.format {
            CaptureFormat::Jsonl => "jsonl",
            CaptureFormat::Pcap => "pcap",
        };
        let ignored = handle
            .ignored
            .iter()
            .map(|item| item.name())
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{:<15} {:<30} {:<8} {:<12} {:<10} {}",
            iface, handle.output_file, format_str, count, limit_str, ignored
        );
    }
}

fn capture_thread(
    iface: &str,
    output_file: &str,
    format: CaptureFormat,
    stop_flag: Arc<AtomicBool>,
    packets_captured: Arc<Mutex<u64>>,
    max_packets: Option<u64>,
    ignored: Vec<CaptureIgnore>,
    ready_sender: mpsc::Sender<Result<(), String>>,
) {
    // Detect if interface is TAP (layer 2) or TUN (layer 3) by checking BROADCAST flag
    let is_tap = is_interface_tap(iface);
    if is_tap {
        println!("Detected L2-ethernet interface");
    } else {
        println!("Detected L3 interface");
    }

    // Create output file
    let mut file = match File::create(output_file) {
        Ok(f) => f,
        Err(e) => {
            let _ = ready_sender.send(Err(format!(
                "could not create output file {}: {}",
                output_file, e
            )));
            return;
        }
    };

    // Write pcap header if needed
    if matches!(format, CaptureFormat::Pcap) {
        if let Err(e) = write_pcap_header(&mut file) {
            let _ = ready_sender.send(Err(format!("could not write pcap header: {}", e)));
            return;
        }
    }

    // Create raw packet socket (AF_PACKET)
    let sock = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };

    if sock < 0 {
        let _ = ready_sender.send(Err("could not create raw capture socket".to_string()));
        return;
    }

    // Get interface index
    let if_index = match get_interface_index(iface) {
        Some(idx) => idx,
        None => {
            unsafe {
                libc::close(sock);
            }
            let _ = ready_sender.send(Err("could not get interface index".to_string()));
            return;
        }
    };

    // Bind to specific interface
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
        unsafe {
            libc::close(sock);
        }
        let _ = ready_sender.send(Err("could not bind raw socket to interface".to_string()));
        return;
    }

    // Set socket to non-blocking for periodic stop check
    unsafe {
        let flags = libc::fcntl(sock, libc::F_GETFL, 0);
        libc::fcntl(sock, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    // The socket is now able to receive packets. Only now may `capture start`
    // return to the script that will produce the traffic under test.
    let _ = ready_sender.send(Ok(()));

    let mut buffer = vec![0u8; 65536]; // Max packet size
    let mut count = 0u64;
    let mut drain = CaptureDrain::default();

    // Capture loop
    loop {
        // A packet sent through a virtual interface can still be queued for
        // receive processing when the injector returns.  Once stop is
        // requested, keep reading for a short quiet period so those packets
        // are not lost at the capture boundary.  The hard limit prevents
        // continuous traffic from delaying shutdown indefinitely.
        let now = Instant::now();
        drain.observe_stop(stop_flag.load(Ordering::SeqCst), now);
        if drain.is_complete(now) {
            break;
        }

        // Check packet limit
        if let Some(max) = max_packets {
            if count >= max {
                break;
            }
        }

        // Try to receive packet with source address (to get packet type)
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut sll_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

        let result = unsafe {
            libc::recvfrom(
                sock,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
                &mut sll as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                &mut sll_len,
            )
        };

        if result < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                // No data available, sleep briefly and continue
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            } else {
                eprintln!("Error receiving packet: errno {}", errno);
                break;
            }
        }

        let packet_len = result as usize;
        if packet_len == 0 {
            continue;
        }
        if should_ignore_packet(&buffer[..packet_len], is_tap, &ignored) {
            continue;
        }
        drain.observe_packet(Instant::now());

        // Determine packet direction
        // PACKET_OUTGOING = 4, PACKET_HOST = 0
        let direction = if sll.sll_pkttype == 4 { "tx" } else { "rx" };

        // Get timestamp
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        // Write packet in appropriate format
        let write_result = match format {
            CaptureFormat::Jsonl => {
                let json_line = packet_to_jsonl(
                    &buffer[..packet_len],
                    timestamp.as_micros(),
                    count,
                    is_tap,
                    direction,
                );
                writeln!(file, "{}", json_line)
            }
            CaptureFormat::Pcap => write_pcap_packet(&mut file, &buffer[..packet_len], timestamp),
        };

        if let Err(e) = write_result {
            eprintln!("Failed to write packet to file: {}", e);
            break;
        }

        if let Err(e) = file.flush() {
            eprintln!("Failed to flush file: {}", e);
            break;
        }

        count += 1;
        *packets_captured.lock().unwrap() = count;
    }

    unsafe {
        libc::close(sock);
    }
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
    unsafe {
        libc::close(sock);
    }

    if result == 0 {
        Some(unsafe { ifr.ifr_ifru.ifru_ifindex })
    } else {
        None
    }
}

fn is_interface_tap(iface_name: &str) -> bool {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return true; // Default to TAP (Ethernet) if we can't check
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let iface_bytes = iface_name.as_bytes();
    let copy_len = iface_bytes.len().min(libc::IFNAMSIZ - 1);

    for i in 0..copy_len {
        ifr.ifr_name[i] = iface_bytes[i] as i8;
    }

    let result = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as i32, &mut ifr) };
    unsafe {
        libc::close(sock);
    }

    if result == 0 {
        let flags = unsafe { ifr.ifr_ifru.ifru_flags };
        // TAP interfaces have BROADCAST flag, TUN interfaces don't
        flags & libc::IFF_BROADCAST as i16 != 0
    } else {
        true // Default to TAP if we can't get flags
    }
}

fn packet_to_jsonl(
    packet: &[u8],
    timestamp_us: u128,
    _seq: u64,
    is_tap: bool,
    direction: &str,
) -> String {
    use oside::protocols::all::*;
    use oside::*;

    // Parse packet using oside - use appropriate decoder based on interface type
    let layers = if is_tap {
        // TAP interface: layer 2 (Ethernet)
        Ether!().ldecode(packet).map(|(stack, _)| stack.layers)
    } else {
        // TUN interface: layer 3 (IP)
        // Try IPv4 first, then IPv6
        if !packet.is_empty() {
            let version = (packet[0] >> 4) & 0x0F;
            if version == 4 {
                IP!().ldecode(packet).map(|(stack, _)| stack.layers)
            } else if version == 6 {
                IPV6!().ldecode(packet).map(|(stack, _)| stack.layers)
            } else {
                None
            }
        } else {
            None
        }
    };

    let layers = match layers {
        Some(l) => l,
        None => {
            // If parsing fails, fallback to hex encoding
            let hex_data: String = packet.iter().map(|b| format!("{:02x}", b)).collect();
            return format!(
                r#"{{"timestamp_us":{},"direction":"{}","data":"{}"}}"#,
                timestamp_us, direction, hex_data
            );
        }
    };

    // Create JSON with timestamp and layers
    let layers_json = match serde_json::to_string(&layers) {
        Ok(j) => j,
        Err(_) => {
            // Fallback to hex if serialization fails
            let hex_data: String = packet.iter().map(|b| format!("{:02x}", b)).collect();
            return format!(
                r#"{{"timestamp_us":{},"direction":"{}","data":"{}"}}"#,
                timestamp_us, direction, hex_data
            );
        }
    };

    format!(
        r#"{{"timestamp_us":{},"direction":"{}","layers":{}}}"#,
        timestamp_us, direction, layers_json
    )
}

// PCAP file format functions
fn write_pcap_header(file: &mut File) -> std::io::Result<()> {
    // PCAP Global Header (24 bytes)
    // https://wiki.wireshark.org/Development/LibpcapFileFormat

    let magic_number: u32 = 0xa1b2c3d4; // Microsecond resolution
    let version_major: u16 = 2;
    let version_minor: u16 = 4;
    let thiszone: i32 = 0; // GMT to local correction
    let sigfigs: u32 = 0; // Accuracy of timestamps
    let snaplen: u32 = 65535; // Max length of captured packets
    let network: u32 = 1; // Data link type (1 = Ethernet)

    file.write_all(&magic_number.to_le_bytes())?;
    file.write_all(&version_major.to_le_bytes())?;
    file.write_all(&version_minor.to_le_bytes())?;
    file.write_all(&thiszone.to_le_bytes())?;
    file.write_all(&sigfigs.to_le_bytes())?;
    file.write_all(&snaplen.to_le_bytes())?;
    file.write_all(&network.to_le_bytes())?;

    Ok(())
}

fn write_pcap_packet(file: &mut File, packet: &[u8], timestamp: Duration) -> std::io::Result<()> {
    // PCAP Packet Header (16 bytes)
    let ts_sec = timestamp.as_secs() as u32;
    let ts_usec = timestamp.subsec_micros() as u32;
    let incl_len = packet.len() as u32; // Number of octets saved
    let orig_len = packet.len() as u32; // Actual length of packet

    file.write_all(&ts_sec.to_le_bytes())?;
    file.write_all(&ts_usec.to_le_bytes())?;
    file.write_all(&incl_len.to_le_bytes())?;
    file.write_all(&orig_len.to_le_bytes())?;

    // Write packet data
    file.write_all(packet)?;

    Ok(())
}

pub fn help_text() -> &'static str {
    "capture <start|stop|show>          - Capture packets to JSONL/PCAP file"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn icmpv6_packet(type_: u8, code: u8, hop_limit: u8) -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        packet[6] = 58;
        packet[7] = hop_limit;
        packet[40] = type_;
        packet[41] = code;
        packet
    }

    #[test]
    fn capture_options_ignore_neighbor_discovery_by_default() {
        let options = parse_start_options(&[]).unwrap();

        assert_eq!(options.format, CaptureFormat::Jsonl);
        assert_eq!(options.max_packets, None);
        assert_eq!(options.ignored, vec![CaptureIgnore::NeighborDiscovery]);
    }

    #[test]
    fn capture_options_can_include_neighbor_discovery() {
        let options = parse_start_options(&["pcap", "12", "include=nd", "ignore=arp"]).unwrap();

        assert_eq!(options.format, CaptureFormat::Pcap);
        assert_eq!(options.max_packets, Some(12));
        assert_eq!(options.ignored, vec![CaptureIgnore::Arp]);
    }

    #[test]
    fn capture_options_reject_unknown_filter_classes() {
        let error = parse_start_options(&["ignore=all"]).unwrap_err();

        assert!(error.contains("unknown capture ignore class"));
    }

    #[test]
    fn neighbor_discovery_filter_is_narrow() {
        let ignored = [CaptureIgnore::NeighborDiscovery];

        assert!(should_ignore_packet(
            &icmpv6_packet(135, 0, 255),
            false,
            &ignored
        ));
        assert!(!should_ignore_packet(
            &icmpv6_packet(128, 0, 255),
            false,
            &ignored
        ));
        assert!(!should_ignore_packet(
            &icmpv6_packet(1, 0, 255),
            false,
            &ignored
        ));
        assert!(!should_ignore_packet(
            &icmpv6_packet(135, 1, 255),
            false,
            &ignored
        ));
        assert!(!should_ignore_packet(
            &icmpv6_packet(135, 0, 64),
            false,
            &ignored
        ));
    }

    #[test]
    fn neighbor_discovery_filter_handles_ethernet() {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        frame.extend(icmpv6_packet(136, 0, 255));

        assert!(should_ignore_packet(
            &frame,
            true,
            &[CaptureIgnore::NeighborDiscovery]
        ));
    }

    #[test]
    fn arp_filter_is_explicit() {
        let mut frame = vec![0u8; 42];
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());

        assert!(!should_ignore_packet(
            &frame,
            true,
            &[CaptureIgnore::NeighborDiscovery]
        ));
        assert!(should_ignore_packet(&frame, true, &[CaptureIgnore::Arp]));
    }

    #[test]
    fn capture_drain_waits_for_quiet_period_after_stop() {
        let start = Instant::now();
        let mut drain = CaptureDrain::default();

        drain.observe_stop(true, start);

        assert!(!drain.is_complete(start));
        assert!(!drain.is_complete(start + CAPTURE_STOP_IDLE / 2));
        assert!(drain.is_complete(start + CAPTURE_STOP_IDLE));
    }

    #[test]
    fn capture_drain_extends_quiet_period_after_packet() {
        let start = Instant::now();
        let packet_time = start + CAPTURE_STOP_IDLE / 2;
        let mut drain = CaptureDrain::default();

        drain.observe_stop(true, start);
        drain.observe_packet(packet_time);

        assert!(!drain.is_complete(start + CAPTURE_STOP_IDLE));
        assert!(drain.is_complete(packet_time + CAPTURE_STOP_IDLE));
    }

    #[test]
    fn capture_drain_has_hard_shutdown_limit() {
        let start = Instant::now();
        let mut drain = CaptureDrain::default();

        drain.observe_stop(true, start);
        drain.observe_packet(start + CAPTURE_STOP_MAX - Duration::from_millis(1));

        assert!(drain.is_complete(start + CAPTURE_STOP_MAX));
    }
}
