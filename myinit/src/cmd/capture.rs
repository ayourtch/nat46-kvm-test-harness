use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Global state for managing captures
lazy_static::lazy_static! {
    static ref CAPTURES: Arc<Mutex<HashMap<String, CaptureHandle>>> = Arc::new(Mutex::new(HashMap::new()));
}

#[derive(Clone, Copy)]
enum CaptureFormat {
    Jsonl,
    Pcap,
}

struct CaptureHandle {
    output_file: String,
    format: CaptureFormat,
    stop_flag: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<()>>,
    packets_captured: Arc<Mutex<u64>>,
    max_packets: Option<u64>,
}

pub fn main(args: &str) {
    let parts: Vec<&str> = args.trim().split_whitespace().collect();

    if parts.is_empty() {
        eprintln!("Usage:");
        eprintln!("  capture start <iface> <file> [jsonl|pcap] [count]  - Start capturing packets");
        eprintln!("  capture stop <iface>                                - Stop capture on interface");
        eprintln!("  capture stop all                                    - Stop all captures");
        eprintln!("  capture show                                        - Show active captures");
        return;
    }

    match parts[0] {
        "start" => {
            if parts.len() < 3 {
                eprintln!("Usage: capture start <iface> <file> [jsonl|pcap] [count]");
                eprintln!("  Format defaults to jsonl if not specified");
                eprintln!("  Count is optional packet limit");
                return;
            }
            let iface = parts[1];
            let file = parts[2];

            // Parse optional format and count
            let mut format = CaptureFormat::Jsonl;
            let mut count = None;

            if parts.len() > 3 {
                // Check if part[3] is a format or count
                match parts[3] {
                    "jsonl" => {
                        format = CaptureFormat::Jsonl;
                        if parts.len() > 4 {
                            count = parts[4].parse::<u64>().ok();
                        }
                    }
                    "pcap" => {
                        format = CaptureFormat::Pcap;
                        if parts.len() > 4 {
                            count = parts[4].parse::<u64>().ok();
                        }
                    }
                    _ => {
                        // Try to parse as count
                        count = parts[3].parse::<u64>().ok();
                    }
                }
            }

            start_capture(iface, file, format, count);
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

fn start_capture(iface: &str, output_file: &str, format: CaptureFormat, max_packets: Option<u64>) {
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

    // Spawn capture thread
    let thread_handle = thread::spawn(move || {
        capture_thread(
            &iface_clone,
            &output_clone,
            format,
            stop_flag_clone,
            packets_captured_clone,
            max_packets,
        );
    });

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
        },
    );

    let format_str = match format {
        CaptureFormat::Jsonl => "jsonl",
        CaptureFormat::Pcap => "pcap",
    };

    println!(
        "Started capture on {} -> {} (format: {}) {}",
        iface,
        output_file,
        format_str,
        if let Some(count) = max_packets {
            format!("(max {} packets)", count)
        } else {
            "(unlimited)".to_string()
        }
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
    println!("{:<15} {:<30} {:<8} {:<12} {}", "Interface", "Output File", "Format", "Packets", "Limit");
    println!("{}", "-".repeat(80));

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
        println!(
            "{:<15} {:<30} {:<8} {:<12} {}",
            iface, handle.output_file, format_str, count, limit_str
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
) {
    // Create output file
    let mut file = match File::create(output_file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to create output file {}: {}", output_file, e);
            return;
        }
    };

    // Write pcap header if needed
    if matches!(format, CaptureFormat::Pcap) {
        if let Err(e) = write_pcap_header(&mut file) {
            eprintln!("Failed to write pcap header: {}", e);
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
        eprintln!("Failed to create raw socket for capture on {}", iface);
        return;
    }

    // Get interface index
    let if_index = match get_interface_index(iface) {
        Some(idx) => idx,
        None => {
            eprintln!("Failed to get interface index for {}", iface);
            unsafe { libc::close(sock); }
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
        eprintln!("Failed to bind socket to interface {}", iface);
        unsafe { libc::close(sock); }
        return;
    }

    // Set socket to non-blocking for periodic stop check
    unsafe {
        let flags = libc::fcntl(sock, libc::F_GETFL, 0);
        libc::fcntl(sock, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let mut buffer = vec![0u8; 65536]; // Max packet size
    let mut count = 0u64;

    // Capture loop
    loop {
        // Check stop flag
        if stop_flag.load(Ordering::SeqCst) {
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

        // Skip outgoing packets to avoid duplicates
        // PACKET_OUTGOING = 4
        if sll.sll_pkttype == 4 {
            continue;
        }

        // Get timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap();

        // Write packet in appropriate format
        let write_result = match format {
            CaptureFormat::Jsonl => {
                let json_line = packet_to_jsonl(&buffer[..packet_len], timestamp.as_micros(), count);
                writeln!(file, "{}", json_line)
            }
            CaptureFormat::Pcap => {
                write_pcap_packet(&mut file, &buffer[..packet_len], timestamp)
            }
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

    unsafe { libc::close(sock); }
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

fn packet_to_jsonl(packet: &[u8], timestamp_us: u128, seq: u64) -> String {
    // Create JSON object with packet data
    // Format: {"seq": N, "timestamp_us": T, "length": L, "data": "hex..."}

    let hex_data: String = packet.iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    format!(
        r#"{{"seq":{},"timestamp_us":{},"length":{},"data":"{}"}}"#,
        seq, timestamp_us, packet.len(), hex_data
    )
}

// PCAP file format functions
fn write_pcap_header(file: &mut File) -> std::io::Result<()> {
    // PCAP Global Header (24 bytes)
    // https://wiki.wireshark.org/Development/LibpcapFileFormat

    let magic_number: u32 = 0xa1b2c3d4;  // Microsecond resolution
    let version_major: u16 = 2;
    let version_minor: u16 = 4;
    let thiszone: i32 = 0;               // GMT to local correction
    let sigfigs: u32 = 0;                // Accuracy of timestamps
    let snaplen: u32 = 65535;            // Max length of captured packets
    let network: u32 = 1;                // Data link type (1 = Ethernet)

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
    let incl_len = packet.len() as u32;  // Number of octets saved
    let orig_len = packet.len() as u32;  // Actual length of packet

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
