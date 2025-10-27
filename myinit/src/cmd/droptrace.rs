use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::collections::VecDeque;

const TRACING_PATH: &str = "/sys/kernel/debug/tracing";
const TRACEFS_PATH: &str = "/sys/kernel/tracing";

// Global state for background tracing
lazy_static::lazy_static! {
    static ref TRACE_STATE: Arc<Mutex<Option<TraceHandle>>> = Arc::new(Mutex::new(None));
}

struct TraceHandle {
    stop_flag: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<()>>,
    buffer: Arc<Mutex<VecDeque<String>>>,
    packet_count: Arc<Mutex<u64>>,
}

fn try_mount_tracing(mount_point: &str, fs_type: &str) -> bool {
    use std::ffi::CString;

    // Create mount point directory if it doesn't exist
    let parent = if mount_point.contains("/debug") {
        "/sys/kernel/debug"
    } else {
        "/sys/kernel/tracing"
    };

    // Ensure /sys/kernel exists first
    let sys_kernel = CString::new("/sys/kernel").unwrap();
    unsafe {
        libc::mkdir(sys_kernel.as_ptr(), 0o755);
    }

    // Create parent directory
    let parent_cstr = match CString::new(parent) {
        Ok(s) => s,
        Err(_) => return false,
    };

    unsafe {
        libc::mkdir(parent_cstr.as_ptr(), 0o755);
    }

    // Try to mount
    let source = CString::new("none").unwrap();
    let target = CString::new(parent).unwrap();
    let fstype = CString::new(fs_type).unwrap();
    let flags = 0u64;
    let data = std::ptr::null::<libc::c_void>();

    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            data,
        )
    };

    if result == 0 {
        println!("Mounted {} at {}", fs_type, parent);
        true
    } else {
        let errno = unsafe { *libc::__errno_location() };
        eprintln!("Failed to mount {} at {}: errno {}", fs_type, parent, errno);
        false
    }
}

pub fn main(args: &str) {
    let parts: Vec<&str> = args.trim().split_whitespace().collect();

    if parts.is_empty() {
        eprintln!("Usage:");
        eprintln!("  droptrace start [count]  - Start tracing packet drops (optional packet count limit)");
        eprintln!("  droptrace stop           - Stop tracing");
        eprintln!("  droptrace show           - Show current trace buffer");
        eprintln!("  droptrace clear          - Clear trace buffer");
        return;
    }

    // Determine which tracing path to use, mounting if necessary
    let trace_base = if std::path::Path::new(TRACEFS_PATH).exists() {
        TRACEFS_PATH
    } else if std::path::Path::new(TRACING_PATH).exists() {
        TRACING_PATH
    } else {
        // Try to mount tracefs first (preferred)
        if try_mount_tracing(TRACEFS_PATH, "tracefs") {
            TRACEFS_PATH
        } else if try_mount_tracing(TRACING_PATH, "debugfs") {
            TRACING_PATH
        } else {
            eprintln!("Error: Could not mount tracing filesystem");
            return;
        }
    };

    match parts[0] {
        "start" => {
            let count = if parts.len() > 1 {
                parts[1].parse::<u64>().ok()
            } else {
                None
            };
            start_trace_background(trace_base, count);
        }
        "stop" => {
            stop_trace_background(trace_base);
        }
        "show" => {
            show_trace_background();
        }
        "clear" => {
            clear_trace_background();
        }
        _ => {
            eprintln!("Unknown command: {}", parts[0]);
            eprintln!("Use: start, stop, show, or clear");
        }
    }
}

fn start_trace_background(base: &str, max_count: Option<u64>) {
    let mut state = TRACE_STATE.lock().unwrap();

    if state.is_some() {
        eprintln!("Tracing already running. Use 'droptrace stop' first.");
        return;
    }

    println!("Enabling skb:kfree_skb tracepoint...");

    // Clear any previous trace
    if let Err(e) = fs::write(format!("{}/trace", base), "") {
        eprintln!("Warning: Could not clear trace: {}", e);
    }

    // Enable the tracepoint
    let enable_path = format!("{}/events/skb/kfree_skb/enable", base);
    if let Err(e) = fs::write(&enable_path, "1") {
        eprintln!("Error enabling tracepoint: {}", e);
        eprintln!("Path: {}", enable_path);
        eprintln!("\nTry running: kconfig tracing");
        return;
    }

    let stop_flag = Arc::new(AtomicBool::new(false));
    let buffer = Arc::new(Mutex::new(VecDeque::new()));
    let packet_count = Arc::new(Mutex::new(0u64));

    let stop_flag_clone = Arc::clone(&stop_flag);
    let buffer_clone = Arc::clone(&buffer);
    let packet_count_clone = Arc::clone(&packet_count);
    let base_owned = base.to_string();

    let thread_handle = thread::spawn(move || {
        trace_thread(&base_owned, stop_flag_clone, buffer_clone, packet_count_clone, max_count);
    });

    *state = Some(TraceHandle {
        stop_flag,
        thread_handle: Some(thread_handle),
        buffer,
        packet_count,
    });

    println!("Tracing started in background. Use 'droptrace show' to view drops.");
    if let Some(count) = max_count {
        println!("Will stop after {} packets", count);
    }
}

fn trace_thread(
    base: &str,
    stop_flag: Arc<AtomicBool>,
    buffer: Arc<Mutex<VecDeque<String>>>,
    packet_count: Arc<Mutex<u64>>,
    max_count: Option<u64>,
) {
    let pipe_path = format!("{}/trace_pipe", base);
    let enable_path = format!("{}/events/skb/kfree_skb/enable", base);

    let file = match File::open(&pipe_path) {
        Ok(f) => f,
        Err(e) => {
            let mut buf = buffer.lock().unwrap();
            buf.push_back(format!("Error opening trace pipe: {}", e));
            let _ = fs::write(&enable_path, "0");
            return;
        }
    };

    let reader = BufReader::new(file);

    for line in reader.lines() {
        if stop_flag.load(Ordering::SeqCst) {
            break;
        }

        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if let Some(parsed) = parse_trace_line(&line) {
            let mut buf = buffer.lock().unwrap();
            buf.push_back(parsed);

            // Keep buffer size reasonable
            if buf.len() > 1000 {
                buf.pop_front();
            }
            drop(buf);

            let mut count = packet_count.lock().unwrap();
            *count += 1;
            let current_count = *count;
            drop(count);

            if let Some(max) = max_count {
                if current_count >= max {
                    break;
                }
            }
        }
    }

    // Disable tracing
    let _ = fs::write(&enable_path, "0");
}

fn stop_trace_background(base: &str) {
    let mut state = TRACE_STATE.lock().unwrap();

    if let Some(mut handle) = state.take() {
        handle.stop_flag.store(true, Ordering::SeqCst);

        if let Some(thread) = handle.thread_handle.take() {
            let count = *handle.packet_count.lock().unwrap();
            drop(state);
            let _ = thread.join();
            println!("Tracing stopped. {} packets captured", count);
        }
    } else {
        eprintln!("No trace running");

        // Also try to disable via filesystem
        let enable_path = format!("{}/events/skb/kfree_skb/enable", base);
        let _ = fs::write(&enable_path, "0");
    }
}

fn show_trace_background() {
    let state = TRACE_STATE.lock().unwrap();

    if let Some(handle) = state.as_ref() {
        let buffer = handle.buffer.lock().unwrap();
        let count = *handle.packet_count.lock().unwrap();

        if buffer.is_empty() {
            println!("No drops captured yet ({} total)", count);
        } else {
            println!("{:<20} {:<10} {:<8} {:<50} {}", "COMM", "PID", "CPU", "LOCATION", "REASON");
            println!("{}", "-".repeat(100));

            for line in buffer.iter() {
                println!("{}", line);
            }

            println!("\nShowing {} drops (buffer limited to last 1000, {} total captured)", buffer.len(), count);
        }
    } else {
        println!("No trace running. Use 'droptrace start' first.");
    }
}

fn clear_trace_background() {
    let state = TRACE_STATE.lock().unwrap();

    if let Some(handle) = state.as_ref() {
        let mut buffer = handle.buffer.lock().unwrap();
        buffer.clear();
        let mut count = handle.packet_count.lock().unwrap();
        *count = 0;
        println!("Trace buffer cleared");
    } else {
        println!("No trace running");
    }
}

fn parse_trace_line(line: &str) -> Option<String> {
    // Example line:
    // curl-883   [001] d.s1   340.799805: kfree_skb: skbaddr=0xffff88811f6a7068 protocol=2048 location=tcp_v4_rcv+0x157 reason: NO_SOCKET

    if !line.contains("kfree_skb:") {
        return None;
    }

    // Split on the colon after "kfree_skb:"
    let parts: Vec<&str> = line.splitn(2, "kfree_skb:").collect();
    if parts.len() != 2 {
        return None;
    }

    let header = parts[0].trim();
    let data = parts[1].trim();

    // Parse header: "comm-pid [cpu] .... timestamp:"
    let header_parts: Vec<&str> = header.split_whitespace().collect();
    if header_parts.len() < 2 {
        return None;
    }

    let comm_pid = header_parts[0];
    let cpu = header_parts[1].trim_matches(|c| c == '[' || c == ']');

    // Split comm and pid
    let (comm, pid) = if let Some(dash_pos) = comm_pid.rfind('-') {
        let (c, p) = comm_pid.split_at(dash_pos);
        (c, &p[1..])
    } else {
        (comm_pid, "?")
    };

    // Parse data: skbaddr=... protocol=... location=... reason: ...
    let mut location = "?";
    let mut reason = "?";

    for part in data.split_whitespace() {
        if part.starts_with("location=") {
            location = &part[9..];
        } else if part.starts_with("reason:") {
            // Reason comes after "reason:" and may have spaces
            if let Some(pos) = data.find("reason:") {
                reason = data[pos + 7..].trim();
            }
            break;
        }
    }

    Some(format!("{:<20} {:<10} {:<8} {:<50} {}",
        comm, pid, cpu, location, reason))
}

pub fn help_text() -> &'static str {
    "droptrace <start|stop|show|clear> - Trace kernel packet drops (skb:kfree_skb)"
}
