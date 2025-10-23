use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::ffi::CString;

pub fn main(args: &str) {
    let args = args.trim();

    // Parse optional line count argument
    let lines = if args.is_empty() {
        100 // Default to last 100 lines
    } else {
        match args.parse::<usize>() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("Usage: dmesg [lines]");
                eprintln!("  lines: number of recent kernel messages to display (default: 100)");
                return;
            }
        }
    };

    // Ensure /dev/kmsg exists
    ensure_kmsg_device();

    // Read and display kernel messages
    match read_recent_kmsg(lines) {
        Ok(messages) => {
            for msg in messages {
                println!("{}", msg);
            }
        }
        Err(e) => {
            eprintln!("Failed to read kernel messages: {}", e);
        }
    }
}

fn ensure_kmsg_device() {
    // Check if /dev/kmsg exists, if not create it
    // /dev/kmsg is a character device with major:minor 1:11
    let kmsg_path = CString::new("/dev/kmsg").unwrap();

    if !Path::new("/dev/kmsg").exists() {
        // Create /dev directory if it doesn't exist
        let dev_path = CString::new("/dev").unwrap();
        unsafe {
            libc::mkdir(dev_path.as_ptr(), 0o755);
        }

        // Create /dev/kmsg character device (major: 1, minor: 11)
        // S_IFCHR | 0600 = character device with rw------- permissions
        let mode = libc::S_IFCHR | 0o600;
        let dev = libc::makedev(1, 11);

        let result = unsafe {
            libc::mknod(kmsg_path.as_ptr(), mode, dev)
        };

        if result != 0 {
            let errno = unsafe { *libc::__errno_location() };
            // Only warn, don't fail - we'll try /proc/kmsg as fallback
            if errno != 17 { // EEXIST is okay
                eprintln!("Warning: Failed to create /dev/kmsg: errno {}", errno);
            }
        }
    }
}

fn read_recent_kmsg(lines: usize) -> Result<Vec<String>, String> {
    // Try to read from /dev/kmsg (preferred) or /proc/kmsg
    let kmsg_paths = ["/dev/kmsg", "/proc/kmsg"];

    for path in &kmsg_paths {
        match File::open(path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                let messages: Vec<String> = reader
                    .lines()
                    .take(lines)
                    .filter_map(|line| line.ok())
                    .collect();

                if !messages.is_empty() {
                    return Ok(messages);
                }
            }
            Err(_) => {
                // Try next path
                continue;
            }
        }
    }

    Err("Unable to read kernel messages from /dev/kmsg or /proc/kmsg".to_string())
}

pub fn help_text() -> &'static str {
    "dmesg [lines]                     - Display kernel messages"
}
