use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::mem;

pub fn main(args: &str) {
    let args = args.trim();

    if args.is_empty() {
        print_usage();
        return;
    }

    // Parse: tap add <name> or tap del <name>
    let parts: Vec<&str> = args.split_whitespace().collect();

    if parts.len() < 2 {
        eprintln!("Error: Invalid number of arguments");
        print_usage();
        return;
    }

    let action = parts[0];
    let name = parts[1];

    match action {
        "add" => {
            match create_tap_interface(name) {
                Ok(_) => {
                    println!("Successfully created TAP interface '{}'", name);
                }
                Err(e) => {
                    eprintln!("Failed to create TAP interface '{}': {}", name, e);
                }
            }
        }
        "del" => {
            eprintln!("TAP interface deletion not yet implemented");
            eprintln!("TAP interfaces are automatically removed when the file descriptor is closed");
        }
        _ => {
            eprintln!("Error: Unknown action '{}'", action);
            print_usage();
        }
    }
}

fn create_tap_interface(name: &str) -> Result<i32, String> {
    const TUNSETIFF: u64 = 0x400454ca;
    const IFF_TAP: i16 = 0x0002;
    const IFF_NO_PI: i16 = 0x1000;

    println!("Creating TAP interface '{}'...", name);

    // Open /dev/net/tun
    let tun_path = "/dev/net/tun";
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(tun_path)
        .map_err(|e| format!("Failed to open {}: {}", tun_path, e))?;

    let fd = file.as_raw_fd();

    // Prepare ifreq structure
    #[repr(C)]
    struct ifreq_with_flags {
        ifr_name: [u8; libc::IFNAMSIZ],
        ifr_flags: i16,
        _padding: [u8; 22], // Total size should be 40 bytes
    }

    let mut ifr: ifreq_with_flags = unsafe { mem::zeroed() };

    // Copy interface name
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
    ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    // Set flags for TAP device
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    // Create the interface using ioctl
    let result = unsafe {
        libc::ioctl(fd, TUNSETIFF as i32, &mut ifr)
    };

    if result < 0 {
        let errno = unsafe { *libc::__errno_location() };
        let error_msg = unsafe {
            let err_str = libc::strerror(errno);
            std::ffi::CStr::from_ptr(err_str)
                .to_string_lossy()
                .into_owned()
        };
        return Err(format!("Failed to create TAP interface: errno {} - {}", errno, error_msg));
    }

    // Keep the file descriptor open by leaking it
    // This prevents the TAP interface from being automatically removed
    std::mem::forget(file);

    Ok(fd)
}

fn print_usage() {
    eprintln!("Usage: tap <action> <name>");
    eprintln!("  action: 'add' to create a TAP interface, 'del' to remove (not yet implemented)");
    eprintln!("  name:   interface name (e.g., tap0, tap1)");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  tap add tap0");
    eprintln!("  tap add tap1");
    eprintln!();
    eprintln!("Note: TAP interfaces are automatically removed when the program exits.");
    eprintln!("      After creating, use 'ifconfig' to configure IP addresses.");
}

pub fn help_text() -> &'static str {
    "tap add <name>                    - Create TAP interface"
}
