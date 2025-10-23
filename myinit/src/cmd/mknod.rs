use std::ffi::CString;
use std::path::Path;

pub fn main(args: &str) {
    let args = args.trim();

    if args.is_empty() {
        print_usage();
        return;
    }

    // Parse arguments: mknod <path> <type> <major> <minor>
    // where type is 'c' (character) or 'b' (block)
    let parts: Vec<&str> = args.split_whitespace().collect();

    if parts.len() != 4 {
        eprintln!("Error: Invalid number of arguments");
        print_usage();
        return;
    }

    let path = parts[0];
    let dev_type = parts[1];
    let major = parts[2];
    let minor = parts[3];

    // Parse major and minor numbers
    let major_num: u32 = match major.parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("Error: Invalid major number '{}'", major);
            return;
        }
    };

    let minor_num: u32 = match minor.parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("Error: Invalid minor number '{}'", minor);
            return;
        }
    };

    // Determine device type
    let mode = match dev_type {
        "c" | "char" => libc::S_IFCHR | 0o666,
        "b" | "block" => libc::S_IFBLK | 0o666,
        _ => {
            eprintln!("Error: Invalid device type '{}'. Use 'c' for character or 'b' for block", dev_type);
            return;
        }
    };

    // Create parent directory if needed
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            let parent_cstr = match CString::new(parent.to_string_lossy().as_bytes()) {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("Error: Invalid path");
                    return;
                }
            };

            unsafe {
                libc::mkdir(parent_cstr.as_ptr(), 0o755);
            }
        }
    }

    // Create the device node
    let path_cstr = match CString::new(path) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Error: Invalid path");
            return;
        }
    };

    let dev = libc::makedev(major_num, minor_num);

    let result = unsafe {
        libc::mknod(path_cstr.as_ptr(), mode, dev)
    };

    if result == 0 {
        println!("Successfully created device node: {}", path);
    } else {
        let errno = unsafe { *libc::__errno_location() };
        let error_msg = unsafe {
            let err_str = libc::strerror(errno);
            std::ffi::CStr::from_ptr(err_str)
                .to_string_lossy()
                .into_owned()
        };

        match errno {
            17 => println!("Device node {} already exists", path), // EEXIST
            _ => eprintln!("Failed to create device node: errno {} - {}", errno, error_msg),
        }
    }
}

fn print_usage() {
    eprintln!("Usage: mknod <path> <type> <major> <minor>");
    eprintln!("  path:  device node path (e.g., /dev/null)");
    eprintln!("  type:  'c' or 'char' for character device, 'b' or 'block' for block device");
    eprintln!("  major: major device number");
    eprintln!("  minor: minor device number");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  mknod /dev/kmsg c 1 11");
    eprintln!("  mknod /dev/net/tun c 10 200");
}

pub fn help_text() -> &'static str {
    "mknod <path> <type> <maj> <min>   - Create device node"
}
