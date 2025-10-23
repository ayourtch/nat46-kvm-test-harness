use std::ffi::CString;
use std::path::Path;

pub fn main(args: &str) {
    let args = args.trim();

    if args.is_empty() {
        print_usage();
        return;
    }

    // Parse arguments - support both simple and full forms:
    // Simple: mount proc (mounts proc at /proc)
    // Simple: mount 9p (mounts host-code at /mnt/host with 9p)
    // Full: mount -t <fstype> <source> <target> [-o <options>]

    let parts: Vec<&str> = args.split_whitespace().collect();

    // Handle simple form first
    if parts.len() == 1 {
        match parts[0] {
            "proc" => {
                mount_proc();
                return;
            }
            "9p" => {
                mount_9p();
                return;
            }
            _ => {
                eprintln!("Error: Unknown simple mount type '{}'", parts[0]);
                eprintln!("Supported simple mounts: proc, 9p");
                return;
            }
        }
    }

    // Parse full form: mount -t <fstype> <source> <target> [-o <options>]
    if parts.len() < 4 || parts[0] != "-t" {
        eprintln!("Error: Invalid syntax");
        print_usage();
        return;
    }

    let fstype = parts[1];
    let source = parts[2];
    let target = parts[3];

    // Parse optional -o options
    let options = if parts.len() >= 6 && parts[4] == "-o" {
        parts[5]
    } else {
        ""
    };

    match mount_filesystem(source, target, fstype, options) {
        Ok(_) => println!("Successfully mounted {} at {}", source, target),
        Err(e) => eprintln!("Mount failed: {}", e),
    }
}

fn mount_proc() {
    let proc_path = CString::new("/proc").unwrap();
    let proc_type = CString::new("proc").unwrap();
    let empty = CString::new("").unwrap();

    // Check if /proc is already mounted by trying to read /proc/mounts
    if Path::new("/proc/mounts").exists() {
        println!("/proc already mounted");
        return;
    }

    println!("Mounting /proc filesystem...");

    // Create /proc directory if it doesn't exist
    unsafe {
        libc::mkdir(proc_path.as_ptr(), 0o755);
    }

    // Mount proc filesystem
    let result = unsafe {
        libc::mount(
            proc_type.as_ptr(),
            proc_path.as_ptr(),
            proc_type.as_ptr(),
            0,
            empty.as_ptr() as *const libc::c_void
        )
    };

    if result == 0 {
        println!("Successfully mounted /proc");
    } else {
        let errno = unsafe { *libc::__errno_location() };
        let error_msg = unsafe {
            let err_str = libc::strerror(errno);
            std::ffi::CStr::from_ptr(err_str)
                .to_string_lossy()
                .into_owned()
        };
        eprintln!("Failed to mount /proc: errno {} - {}", errno, error_msg);
    }
}

fn mount_9p() {
    println!("Mounting 9p filesystem...");

    // Check if 9p filesystem is available
    if Path::new("/proc/filesystems").exists() {
        if let Ok(content) = std::fs::read_to_string("/proc/filesystems") {
            if !content.contains("9p") {
                eprintln!("Warning: 9p filesystem not found in /proc/filesystems");
                eprintln!("Make sure 9p kernel modules are loaded (9pnet, 9pnet_virtio, 9p)");
            }
        }
    }

    // Create /mnt directory if it doesn't exist
    let mnt_path = CString::new("/mnt").unwrap();
    unsafe {
        libc::mkdir(mnt_path.as_ptr(), 0o755);
    }

    // Create /mnt/host directory
    let mnt_host_path = CString::new("/mnt/host").unwrap();
    unsafe {
        if libc::mkdir(mnt_host_path.as_ptr(), 0o755) != 0 {
            let errno = *libc::__errno_location();
            // EEXIST (errno 17) is fine, directory already exists
            if errno != 17 {
                eprintln!("Warning: failed to create /mnt/host: errno {}", errno);
            }
        }
    }

    // Mount 9p filesystem with default settings
    match mount_filesystem("host-code", "/mnt/host", "9p", "trans=virtio,version=9p2000.L") {
        Ok(_) => println!("Successfully mounted host-code at /mnt/host"),
        Err(e) => eprintln!("Failed to mount 9p filesystem: {}", e),
    }
}

fn mount_filesystem(source: &str, target: &str, fstype: &str, options: &str) -> Result<(), String> {
    // Create target directory if it doesn't exist
    let target_path = CString::new(target)
        .map_err(|_| "Invalid target path".to_string())?;

    unsafe {
        if libc::mkdir(target_path.as_ptr(), 0o755) != 0 {
            let errno = *libc::__errno_location();
            // EEXIST (errno 17) is okay - directory already exists
            if errno != 17 {
                let err_str = libc::strerror(errno);
                let msg = std::ffi::CStr::from_ptr(err_str)
                    .to_string_lossy()
                    .into_owned();
                eprintln!("Warning: failed to create {}: errno {} - {}", target, errno, msg);
            }
        }
    }

    // Prepare mount arguments
    let source_cstr = CString::new(source)
        .map_err(|_| "Invalid source".to_string())?;
    let target_cstr = CString::new(target)
        .map_err(|_| "Invalid target".to_string())?;
    let fstype_cstr = CString::new(fstype)
        .map_err(|_| "Invalid filesystem type".to_string())?;
    let options_cstr = CString::new(options)
        .map_err(|_| "Invalid options".to_string())?;

    println!("Attempting to mount {} at {} (type: {}, options: {})",
             source, target, fstype, if options.is_empty() { "none" } else { options });

    // Perform the mount
    let result = unsafe {
        libc::mount(
            source_cstr.as_ptr(),
            target_cstr.as_ptr(),
            fstype_cstr.as_ptr(),
            0,
            if options.is_empty() {
                std::ptr::null()
            } else {
                options_cstr.as_ptr() as *const libc::c_void
            }
        )
    };

    if result == 0 {
        Ok(())
    } else {
        let errno = unsafe { *libc::__errno_location() };
        let error_msg = unsafe {
            let err_str = libc::strerror(errno);
            std::ffi::CStr::from_ptr(err_str)
                .to_string_lossy()
                .into_owned()
        };
        Err(format!("errno {} - {}", errno, error_msg))
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  mount proc                                    - Mount /proc filesystem");
    eprintln!("  mount 9p                                      - Mount 9p filesystem at /mnt/host");
    eprintln!("  mount -t <fstype> <source> <target> [-o <options>]");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  mount proc");
    eprintln!("  mount 9p");
    eprintln!("  mount -t proc proc /proc");
    eprintln!("  mount -t 9p host-code /mnt/host -o trans=virtio,version=9p2000.L");
}

pub fn help_text() -> &'static str {
    "mount <target>                    - Mount filesystem (proc, 9p, or full syntax)"
}
