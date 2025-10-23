use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::ffi::CString;
use std::path::Path;

// MODULE_INIT_COMPRESSED_FILE flag for finit_module
const MODULE_INIT_COMPRESSED_FILE: i32 = 4;

pub fn main(args: &str) {
    let args = args.trim();

    if args.is_empty() {
        eprintln!("Usage: insmod <module_path>");
        return;
    }

    let requested_path = args;

    // Determine which file to use (.ko or .ko.zst)
    let (actual_path, is_compressed) = find_module_file(requested_path);

    if actual_path.is_none() {
        eprintln!("Error: Module file '{}' not found", requested_path);
        eprintln!("  (also checked for .ko.zst variant)");
        return;
    }

    let module_path = actual_path.unwrap();

    match insmod_internal(&module_path, is_compressed) {
        Ok(_) => {
            println!("Successfully loaded module: {}", module_path);
        }
        Err(e) => {
            eprintln!("Failed to load module {}: {}", module_path, e);
            eprintln!("\nRecent kernel messages:");

            // Try to show kernel messages for debugging
            if let Ok(messages) = read_recent_kmsg(20) {
                for msg in messages {
                    eprintln!("  {}", msg);
                }
            }
        }
    }
}

fn find_module_file(requested_path: &str) -> (Option<String>, bool) {
    // Check if exact path exists
    if Path::new(requested_path).exists() {
        let is_compressed = requested_path.ends_with(".ko.zst");
        return (Some(requested_path.to_string()), is_compressed);
    }

    // If requested path ends with .ko, also try .ko.zst
    if requested_path.ends_with(".ko") {
        let zst_path = format!("{}.zst", requested_path);
        if Path::new(&zst_path).exists() {
            return (Some(zst_path), true);
        }
    }

    // If requested path doesn't have .ko extension, try both .ko and .ko.zst
    if !requested_path.ends_with(".ko") && !requested_path.ends_with(".ko.zst") {
        let ko_path = format!("{}.ko", requested_path);
        if Path::new(&ko_path).exists() {
            return (Some(ko_path), false);
        }

        let zst_path = format!("{}.ko.zst", requested_path);
        if Path::new(&zst_path).exists() {
            return (Some(zst_path), true);
        }
    }

    (None, false)
}

fn insmod_internal(module_path: &str, is_compressed: bool) -> Result<(), String> {
    // Open the kernel module file
    let file = File::open(module_path)
        .map_err(|e| format!("Failed to open {}: {}", module_path, e))?;

    let fd = file.as_raw_fd();
    let params = CString::new("").unwrap();

    // Set flags based on whether the module is compressed
    let flags = if is_compressed {
        MODULE_INIT_COMPRESSED_FILE
    } else {
        0
    };

    // Use finit_module syscall (syscall number 313 on x86_64)
    let result = unsafe {
        libc::syscall(libc::SYS_finit_module, fd, params.as_ptr(), flags)
    };

    if result == 0 {
        Ok(())
    } else {
        // Get the actual errno
        let errno = unsafe { *libc::__errno_location() };
        let error_msg = unsafe {
            let err_str = libc::strerror(errno);
            std::ffi::CStr::from_ptr(err_str)
                .to_string_lossy()
                .into_owned()
        };

        Err(format!("insmod failed with return code: {} (errno: {} - {})",
                    result, errno, error_msg))
    }
}

fn read_recent_kmsg(lines: usize) -> Result<Vec<String>, String> {
    use std::io::{BufRead, BufReader};
    use std::fs::File;

    // Try to read from /dev/kmsg (preferred) or /proc/kmsg
    let kmsg_paths = ["/dev/kmsg", "/proc/kmsg"];

    for path in &kmsg_paths {
        if let Ok(file) = File::open(path) {
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
    }

    Err("Unable to read kernel messages".to_string())
}

pub fn help_text() -> &'static str {
    "insmod <module>                   - Load kernel module (.ko or .ko.zst)"
}
