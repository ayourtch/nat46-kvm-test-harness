use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::ffi::CString;
use std::path::Path;

pub fn main(args: &str) {
    let args = args.trim();

    if args.is_empty() {
        eprintln!("Usage: insmod <module_path>");
        return;
    }

    let module_path = args;

    if !Path::new(module_path).exists() {
        eprintln!("Error: Module file '{}' not found", module_path);
        return;
    }

    match insmod_internal(module_path) {
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

fn insmod_internal(module_path: &str) -> Result<(), String> {
    // Open the kernel module file
    let file = File::open(module_path)
        .map_err(|e| format!("Failed to open {}: {}", module_path, e))?;

    let fd = file.as_raw_fd();
    let params = CString::new("").unwrap();

    // Use finit_module syscall (syscall number 313 on x86_64)
    let result = unsafe {
        libc::syscall(libc::SYS_finit_module, fd, params.as_ptr(), 0)
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
    "insmod <module>                   - Load kernel module"
}
