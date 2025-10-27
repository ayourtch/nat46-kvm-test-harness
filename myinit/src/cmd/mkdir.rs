use std::ffi::CString;

pub fn main(args: &str) {
    let args = args.trim();

    if args.is_empty() {
        eprintln!("Usage: mkdir [-p] <directory>");
        return;
    }

    let parts: Vec<&str> = args.split_whitespace().collect();
    let (recursive, path) = if parts.len() >= 2 && parts[0] == "-p" {
        (true, parts[1])
    } else {
        (false, parts[0])
    };

    if recursive {
        create_dir_recursive(path);
    } else {
        create_dir(path);
    }
}

fn create_dir(path: &str) {
    let path_cstr = match CString::new(path) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Invalid path: {}", path);
            return;
        }
    };

    let result = unsafe { libc::mkdir(path_cstr.as_ptr(), 0o755) };

    if result == 0 {
        println!("Created directory: {}", path);
    } else {
        let errno = unsafe { *libc::__errno_location() };
        eprintln!("Failed to create directory {}: errno {}", path, errno);
    }
}

fn create_dir_recursive(path: &str) {
    let path = path.trim_end_matches('/');
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    let mut current_path = String::new();
    for component in components {
        if path.starts_with('/') && current_path.is_empty() {
            current_path.push('/');
        } else if !current_path.is_empty() && !current_path.ends_with('/') {
            current_path.push('/');
        }
        current_path.push_str(component);

        let path_cstr = match CString::new(current_path.as_str()) {
            Ok(s) => s,
            Err(_) => continue,
        };

        unsafe {
            libc::mkdir(path_cstr.as_ptr(), 0o755);
            // Ignore errors - directory might already exist
        };
    }

    println!("Created directory path: {}", path);
}

pub fn help_text() -> &'static str {
    "mkdir [-p] <dir>                  - Create directory (-p for recursive)"
}
