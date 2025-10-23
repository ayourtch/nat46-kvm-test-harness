use std::fs;

pub fn main(args: &str) {
    let path = if args.is_empty() { "." } else { args.trim() };

    println!("Contents of {}:", path);

    match fs::read_dir(path) {
        Ok(entries) => {
            let mut items: Vec<_> = entries
                .filter_map(|e| e.ok())
                .collect();

            // Sort by name
            items.sort_by_key(|e| e.file_name());

            for entry in items {
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy();

                if let Ok(metadata) = entry.metadata() {
                    let file_type = if metadata.is_dir() {
                        "d"
                    } else if metadata.is_symlink() {
                        "l"
                    } else {
                        "-"
                    };

                    let size = metadata.len();

                    // Print in format similar to ls -l
                    println!("  {} {:>10} {}", file_type, size, file_name_str);
                } else {
                    println!("  ? {:>10} {}", "?", file_name_str);
                }
            }
        }
        Err(e) => {
            eprintln!("ls: cannot access '{}': {}", path, e);
        }
    }
    println!();
}

pub fn help_text() -> &'static str {
    "ls [path]                         - List directory contents"
}
