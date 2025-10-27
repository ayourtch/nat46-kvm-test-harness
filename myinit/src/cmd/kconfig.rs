use std::fs;

pub fn main(args: &str) {
    let config_option = args.trim();

    if config_option.is_empty() {
        eprintln!("Usage: kconfig <CONFIG_NAME>");
        eprintln!("Example: kconfig CONFIG_FTRACE");
        eprintln!("         kconfig CONFIG_DEBUG_FS");
        return;
    }

    // Try different locations for kernel config
    let config_paths = [
        "/proc/config.gz",
        "/boot/config",
        "/proc/config",
        "/sys/kernel/config",
    ];

    // Also check /proc/kallsyms for tracing symbols
    if config_option == "CONFIG_FTRACE" || config_option == "tracing" {
        check_tracing_available();
        return;
    }

    for path in &config_paths {
        if let Ok(exists) = std::path::Path::new(path).try_exists() {
            if exists {
                println!("Found kernel config at: {}", path);
                // TODO: parse config (would need gzip support for .gz)
                return;
            }
        }
    }

    println!("Kernel config not found in standard locations");
    println!("Checking for tracing support via /proc...");
    check_tracing_available();
}

fn check_tracing_available() {
    println!("\n=== Checking kernel tracing support ===\n");

    // Check if ftrace is available via /proc/sys/kernel
    if let Ok(content) = fs::read_to_string("/proc/sys/kernel/ftrace_enabled") {
        println!("✓ ftrace_enabled: {}", content.trim());
    } else {
        println!("✗ /proc/sys/kernel/ftrace_enabled not found");
    }

    // Check for trace-related entries in /proc/kallsyms
    if let Ok(content) = fs::read_to_string("/proc/kallsyms") {
        let trace_count = content.lines()
            .filter(|line| line.contains("trace") || line.contains("ftrace"))
            .count();
        if trace_count > 0 {
            println!("✓ Found {} trace-related kernel symbols", trace_count);
        } else {
            println!("✗ No trace-related symbols in /proc/kallsyms");
        }
    }

    // Check /proc/filesystems for debugfs/tracefs
    if let Ok(content) = fs::read_to_string("/proc/filesystems") {
        println!("\n=== Available filesystems ===");
        for line in content.lines() {
            if line.contains("debugfs") || line.contains("tracefs") {
                println!("✓ {}", line.trim());
            }
        }

        let has_debugfs = content.contains("debugfs");
        let has_tracefs = content.contains("tracefs");

        if !has_debugfs && !has_tracefs {
            println!("✗ Neither debugfs nor tracefs available");
            println!("\nKernel likely not compiled with:");
            println!("  CONFIG_DEBUG_FS=y");
            println!("  CONFIG_FTRACE=y");
        }
    }

    // Check if tracing directory already exists
    println!("\n=== Checking tracing directories ===");
    for path in &["/sys/kernel/debug/tracing", "/sys/kernel/tracing", "/sys/kernel/debug"] {
        if std::path::Path::new(path).exists() {
            println!("✓ {} exists", path);
        } else {
            println!("✗ {} does not exist", path);
        }
    }
}

pub fn help_text() -> &'static str {
    "kconfig <option>                  - Check kernel config (e.g., CONFIG_FTRACE)"
}
