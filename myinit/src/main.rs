mod cmd;

use std::thread;
use std::time::Duration;
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::io::{self, Write, Read};

fn set_stdin_nonblocking(blocking: bool) {
    unsafe {
        let flags = libc::fcntl(0, libc::F_GETFL, 0);
        if blocking {
            libc::fcntl(0, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        } else {
            libc::fcntl(0, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

fn check_for_input() -> bool {
    let mut buf = [0u8; 1];
    set_stdin_nonblocking(false);

    unsafe {
        let flags = libc::fcntl(0, libc::F_GETFL, 0);
        libc::fcntl(0, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let result = io::stdin().read(&mut buf).is_ok() && buf[0] != 0;

    set_stdin_nonblocking(true);
    result
}

fn redirect_stdout_to_file(file_path: &str) -> Result<(i32, i32), String> {
    // Save original stdout
    let saved_stdout = unsafe { libc::dup(1) };
    if saved_stdout < 0 {
        return Err("Failed to duplicate stdout".to_string());
    }

    // Open the output file
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(file_path)
        .map_err(|e| format!("Failed to open {}: {}", file_path, e))?;

    let fd = file.as_raw_fd();

    // Redirect stdout to the file
    if unsafe { libc::dup2(fd, 1) } < 0 {
        unsafe { libc::close(saved_stdout); }
        return Err("Failed to redirect stdout".to_string());
    }

    // Keep the file open by forgetting it
    std::mem::forget(file);

    Ok((saved_stdout, fd))
}

fn restore_stdout(saved_stdout: i32, file_fd: i32) {
    // Restore original stdout
    unsafe {
        libc::dup2(saved_stdout, 1);
        libc::close(saved_stdout);
        libc::close(file_fd);
    }

    // Flush stdout to ensure everything is written
    io::stdout().flush().ok();
}

fn redirect_stdin_from_file(file_path: &str) -> Result<(i32, i32), String> {
    // Save original stdin
    let saved_stdin = unsafe { libc::dup(0) };
    if saved_stdin < 0 {
        return Err("Failed to duplicate stdin".to_string());
    }

    // Open the input file
    let file = OpenOptions::new()
        .read(true)
        .open(file_path)
        .map_err(|e| format!("Failed to open {}: {}", file_path, e))?;

    let fd = file.as_raw_fd();

    // Redirect stdin from the file
    if unsafe { libc::dup2(fd, 0) } < 0 {
        unsafe { libc::close(saved_stdin); }
        return Err("Failed to redirect stdin".to_string());
    }

    // Keep the file open by forgetting it
    std::mem::forget(file);

    Ok((saved_stdin, fd))
}

fn restore_stdin(saved_stdin: i32, file_fd: i32) {
    // Restore original stdin
    unsafe {
        libc::dup2(saved_stdin, 0);
        libc::close(saved_stdin);
        libc::close(file_fd);
    }
}

fn execute_command(command: &str, args: &str) -> bool {
    cmd::execute(command, args)
}

// Parse and execute a full command line (supports input and output redirection)
fn execute_line(line: &str) {
    // Check for input redirection first
    let (cmd_line, input_file) = if let Some(pos) = line.find('<') {
        let cmd = line[..pos].trim();
        let file = line[pos + 1..].trim();
        // Extract just the filename (stop at > if present)
        let input_filename = if let Some(out_pos) = file.find('>') {
            file[..out_pos].trim()
        } else {
            file
        };
        (cmd, Some(input_filename))
    } else {
        (line, None)
    };

    // Check for output redirection
    let (cmd_part, output_file) = if let Some(pos) = cmd_line.find('>') {
        let cmd = cmd_line[..pos].trim();
        let file = cmd_line[pos + 1..].trim();
        (cmd, Some(file))
    } else {
        (cmd_line, None)
    };

    let parts: Vec<&str> = cmd_part.splitn(2, ' ').collect();
    let command = parts[0];
    let args = if parts.len() > 1 { parts[1] } else { "" };

    // Handle input redirection
    let input_redirect_info = if let Some(file_path) = input_file {
        match redirect_stdin_from_file(file_path) {
            Ok(info) => Some(info),
            Err(e) => {
                eprintln!("Input redirection error: {}", e);
                return;
            }
        }
    } else {
        None
    };

    // Handle output redirection
    let output_redirect_info = if let Some(file_path) = output_file {
        match redirect_stdout_to_file(file_path) {
            Ok(info) => Some(info),
            Err(e) => {
                eprintln!("Output redirection error: {}", e);
                // Restore stdin if it was redirected
                if let Some((saved_stdin, file_fd)) = input_redirect_info {
                    restore_stdin(saved_stdin, file_fd);
                }
                return;
            }
        }
    } else {
        None
    };

    // Execute the command
    execute_command(command, args);

    // Restore stdout if it was redirected
    if let Some((saved_stdout, file_fd)) = output_redirect_info {
        restore_stdout(saved_stdout, file_fd);
    }

    // Restore stdin if it was redirected
    if let Some((saved_stdin, file_fd)) = input_redirect_info {
        restore_stdin(saved_stdin, file_fd);
    }
}

// Execute a script (multiple commands, one per line)
pub fn execute_script(script: &str) {
    for line in script.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        execute_line(line);
    }
}

fn interactive_shell() {
    println!("\nEntering interactive mode.");
    execute_command("help", "");
    println!();

    set_stdin_nonblocking(true);

    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                let input = input.trim();

                if input.is_empty() {
                    continue;
                }

                // Check if command should cause exit (before redirections)
                let base_cmd = input.split_whitespace().next().unwrap_or("");

                // Use execute_line for full redirection support
                execute_line(input);

                // Check if we should exit
                if base_cmd == "poweroff" {
                    break; // Exit shell
                }
            }
            Err(e) => {
                eprintln!("Error reading input: {}", e);
            }
        }
    }
}

fn main() {
    // Minimal startup script - only what's needed to mount filesystems
    let startup_script = r#"
# Mount proc filesystem
mount proc

# Load 9p kernel modules (required for host filesystem access)
insmod /netfs.ko
insmod /9pnet.ko
insmod /9pnet_virtio.ko
insmod /9p.ko

# Mount host filesystem
mount 9p
"#;

    // Execute the minimal startup script
    execute_script(startup_script);

    // Check for and execute startup.run (modifiable initialization script)
    use std::path::Path;
    let startup_paths = [
        "/mnt/host/test-harness/startup.run",
        "/startup.run",
    ];

    let mut found_startup = false;
    for startup_path in &startup_paths {
        if Path::new(startup_path).exists() {
            println!("\nExecuting {}...", startup_path);
            execute_command("run", startup_path);
            found_startup = true;
            break;
        }
    }

    if !found_startup {
        println!("\nNo startup.run found (checked /mnt/host/test-harness/startup.run, /startup.run), skipping.");
    }

    // First countdown: Check for autoexec.run
    println!("\nChecking for autoexec.run in 5 seconds...");
    println!("Press any key to skip autoexec.");

    let mut skip_autoexec = false;
    for i in (1..=5).rev() {
        println!("{} seconds remaining...", i);

        // Check for input during this second
        for _ in 0..10 {
            thread::sleep(Duration::from_millis(100));
            if check_for_input() {
                skip_autoexec = true;
                break;
            }
        }

        if skip_autoexec {
            break;
        }
    }

    let mut interactive_mode = skip_autoexec;

    if !skip_autoexec {
        // Try to run autoexec.run
        let autoexec_paths = [
            "/mnt/host/test-harness/autoexec.run",
            "/autoexec.run",
        ];

        let mut found_autoexec = false;
        for autoexec_path in &autoexec_paths {
            if Path::new(autoexec_path).exists() {
                println!("\nExecuting {}...", autoexec_path);
                execute_command("run", autoexec_path);
                found_autoexec = true;
                break;
            }
        }

        if !found_autoexec {
            println!("\nNo autoexec.run found (checked /mnt/host/test-harness/autoexec.run, /autoexec.run), skipping.");
        }

        // Second countdown: Shutdown or interactive mode (only if didn't skip autoexec)
        println!("\nSystem will shutdown in 10 seconds...");
        println!("Press any key to enter interactive mode.");

        for i in (1..=10).rev() {
            println!("{} seconds remaining...", i);

            // Check for input during this second
            for _ in 0..10 {
                thread::sleep(Duration::from_millis(100));
                if check_for_input() {
                    interactive_mode = true;
                    break;
                }
            }

            if interactive_mode {
                break;
            }
        }
    } else {
        println!("\nSkipped autoexec.run, entering interactive mode.");
    }

    if interactive_mode {
        interactive_shell();
    } else {
        execute_command("poweroff", "");
    }
}
