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

fn execute_command(command: &str, args: &str) -> bool {
    cmd::execute(command, args)
}

// Parse and execute a full command line (supports output redirection)
fn execute_line(line: &str) {
    // Check for output redirection
    let (cmd_part, redirect_file) = if let Some(pos) = line.find('>') {
        let cmd = line[..pos].trim();
        let file = line[pos + 1..].trim();
        (cmd, Some(file))
    } else {
        (line, None)
    };

    let parts: Vec<&str> = cmd_part.splitn(2, ' ').collect();
    let command = parts[0];
    let args = if parts.len() > 1 { parts[1] } else { "" };

    // Handle output redirection
    let redirect_info = if let Some(file_path) = redirect_file {
        match redirect_stdout_to_file(file_path) {
            Ok(info) => Some(info),
            Err(e) => {
                eprintln!("Redirection error: {}", e);
                return;
            }
        }
    } else {
        None
    };

    // Execute the command
    execute_command(command, args);

    // Restore stdout if it was redirected
    if let Some((saved_stdout, file_fd)) = redirect_info {
        restore_stdout(saved_stdout, file_fd);
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

                // Check for output redirection
                let (cmd_part, redirect_file) = if let Some(pos) = input.find('>') {
                    let cmd = input[..pos].trim();
                    let file = input[pos + 1..].trim();
                    (cmd, Some(file))
                } else {
                    (input, None)
                };

                let parts: Vec<&str> = cmd_part.splitn(2, ' ').collect();
                let command = parts[0];
                let args = if parts.len() > 1 { parts[1] } else { "" };

                // Handle output redirection
                let redirect_info = if let Some(file_path) = redirect_file {
                    match redirect_stdout_to_file(file_path) {
                        Ok(info) => Some(info),
                        Err(e) => {
                            eprintln!("Redirection error: {}", e);
                            continue;
                        }
                    }
                } else {
                    None
                };

                // Execute the command
                let should_exit = execute_command(command, args);

                // Restore stdout if it was redirected
                if let Some((saved_stdout, file_fd)) = redirect_info {
                    restore_stdout(saved_stdout, file_fd);
                }

                if should_exit {
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
    // Startup script - one command per line
    let startup_script = r#"
# Mount filesystems
mount proc
ls /

# Load kernel modules
insmod /netfs.ko
insmod /9pnet.ko
insmod /9pnet_virtio.ko
insmod /9p.ko
insmod /nf_defrag_ipv6.ko
insmod /nat46.ko

# Test nat46 module
ls /proc/net
ls /proc/net/nat46
echo add nat46dev > /proc/net/nat46/control

# Setup TAP interfaces
mknod /dev/net/tun c 10 200
tap add tap0
ifconfig tap0 192.168.1.1 netmask 255.255.255.0
ifconfig tap0 2001:db8:1::1/64
ifconfig tap0 up
tap add tap1
ifconfig tap1 2001:db8::1/64
ifconfig tap1 up
ifconfig

# Mount host filesystem
mount 9p
"#;

    // Execute the startup script
    execute_script(startup_script);

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
        use std::path::Path;
        if Path::new("/mnt/host/test-harness/autoexec.run").exists() {
            println!("\nExecuting /mnt/host/test-harness/autoexec.run...");
            execute_command("run", "/mnt/host/test-harness/autoexec.run");
        } else {
            println!("\nNo /mnt/host/test-harness/autoexec.run found, skipping.");
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
