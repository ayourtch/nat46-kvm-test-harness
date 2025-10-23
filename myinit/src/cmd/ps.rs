use std::fs;

pub fn main(_args: &str) {
    // Read /proc to find all process directories
    println!("{:>5} {:>5} {}", "PID", "PPID", "CMD");

    match fs::read_dir("/proc") {
        Ok(entries) => {
            let mut processes: Vec<(u32, u32, String)> = Vec::new();

            for entry in entries {
                if let Ok(entry) = entry {
                    let file_name = entry.file_name();
                    let file_name_str = file_name.to_string_lossy();

                    // Check if this is a numeric directory (process ID)
                    if let Ok(pid) = file_name_str.parse::<u32>() {
                        // Read /proc/[pid]/stat for process info
                        let stat_path = format!("/proc/{}/stat", pid);
                        if let Ok(stat_content) = fs::read_to_string(&stat_path) {
                            // Parse stat file
                            // Format: pid (comm) state ppid ...
                            let parts: Vec<&str> = stat_content.split_whitespace().collect();

                            if parts.len() >= 4 {
                                // Extract command name (between parentheses)
                                let comm_start = stat_content.find('(');
                                let comm_end = stat_content.rfind(')');

                                let comm = if let (Some(start), Some(end)) = (comm_start, comm_end) {
                                    stat_content[start + 1..end].to_string()
                                } else {
                                    "?".to_string()
                                };

                                // PPID is the 4th field (after the closing parenthesis and state)
                                // Find the position after the command name
                                if let Some(after_comm) = comm_end {
                                    let remaining = &stat_content[after_comm + 1..];
                                    let remaining_parts: Vec<&str> = remaining.split_whitespace().collect();

                                    if remaining_parts.len() >= 2 {
                                        let ppid = remaining_parts[1].parse::<u32>().unwrap_or(0);
                                        processes.push((pid, ppid, comm));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Sort by PID
            processes.sort_by_key(|p| p.0);

            // Display processes
            for (pid, ppid, cmd) in processes {
                println!("{:>5} {:>5} {}", pid, ppid, cmd);
            }
        }
        Err(e) => {
            eprintln!("ps: cannot read /proc: {}", e);
        }
    }
}

pub fn help_text() -> &'static str {
    "ps                                - Display running processes"
}
