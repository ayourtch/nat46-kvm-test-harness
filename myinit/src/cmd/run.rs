use std::fs;

pub fn main(args: &str) {
    let args = args.trim();

    if args.is_empty() {
        print_usage();
        return;
    }

    let script_path = args;

    // Read the script file
    match fs::read_to_string(script_path) {
        Ok(content) => {
            println!("Running script: {}", script_path);
            // Execute the script content using the parent's execute_script function
            // This will be called from main.rs which has access to execute_script
            crate::execute_script(&content);
        }
        Err(e) => {
            eprintln!("Failed to read script file '{}': {}", script_path, e);
        }
    }
}

fn print_usage() {
    eprintln!("Usage: run <script_file>");
    eprintln!("  script_file: path to script file containing commands (one per line)");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  run /mnt/host/scripts/setup.sh");
    eprintln!("  run /tmp/init-script.txt");
    eprintln!();
    eprintln!("Script format:");
    eprintln!("  - One command per line");
    eprintln!("  - Lines starting with # are comments");
    eprintln!("  - Empty lines are ignored");
    eprintln!("  - Supports output redirection (>)");
}

pub fn help_text() -> &'static str {
    "run <script>                      - Run script file (one command per line)"
}
