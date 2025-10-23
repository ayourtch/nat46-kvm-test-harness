use std::fs;
use std::io::{self, Read, Write};

pub fn main(args: &str) {
    let args = args.trim();

    if args.is_empty() {
        // No file specified - read from stdin
        cat_stdin();
    } else {
        // Read from file
        cat_file(args);
    }
}

fn cat_stdin() {
    let mut buffer = [0u8; 8192];
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    loop {
        match handle.read(&mut buffer) {
            Ok(0) => break, // EOF
            Ok(n) => {
                if let Err(e) = io::stdout().write_all(&buffer[..n]) {
                    eprintln!("cat: write error: {}", e);
                    break;
                }
            }
            Err(e) => {
                eprintln!("cat: read error: {}", e);
                break;
            }
        }
    }
}

fn cat_file(path: &str) {
    match fs::read_to_string(path) {
        Ok(content) => {
            print!("{}", content);
        }
        Err(e) => {
            eprintln!("cat: {}: {}", path, e);
        }
    }
}

pub fn help_text() -> &'static str {
    "cat [file]                        - Display file contents (or stdin)"
}
