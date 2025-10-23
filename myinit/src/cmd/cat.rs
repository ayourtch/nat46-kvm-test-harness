use std::fs;

pub fn main(args: &str) {
    if args.is_empty() {
        eprintln!("cat: missing file operand");
        eprintln!("Usage: cat <file>");
        return;
    }

    let path = args.trim();

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
    "cat <file>                        - Display file contents"
}
