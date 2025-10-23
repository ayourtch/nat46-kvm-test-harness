pub fn main(args: &str) {
    println!("{}", args);
}

pub fn help_text() -> &'static str {
    "echo <text>                       - Echo text to output"
}
