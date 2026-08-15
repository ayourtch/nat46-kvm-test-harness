use std::io::{self, Write};

pub fn main(args: &str) {
    let stdout = io::stdout();
    let stderr = io::stderr();
    run(args, &mut stdout.lock(), &mut stderr.lock());
}

fn run<W: Write, E: Write>(args: &str, output: &mut W, error_output: &mut E) {
    if let Err(error) = write_line(args, output) {
        // A shell command's output failure must not unwind the init process.
        let _ = writeln!(error_output, "echo: write error: {}", error);
    }
}

fn write_line<W: Write>(args: &str, output: &mut W) -> io::Result<()> {
    let mut line = String::with_capacity(args.len() + 1);
    line.push_str(args);
    line.push('\n');

    // Keep the line in one write. Proc control files treat each write as a
    // command, so writing the trailing newline separately would be incorrect.
    output.write_all(line.as_bytes())
}

pub fn help_text() -> &'static str {
    "echo <text>                       - Echo text to output"
}

#[cfg(test)]
mod tests {
    use super::*;

    struct InvalidArgumentWriter;

    impl Write for InvalidArgumentWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writes_the_command_and_newline_together() {
        let mut output = Vec::new();

        write_line("add nat46dev", &mut output).unwrap();

        assert_eq!(output, b"add nat46dev\n");
    }

    #[test]
    fn reports_a_write_error_without_panicking() {
        let mut output = InvalidArgumentWriter;
        let mut error_output = Vec::new();

        run("invalid command", &mut output, &mut error_output);

        assert_eq!(
            String::from_utf8(error_output).unwrap(),
            "echo: write error: Invalid argument (os error 22)\n"
        );
    }
}
