use std::fs;
use std::io::{self, Write, Read};

pub fn main(args: &str) {
    let filename = args.trim();

    if filename.is_empty() {
        eprintln!("Usage: edit <filename>");
        return;
    }

    if let Err(e) = run_editor(filename) {
        eprintln!("Editor error: {}", e);
    }
}

struct Editor {
    lines: Vec<String>,
    cursor_row: usize,
    cursor_col: usize,
    offset_row: usize,
    offset_col: usize,
    filename: String,
    modified: bool,
    term_rows: usize,
    term_cols: usize,
}

impl Editor {
    fn new(filename: &str) -> io::Result<Self> {
        let content = match fs::read_to_string(filename) {
            Ok(c) => c,
            Err(_) => String::new(), // New file
        };

        let lines: Vec<String> = if content.is_empty() {
            vec![String::new()]
        } else {
            content.lines().map(|s| s.to_string()).collect()
        };

        Ok(Editor {
            lines,
            cursor_row: 0,
            cursor_col: 0,
            offset_row: 0,
            offset_col: 0,
            filename: filename.to_string(),
            modified: false,
            term_rows: 24,
            term_cols: 80,
        })
    }

    fn save(&mut self) -> io::Result<()> {
        let content = self.lines.join("\n");
        fs::write(&self.filename, content)?;
        self.modified = false;
        Ok(())
    }

    fn insert_char(&mut self, ch: char) {
        if self.cursor_row >= self.lines.len() {
            self.lines.push(String::new());
        }

        let line = &mut self.lines[self.cursor_row];
        if self.cursor_col > line.len() {
            self.cursor_col = line.len();
        }

        line.insert(self.cursor_col, ch);
        self.cursor_col += 1;
        self.modified = true;
    }

    fn insert_newline(&mut self) {
        if self.cursor_row >= self.lines.len() {
            self.lines.push(String::new());
            self.cursor_row = self.lines.len() - 1;
            self.cursor_col = 0;
        } else {
            let current_line = &self.lines[self.cursor_row];
            let rest = current_line[self.cursor_col..].to_string();
            self.lines[self.cursor_row].truncate(self.cursor_col);
            self.lines.insert(self.cursor_row + 1, rest);
            self.cursor_row += 1;
            self.cursor_col = 0;
        }
        self.modified = true;
    }

    fn delete_char(&mut self) {
        if self.cursor_row >= self.lines.len() {
            return;
        }

        let line = &mut self.lines[self.cursor_row];

        if self.cursor_col > 0 && self.cursor_col <= line.len() {
            line.remove(self.cursor_col - 1);
            self.cursor_col -= 1;
            self.modified = true;
        } else if self.cursor_col == 0 && self.cursor_row > 0 {
            // Join with previous line
            let current_line = self.lines.remove(self.cursor_row);
            self.cursor_row -= 1;
            self.cursor_col = self.lines[self.cursor_row].len();
            self.lines[self.cursor_row].push_str(&current_line);
            self.modified = true;
        }
    }

    fn delete_char_forward(&mut self) {
        if self.cursor_row >= self.lines.len() {
            return;
        }

        let line = &mut self.lines[self.cursor_row];

        if self.cursor_col < line.len() {
            line.remove(self.cursor_col);
            self.modified = true;
        } else if self.cursor_row < self.lines.len() - 1 {
            // Join with next line
            let next_line = self.lines.remove(self.cursor_row + 1);
            self.lines[self.cursor_row].push_str(&next_line);
            self.modified = true;
        }
    }

    fn kill_line(&mut self) {
        // Kill from cursor to end of line (Ctrl-K)
        if self.cursor_row >= self.lines.len() {
            return;
        }

        let line = &mut self.lines[self.cursor_row];

        if self.cursor_col < line.len() {
            // Delete from cursor to end of line
            line.truncate(self.cursor_col);
            self.modified = true;
        } else if self.cursor_row < self.lines.len() - 1 {
            // At end of line - join with next line (like Ctrl-K in nano)
            let next_line = self.lines.remove(self.cursor_row + 1);
            self.lines[self.cursor_row].push_str(&next_line);
            self.modified = true;
        }
    }

    fn move_to_line_start(&mut self) {
        self.cursor_col = 0;

        // Adjust scroll if needed
        if self.cursor_col < self.offset_col {
            self.offset_col = 0;
        }
    }

    fn move_to_line_end(&mut self) {
        let line_len = self.lines.get(self.cursor_row).map(|l| l.len()).unwrap_or(0);
        self.cursor_col = line_len;

        // Adjust scroll if needed
        if self.cursor_col >= self.offset_col + self.term_cols {
            self.offset_col = self.cursor_col.saturating_sub(self.term_cols - 1);
        }
    }

    fn move_cursor(&mut self, key: char) {
        match key {
            'A' => { // Up
                if self.cursor_row > 0 {
                    self.cursor_row -= 1;
                    let line_len = self.lines.get(self.cursor_row).map(|l| l.len()).unwrap_or(0);
                    if self.cursor_col > line_len {
                        self.cursor_col = line_len;
                    }
                }
            }
            'B' => { // Down
                if self.cursor_row < self.lines.len() - 1 {
                    self.cursor_row += 1;
                    let line_len = self.lines.get(self.cursor_row).map(|l| l.len()).unwrap_or(0);
                    if self.cursor_col > line_len {
                        self.cursor_col = line_len;
                    }
                }
            }
            'C' => { // Right
                let line_len = self.lines.get(self.cursor_row).map(|l| l.len()).unwrap_or(0);
                if self.cursor_col < line_len {
                    self.cursor_col += 1;
                } else if self.cursor_row < self.lines.len() - 1 {
                    self.cursor_row += 1;
                    self.cursor_col = 0;
                }
            }
            'D' => { // Left
                if self.cursor_col > 0 {
                    self.cursor_col -= 1;
                } else if self.cursor_row > 0 {
                    self.cursor_row -= 1;
                    self.cursor_col = self.lines.get(self.cursor_row).map(|l| l.len()).unwrap_or(0);
                }
            }
            _ => {}
        }

        // Adjust scroll
        if self.cursor_row < self.offset_row {
            self.offset_row = self.cursor_row;
        }
        if self.cursor_row >= self.offset_row + self.term_rows - 2 {
            self.offset_row = self.cursor_row - (self.term_rows - 3);
        }
        if self.cursor_col < self.offset_col {
            self.offset_col = self.cursor_col;
        }
        if self.cursor_col >= self.offset_col + self.term_cols {
            self.offset_col = self.cursor_col - self.term_cols + 1;
        }
    }

    fn refresh_screen(&self) {
        print!("\x1b[?25l"); // Hide cursor
        print!("\x1b[H"); // Move to home

        // Draw status line at top
        print!("\x1b[7m"); // Reverse video
        let status = format!(
            " {} {} | Line {}/{} Col {} ",
            self.filename,
            if self.modified { "[+]" } else { "" },
            self.cursor_row + 1,
            self.lines.len(),
            self.cursor_col + 1
        );
        print!("{:width$}", status, width = self.term_cols);
        print!("\x1b[0m\r\n"); // Reset

        // Draw content lines
        for row in 0..(self.term_rows - 2) {
            print!("\x1b[2K"); // Clear line
            let file_row = row + self.offset_row;

            if file_row < self.lines.len() {
                let line = &self.lines[file_row];
                let start = self.offset_col.min(line.len());
                let end = (self.offset_col + self.term_cols).min(line.len());
                if start < line.len() {
                    print!("{}", &line[start..end]);
                }
            } else {
                print!("~");
            }
            print!("\r\n");
        }

        // Draw help line at bottom
        print!("\x1b[7m"); // Reverse video
        let help = " ^S Save | ^Q Quit | ^X Exit | ^A Home | ^E End | ^K Cut ";
        print!("{:width$}", help, width = self.term_cols);
        print!("\x1b[0m");

        // Position cursor
        let screen_row = self.cursor_row - self.offset_row + 2; // +2 for status line
        let screen_col = self.cursor_col - self.offset_col + 1; // +1 for 1-based
        print!("\x1b[{};{}H", screen_row, screen_col);

        print!("\x1b[?25h"); // Show cursor
        io::stdout().flush().unwrap();
    }
}

fn run_editor(filename: &str) -> io::Result<()> {
    let mut editor = Editor::new(filename)?;

    // Set terminal to raw mode
    set_raw_mode(true)?;

    // Clear screen
    print!("\x1b[2J\x1b[H");
    io::stdout().flush()?;

    editor.refresh_screen();

    let mut stdin = io::stdin();
    let mut buf = [0u8; 1];

    loop {
        stdin.read_exact(&mut buf)?;
        let ch = buf[0];

        match ch {
            // Ctrl+A - Move to beginning of line
            1 => {
                editor.move_to_line_start();
            }
            // Ctrl+E - Move to end of line
            5 => {
                editor.move_to_line_end();
            }
            // Ctrl+K - Kill to end of line
            11 => {
                editor.kill_line();
            }
            // Ctrl+Q - Quit
            17 => {
                if editor.modified {
                    // Show warning
                    print!("\x1b[{};1H\x1b[2K", editor.term_rows);
                    print!("File modified! Press Ctrl+Q again to quit without saving, or Ctrl+S to save");
                    io::stdout().flush()?;

                    stdin.read_exact(&mut buf)?;
                    if buf[0] == 17 {
                        break;
                    } else if buf[0] == 19 {
                        if let Err(e) = editor.save() {
                            print!("\x1b[{};1H\x1b[2K", editor.term_rows);
                            print!("Error saving: {}", e);
                            io::stdout().flush()?;
                            std::thread::sleep(std::time::Duration::from_secs(2));
                        } else {
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
            // Ctrl+S - Save
            19 => {
                if let Err(e) = editor.save() {
                    print!("\x1b[{};1H\x1b[2K", editor.term_rows);
                    print!("Error saving: {}", e);
                    io::stdout().flush()?;
                    std::thread::sleep(std::time::Duration::from_secs(2));
                } else {
                    print!("\x1b[{};1H\x1b[2K", editor.term_rows);
                    print!("File saved!");
                    io::stdout().flush()?;
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
            // Ctrl+X - Exit (with save)
            24 => {
                if editor.modified {
                    if let Err(e) = editor.save() {
                        print!("\x1b[{};1H\x1b[2K", editor.term_rows);
                        print!("Error saving: {}", e);
                        io::stdout().flush()?;
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        continue;
                    }
                }
                break;
            }
            // Enter
            13 | 10 => {
                editor.insert_newline();
            }
            // Backspace
            127 | 8 => {
                editor.delete_char();
            }
            // Delete (some terminals send escape sequence)
            // Escape sequences
            27 => {
                // Read next char
                let mut seq = [0u8; 2];
                if stdin.read(&mut seq[0..1]).is_ok() {
                    if seq[0] == b'[' {
                        if stdin.read(&mut seq[1..2]).is_ok() {
                            match seq[1] {
                                b'A' | b'B' | b'C' | b'D' => {
                                    editor.move_cursor(seq[1] as char);
                                }
                                b'3' => {
                                    // Delete key sends ESC[3~
                                    let mut tilde = [0u8; 1];
                                    if stdin.read(&mut tilde).is_ok() && tilde[0] == b'~' {
                                        editor.delete_char_forward();
                                    }
                                }
                                b'H' => {
                                    // Home
                                    editor.cursor_col = 0;
                                }
                                b'F' => {
                                    // End
                                    let line_len = editor.lines.get(editor.cursor_row).map(|l| l.len()).unwrap_or(0);
                                    editor.cursor_col = line_len;
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            // Regular characters
            32..=126 => {
                editor.insert_char(ch as char);
            }
            // Tab
            9 => {
                editor.insert_char(' ');
                editor.insert_char(' ');
                editor.insert_char(' ');
                editor.insert_char(' ');
            }
            _ => {
                // Ignore other control characters
            }
        }

        editor.refresh_screen();
    }

    // Restore terminal
    set_raw_mode(false)?;
    print!("\x1b[2J\x1b[H");
    io::stdout().flush()?;

    Ok(())
}

fn set_raw_mode(enable: bool) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let stdin_fd = io::stdin().as_raw_fd();

    if enable {
        // Get current settings
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(stdin_fd, &mut termios) } != 0 {
            return Err(io::Error::last_os_error());
        }

        // Save original settings (we'll restore in disable)
        // Modify for raw mode
        termios.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG | libc::IEXTEN);
        termios.c_iflag &= !(libc::IXON | libc::ICRNL | libc::BRKINT | libc::INPCK | libc::ISTRIP);
        termios.c_oflag &= !(libc::OPOST);
        termios.c_cflag |= libc::CS8;
        termios.c_cc[libc::VMIN] = 1;
        termios.c_cc[libc::VTIME] = 0;

        if unsafe { libc::tcsetattr(stdin_fd, libc::TCSAFLUSH, &termios) } != 0 {
            return Err(io::Error::last_os_error());
        }
    } else {
        // Restore to sane defaults
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(stdin_fd, &mut termios) } != 0 {
            return Err(io::Error::last_os_error());
        }

        termios.c_lflag |= libc::ECHO | libc::ICANON;
        termios.c_iflag |= libc::ICRNL;
        termios.c_oflag |= libc::OPOST;

        if unsafe { libc::tcsetattr(stdin_fd, libc::TCSAFLUSH, &termios) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

pub fn help_text() -> &'static str {
    "edit <file>                       - Edit file with simple VT100 editor"
}
