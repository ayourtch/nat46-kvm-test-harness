use std::fs;
use std::io::{self, Write, Read};
use oside::*;
use oside::protocols::all::*;

pub fn main(args: &str) {
    let filename = args.trim();

    if filename.is_empty() {
        eprintln!("Usage: oside <jsonl-file>");
        return;
    }

    if let Err(e) = run_editor(filename) {
        eprintln!("Editor error: {}", e);
    }
}

#[derive(Clone)]
struct PacketEntry {
    timestamp_us: u128,
    layers: Vec<Box<dyn Layer>>,
}

struct Editor {
    packets: Vec<PacketEntry>,
    current_packet: usize,
    current_layer: isize,  // -1 = timestamp, 0+ = layer index
    current_field: usize,
    filename: String,
    modified: bool,
    mode: EditorMode,
    edit_buffer: String,
    edit_cursor: usize,  // Cursor position within edit_buffer
    message: String,
}

#[derive(PartialEq)]
enum EditorMode {
    Navigation,
    Editing,
}

impl Editor {
    fn new(filename: &str) -> io::Result<Self> {
        let content = fs::read_to_string(filename)?;
        let mut packets = Vec::new();

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let json: serde_json::Value = match serde_json::from_str(line) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("Warning: Failed to parse line: {}", e);
                    continue;
                }
            };

            let timestamp_us = json.get("timestamp_us")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u128;

            let layers: Vec<Box<dyn Layer>> = if let Some(layers_val) = json.get("layers") {
                match serde_json::from_value(layers_val.clone()) {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("Warning: Failed to parse layers: {}", e);
                        continue;
                    }
                }
            } else {
                continue;
            };

            packets.push(PacketEntry { timestamp_us, layers });
        }

        if packets.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "No valid packets found"));
        }

        Ok(Editor {
            packets,
            current_packet: 0,
            current_layer: -1,  // Start at timestamp
            current_field: 0,
            filename: filename.to_string(),
            modified: false,
            mode: EditorMode::Navigation,
            edit_buffer: String::new(),
            edit_cursor: 0,
            message: String::new(),
        })
    }

    fn save(&mut self) -> io::Result<()> {
        let mut lines = Vec::new();

        for packet in &self.packets {
            let stack = LayerStack {
                filled: true,
                layers: packet.layers.clone(),
            };
            let layers_json = serde_json::to_string(&stack.layers)?;
            let line = format!(r#"{{"timestamp_us":{},"layers":{}}}"#, packet.timestamp_us, layers_json);
            lines.push(line);
        }

        fs::write(&self.filename, lines.join("\n"))?;
        self.modified = false;
        self.message = "Saved!".to_string();
        Ok(())
    }

    fn get_layer_summary(&self, layer: &Box<dyn Layer>) -> String {
        let type_name = layer.typetag_name();

        // Try to get some key info based on layer type
        let json = serde_json::to_value(layer).unwrap_or(serde_json::Value::Null);

        match type_name {
            "ether" => {
                format!("Ether {} -> {}",
                    json.get("src").and_then(|v| v.as_str()).unwrap_or("?"),
                    json.get("dst").and_then(|v| v.as_str()).unwrap_or("?"))
            }
            "Ip" => {
                format!("IPv4 {} -> {}",
                    json.get("src").and_then(|v| v.as_str()).unwrap_or("?"),
                    json.get("dst").and_then(|v| v.as_str()).unwrap_or("?"))
            }
            "IPV6" => {
                format!("IPv6 {} -> {}",
                    json.get("src").and_then(|v| v.as_str()).unwrap_or("?"),
                    json.get("dst").and_then(|v| v.as_str()).unwrap_or("?"))
            }
            "Tcp" => {
                format!("TCP {} -> {}",
                    json.get("sport").and_then(|v| v.as_u64()).unwrap_or(0),
                    json.get("dport").and_then(|v| v.as_u64()).unwrap_or(0))
            }
            "Udp" => {
                format!("UDP {} -> {}",
                    json.get("sport").and_then(|v| v.as_u64()).unwrap_or(0),
                    json.get("dport").and_then(|v| v.as_u64()).unwrap_or(0))
            }
            _ => type_name.to_string(),
        }
    }

    fn get_layer_fields(&self, layer: &Box<dyn Layer>) -> Vec<(String, String)> {
        let json = serde_json::to_value(layer).unwrap_or(serde_json::Value::Null);
        let mut fields = Vec::new();

        if let Some(obj) = json.as_object() {
            for (key, value) in obj {
                if key == "layertype" {
                    continue;
                }
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                        // Use proper JSON serialization for complex types
                        serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
                    },
                    serde_json::Value::Null => "null".to_string(),
                };
                fields.push((key.clone(), value_str));
            }
        }

        fields
    }

    fn refresh_screen(&self) {
        print!("\x1b[?25l"); // Hide cursor

        let packet = &self.packets[self.current_packet];

        // Title bar at line 1
        print!("\x1b[1;1H\x1b[7m");
        let title = format!(
            " {} {} | Packet {}/{} {} ",
            self.filename,
            if self.modified { "[+]" } else { "" },
            self.current_packet + 1,
            self.packets.len(),
            if self.mode == EditorMode::Editing { "[EDIT]" } else { "" }
        );
        print!("{:width$}\x1b[0m", title, width = 80);

        // Clear content area (lines 2-23)
        for line in 2..24 {
            print!("\x1b[{};1H\x1b[2K", line);
        }

        let mut current_line = 2;
        let mut edit_cursor_row = 0;
        let mut edit_cursor_col = 0;

        // Timestamp (editable) - layer -1
        let ts_marker = if self.current_layer == -1 && self.mode == EditorMode::Navigation {
            ">"
        } else if self.current_layer == -1 && self.mode == EditorMode::Editing {
            "*"
        } else {
            " "
        };

        if self.current_layer == -1 && self.mode == EditorMode::Editing {
            print!("\x1b[{};1H{} timestamp_us: [{}]", current_line, ts_marker, self.edit_buffer);
            edit_cursor_row = current_line;
            edit_cursor_col = 1 + 1 + "timestamp_us".len() + 3 + self.edit_cursor + 1;
        } else {
            print!("\x1b[{};1H{} timestamp_us: {}", current_line, ts_marker, packet.timestamp_us);
        }
        current_line += 2;

        // Layers
        print!("\x1b[{};1H=== Layers ===", current_line);
        current_line += 1;

        for (idx, layer) in packet.layers.iter().enumerate() {
            if current_line >= 23 {
                break;
            }
            let marker = if self.current_layer >= 0 && idx == (self.current_layer as usize) { ">" } else { " " };
            let summary = self.get_layer_summary(layer);
            print!("\x1b[{};1H{} [{}] {}", current_line, marker, idx, summary);
            current_line += 1;
        }

        current_line += 1;

        // Current layer fields
        if self.current_layer >= 0 && (self.current_layer as usize) < packet.layers.len() && current_line < 23 {
            print!("\x1b[{};1H=== Layer {} Fields ===", current_line, self.current_layer);
            current_line += 1;

            let fields = self.get_layer_fields(&packet.layers[self.current_layer as usize]);

            for (idx, (key, value)) in fields.iter().enumerate() {
                if current_line >= 23 {
                    break;
                }

                let marker = if idx == self.current_field && self.mode == EditorMode::Navigation {
                    ">"
                } else if idx == self.current_field && self.mode == EditorMode::Editing {
                    "*"
                } else {
                    " "
                };

                if idx == self.current_field && self.mode == EditorMode::Editing {
                    // Show edit buffer with actual cursor
                    print!("\x1b[{};1H{} {}: [{}]", current_line, marker, key, self.edit_buffer);

                    // Calculate cursor position
                    edit_cursor_row = current_line;
                    // Column = marker(1) + space(1) + key + ": [" (3) + cursor_pos + 1 (1-indexed)
                    edit_cursor_col = 1 + 1 + key.len() + 3 + self.edit_cursor + 1;
                } else {
                    print!("\x1b[{};1H{} {}: {}", current_line, marker, key, value);
                }
                current_line += 1;
            }
        }

        // Message line at line 24
        print!("\x1b[24;1H\x1b[2K{}", self.message);

        // Help bar at line 25
        print!("\x1b[25;1H\x1b[7m");
        let help = if self.mode == EditorMode::Navigation {
            " n/p:Pkt | e:Edit | a:Add | r:Rem | f:CalcAuto | d:Del | c:Copy | s:Save | q:Quit "
        } else {
            " Arrows:Move | Del/Bksp | ^A/E:Home/End | ^K/U:Kill | Enter:Save | Esc:Cancel "
        };
        print!("{:width$}\x1b[0m", help, width = 80);

        // Position cursor for editing
        if self.mode == EditorMode::Editing {
            print!("\x1b[{};{}H", edit_cursor_row, edit_cursor_col);
        }

        print!("\x1b[?25h"); // Show cursor
        io::stdout().flush().unwrap();
    }

    fn start_editing(&mut self) {
        // Check if we're on the timestamp field (layer -1)
        if self.current_layer == -1 {
            self.edit_buffer = self.packets[self.current_packet].timestamp_us.to_string();
            self.edit_cursor = self.edit_buffer.len();
            self.mode = EditorMode::Editing;
            return;
        }

        if self.current_layer < 0 || (self.current_layer as usize) >= self.packets[self.current_packet].layers.len() {
            return;
        }

        let fields = self.get_layer_fields(&self.packets[self.current_packet].layers[self.current_layer as usize]);

        if self.current_field >= fields.len() {
            return;
        }

        self.edit_buffer = fields[self.current_field].1.clone();
        self.edit_cursor = self.edit_buffer.len();  // Start at end
        self.mode = EditorMode::Editing;
    }

    fn save_edit(&mut self) -> Result<(), String> {
        // Handle timestamp editing (layer -1)
        if self.current_layer == -1 {
            let new_timestamp = self.edit_buffer.parse::<u128>()
                .map_err(|_| "Invalid timestamp value".to_string())?;
            self.packets[self.current_packet].timestamp_us = new_timestamp;
            self.modified = true;
            self.mode = EditorMode::Navigation;
            self.message = "Timestamp updated".to_string();
            return Ok(());
        }

        if self.current_layer < 0 || (self.current_layer as usize) >= self.packets[self.current_packet].layers.len() {
            return Err("Invalid layer".to_string());
        }

        let fields = self.get_layer_fields(&self.packets[self.current_packet].layers[self.current_layer as usize]);

        if self.current_field >= fields.len() {
            return Err("Invalid field".to_string());
        }

        let field_name = &fields[self.current_field].0;
        let new_value = &self.edit_buffer;

        // Get the layer as JSON
        let mut json = serde_json::to_value(&self.packets[self.current_packet].layers[self.current_layer as usize])
            .map_err(|e| format!("Serialization error: {}", e))?;

        // Update the field
        if let Some(obj) = json.as_object_mut() {
            // Get original value to determine type
            let original_value = obj.get(field_name);

            let new_val = if new_value.starts_with('[') || new_value.starts_with('{') {
                // Try to parse as JSON for arrays/objects
                serde_json::from_str(new_value)
                    .unwrap_or_else(|_| serde_json::Value::String(new_value.clone()))
            } else if let Ok(n) = new_value.parse::<i64>() {
                serde_json::Value::Number(n.into())
            } else if let Ok(n) = new_value.parse::<f64>() {
                serde_json::Number::from_f64(n)
                    .map(serde_json::Value::Number)
                    .unwrap_or_else(|| serde_json::Value::String(new_value.clone()))
            } else if new_value == "true" || new_value == "false" {
                serde_json::Value::Bool(new_value == "true")
            } else if new_value == "null" {
                serde_json::Value::Null
            } else if new_value.starts_with('"') && new_value.ends_with('"') {
                // Quoted string - remove quotes
                let unquoted = &new_value[1..new_value.len()-1];
                serde_json::Value::String(unquoted.to_string())
            } else {
                // Keep original type structure if possible
                match original_value {
                    Some(serde_json::Value::Number(_)) => {
                        // Try harder to parse as number
                        if let Ok(n) = new_value.parse::<i64>() {
                            serde_json::Value::Number(n.into())
                        } else {
                            serde_json::Value::String(new_value.clone())
                        }
                    }
                    _ => serde_json::Value::String(new_value.clone())
                }
            };

            obj.insert(field_name.clone(), new_val);
        }

        // Deserialize back to layer
        let new_layer: Box<dyn Layer> = serde_json::from_value(json)
            .map_err(|e| format!("Deserialization error: {}", e))?;

        self.packets[self.current_packet].layers[self.current_layer as usize] = new_layer;
        self.modified = true;
        self.mode = EditorMode::Navigation;
        self.message = "Field updated".to_string();

        Ok(())
    }

    fn delete_packet(&mut self) {
        if self.packets.len() > 1 {
            self.packets.remove(self.current_packet);
            if self.current_packet >= self.packets.len() {
                self.current_packet = self.packets.len() - 1;
            }
            self.modified = true;
            self.message = "Packet deleted".to_string();
        } else {
            self.message = "Cannot delete last packet".to_string();
        }
    }

    fn copy_packet(&mut self) {
        let copy = self.packets[self.current_packet].clone();
        self.packets.insert(self.current_packet + 1, copy);
        self.current_packet += 1;
        self.modified = true;
        self.message = "Packet copied".to_string();
    }

    fn remove_layer(&mut self) {
        if self.current_layer < 0 {
            self.message = "Cannot remove timestamp".to_string();
            return;
        }

        let packet = &mut self.packets[self.current_packet];

        if packet.layers.len() <= 1 {
            self.message = "Cannot remove last layer".to_string();
            return;
        }

        if (self.current_layer as usize) < packet.layers.len() {
            packet.layers.remove(self.current_layer as usize);
            if (self.current_layer as usize) >= packet.layers.len() && self.current_layer > 0 {
                self.current_layer -= 1;
            }
            self.current_field = 0;
            self.modified = true;
            self.message = "Layer removed".to_string();
        }
    }

    fn add_layer(&mut self, layer_type: &str) -> Result<(), String> {
        let new_layer: Box<dyn Layer> = match layer_type {
            "ether" => Box::new(Ether!()),
            "ip" => Box::new(IP!()),
            "ipv6" => Box::new(IPV6!()),
            "tcp" => Box::new(TCP!()),
            "udp" => Box::new(UDP!()),
            "icmp" => Box::new(ICMP!()),
            "arp" => Box::new(ARP!()),
            "raw" => Box::new(Raw!("".into())),
            _ => return Err(format!("Unknown layer type: {}", layer_type)),
        };

        let packet = &mut self.packets[self.current_packet];

        // If at timestamp (-1), insert at position 0
        // If at a layer, insert after current layer
        let insert_pos = if self.current_layer < 0 {
            0
        } else {
            (self.current_layer as usize) + 1
        };

        packet.layers.insert(insert_pos, new_layer);
        self.current_layer = insert_pos as isize;
        self.current_field = 0;
        self.modified = true;
        self.message = format!("Added {} layer", layer_type);

        Ok(())
    }

    fn recalculate_auto_fields(&mut self) -> Result<(), String> {
        let packet = &mut self.packets[self.current_packet];

        // Create a LayerStack with filled=false to trigger auto field calculation
        let stack = LayerStack {
            filled: false,
            layers: packet.layers.clone(),
        };

        // Encode the packet - this actually calculates checksums, lengths, etc.
        let encoded = stack.lencode();

        // Decode it back to get the filled layers
        // Start with the first layer's decoder
        if packet.layers.is_empty() {
            return Err("No layers to recalculate".to_string());
        }

        // Use Ether as the starting decoder (most common case)
        let decoded = Ether!().ldecode(&encoded)
            .ok_or("Failed to decode packet".to_string())?;

        // Update packet with recalculated layers
        packet.layers = decoded.0.layers;
        self.modified = true;
        self.message = "Auto fields recalculated (checksums, lengths, etc.)".to_string();

        Ok(())
    }
}

fn show_layer_menu(stdin: &mut io::Stdin) -> Option<String> {
    // Show layer selection menu
    print!("\x1b[10;20H\x1b[7m                                        \x1b[0m");
    print!("\x1b[11;20H\x1b[7m  Select Layer Type:                   \x1b[0m");
    print!("\x1b[12;20H\x1b[7m                                        \x1b[0m");
    print!("\x1b[13;20H  1. Ethernet (ether)                    ");
    print!("\x1b[14;20H  2. IPv4 (ip)                           ");
    print!("\x1b[15;20H  3. IPv6 (ipv6)                         ");
    print!("\x1b[16;20H  4. TCP                                 ");
    print!("\x1b[17;20H  5. UDP                                 ");
    print!("\x1b[18;20H  6. ICMP                                ");
    print!("\x1b[19;20H  7. ARP                                 ");
    print!("\x1b[20;20H  8. Raw                                 ");
    print!("\x1b[21;20H\x1b[7m  Esc to cancel                        \x1b[0m");
    io::stdout().flush().unwrap();

    let mut buf = [0u8; 1];
    loop {
        if stdin.read_exact(&mut buf).is_ok() {
            match buf[0] {
                b'1' => return Some("ether".to_string()),
                b'2' => return Some("ip".to_string()),
                b'3' => return Some("ipv6".to_string()),
                b'4' => return Some("tcp".to_string()),
                b'5' => return Some("udp".to_string()),
                b'6' => return Some("icmp".to_string()),
                b'7' => return Some("arp".to_string()),
                b'8' => return Some("raw".to_string()),
                27 => return None, // Esc
                _ => continue,
            }
        }
    }
}

fn run_editor(filename: &str) -> io::Result<()> {
    let mut editor = Editor::new(filename)?;

    // Set terminal to raw mode
    set_raw_mode(true)?;

    print!("\x1b[2J\x1b[H");
    io::stdout().flush()?;

    editor.refresh_screen();

    let mut stdin = io::stdin();
    let mut buf = [0u8; 1];

    loop {
        stdin.read_exact(&mut buf)?;
        let ch = buf[0];

        editor.message.clear();

        match editor.mode {
            EditorMode::Navigation => {
                match ch {
                    // q - Quit
                    b'q' => {
                        if editor.modified {
                            editor.message = "Unsaved changes! Press 's' to save, 'Q' to quit anyway".to_string();
                            editor.refresh_screen();
                            stdin.read_exact(&mut buf)?;
                            if buf[0] == b'Q' {
                                break;
                            } else if buf[0] == b's' {
                                let _ = editor.save();
                                break;
                            }
                            continue;
                        }
                        break;
                    }
                    // s - Save
                    b's' => {
                        if let Err(e) = editor.save() {
                            editor.message = format!("Save error: {}", e);
                        }
                    }
                    // n - Next packet
                    b'n' => {
                        if editor.current_packet < editor.packets.len() - 1 {
                            editor.current_packet += 1;
                            editor.current_layer = 0;
                            editor.current_field = 0;
                        }
                    }
                    // p - Previous packet
                    b'p' => {
                        if editor.current_packet > 0 {
                            editor.current_packet -= 1;
                            editor.current_layer = 0;
                            editor.current_field = 0;
                        }
                    }
                    // e - Edit current field
                    b'e' => {
                        editor.start_editing();
                    }
                    // d - Delete packet
                    b'd' => {
                        editor.delete_packet();
                    }
                    // c - Copy packet
                    b'c' => {
                        editor.copy_packet();
                    }
                    // r - Remove layer
                    b'r' => {
                        editor.remove_layer();
                    }
                    // a - Add layer
                    b'a' => {
                        if let Some(layer_type) = show_layer_menu(&mut stdin) {
                            if let Err(e) = editor.add_layer(&layer_type) {
                                editor.message = format!("Error: {}", e);
                            }
                        } else {
                            editor.message = "Cancelled".to_string();
                        }
                    }
                    // f - Fill/recalculate auto fields
                    b'f' => {
                        if let Err(e) = editor.recalculate_auto_fields() {
                            editor.message = format!("Error: {}", e);
                        }
                    }
                    // Arrow keys
                    27 => {
                        let mut seq = [0u8; 2];
                        if stdin.read(&mut seq[0..1]).is_ok() && seq[0] == b'[' {
                            if stdin.read(&mut seq[1..2]).is_ok() {
                                match seq[1] {
                                    b'A' => { // Up
                                        if editor.current_layer == -1 {
                                            // Already at timestamp, can't go up
                                        } else if editor.current_field > 0 {
                                            editor.current_field -= 1;
                                        } else if editor.current_layer > 0 {
                                            editor.current_layer -= 1;
                                            let fields = editor.get_layer_fields(
                                                &editor.packets[editor.current_packet].layers[editor.current_layer as usize]
                                            );
                                            editor.current_field = fields.len().saturating_sub(1);
                                        } else {
                                            // current_layer == 0, current_field == 0, go to timestamp
                                            editor.current_layer = -1;
                                            editor.current_field = 0;
                                        }
                                    }
                                    b'B' => { // Down
                                        let packet = &editor.packets[editor.current_packet];
                                        if editor.current_layer == -1 {
                                            // At timestamp, go to layer 0 first field
                                            if !packet.layers.is_empty() {
                                                editor.current_layer = 0;
                                                editor.current_field = 0;
                                            }
                                        } else if (editor.current_layer as usize) < packet.layers.len() {
                                            let fields = editor.get_layer_fields(&packet.layers[editor.current_layer as usize]);
                                            if editor.current_field < fields.len() - 1 {
                                                editor.current_field += 1;
                                            } else if (editor.current_layer as usize) < packet.layers.len() - 1 {
                                                editor.current_layer += 1;
                                                editor.current_field = 0;
                                            }
                                        }
                                    }
                                    b'C' => { // Right - next layer
                                        let packet = &editor.packets[editor.current_packet];
                                        if editor.current_layer >= 0 && (editor.current_layer as usize) < packet.layers.len() - 1 {
                                            editor.current_layer += 1;
                                            editor.current_field = 0;
                                        }
                                    }
                                    b'D' => { // Left - prev layer
                                        if editor.current_layer > 0 {
                                            editor.current_layer -= 1;
                                            editor.current_field = 0;
                                        } else if editor.current_layer == 0 {
                                            editor.current_layer = -1;
                                            editor.current_field = 0;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            EditorMode::Editing => {
                match ch {
                    // Enter - Save edit
                    13 | 10 => {
                        if let Err(e) = editor.save_edit() {
                            editor.message = format!("Error: {}", e);
                            editor.mode = EditorMode::Navigation;
                        }
                    }
                    // Escape sequence (arrow keys, delete, home, end)
                    27 => {
                        let mut seq = [0u8; 2];
                        if stdin.read(&mut seq[0..1]).is_ok() && seq[0] == b'[' {
                            if stdin.read(&mut seq[1..2]).is_ok() {
                                match seq[1] {
                                    b'C' => { // Right arrow
                                        if editor.edit_cursor < editor.edit_buffer.len() {
                                            editor.edit_cursor += 1;
                                        }
                                    }
                                    b'D' => { // Left arrow
                                        if editor.edit_cursor > 0 {
                                            editor.edit_cursor -= 1;
                                        }
                                    }
                                    b'H' => { // Home
                                        editor.edit_cursor = 0;
                                    }
                                    b'F' => { // End
                                        editor.edit_cursor = editor.edit_buffer.len();
                                    }
                                    b'3' => { // Delete key (ESC[3~)
                                        let mut tilde = [0u8; 1];
                                        if stdin.read(&mut tilde).is_ok() && tilde[0] == b'~' {
                                            if editor.edit_cursor < editor.edit_buffer.len() {
                                                editor.edit_buffer.remove(editor.edit_cursor);
                                            }
                                        }
                                    }
                                    _ => {
                                        // If not a recognized sequence, treat as ESC (cancel)
                                        editor.mode = EditorMode::Navigation;
                                        editor.message = "Edit cancelled".to_string();
                                    }
                                }
                            } else {
                                // ESC without complete sequence - cancel
                                editor.mode = EditorMode::Navigation;
                                editor.message = "Edit cancelled".to_string();
                            }
                        } else {
                            // ESC alone - cancel
                            editor.mode = EditorMode::Navigation;
                            editor.message = "Edit cancelled".to_string();
                        }
                    }
                    // Backspace - delete before cursor
                    127 | 8 => {
                        if editor.edit_cursor > 0 {
                            editor.edit_cursor -= 1;
                            editor.edit_buffer.remove(editor.edit_cursor);
                        }
                    }
                    // Ctrl+A - move to start
                    1 => {
                        editor.edit_cursor = 0;
                    }
                    // Ctrl+E - move to end
                    5 => {
                        editor.edit_cursor = editor.edit_buffer.len();
                    }
                    // Ctrl+K - kill to end of line
                    11 => {
                        editor.edit_buffer.truncate(editor.edit_cursor);
                    }
                    // Ctrl+U - kill to start of line
                    21 => {
                        editor.edit_buffer.drain(..editor.edit_cursor);
                        editor.edit_cursor = 0;
                    }
                    // Regular characters - insert at cursor
                    32..=126 => {
                        editor.edit_buffer.insert(editor.edit_cursor, ch as char);
                        editor.edit_cursor += 1;
                    }
                    _ => {}
                }
            }
        }

        editor.refresh_screen();
    }

    set_raw_mode(false)?;
    print!("\x1b[2J\x1b[H");
    io::stdout().flush()?;

    Ok(())
}

fn set_raw_mode(enable: bool) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let stdin_fd = io::stdin().as_raw_fd();

    if enable {
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(stdin_fd, &mut termios) } != 0 {
            return Err(io::Error::last_os_error());
        }

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
    "oside <file>                      - Edit oside JSONL packets interactively"
}
