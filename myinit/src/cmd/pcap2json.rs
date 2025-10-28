use oside::protocols::all::*;
use oside::protocols::pcap_file::*;
use oside::*;

pub fn main(args: &str) {
    let parts: Vec<&str> = args.trim().split_whitespace().collect();

    if parts.len() != 2 {
        eprintln!("Usage: pcap2json <input.pcap> <output.jsonl>");
        eprintln!("  Converts PCAP file to JSONL format (oside layers with timestamps)");
        return;
    }

    let input_file = parts[0];
    let output_file = parts[1];

    // Read input PCAP file
    let bytes = match read_file(input_file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading file {}: {}", input_file, e);
            return;
        }
    };

    // Parse PCAP file
    let binding = match PcapFile!().ldecode(&bytes) {
        Some(b) => b,
        None => {
            eprintln!("Error: Failed to parse PCAP file");
            return;
        }
    };

    let pcap = match binding.0.get_layer(PcapFile!()) {
        Some(p) => p,
        None => {
            eprintln!("Error: No PCAP layer found");
            return;
        }
    };

    // Convert packets to JSONL format (one JSON object per line)
    let mut jsonl_lines = Vec::new();
    let mut packet_count = 0;

    for p in &pcap.d.packets {
        let pkt = match pcap.d.network.value() {
            1 => Ether!().ldecode(&p.data).unwrap().0,  // Ethernet
            x => {
                eprintln!("Warning: Network type {} not fully supported, treating as raw", x);
                // For unsupported types, try Ethernet anyway
                match Ether!().ldecode(&p.data) {
                    Some(pkt) => pkt.0,
                    None => {
                        eprintln!("Error: Could not parse packet");
                        continue;
                    }
                }
            }
        };

        // Calculate timestamp in microseconds
        let timestamp_us = (p.ts_sec.value() as u128) * 1_000_000 + (p.ts_usec.value() as u128);

        // Create JSONL entry with timestamp_us, direction, and layers
        let entry = serde_json::json!({
            "timestamp_us": timestamp_us,
            "direction": "rx",  // PCAP doesn't have direction info, default to rx
            "layers": pkt.layers
        });

        match serde_json::to_string(&entry) {
            Ok(line) => jsonl_lines.push(line),
            Err(e) => {
                eprintln!("Error serializing packet {}: {}", packet_count, e);
                continue;
            }
        }

        packet_count += 1;
    }

    // Write JSONL output (one JSON object per line)
    let jsonl_str = jsonl_lines.join("\n") + "\n";

    if let Err(e) = std::fs::write(output_file, jsonl_str) {
        eprintln!("Error writing to {}: {}", output_file, e);
        return;
    }

    println!("Converted {} packets from {} to {}",
             packet_count, input_file, output_file);
}

fn read_file(filename: &str) -> Result<Vec<u8>, String> {
    use std::fs::File;
    use std::io::Read;

    let mut f = File::open(filename)
        .map_err(|e| format!("Failed to open file: {}", e))?;

    let metadata = std::fs::metadata(filename)
        .map_err(|e| format!("Failed to read metadata: {}", e))?;

    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    Ok(buffer)
}

pub fn help_text() -> &'static str {
    "pcap2json <in.pcap> <out.jsonl>  - Convert PCAP to JSONL format (oside layers)"
}
