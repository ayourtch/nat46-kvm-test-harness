use oside::protocols::pcap_file::*;
use oside::*;
use std::io::{BufRead, BufReader};
use std::fs::File;

pub fn main(args: &str) {
    let parts: Vec<&str> = args.trim().split_whitespace().collect();

    if parts.len() != 2 {
        eprintln!("Usage: json2pcap <input.jsonl> <output.pcap>");
        eprintln!("  Converts JSONL format (oside layers with timestamps) to PCAP file");
        return;
    }

    let input_file = parts[0];
    let output_file = parts[1];

    // Open JSONL input file
    let file = match File::open(input_file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error reading file {}: {}", input_file, e);
            return;
        }
    };

    let reader = BufReader::new(file);

    // Create PCAP file
    let mut pcap = PcapFile!();
    let mut packet_count = 0;

    // Process each line of JSONL
    for (line_num, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Error reading line {}: {}", line_num + 1, e);
                continue;
            }
        };

        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }

        // Parse JSON line
        let json: serde_json::Value = match serde_json::from_str(&line) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("Error parsing line {}: {}", line_num + 1, e);
                continue;
            }
        };

        // Extract timestamp_us (default to 0 if not present)
        let timestamp_us = json.get("timestamp_us")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u128;

        let ts_sec = (timestamp_us / 1_000_000) as u32;
        let ts_usec = (timestamp_us % 1_000_000) as u32;

        // Extract layers
        let layers: Vec<Box<dyn oside::Layer>> = if let Some(layers_val) = json.get("layers") {
            match serde_json::from_value(layers_val.clone()) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Error parsing layers on line {}: {}", line_num + 1, e);
                    continue;
                }
            }
        } else {
            eprintln!("Warning: Line {} has no 'layers' field, skipping", line_num + 1);
            continue;
        };

        // Create LayerStack and encode to bytes
        let stack = LayerStack {
            filled: true,
            layers,
        };
        let packet_data = stack.lencode();

        // Create PCAP packet with timestamp
        let pp = PcapPacket!(
            ts_sec = ts_sec,
            ts_usec = ts_usec,
            data = packet_data
        );
        pcap.push(pp);
        packet_count += 1;
    }

    // Write PCAP output
    if let Err(e) = pcap.write(output_file) {
        eprintln!("Error writing PCAP file {}: {}", output_file, e);
        return;
    }

    println!("Converted {} packets from {} to {}",
             packet_count, input_file, output_file);
}

pub fn help_text() -> &'static str {
    "json2pcap <in.jsonl> <out.pcap>  - Convert JSONL (oside layers) to PCAP format"
}
