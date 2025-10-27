use oside::protocols::all::*;
use oside::protocols::pcap_file::*;
use oside::*;

pub fn main(args: &str) {
    let parts: Vec<&str> = args.trim().split_whitespace().collect();

    if parts.len() != 2 {
        eprintln!("Usage: pcap2json <input.pcap> <output.json>");
        eprintln!("  Converts PCAP file to JSON format");
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

    // Convert packets to JSON
    let mut json_packets = Vec::new();

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
        json_packets.push(pkt.layers);
    }

    // Write JSON output
    let json_str = match serde_json::to_string_pretty(&json_packets) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error serializing to JSON: {}", e);
            return;
        }
    };

    if let Err(e) = std::fs::write(output_file, json_str) {
        eprintln!("Error writing to {}: {}", output_file, e);
        return;
    }

    println!("Converted {} packets from {} to {}",
             json_packets.len(), input_file, output_file);
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
    "pcap2json <in.pcap> <out.json>   - Convert PCAP to JSON format"
}
