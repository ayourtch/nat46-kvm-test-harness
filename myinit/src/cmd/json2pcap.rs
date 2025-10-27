use oside::protocols::pcap_file::*;
use oside::*;

pub fn main(args: &str) {
    let parts: Vec<&str> = args.trim().split_whitespace().collect();

    if parts.len() != 2 {
        eprintln!("Usage: json2pcap <input.json> <output.pcap>");
        eprintln!("  Converts JSON format to PCAP file");
        return;
    }

    let input_file = parts[0];
    let output_file = parts[1];

    // Read JSON input
    let json_str = match std::fs::read_to_string(input_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error reading file {}: {}", input_file, e);
            return;
        }
    };

    // Parse JSON into packet layers
    let pkts: Vec<Vec<Box<dyn oside::Layer>>> = match serde_json::from_str(&json_str) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error parsing JSON: {}", e);
            return;
        }
    };

    // Create PCAP file
    let mut pcap = PcapFile!();

    for p in pkts {
        let p = LayerStack {
            filled: true,
            layers: p,
        };
        let pp = PcapPacket!(data = p.lencode());
        pcap.push(pp);
    }

    // Write PCAP output
    if let Err(e) = pcap.write(output_file) {
        eprintln!("Error writing PCAP file {}: {}", output_file, e);
        return;
    }

    println!("Converted {} packets from {} to {}",
             pcap.d.packets.len(), input_file, output_file);
}

pub fn help_text() -> &'static str {
    "json2pcap <in.json> <out.pcap>   - Convert JSON to PCAP format"
}
