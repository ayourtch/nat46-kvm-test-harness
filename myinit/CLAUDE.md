# Claude Code Session Context - myinit Project

## Project Overview

This is a custom Rust-based init program (`myinit`) designed to run as PID 1 in a minimal Linux environment (firecracker/KVM VM). It serves as a **script-based system initialization** and interactive shell environment for testing the nat46 kernel module and network configurations.

**Key Focus:** Network testing, packet manipulation, NAT46 debugging with powerful built-in tools.

## Architecture

### Directory Structure
```
/home/ayourtch/rust/nat46-kvm-test-harness/myinit/
├── src/
│   ├── main.rs                 # Core init with script executor (297 lines)
│   └── cmd/                    # Command modules (auto-discovered)
│       ├── mod.rs              # Auto-generation macro
│       ├── cat.rs              # Display file contents
│       ├── capture.rs          # Packet capture (PCAP/JSONL) with smart TAP/TUN detection
│       ├── dmesg.rs            # Display kernel messages
│       ├── droptrace.rs        # Kernel packet drop tracer (skb:kfree_skb)
│       ├── echo.rs             # Echo text to output
│       ├── edit.rs             # VT100 text editor
│       ├── fakehost.rs         # Fake host ARP responder
│       ├── help.rs             # Auto-generated help
│       ├── ifconfig.rs         # Network interface configuration
│       ├── inject.rs           # Packet injection with timing
│       ├── insmod.rs           # Load kernel modules
│       ├── ip.rs               # IP routing commands
│       ├── json2pcap.rs        # Convert JSONL to PCAP
│       ├── kconfig.rs          # Check kernel configuration
│       ├── ls.rs               # List directory contents
│       ├── mkdir.rs            # Create directories
│       ├── mknod.rs            # Create device nodes
│       ├── mount.rs            # Mount filesystems
│       ├── netcat.rs           # Network connectivity tool
│       ├── oside.rs            # Interactive packet editor
│       ├── pcap2json.rs        # Convert PCAP to JSONL
│       ├── ping.rs             # ICMP ping utility
│       ├── poweroff.rs         # System shutdown
│       ├── ps.rs               # Display running processes
│       ├── run.rs              # Execute script files
│       └── tap.rs              # Create TAP interfaces
├── Cargo.toml
└── CLAUDE.md                   # This file
```

## Key Features

### 1. Three-Stage Initialization System

The program runs as init (PID 1) and uses a **three-stage initialization process**:

#### Stage 1: Minimal Built-in Initialization (Embedded)

A minimal script hardcoded in the binary that only mounts essential filesystems:

```rust
let startup_script = r#"
# Mount proc filesystem
mount proc

# Load 9p kernel modules (required for host filesystem access)
insmod /netfs.ko
insmod /9pnet.ko
insmod /9pnet_virtio.ko
insmod /9p.ko

# Mount host filesystem
mount 9p
"#;
```

**Purpose:** Only mount what's needed to access external scripts.

#### Stage 2: Modifiable System Initialization (startup.run)

After mounting host filesystem, looks for **`startup.run`** in these locations:
1. `/mnt/host/startup.run` (from host filesystem)
2. `/startup.run` (from initrd)

**Example startup.run:**
```bash
# Example startup.run - Modifiable system initialization
# Load additional kernel modules
insmod /nf_defrag_ipv6.ko
insmod /nat46.ko

# Test nat46 module
echo add nat46dev > /proc/net/nat46/control

# Setup TAP interfaces
mknod /dev/net/tun c 10 200
tap add tap0
ifconfig tap0 192.168.1.1 netmask 255.255.255.0
ifconfig tap0 2001:db8:1::1/64
ifconfig tap0 up
```

**Benefits:**
- Modify without rebuilding initrd
- Customize test environment on host filesystem
- Version control with your test code

**Features:**
- Pure shell-like syntax
- Comment support (lines starting with `#`)
- Output redirection support (`>`)
- Full access to all 27 built-in commands

#### Stage 3: Test Automation (autoexec.run)

After system initialization (stages 1 & 2), the system has a **two-stage countdown**:

**Countdown 1: Autoexec (5 seconds)**
- Looks for `autoexec.run` in these locations:
  - `/mnt/host/autoexec.run` (from host filesystem)
  - `/autoexec.run` (from initrd)
- Press any key → skip autoexec, enter interactive mode immediately
- Timeout → execute autoexec.run if it exists
- If file doesn't exist → print message and continue

**Countdown 2: Shutdown (10 seconds) - only if autoexec wasn't skipped**
- Press any key → enter interactive mode
- Timeout → poweroff

**Example autoexec.run:**
```bash
# Automated testing
echo "Running automated tests..."
capture start tap0 /tmp/capture.jsonl jsonl 100
ping 192.168.1.2
capture stop tap0
echo "Tests complete"
poweroff
```

### 2. Interactive Shell with Powerful Networking Tools

The program provides an interactive shell with **auto-discovered commands** (27 total):

#### File Operations
- `cat <file>` - Display file contents
- `ls [path]` - List directory contents
- `echo <text>` - Echo text to output
- `edit <file>` - VT100 text editor (Ctrl+S save, Ctrl+Q quit, Ctrl+X save+exit)
- `mkdir [-p] <dir>` - Create directories

#### Process Operations
- `ps` - Display running processes

#### Network Configuration
- `ifconfig` - Display all network interfaces
- `ifconfig <iface>` - Display specific interface
- `ifconfig <iface> <ip> [netmask <mask>]` - Set IPv4 address
- `ifconfig <iface> <ipv6/prefix>` - Set IPv6 address
- `ifconfig <iface> up/down` - Bring interface up/down
- `ifconfig <iface> promisc/-promisc` - Enable/disable promiscuous mode
- `ifconfig <iface> hw ether <mac>` - Set MAC address
- `tap add <name>` - Create TAP interface
- `ip route ...` - IP routing configuration

#### Network Testing & Debugging
- `ping <destination>` - ICMP ping utility
- `netcat` - Network connectivity tool
- `fakehost add <iface> <ipv4>` - Add fake host responding to ARP
- `fakehost del <iface> <ipv4>` - Remove fake host
- `fakehost show` - Show all fake hosts

#### Packet Capture & Analysis
- `capture start <iface> <file> [jsonl|pcap] [count]` - Start packet capture (auto-detects L2/L3)
- `capture stop <iface>` - Stop capture
- `capture show` - Show active captures
- `inject <pcap|jsonl> <iface>` - Replay packets with original timing
- `pcap2json <input.pcap> <output.jsonl>` - Convert PCAP to JSONL
- `json2pcap <input.jsonl> <output.pcap>` - Convert JSONL to PCAP
- `oside <file.jsonl>` - Interactive packet editor with layer/field manipulation

#### Kernel Debugging
- `droptrace start [count]` - Start tracing packet drops (background)
- `droptrace stop` - Stop tracing
- `droptrace show` - Show captured drops
- `droptrace clear` - Clear drop buffer
- `kconfig tracing` - Check kernel tracing support
- `dmesg [lines]` - Display kernel messages

#### System Operations
- `mount proc` - Mount /proc filesystem
- `mount 9p` - Mount 9p filesystem at /mnt/host
- `mount -t <type> <src> <tgt> [-o <opts>]` - Mount filesystem
- `insmod <module>` - Load kernel module
- `mknod <path> <type> <maj> <min>` - Create device node
- `run <script>` - Run script file (one command per line)
- `help [command]` - Show help for commands
- `poweroff` - Shutdown the system

#### Output Redirection

All commands support output redirection:
```bash
ls / > /tmp/rootdir.txt
ifconfig > /tmp/interfaces.txt
echo add nat46dev > /proc/net/nat46/control
```

## Auto-Generated Command System

### The Magic: define_commands! Macro

**ALL commands are defined in ONE place** - `src/cmd/mod.rs`:

```rust
define_commands! {
    cat,
    capture,
    dmesg,
    droptrace,
    echo,
    edit,
    fakehost,
    help,
    ifconfig,
    inject,
    insmod,
    ip,
    json2pcap,
    kconfig,
    ls,
    mkdir,
    mknod,
    mount,
    netcat,
    oside,
    pcap2json,
    ping,
    poweroff,
    ps,
    run,
    tap,
}
```

This macro **automatically generates**:
1. Module declarations (`pub mod cat;`, `pub mod echo;`, etc.)
2. Command dispatcher (`cmd::execute()` function)
3. Help aggregator (`cmd::print_all_help()` function)

### Adding a New Command

1. Create `src/cmd/newcomand.rs`
2. Implement two functions:
   ```rust
   pub fn main(args: &str) {
       // Command implementation
   }

   pub fn help_text() -> &'static str {
       "newcomand <args>                 - Brief description"
   }
   ```
3. Add `newcomand` to the list in `cmd/mod.rs`

**That's it!** Everything else is auto-generated.

## Advanced Features

### Packet Capture with Smart TAP/TUN Detection

The `capture` command automatically detects whether an interface is:
- **L2-ethernet (TAP)**: Has `IFF_BROADCAST` flag → uses Ethernet decoder
- **L3 (TUN)**: No `IFF_BROADCAST` flag → uses IP/IPv6 decoder

```bash
capture start nat46 nat46.jsonl
# Detected L3 interface

capture start tap0 tap0.jsonl pcap
# Detected L2-ethernet interface
```

**Features:**
- Auto-detects interface type using `IFF_BROADCAST` flag
- Bidirectional capture (tags packets as "rx" or "tx")
- JSONL format with oside structured parsing
- PCAP format for Wireshark compatibility
- Background operation
- Packet count limit support

**JSONL Format:**
```json
{
  "timestamp_us": 1761596197426295,
  "direction": "rx",
  "layers": [
    {"layertype": "Ip", "src": "192.168.1.1", "dst": "10.0.0.1", ...},
    {"layertype": "Tcp", "sport": 12345, "dport": 80, ...}
  ]
}
```

### Packet Injection with Timing Preservation

The `inject` command replays packets at their original capture timing:

```bash
inject capture.jsonl tap0
inject capture.pcap tap0
```

**Features:**
- Preserves original packet timing
- Auto-detects PCAP vs JSONL format
- Uses TAP file descriptor registry for direct injection
- Falls back to AF_PACKET raw sockets
- Supports both hex-encoded and oside structured JSONL

### Interactive Packet Editor (oside)

Full-featured packet editor with layer/field manipulation:

```bash
oside packets.jsonl
```

**Features:**
- **Navigation:** Arrow keys to move between packets, layers, and fields
- **Timestamp editing:** Layer -1 (simplified architecture)
- **Layer management:**
  - `a` - Add new layer (Ethernet, IP, IPv6, TCP, UDP, ICMP, ARP, Raw)
  - `r` - Remove current layer
- **Field editing:**
  - `e` - Edit current field
  - Supports complex JSON fields (IPv4 flags, etc.)
  - Arrow keys, Home, End, Delete, Backspace
  - Ctrl+A/E - Jump to start/end
  - Ctrl+K/U - Kill to end/start
  - Enter - Save, Esc - Cancel
- **Auto field calculation:**
  - `f` - Recalculate checksums, lengths, etc.
- **Packet operations:**
  - `n`/`p` - Next/previous packet
  - `d` - Delete packet
  - `c` - Copy packet
  - `s` - Save file
  - `q` - Quit (with unsaved changes warning)

**Architecture highlight:** Uses layer -1 for timestamp, eliminating field index adjustments throughout the codebase.

### Fake Host ARP Responder

Create virtual hosts that respond to ARP requests without needing real machines:

```bash
fakehost add tap0 192.168.1.10
fakehost add tap0 192.168.1.20
fakehost show
fakehost del tap0 192.168.1.10
```

**Features:**
- Runs in background thread per interface
- Monitors TAP interface for ARP requests
- Automatically responds with interface's MAC address
- Multiple IPs per interface
- Perfect for NAT46 testing without real hosts

**Output:**
```
ARP: Who has 192.168.1.10? Tell 192.168.1.5 - Responding with MAC 02:42:ac:11:00:02
```

**Note:** Currently IPv4/ARP only. IPv6/NDP support planned.

### Kernel Packet Drop Tracer

Real-time kernel packet drop tracing using `skb:kfree_skb` tracepoint:

```bash
droptrace start
# Do your network tests...
droptrace show
droptrace stop
```

**Features:**
- Runs in background, doesn't block shell
- Automatically mounts tracefs/debugfs if needed
- Shows drop location (kernel function) and reason
- Buffers last 1000 drops
- Optional packet count limit

**Output:**
```
COMM                 PID        CPU      LOCATION                                           REASON
----------------------------------------------------------------------------------------------------
init                 1          000      ip_rcv_core+0x274/0x390                            OTHERHOST
ping                 123        000      icmp_rcv+0x245                                     NO_ROUTE
```

**Common drop reasons:**
- `OTHERHOST` - Destination MAC doesn't match (enable promiscuous mode)
- `NO_SOCKET` - No listening socket
- `NO_ROUTE` - No route to destination
- And many more...

### Network Interface Advanced Configuration

Extended `ifconfig` capabilities:

```bash
# Promiscuous mode (accept all packets)
ifconfig tap0 promisc
ifconfig tap0 -promisc

# MAC address change
ifconfig tap0 down
ifconfig tap0 hw ether 02:42:ac:11:00:02
ifconfig tap0 up

# Status shows new fields
ifconfig tap0
#   HWaddr: 02:42:ac:11:00:02
#   Flags: UP BROADCAST RUNNING PROMISC MULTICAST
```

### TAP File Descriptor Registry

Global registry for sharing TAP file descriptors between commands:

```rust
// In tap.rs
lazy_static! {
    pub static ref TAP_FDS: Mutex<HashMap<String, i32>> = ...;
}
```

**Used by:**
- `inject` - Direct packet injection into TAP
- `fakehost` - Reading/writing to TAP for ARP responses

**Benefits:**
- No EBUSY errors from multiple attachments
- Efficient packet injection
- Shared access across commands

## Implementation Details

### Script Execution

The `execute_script()` function:
```rust
pub fn execute_script(script: &str) {
    for line in script.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        execute_line(line);
    }
}
```

### Command Line Parsing

The `execute_line()` function handles:
- Parsing command and arguments
- Output redirection detection (`>`)
- Stdout redirection and restoration

### Network Interface Management

Uses ioctl syscalls for network configuration:
- `SIOCGIFFLAGS` / `SIOCSIFFLAGS` - Get/set interface flags (including IFF_PROMISC)
- `SIOCGIFADDR` / `SIOCSIFADDR` - Get/set IPv4 address
- `SIOCGIFNETMASK` / `SIOCSIFNETMASK` - Get/set netmask
- `SIOCGIFHWADDR` / `SIOCSIFHWADDR` - Get/set MAC address
- `SIOCGIFINDEX` - Get interface index
- `SIOCGIFMTU` - Get MTU
- `TUNSETIFF` - Create TAP interface

IPv6 addresses:
- Uses `in6_ifreq` structure with ioctl `SIOCSIFADDR` (0x8916)
- Reads from `/proc/net/if_inet6` to display addresses

### TAP Interface Setup

TAP interfaces are created using:
1. Open `/dev/net/tun`
2. Use `TUNSETIFF` ioctl with `IFF_TAP | IFF_NO_PI` flags
3. Store file descriptor in global registry
4. Keep FD open (using `mem::forget`) to maintain interface

### Packet Capture Implementation

Uses `AF_PACKET` raw sockets:
1. Create raw packet socket
2. Bind to specific interface
3. Check interface flags to determine TAP vs TUN
4. Use `recvfrom` to get packet with direction info (sll_pkttype)
5. Parse with appropriate oside decoder (Ether vs IP/IPV6)
6. Tag with "rx" or "tx" direction
7. Write to JSONL or PCAP file

### Packet Injection Implementation

1. Parse file format (PCAP or JSONL)
2. Extract packets with timestamps
3. Check TAP FD registry first
4. If TAP FD available, use `write()` for direct injection
5. Otherwise, use AF_PACKET raw socket with `send()`
6. Preserve timing with `thread::sleep(Duration)`

### oside Integration

The oside library provides a powerful packet manipulation framework with protocol-aware layer composition.

**Core Concepts:**
- `Layer` trait: All protocol types implement this
- `LayerStack`: Container for composed protocol layers
- Protocol macros: `Ether!()`, `IP!()`, `ARP!()`, `ICMP!()`, etc.
- Encoders/decoders: `ldecode()` for parsing, `lencode()` for serialization
- Automatic field calculation: checksums, lengths, etc.

#### Basic Usage Patterns

**1. Parsing Packets:**
```rust
use oside::protocols::all::*;
use oside::*;

// Decode from bytes
let (stack, _) = Ether!().ldecode(packet)?;

// Check if layer exists
if let Some(arp) = stack.get_layer(ARP!()) {
    // Process ARP layer
}

// Or use pattern for layers that must exist
if stack.get_layer(Icmpv6NeighborSolicitation!()).is_some() {
    // Process NS
}
```

**2. Accessing Layer Data:**
```rust
// Extract layer from stack - use the typed reference
let ip_layer = &stack[IP!()];
let eth_layer = &stack[Ether!()];

// Access field values - ALWAYS use .value()
let src_ip: Ipv4Addr = ip_layer.src.value().into();
let dst_mac = eth_layer.dst.clone();

// For string conversion
let ip_str = ip_layer.src.value().to_string();

// IMPORTANT: Use direct field access, NOT JSON serialization
// Each protocol struct has strongly-typed fields accessible directly
```

**3. Building Packets (Layer Composition):**
```rust
// Use / operator to chain layers
let packet = Ether!(
    dst = "ff:ff:ff:ff:ff:ff",
    src = "00:11:22:33:44:55",
    etype = 0x0806
) / ARP!(
    op = 2,
    hwsrc = ArpHardwareAddress::from("00:11:22:33:44:55"),
    psrc = ArpProtocolAddress::from("192.168.1.1")
);

// Encode to bytes
let bytes = packet.lencode();
```

**4. ICMP/ICMPv6 Packet Structure:**

ICMP packets have multiple layers:
- Header layer: `ICMP!()` or `ICMPV6!()`
- Message type layers: `Echo!()`, `EchoReply!()`, etc.
- Data layer: `Raw!()`

```rust
// ICMP Echo Request parsing
let icmp_layer = &stack[ICMP!()];
let echo_layer = &stack[Echo!()];
let data_layer = &stack[Raw!()];

// Check ICMP type - use direct field access
let icmp_type = icmp_layer.typ.value();  // 8 = Echo Request

// Build ICMP Echo Reply
let reply = Ether!(...)
    / IP!(...)
    / ICMP!()
    / EchoReply!(
        identifier = echo_layer.identifier.value().clone(),
        sequence = echo_layer.sequence.value().clone()
    )
    / data_layer.clone();  // Preserve original data
```

**5. ICMPv6 Neighbor Discovery:**

```rust
use oside::protocols::icmpv6::*;

// Neighbor Solicitation parsing
let ns = &stack[Icmpv6NeighborSolicitation!()];
let target_ip: Ipv6Addr = ns.target_address.value().into();

// Neighbor Advertisement reply
let reply = Ether!(...)
    / IPV6!(hop_limit = 255, ...)
    / ICMPV6!()
    / Icmpv6NeighborAdvertisement!(
        target_address = ns.target_address.value().clone(),
        flags = 0x60000000,  // Solicited + Override
        options = vec![TargetLinkLayerAddress("00:11:22:33:44:55".into())]
    );
```

#### Important API Patterns

**Field Access (The Correct Way):**
- **ALWAYS** use `.value()` to get field contents
- Use `.clone()` when reusing field values in new packets
- Convert to standard types with `.into()` or `.to_string()`
- Access fields directly on typed structs - each protocol has its own struct with named fields
- **NEVER** use JSON serialization as an intermediate step

**Type Conversions:**
```rust
// oside -> std types
let ipv4: Ipv4Addr = oside_ipv4.into();
let ipv6: Ipv6Addr = oside_ipv6.into();

// String conversions
let ip_str = oside_ip.to_string();
let mac_str = "00:11:22:33:44:55";
```

**Layer Composition Rules:**
- Use `/` operator between layers
- Result is a `LayerStack`, not individual layers
- Call `.lencode()` on final stack to get bytes
- Order matters: Ether / IP / TCP (outer to inner)

**Auto-Fill Checksums:**
```rust
// Method 1: Encode then decode (forces recalculation)
let encoded = stack.lencode();
let (decoded, _) = Ether!().ldecode(&encoded)?;
// Now checksums are correct

// Method 2: Use filled=false (during construction)
let stack = LayerStack { filled: false, layers };
let bytes = stack.lencode();  // Checksums calculated during encoding
```

#### Common Patterns from fakehost.rs

**ARP Reply:**
```rust
let arp_reply = ARP!(
    op = 2,  // Reply
    hwsrc = ArpHardwareAddress::from(mac_str.as_str()),
    psrc = ArpProtocolAddress::from(ip_str),
    hwdst = ArpHardwareAddress::from(sender_mac),
    pdst = ArpProtocolAddress::from(sender_ip)
);

let packet = Ether!(...) / arp_reply;
```

**IPv6 Neighbor Advertisement:**
```rust
let na = Icmpv6NeighborAdvertisement!(
    target_address = target_addr.clone(),
    flags = 0x60000000,  // S+O flags
    options = vec![TargetLinkLayerAddress(mac.into())]
);

let packet = Ether!(...) / IPV6!(hop_limit = 255, ...) / ICMPV6!() / na;
```

**ICMP Echo Reply:**
```rust
let reply = Ether!(...)
    / IP!(...)
    / ICMP!()
    / EchoReply!(
        identifier = request.identifier.value().clone(),
        sequence = request.sequence.value().clone()
    )
    / original_data.clone();
```

#### Key Lessons Learned

**Working with Protocol Fields:**
1. Extract the typed layer: `let icmp = &stack[ICMP!()];`
2. Access fields directly: `icmp.typ.value()`
3. Use the strongly-typed API - don't resort to JSON

**Layer Detection:**
```rust
// Check if layer exists before accessing
if stack.get_layer(IP!()).is_some() {
    let ip = &stack[IP!()];  // Safe now
}
```

**Import Organization:**
```rust
use oside::*;
use oside::protocols::all::*;
// For specific ICMPv6 types:
use oside::protocols::icmpv6::*;
```

### Kernel Tracing Infrastructure

Uses kernel ftrace/tracepoints via sysfs:
1. Mount tracefs at `/sys/kernel/tracing` or debugfs at `/sys/kernel/debug`
2. Enable tracepoint: `echo 1 > /sys/kernel/tracing/events/skb/kfree_skb/enable`
3. Read from `trace_pipe` (blocking, real-time)
4. Parse output to extract drop location and reason
5. Buffer in memory (VecDeque with 1000 entry limit)
6. Run in background thread

### 9P Filesystem

Mount options used:
```
trans=virtio,version=9p2000.L
```

The mount will fail with "No such device" (errno 19) if:
- Kernel modules aren't loaded
- The `host-code` tag doesn't match the KVM `-device` parameter
- The 9p filesystem isn't registered in the kernel

### Output Redirection Implementation

Uses file descriptor manipulation:
1. Save stdout with `dup(1)`
2. Open output file
3. Redirect stdout to file with `dup2(fd, 1)`
4. Execute command
5. Restore stdout with `dup2(saved_stdout, 1)`
6. Close temporary descriptors

## Build and Deployment

### Building
```bash
cargo build --release
```

The binary will be at: `target/x86_64-unknown-linux-musl/release/myinit`

### Dependencies
- libc 0.2.177
- lazy_static (for global state)
- serde, serde_json (for JSON handling)
- oside (packet manipulation library)

### Creating initrd

The initrd should contain:
- `myinit` binary (as `/init`)
- Kernel modules (`.ko` files) in root directory
- Optional: `/autoexec.run` script for custom initialization

## KVM/Firecracker Setup

### Required Kernel Modules (placed in root of initrd)
- `netfs.ko`
- `9pnet.ko`
- `9pnet_virtio.ko`
- `9p.ko`
- `nf_defrag_ipv6.ko`
- `nat46.ko`

### KVM Command Line Example
```bash
kvm -kernel $KERNEL \
  -initrd initrd.gz \
  -net nic,model=virtio,macaddr=52:54:00:12:34:56 \
  -net user,hostfwd=tcp:127.0.0.1:4444-:22 \
  -append 'console=hvc0' \
  -chardev stdio,id=stdio,mux=on,signal=off \
  -device virtio-serial-pci \
  -device virtconsole,chardev=stdio \
  -mon chardev=stdio \
  -display none \
  -fsdev local,id=fs1,path=/home/ayourtch/fun/nat46/,security_model=none \
  -s \
  -device virtio-9p-pci,fsdev=fs1,mount_tag=host-code
```

Key parameters:
- `mount_tag=host-code` - Must match the source in mount call
- Host path: `/home/ayourtch/fun/nat46/`
- Mount point in guest: `/mnt/host`

## Debugging

### When things go wrong, check:
1. Kernel messages: `dmesg`
2. Available filesystems: `cat /proc/filesystems`
3. Network interfaces: `ifconfig` or `cat /proc/net/dev`
4. IPv6 addresses: `cat /proc/net/if_inet6`
5. Module dependencies: check load order
6. Packet drops: `droptrace start`
7. Kernel tracing: `kconfig tracing`

### Common Issues and Solutions

**"Unknown symbol nf_ct_frag6_gather (err -2)"**
- Missing `nf_defrag_ipv6.ko`

**"Unknown symbol __fscache_acquire_volume (err -2)"**
- Missing `netfs.ko`

**"No such device" (errno 19) on 9p mount**
- Missing 9p modules or wrong mount tag
- Check `/proc/filesystems` for "9p" entry

**"No such file or directory" (errno 2) on insmod**
- Module file doesn't exist
- Module dependencies not loaded

**OTHERHOST packet drops**
- Enable promiscuous mode: `ifconfig <iface> promisc`

**Can't inject packets to TAP**
- Make sure TAP was created with `tap add` command
- Check TAP FD registry with fakehost or inject

**Tracing not available**
- Check kernel config: `kconfig tracing`
- Ensure debugfs or tracefs support compiled in kernel
- Try manual mount: `mount -t tracefs none /sys/kernel/tracing`

## Example Workflows

### Customizing System Initialization

Create `startup.run` on your host filesystem to customize the VM environment:

```bash
# /path/to/nat46-kvm-test-harness/startup.run

# Load kernel modules
insmod /nf_defrag_ipv6.ko
insmod /nat46.ko

# Configure NAT46
echo add nat46dev > /proc/net/nat46/control

# Setup network interfaces
mknod /dev/net/tun c 10 200
tap add tap0
tap add tap1
ifconfig tap0 192.168.1.1 netmask 255.255.255.0 up
ifconfig tap1 2001:db8::1/64 up

# Add fake hosts for testing
fakehost add tap0 192.168.1.10 icmp
fakehost add tap1 2001:db8::100 icmp router

# Start background monitoring
droptrace start
```

This runs automatically after filesystem mount, no need to rebuild initrd!

### NAT46 Testing with Fake Hosts

```bash
# Setup interfaces
tap add tap0
tap add tap1
ifconfig tap0 192.168.1.1 netmask 255.255.255.0 up promisc
ifconfig tap1 2001:db8::1/64 up promisc

# Add fake hosts
fakehost add tap0 192.168.1.10
fakehost add tap0 192.168.1.20

# Start captures and drop tracing
capture start tap0 tap0.jsonl
capture start tap1 tap1.jsonl
droptrace start

# Do your NAT46 tests...
# (packets will be captured, drops traced, ARP handled)

# Check results
capture show
droptrace show
fakehost show

# Stop everything
capture stop tap0
capture stop tap1
droptrace stop
```

### Packet Replay and Analysis

```bash
# Capture packets
capture start tap0 original.jsonl 100

# Edit packets
oside original.jsonl
# (modify addresses, ports, etc.)

# Replay modified packets
inject original.jsonl tap1

# Convert to PCAP for Wireshark
json2pcap original.jsonl original.pcap
```

### Custom Network Configuration

Create `/autoexec.run`:
```bash
# Custom network setup
echo "Configuring custom network..."

# Create and configure interfaces
tap add tap0
ifconfig tap0 172.16.0.1 netmask 255.255.255.0 up promisc
ifconfig tap0 hw ether 02:42:ac:11:00:01

# Add fake hosts
fakehost add tap0 172.16.0.10
fakehost add tap0 172.16.0.20

# Start background monitoring
droptrace start
capture start tap0 /mnt/host/tap0.jsonl
```

### Test Automation

Create `/autoexec.run`:
```bash
# Automated testing
echo "Running automated tests..."

# Start monitoring
droptrace start
capture start nat46 /tmp/nat46.jsonl 1000

# Run tests
ping -c 10 192.168.1.1 > /tmp/ping-results.txt

# Gather results
droptrace show > /tmp/drops.txt
capture stop nat46
ifconfig > /tmp/interfaces.txt
ps > /tmp/processes.txt

echo "Tests complete"
poweroff
```

## Code Statistics

- **Total commands**: 27
- **Main.rs**: 297 lines (73% reduction from original)
- **Command modules**: ~5000 lines total
- **Binary size**: ~2MB (with oside)
- **Build time**: ~5 seconds

**Main.rs Functions (Only 9!):**
1. `set_stdin_nonblocking()` - Stdin management
2. `check_for_input()` - Input checking
3. `redirect_stdout_to_file()` - Redirection support
4. `restore_stdout()` - Restore stdout
5. `execute_command()` - Calls `cmd::execute()`
6. `execute_line()` - Full line parser with redirection
7. `execute_script()` - Script executor (public, used by `run` command)
8. `interactive_shell()` - Interactive mode
9. `main()` - Boot orchestration

## Architecture Highlights

### Pure Command-Driven Design
- **Everything** is a command (even `help` and `poweroff`)
- Boot sequence is a **literal shell script** embedded in Rust
- External scripts via `/autoexec.run` for customization
- Zero hardcoded logic - all operations use composable commands

### Macro-Driven Auto-Generation
- Single list of commands in `cmd/mod.rs`
- Automatic command dispatch generation
- Automatic help text aggregation
- Adding commands is trivial (3 steps)

### Script-First Philosophy
- Built-in startup script
- Auto-execute support (`/autoexec.run`)
- Interactive script execution (`run` command)
- All scripts support comments and output redirection

### Network Testing Focus
- Comprehensive packet capture/injection tools
- Smart L2/L3 detection
- Fake host ARP responder
- Kernel-level drop tracing
- Interactive packet editor
- Bidirectional traffic visibility

## References

- **Project location**: `/home/ayourtch/rust/nat46-kvm-test-harness/myinit/`
- **nat46 module**: `/home/ayourtch/fun/nat46/`
- **Kernel version**: 6.8.0-85-generic
- **Rust edition**: 2021
- **Key dependencies**:
  - libc 0.2.177
  - oside (packet manipulation library from https://github.com/ayourtch/oside)
  - lazy_static
  - serde/serde_json

---

**Last updated:** 2025-01-27
**Session type:** Network testing tools - packet capture/injection, drop tracing, fake hosts, oside integration
**Key achievements:**
- 27 commands total
- Smart TAP/TUN detection
- Bidirectional packet capture
- Interactive packet editor with layer -1 architecture
- Kernel drop tracer with background operation
- Fake host ARP responder
- Complete packet manipulation pipeline (capture → edit → replay)
