use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket, SocketAddr, ToSocketAddrs};
use std::time::Duration;

pub fn main(args: &str) {
    let parts: Vec<&str> = args.trim().split_whitespace().collect();

    if parts.is_empty() {
        print_usage();
        return;
    }

    let mut listen_mode = false;
    let mut udp_mode = false;
    let mut ipv6_mode = false;
    let mut verbose = false;
    let mut host = None;
    let mut port = None;

    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            "-l" => listen_mode = true,
            "-u" => udp_mode = true,
            "-6" => ipv6_mode = true,
            "-v" => verbose = true,
            "-h" | "--help" => {
                print_usage();
                return;
            }
            arg => {
                if host.is_none() {
                    host = Some(arg);
                } else if port.is_none() {
                    port = Some(arg);
                } else {
                    eprintln!("Unknown argument: {}", arg);
                    return;
                }
            }
        }
        i += 1;
    }

    // Validate arguments
    if listen_mode {
        // Listen mode: port is required, host is optional
        if port.is_none() {
            if let Some(h) = host {
                port = Some(h);
                host = None;
            } else {
                eprintln!("Error: Port required for listen mode");
                print_usage();
                return;
            }
        }
    } else {
        // Client mode: both host and port required
        if host.is_none() || port.is_none() {
            eprintln!("Error: Both host and port required for client mode");
            print_usage();
            return;
        }
    }

    let port_num = match port.unwrap().parse::<u16>() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Error: Invalid port number");
            return;
        }
    };

    if listen_mode {
        if udp_mode {
            udp_listen(host, port_num, ipv6_mode, verbose);
        } else {
            tcp_listen(host, port_num, ipv6_mode, verbose);
        }
    } else {
        if udp_mode {
            udp_connect(host.unwrap(), port_num, ipv6_mode, verbose);
        } else {
            tcp_connect(host.unwrap(), port_num, ipv6_mode, verbose);
        }
    }
}

fn print_usage() {
    eprintln!("Usage: nc [options] [host] port");
    eprintln!("       nc [options] -l [host] port");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -l          Listen mode (server)");
    eprintln!("  -u          UDP mode (default: TCP)");
    eprintln!("  -6          Force IPv6");
    eprintln!("  -v          Verbose output");
    eprintln!("  -h, --help  Show this help");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  nc -l 8080              # TCP server on port 8080");
    eprintln!("  nc -l -u 8080           # UDP server on port 8080");
    eprintln!("  nc 192.168.1.1 8080     # TCP client");
    eprintln!("  nc -u 192.168.1.1 8080  # UDP client");
    eprintln!("  nc -6 ::1 8080          # IPv6 TCP client");
}

fn tcp_listen(host: Option<&str>, port: u16, ipv6_mode: bool, verbose: bool) {
    let bind_addr = if let Some(h) = host {
        format!("{}:{}", h, port)
    } else {
        if ipv6_mode {
            format!("[::]:{}", port)
        } else {
            format!("0.0.0.0:{}", port)
        }
    };

    if verbose {
        eprintln!("Listening on {} (TCP)...", bind_addr);
    }

    let listener = match TcpListener::bind(&bind_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to {}: {}", bind_addr, e);
            return;
        }
    };

    match listener.accept() {
        Ok((mut stream, addr)) => {
            if verbose {
                eprintln!("Connection from {}", addr);
            }

            handle_tcp_connection(&mut stream);

            if verbose {
                eprintln!("Connection closed");
            }
        }
        Err(e) => {
            eprintln!("Failed to accept connection: {}", e);
        }
    }
}

fn tcp_connect(host: &str, port: u16, ipv6_mode: bool, verbose: bool) {
    let addr_str = format!("{}:{}", host, port);

    if verbose {
        eprintln!("Connecting to {} (TCP)...", addr_str);
    }

    // Resolve address
    let addrs: Vec<SocketAddr> = match addr_str.to_socket_addrs() {
        Ok(addrs) => addrs.collect(),
        Err(e) => {
            eprintln!("Failed to resolve {}: {}", addr_str, e);
            return;
        }
    };

    // Filter by IP version if requested
    let filtered_addrs: Vec<SocketAddr> = if ipv6_mode {
        addrs.into_iter().filter(|a| a.is_ipv6()).collect()
    } else {
        addrs
    };

    if filtered_addrs.is_empty() {
        eprintln!("No addresses found for {}", addr_str);
        return;
    }

    let target_addr = filtered_addrs[0];

    let mut stream = match TcpStream::connect_timeout(&target_addr, Duration::from_secs(10)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to connect to {}: {}", target_addr, e);
            return;
        }
    };

    if verbose {
        eprintln!("Connected to {}", target_addr);
    }

    handle_tcp_connection(&mut stream);
}

fn handle_tcp_connection(stream: &mut TcpStream) {
    // Set non-blocking mode for stdin checking
    let stdin_fd = 0;
    unsafe {
        let flags = libc::fcntl(stdin_fd, libc::F_GETFL, 0);
        libc::fcntl(stdin_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    // Clone stream for reading
    let mut read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to clone stream: {}", e);
            return;
        }
    };

    // Set read timeout
    let _ = read_stream.set_read_timeout(Some(Duration::from_millis(100)));

    let mut stdin_buf = [0u8; 8192];
    let mut net_buf = [0u8; 8192];

    loop {
        // Check for stdin input
        let stdin_result = io::stdin().read(&mut stdin_buf);
        if let Ok(n) = stdin_result {
            if n > 0 {
                if let Err(e) = stream.write_all(&stdin_buf[..n]) {
                    eprintln!("Write error: {}", e);
                    break;
                }
            }
        }

        // Check for network input
        match read_stream.read(&mut net_buf) {
            Ok(0) => {
                // Connection closed
                break;
            }
            Ok(n) => {
                if let Err(e) = io::stdout().write_all(&net_buf[..n]) {
                    eprintln!("Stdout error: {}", e);
                    break;
                }
                let _ = io::stdout().flush();
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No data, continue
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                eprintln!("Read error: {}", e);
                break;
            }
        }
    }

    // Restore blocking mode for stdin
    unsafe {
        let flags = libc::fcntl(stdin_fd, libc::F_GETFL, 0);
        libc::fcntl(stdin_fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }
}

fn udp_listen(host: Option<&str>, port: u16, ipv6_mode: bool, verbose: bool) {
    let bind_addr = if let Some(h) = host {
        format!("{}:{}", h, port)
    } else {
        if ipv6_mode {
            format!("[::]:{}", port)
        } else {
            format!("0.0.0.0:{}", port)
        }
    };

    if verbose {
        eprintln!("Listening on {} (UDP)...", bind_addr);
    }

    let socket = match UdpSocket::bind(&bind_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to bind to {}: {}", bind_addr, e);
            return;
        }
    };

    let _ = socket.set_read_timeout(Some(Duration::from_millis(100)));

    // Set stdin non-blocking
    let stdin_fd = 0;
    unsafe {
        let flags = libc::fcntl(stdin_fd, libc::F_GETFL, 0);
        libc::fcntl(stdin_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let mut stdin_buf = [0u8; 8192];
    let mut net_buf = [0u8; 8192];
    let mut peer_addr: Option<SocketAddr> = None;

    loop {
        // Check for stdin input (to send to last peer)
        if let Some(peer) = peer_addr {
            let stdin_result = io::stdin().read(&mut stdin_buf);
            if let Ok(n) = stdin_result {
                if n > 0 {
                    if let Err(e) = socket.send_to(&stdin_buf[..n], peer) {
                        eprintln!("Send error: {}", e);
                    }
                }
            }
        }

        // Check for network input
        match socket.recv_from(&mut net_buf) {
            Ok((n, addr)) => {
                if peer_addr.is_none() || peer_addr.unwrap() != addr {
                    if verbose {
                        eprintln!("Received from {}", addr);
                    }
                    peer_addr = Some(addr);
                }

                if let Err(e) = io::stdout().write_all(&net_buf[..n]) {
                    eprintln!("Stdout error: {}", e);
                    break;
                }
                let _ = io::stdout().flush();
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                eprintln!("Receive error: {}", e);
                break;
            }
        }
    }

    // Restore blocking mode
    unsafe {
        let flags = libc::fcntl(stdin_fd, libc::F_GETFL, 0);
        libc::fcntl(stdin_fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }
}

fn udp_connect(host: &str, port: u16, ipv6_mode: bool, verbose: bool) {
    let addr_str = format!("{}:{}", host, port);

    if verbose {
        eprintln!("Connecting to {} (UDP)...", addr_str);
    }

    // Resolve address
    let addrs: Vec<SocketAddr> = match addr_str.to_socket_addrs() {
        Ok(addrs) => addrs.collect(),
        Err(e) => {
            eprintln!("Failed to resolve {}: {}", addr_str, e);
            return;
        }
    };

    // Filter by IP version if requested
    let filtered_addrs: Vec<SocketAddr> = if ipv6_mode {
        addrs.into_iter().filter(|a| a.is_ipv6()).collect()
    } else {
        addrs
    };

    if filtered_addrs.is_empty() {
        eprintln!("No addresses found for {}", addr_str);
        return;
    }

    let target_addr = filtered_addrs[0];

    // Bind to appropriate local address
    let bind_addr = match target_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };

    let socket = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create socket: {}", e);
            return;
        }
    };

    if let Err(e) = socket.connect(target_addr) {
        eprintln!("Failed to connect to {}: {}", target_addr, e);
        return;
    }

    if verbose {
        eprintln!("Connected to {} (UDP)", target_addr);
    }

    let _ = socket.set_read_timeout(Some(Duration::from_millis(100)));

    // Set stdin non-blocking
    let stdin_fd = 0;
    unsafe {
        let flags = libc::fcntl(stdin_fd, libc::F_GETFL, 0);
        libc::fcntl(stdin_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let mut stdin_buf = [0u8; 8192];
    let mut net_buf = [0u8; 8192];

    loop {
        // Check for stdin input
        let stdin_result = io::stdin().read(&mut stdin_buf);
        if let Ok(n) = stdin_result {
            if n > 0 {
                if let Err(e) = socket.send(&stdin_buf[..n]) {
                    eprintln!("Send error: {}", e);
                    break;
                }
            }
        }

        // Check for network input
        match socket.recv(&mut net_buf) {
            Ok(n) => {
                if let Err(e) = io::stdout().write_all(&net_buf[..n]) {
                    eprintln!("Stdout error: {}", e);
                    break;
                }
                let _ = io::stdout().flush();
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                eprintln!("Receive error: {}", e);
                break;
            }
        }
    }

    // Restore blocking mode
    unsafe {
        let flags = libc::fcntl(stdin_fd, libc::F_GETFL, 0);
        libc::fcntl(stdin_fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }
}

pub fn help_text() -> &'static str {
    "nc [OPTIONS] [host] port          - Netcat - network connections (TCP/UDP)"
}
