// Macro to define commands - this generates both the module declarations
// and the necessary functions to dispatch and show help
macro_rules! define_commands {
    ( $( $name:ident ),* $(,)? ) => {
        // Declare all command modules
        $(
            pub mod $name;
        )*

        // Generate the execute function
        pub fn execute(command: &str, args: &str) -> bool {
            match command {
                $(
                    stringify!($name) => {
                        $name::main(args);
                        // Special case: poweroff should signal exit
                        if stringify!($name) == "poweroff" {
                            return true;
                        }
                    }
                )*
                _ => {
                    println!("Unknown command: {}", command);
                    println!("Type 'help' for available commands.");
                }
            }
            false // Continue shell
        }

        // Generate the help printer
        pub fn print_all_help() {
            $(
                println!("  {}", $name::help_text());
            )*
        }
    };
}

// Define all commands here - adding a new command is just adding it to this list!
define_commands! {
    cat,
    capture,
    dmesg,
    echo,
    help,
    ifconfig,
    insmod,
    ls,
    mknod,
    mount,
    ping,
    poweroff,
    ps,
    run,
    tap,
}
