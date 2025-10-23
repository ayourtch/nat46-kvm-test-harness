pub fn main(_args: &str) {
    println!("Shutting down system now...");
    unsafe {
        libc::syscall(libc::SYS_reboot,
                      libc::LINUX_REBOOT_MAGIC1,
                      libc::LINUX_REBOOT_MAGIC2,
                      libc::LINUX_REBOOT_CMD_POWER_OFF,
                      0);
    }
}

pub fn help_text() -> &'static str {
    "poweroff                          - Shutdown the system"
}
