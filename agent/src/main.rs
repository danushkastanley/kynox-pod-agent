use anyhow::Result;
use env_logger;
use log::info;
use agent_core::syscalls::SyscallMonitor;

fn main() -> Result<()> {
    env_logger::init();

    let mut monitor = SyscallMonitor::new()?;
    monitor.attach()?;
    monitor.setup_ring_buffer()?;

    info!("eBPF agent started successfully! Monitoring syscalls...");
    info!("Polling ring buffer for events...");

    loop {
        if let Err(e) = monitor.poll(100) {
            if let Some(errno) = e.downcast_ref::<libbpf_rs::Error>() {
                if let libbpf_rs::Error::System(code) = errno {
                    if *code == libc::EINTR {
                        info!("Poll interrupted (EINTR), exiting.");
                        break;
                    }
                }
            }
            return Err(e);
        }
    }

    Ok(())
}
