use std::fs;
use std::process::Command;

use anyhow::{Context, Result};

/// Enter a user + mount namespace with full subuid/subgid mapping.
/// Both namespaces must be created together so that fsopen() works
/// (it requires CAP_SYS_ADMIN in the mount namespace's owning userns).
pub fn setup() -> Result<()> {
    let pid = std::process::id();
    let real_uid = rustix::process::getuid().as_raw();
    let real_gid = rustix::process::getgid().as_raw();

    let (uid_start, uid_count) = parse_subid("/etc/subuid", real_uid)?;
    let (gid_start, gid_count) = parse_subid("/etc/subgid", real_gid)?;

    // Try newuidmap/newgidmap first (supports multiple subuid ranges).
    // These are setuid binaries that must run OUTSIDE the user namespace,
    // so we fork a helper child before calling unshare.
    let (read_fd, write_fd) = rustix::pipe::pipe()?;

    match unsafe { libc::fork() } {
        -1 => anyhow::bail!("fork failed: {}", std::io::Error::last_os_error()),
        0 => {
            drop(write_fd);
            let mut buf = [0u8; 1];
            rustix::io::read(&read_fd, &mut buf).ok();
            drop(read_fd);

            if uid_count > 0 && gid_count > 0 {
                let uid_ok = Command::new("newuidmap")
                    .arg(pid.to_string())
                    .arg("0")
                    .arg(real_uid.to_string())
                    .arg("1")
                    .arg("1")
                    .arg(uid_start.to_string())
                    .arg(uid_count.to_string())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);

                let gid_ok = Command::new("newgidmap")
                    .arg(pid.to_string())
                    .arg("0")
                    .arg(real_gid.to_string())
                    .arg("1")
                    .arg("1")
                    .arg(gid_start.to_string())
                    .arg(gid_count.to_string())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);

                std::process::exit(if uid_ok && gid_ok { 0 } else { 1 });
            }
            std::process::exit(1);
        }
        child_pid => {
            drop(read_fd);
            unsafe {
                rustix::thread::unshare_unsafe(
                    rustix::thread::UnshareFlags::NEWUSER | rustix::thread::UnshareFlags::NEWNS,
                )
            }
            .context("unshare(CLONE_NEWUSER | CLONE_NEWNS)")?;

            rustix::io::write(&write_fd, b"g").ok();
            drop(write_fd);

            let mut status = 0i32;
            unsafe { libc::waitpid(child_pid, &mut status, 0) };
            let child_succeeded = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;

            if !child_succeeded {
                fs::write(format!("/proc/{pid}/setgroups"), "deny\n")
                    .context("Writing setgroups")?;
                fs::write(format!("/proc/{pid}/uid_map"), format!("0 {real_uid} 1\n"))
                    .context("Writing uid_map")?;
                fs::write(format!("/proc/{pid}/gid_map"), format!("0 {real_gid} 1\n"))
                    .context("Writing gid_map")?;
            }

            Ok(())
        }
    }
}

fn parse_subid(path: &str, id: u32) -> Result<(u64, u64)> {
    let username = get_username(id);
    let content = fs::read_to_string(path).unwrap_or_default();
    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }
        let matches =
            parts[0] == id.to_string() || username.as_ref().map(|u| u == parts[0]).unwrap_or(false);
        if matches {
            let start: u64 = parts[1].parse().context("Parsing subid start")?;
            let count: u64 = parts[2].parse().context("Parsing subid count")?;
            return Ok((start, count));
        }
    }
    Ok((0, 0))
}

fn get_username(uid: u32) -> Option<String> {
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) };
    Some(name.to_string_lossy().into_owned())
}
