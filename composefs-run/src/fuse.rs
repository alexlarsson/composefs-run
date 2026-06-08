use std::fs;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use composefs::fsverity::{FsVerityHashValue, Sha256HashValue, Sha512HashValue};
use composefs::repository::{Repository, read_repo_algorithm};
use rustix::fs::{CWD, Mode, OFlags};
use rustix::mount::{FsMountFlags, MountAttrFlags};

/// Arguments for the internal FUSE server mode.
#[derive(Debug, Parser)]
pub struct FuseServeArgs {
    /// Path to the composefs repository
    #[clap(long)]
    repo: std::path::PathBuf,

    /// EROFS image hex id in the repository
    #[clap(long)]
    image: String,

    /// File descriptor number for /dev/fuse
    #[clap(long)]
    fuse_fd: i32,
}

/// Double-fork + exec a FUSE server process. The grandchild is reparented
/// to init so crun doesn't wait for it. The server exits when the FUSE
/// mount is unmounted (ENODEV on the /dev/fuse fd).
pub fn spawn_server(repo_path: &Path, erofs_hex: &str, fuse_fd: i32) -> Result<()> {
    let self_exe = std::env::current_exe().context("Resolving own binary path")?;
    match unsafe { libc::fork() } {
        -1 => anyhow::bail!("fork failed: {}", std::io::Error::last_os_error()),
        0 => match unsafe { libc::fork() } {
            -1 => std::process::exit(1),
            0 => {
                unsafe {
                    libc::setsid();
                    libc::fcntl(fuse_fd, libc::F_SETFD, 0);
                }
                let err = Command::new(&self_exe)
                    .arg("--internal-fuse-serve")
                    .arg("--repo")
                    .arg(repo_path)
                    .arg("--image")
                    .arg(erofs_hex)
                    .arg("--fuse-fd")
                    .arg(fuse_fd.to_string())
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::inherit())
                    .exec();
                eprintln!("Failed to exec FUSE server: {err}");
                std::process::exit(1);
            }
            _ => std::process::exit(0),
        },
        child_pid => {
            let mut status = 0i32;
            unsafe { libc::waitpid(child_pid, &mut status, 0) };
        }
    }
    Ok(())
}

/// Like composefs_fuse::mount_fuse() but without `allow_other`, which
/// requires /etc/fuse.conf `user_allow_other` or CAP_SYS_ADMIN in the
/// init user namespace. We don't need it since only our own process tree
/// accesses the mount.
/// TODO: fix upstream composefs_fuse::mount_fuse() to make allow_other
/// optional, then use that instead.
pub fn mount_rootless(dev_fuse: impl AsFd) -> Result<rustix::fd::OwnedFd> {
    let fusefs = composefs::mount::FsHandle::open("fuse")?;
    rustix::mount::fsconfig_set_flag(fusefs.as_fd(), "ro")?;
    rustix::mount::fsconfig_set_flag(fusefs.as_fd(), "default_permissions")?;
    rustix::mount::fsconfig_set_string(fusefs.as_fd(), "source", "composefs-fuse")?;
    rustix::mount::fsconfig_set_string(fusefs.as_fd(), "rootmode", "040555")?;
    rustix::mount::fsconfig_set_string(fusefs.as_fd(), "user_id", "0")?;
    rustix::mount::fsconfig_set_string(fusefs.as_fd(), "group_id", "0")?;
    rustix::mount::fsconfig_set_string(
        fusefs.as_fd(),
        "fd",
        format!("{}", dev_fuse.as_fd().as_raw_fd()),
    )?;
    rustix::mount::fsconfig_create(fusefs.as_fd())?;
    Ok(rustix::mount::fsmount(
        fusefs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?)
}

/// Run the FUSE server (called via --internal-fuse-serve).
pub fn run_server(args: &FuseServeArgs) -> Result<()> {
    let repo_fd = rustix::fs::open(
        &args.repo,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("Opening repository at {}", args.repo.display()))?;

    let algorithm = read_repo_algorithm(&repo_fd)?
        .context("No meta.json found — is this a composefs repository?")?;

    match algorithm {
        composefs::fsverity::Algorithm::Sha256 { .. } => run_server_typed::<Sha256HashValue>(args),
        composefs::fsverity::Algorithm::Sha512 { .. } => run_server_typed::<Sha512HashValue>(args),
    }
}

fn run_server_typed<ObjectID: FsVerityHashValue>(args: &FuseServeArgs) -> Result<()> {
    let repo = Repository::<ObjectID>::open_path(CWD, &args.repo)
        .context("Opening composefs repository")?;

    let (image_fd, _) = repo
        .open_image(&args.image)
        .context("Opening EROFS image")?;
    let mut image_data = Vec::new();
    std::fs::File::from(image_fd)
        .read_to_end(&mut image_data)
        .context("Reading EROFS image")?;

    let filesystem = composefs::erofs::reader::erofs_to_filesystem::<ObjectID>(&image_data)
        .context("Parsing EROFS image")?;

    let fd_path =
        fs::read_link(format!("/proc/self/fd/{}", args.fuse_fd)).context("Invalid --fuse-fd")?;
    ensure!(
        fd_path == Path::new("/dev/fuse"),
        "--fuse-fd {} does not point to /dev/fuse (got {})",
        args.fuse_fd,
        fd_path.display()
    );
    let dev_fuse = unsafe { std::os::fd::OwnedFd::from_raw_fd(args.fuse_fd) };

    composefs_fuse::serve_tree_fuse(dev_fuse, &filesystem, &repo).context("FUSE server error")?;

    Ok(())
}
