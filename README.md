# composefs-run

A minimal container runner that runs OCI containers directly from
[composefs-rs](https://github.com/containers/composefs-rs)
repositories using [crun](https://github.com/containers/crun), without
requiring podman's full runtime infrastructure or persistent state
tracking.

### Features

- Mostly CLI-compatible with `podman run`
- **Rootful mode**: kernel erofs + overlayfs, bridge networking via
  [netavark](https://github.com/containers/netavark)
- **Rootless mode**: FUSE-based composefs + unprivileged overlayfs
  (`userxattr`), user namespace with subuid/subgid mapping,
  [pasta](https://passt.top/) networking
- SELinux labeling with MCS category separation
- Seccomp profiles (default from containers-common, or from image labels)
- Minimal host state: transient overlay in `/var/tmp`, tmpfs-backed bundle,
  no global database
- Default to transient overlays, persistent overlay via `--overlay-dir`
- OCI poststop hooks for automatic cleanup

### Quick start

```bash
# Build (requires composefs-rs as a dependency)
cargo build

# Pull an image into a composefs repository
cfsctl init --insecure /tmp/repo
cfsctl --repo /tmp/repo oci pull docker://quay.io/centos/centos:stream10 cs10

# Run a container (rootless — automatic)
target/debug/cfsrun --repo /tmp/repo -it cs10 -- bash

# Run as root (uses kernel erofs + bridge networking)
sudo target/debug/cfsrun --repo /tmp/repo -it cs10 -- bash
```

### Common options

```
cfsrun [OPTIONS] <IMAGE> [-- <CMD>...]

Options:
  --repo <PATH>           Path to composefs repository
  -i, --interactive       Keep stdin open
  -t, --tty               Allocate a pseudo-TTY
  -e, --env <KEY=VALUE>   Set environment variables
  -u, --user <UID[:GID]>  Override user
  -w, --workdir <PATH>    Override working directory
  -v, --volume <H:C[:ro]> Bind mount
  --device <PATH[:PATH[:PERMS]]>  Add host device
  --read-only             Read-only rootfs
  --overlay-dir <PATH>    Persistent overlay directory
  --network <MODE>        host|pasta|bridge|private
  --hostname <NAME>       Container hostname
  --privileged            Full capabilities, no seccomp/SELinux
  --cap-add/--cap-drop    Modify capabilities
  --security-opt <OPT>    seccomp, label, no-new-privileges
  --dns/--dns-search      DNS configuration
  -p, --publish <H:C>     Port forwarding
  --add-host <HOST:IP>    Extra /etc/hosts entries
```

### Testing

```bash
# Unit tests (no container image needed)
just test-unit

# Integration tests (requires cfsctl in PATH, pulls test image)
just cfsctl=/path/to/cfsctl test-integration

# All tests
just cfsctl=/path/to/cfsctl test
```

### License

Apache-2.0 OR MIT
