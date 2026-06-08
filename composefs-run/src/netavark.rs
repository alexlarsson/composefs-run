//! Bridge networking via netavark for rootful containers.
//!
//! Types match netavark's JSON protocol. Only the subset needed for
//! basic bridge setup is included.

use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Network configuration passed to netavark via `network_info` in the
/// JSON input. Describes a bridge network (driver, subnets, IPAM driver).
/// Matches the `Network` struct in netavark's `src/network/types.rs`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Network {
    pub dns_enabled: bool,
    pub driver: String,
    pub id: String,
    pub internal: bool,
    pub ipv6_enabled: bool,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnets: Option<Vec<Subnet>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipam_options: Option<HashMap<String, String>>,
}

/// A subnet within a network, with its gateway address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subnet {
    pub subnet: String,
    pub gateway: String,
}

/// Top-level JSON input piped to `netavark setup` / `netavark teardown`.
/// Contains the container identity, per-network options, network definitions,
/// and optional port mappings.
/// Matches `NetworkOptions` in netavark's `src/network/types.rs`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkOptions {
    pub container_id: String,
    pub container_name: String,
    /// Per-network options keyed by network name (must match `network_info`).
    pub networks: HashMap<String, PerNetworkOptions>,
    /// Network definitions keyed by network name.
    pub network_info: HashMap<String, Network>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_mappings: Option<Vec<PortMapping>>,
}

/// Options for a container on a specific network. The caller (us) is
/// responsible for IP allocation — netavark does not auto-assign IPs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerNetworkOptions {
    pub interface_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub static_ips: Option<Vec<IpAddr>>,
}

/// A port forwarding rule. Netavark sets up iptables/nftables NAT rules
/// to forward `host_ip:host_port` to `container_port` inside the netns.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortMapping {
    pub container_port: u16,
    pub host_ip: String,
    pub host_port: u16,
    pub protocol: String,
}

const NETWORK_NAME: &str = "cfsrun";
const DEFAULT_CONFIG_DIR: &str = "/run/cfsrun/netavark";
const DEFAULT_SUBNET: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 89, 0, 0);
const DEFAULT_PREFIX_LEN: u8 = 24;
const DEFAULT_GATEWAY: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 89, 0, 1);

const HELPER_DIRS: &[&str] = &[
    "/usr/local/libexec/podman",
    "/usr/local/lib/podman",
    "/usr/libexec/podman",
    "/usr/lib/podman",
];

fn find_netavark() -> Result<PathBuf> {
    for dir in HELPER_DIRS {
        let path = Path::new(dir).join("netavark");
        if path.exists() {
            return Ok(path);
        }
    }
    anyhow::bail!(
        "netavark not found in {}",
        HELPER_DIRS
            .iter()
            .map(|d| format!("{d}/netavark"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn default_network() -> Network {
    Network {
        dns_enabled: false,
        driver: "bridge".into(),
        id: "cfsrun-bridge".into(),
        internal: false,
        ipv6_enabled: false,
        name: NETWORK_NAME.into(),
        network_interface: Some("cfsrun0".into()),
        subnets: Some(vec![Subnet {
            subnet: format!("{DEFAULT_SUBNET}/{DEFAULT_PREFIX_LEN}"),
            gateway: DEFAULT_GATEWAY.to_string(),
        }]),
        ipam_options: Some(HashMap::from([("driver".into(), "host-local".into())])),
    }
}

fn ipam_dir() -> PathBuf {
    Path::new(DEFAULT_CONFIG_DIR).join("ipam")
}

/// Allocate an IP from the subnet by creating a symlink. Hashes the
/// container ID for the initial candidate, then increments until a
/// free slot is found.
fn allocate_ip(
    subnet: std::net::Ipv4Addr,
    prefix_len: u8,
    gateway: std::net::Ipv4Addr,
    container_id: &str,
) -> Result<IpAddr> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let dir = ipam_dir();
    fs::create_dir_all(&dir)?;

    let base = u32::from(subnet);
    let host_bits = 32 - prefix_len;
    let pool_size = (1u32 << host_bits) - 2; // exclude network and broadcast
    let gateway_host = u32::from(gateway) - base;

    let mut hasher = DefaultHasher::new();
    container_id.hash(&mut hasher);
    let start = hasher.finish() as u32 % pool_size;

    for i in 0..pool_size {
        let host = (start + i) % pool_size + 1; // 1..pool_size (skip .0)
        if host == gateway_host {
            continue;
        }
        let ip = std::net::Ipv4Addr::from(base + host);
        let path = dir.join(ip.to_string());
        match std::os::unix::fs::symlink(container_id, &path) {
            Ok(()) => return Ok(IpAddr::V4(ip)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).context("IPAM allocation"),
        }
    }
    anyhow::bail!("No free IPs in {subnet}/{prefix_len}")
}

fn release_ip(ip: &IpAddr) {
    let path = ipam_dir().join(ip.to_string());
    let _ = fs::remove_file(path);
}

fn build_options(container_id: &str, port_mappings: &[PortMapping], ip: IpAddr) -> NetworkOptions {
    let network = default_network();
    let mut network_info = HashMap::new();
    network_info.insert(NETWORK_NAME.into(), network);

    let mut networks = HashMap::new();
    networks.insert(
        NETWORK_NAME.into(),
        PerNetworkOptions {
            interface_name: "eth0".into(),
            static_ips: Some(vec![ip]),
        },
    );

    NetworkOptions {
        container_id: container_id.into(),
        container_name: container_id.into(),
        networks,
        network_info,
        port_mappings: if port_mappings.is_empty() {
            None
        } else {
            Some(port_mappings.to_vec())
        },
    }
}

/// Run netavark setup for the given network namespace.
/// Returns the allocated IP address.
pub fn setup(netns_path: &Path, container_id: &str, publish: &[super::PortSpec]) -> Result<IpAddr> {
    let ip = allocate_ip(
        DEFAULT_SUBNET,
        DEFAULT_PREFIX_LEN,
        DEFAULT_GATEWAY,
        container_id,
    )?;
    let port_mappings: Vec<PortMapping> = publish
        .iter()
        .map(|p| PortMapping {
            host_port: p.host_port,
            container_port: p.container_port,
            host_ip: "0.0.0.0".into(),
            protocol: p.protocol.clone(),
        })
        .collect();
    let options = build_options(container_id, &port_mappings, ip);
    let options_json = serde_json::to_string(&options)?;

    let config_dir = Path::new(DEFAULT_CONFIG_DIR);
    fs::create_dir_all(config_dir).ok();

    let netavark = find_netavark()?;
    let output = Command::new(&netavark)
        .arg("--config")
        .arg(config_dir)
        .arg("setup")
        .arg(netns_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(options_json.as_bytes())?;
            child.wait_with_output()
        })
        .context("Running netavark setup")?;

    if !output.status.success() {
        release_ip(&ip);
        anyhow::bail!(
            "netavark setup failed: {} {}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
    }

    Ok(ip)
}

/// Run netavark teardown for the given network namespace.
pub fn teardown(netns_path: &Path, container_id: &str, ip: IpAddr) -> Result<()> {
    let options = build_options(container_id, &[], ip);
    let options_json = serde_json::to_string(&options)?;

    let netavark = find_netavark()?;
    let output = Command::new(&netavark)
        .arg("--config")
        .arg(DEFAULT_CONFIG_DIR)
        .arg("teardown")
        .arg(netns_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(options_json.as_bytes())?;
            child.wait_with_output()
        })
        .context("Running netavark teardown")?;

    if !output.status.success() {
        eprintln!(
            "warning: netavark teardown failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    release_ip(&ip);
    Ok(())
}
