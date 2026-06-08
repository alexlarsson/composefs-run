//! Seccomp profile loading and conversion.
//!
//! Reads the high-level seccomp profile format used by containers-common
//! (with capability-conditional and architecture-conditional rules) and
//! converts it to the OCI runtime spec's `LinuxSeccomp` format.

use anyhow::{Context, Result, bail};
use oci_spec::runtime::{LinuxSeccomp, LinuxSeccompAction, LinuxSeccompArg, LinuxSyscall};
use serde::Deserialize;
use std::collections::HashSet;

/// Default seccomp profile path (from containers-common).
pub const DEFAULT_SECCOMP_PROFILE: &str = "/usr/share/containers/seccomp.json";

// ─── High-level profile types (containers-common format) ────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeccompProfile {
    default_action: String,
    #[serde(default)]
    default_errno_ret: Option<u32>,
    #[serde(default)]
    default_errno: Option<String>,
    #[serde(default)]
    arch_map: Vec<ArchMap>,
    #[serde(default)]
    architectures: Vec<String>,
    #[serde(default)]
    syscalls: Vec<SyscallRule>,
    #[serde(default)]
    flags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArchMap {
    architecture: String,
    #[serde(default)]
    sub_architectures: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyscallRule {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    names: Vec<String>,
    action: String,
    #[serde(default)]
    args: Vec<ArgRule>,
    #[serde(default)]
    includes: Filter,
    #[serde(default)]
    excludes: Filter,
    #[serde(default)]
    errno_ret: Option<u32>,
    #[serde(default)]
    errno: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Filter {
    #[serde(default)]
    caps: Vec<String>,
    #[serde(default)]
    arches: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArgRule {
    index: u32,
    value: u64,
    #[serde(default)]
    value_two: u64,
    op: String,
}

// ─── Errno name → number mapping ────────────────────────────────────────────

fn errno_from_name(name: &str) -> Option<u32> {
    Some(match name {
        "EPERM" => 1,
        "ENOENT" => 2,
        "ESRCH" => 3,
        "EIO" => 5,
        "ENXIO" => 6,
        "E2BIG" => 7,
        "ENOEXEC" => 8,
        "EBADF" => 9,
        "ECHILD" => 10,
        "EDEADLK" => 35,
        "ENOMEM" => 12,
        "EACCES" => 13,
        "EFAULT" => 14,
        "EBUSY" => 16,
        "EEXIST" => 17,
        "ENODEV" => 19,
        "ENOTDIR" => 20,
        "EISDIR" => 21,
        "EINVAL" => 22,
        "EMFILE" => 24,
        "ENOSPC" => 28,
        "ENOSYS" => 38,
        "ENOTSUP" | "EOPNOTSUPP" => 95,
        _ => return None,
    })
}

fn resolve_errno(errno_name: &Option<String>, errno_ret: &Option<u32>) -> Option<u32> {
    if let Some(name) = errno_name {
        if let Some(num) = errno_from_name(name) {
            return Some(num);
        }
        if let Ok(num) = name.parse::<u32>() {
            return Some(num);
        }
    }
    *errno_ret
}

// ─── Architecture detection ─────────────────────────────────────────────────

fn native_arch() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "SCMP_ARCH_X86_64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "SCMP_ARCH_AARCH64"
    }
    #[cfg(target_arch = "s390x")]
    {
        "SCMP_ARCH_S390X"
    }
    #[cfg(target_arch = "powerpc64")]
    {
        "SCMP_ARCH_PPC64LE"
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "s390x",
        target_arch = "powerpc64"
    )))]
    {
        "SCMP_ARCH_NATIVE"
    }
}

fn native_arch_string() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "amd64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }
    #[cfg(target_arch = "s390x")]
    {
        "s390x"
    }
    #[cfg(target_arch = "powerpc64")]
    {
        "ppc64le"
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "s390x",
        target_arch = "powerpc64"
    )))]
    {
        "unknown"
    }
}

// ─── Profile loading and conversion ─────────────────────────────────────────

pub enum SeccompSource {
    File(std::path::PathBuf),
    Inline(String),
}

impl SeccompSource {
    pub fn load(&self, capabilities: &HashSet<String>) -> Result<LinuxSeccomp> {
        match self {
            Self::File(path) => {
                let data = std::fs::read_to_string(path)
                    .with_context(|| format!("Reading seccomp profile from {}", path.display()))?;
                let profile: SeccompProfile = serde_json::from_str(&data)
                    .with_context(|| format!("Parsing seccomp profile from {}", path.display()))?;
                convert_profile(&profile, capabilities)
            }
            Self::Inline(json) => {
                let profile: SeccompProfile = serde_json::from_str(json)
                    .context("Parsing seccomp profile from image label")?;
                convert_profile(&profile, capabilities)
            }
        }
    }
}

/// Convert a high-level seccomp profile to the OCI runtime spec format.
fn convert_profile(
    profile: &SeccompProfile,
    capabilities: &HashSet<String>,
) -> Result<LinuxSeccomp> {
    let arch = native_arch_string();

    // Resolve architectures from archMap
    let mut architectures = Vec::new();
    if !profile.architectures.is_empty() {
        architectures = profile
            .architectures
            .iter()
            .map(|a| a.parse().context("parsing architecture"))
            .collect::<Result<_>>()?;
    } else if !profile.arch_map.is_empty() {
        for entry in &profile.arch_map {
            // Find the archMap entry matching our native arch
            let native = native_arch();
            if entry.architecture == native {
                architectures.push(entry.architecture.parse().context("parsing architecture")?);
                for sub in &entry.sub_architectures {
                    architectures.push(sub.parse().context("parsing sub-architecture")?);
                }
                break;
            }
        }
    }

    let default_errno = resolve_errno(&profile.default_errno, &profile.default_errno_ret);

    let mut syscalls = Vec::new();

    for rule in &profile.syscalls {
        // Evaluate excludes (if any match, skip this rule)
        if !rule.excludes.arches.is_empty() && rule.excludes.arches.contains(&arch.to_string()) {
            continue;
        }
        if !rule.excludes.caps.is_empty()
            && rule.excludes.caps.iter().any(|c| capabilities.contains(c))
        {
            continue;
        }

        // Evaluate includes (all must match)
        if !rule.includes.arches.is_empty() && !rule.includes.arches.contains(&arch.to_string()) {
            continue;
        }
        if !rule.includes.caps.is_empty()
            && rule.includes.caps.iter().any(|c| !capabilities.contains(c))
        {
            continue;
        }

        // Collect syscall names
        let names: Vec<String> = if let Some(name) = &rule.name {
            if !rule.names.is_empty() {
                bail!("seccomp rule has both 'name' and 'names', use one or the other");
            }
            vec![name.clone()]
        } else if !rule.names.is_empty() {
            rule.names.clone()
        } else {
            continue;
        };

        let errno_ret = resolve_errno(&rule.errno, &rule.errno_ret);

        let action: LinuxSeccompAction = rule
            .action
            .parse()
            .with_context(|| format!("parsing seccomp action '{}'", rule.action))?;

        let args: Vec<LinuxSeccompArg> = rule
            .args
            .iter()
            .map(|a| {
                let arg: LinuxSeccompArg = serde_json::from_value(serde_json::json!({
                    "index": a.index,
                    "value": a.value,
                    "valueTwo": a.value_two,
                    "op": a.op,
                }))?;
                Ok(arg)
            })
            .collect::<Result<_>>()?;

        let mut syscall = LinuxSyscall::default();
        syscall.set_names(names);
        syscall.set_action(action);
        if let Some(e) = errno_ret {
            syscall.set_errno_ret(Some(e));
        }
        if !args.is_empty() {
            syscall.set_args(Some(args));
        }
        syscalls.push(syscall);
    }

    let default_action: LinuxSeccompAction = profile.default_action.parse().with_context(|| {
        format!(
            "parsing default seccomp action '{}'",
            profile.default_action
        )
    })?;

    // LinuxSeccompBuilder consumes self on each setter, so we must
    // build conditionally by chaining into a single expression.
    let mut spec = LinuxSeccomp::default();
    spec.set_default_action(default_action);
    spec.set_syscalls(Some(syscalls));
    if let Some(e) = default_errno {
        spec.set_default_errno_ret(Some(e));
    }
    if !architectures.is_empty() {
        spec.set_architectures(Some(architectures));
    }
    if !profile.flags.is_empty() {
        let flags: Vec<oci_spec::runtime::LinuxSeccompFilterFlag> = profile
            .flags
            .iter()
            .filter_map(|f| f.parse().ok())
            .collect();
        if !flags.is_empty() {
            spec.set_flags(Some(flags));
        }
    }

    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_known_names() {
        assert_eq!(errno_from_name("EPERM"), Some(1));
        assert_eq!(errno_from_name("ENOSYS"), Some(38));
        assert_eq!(errno_from_name("EINVAL"), Some(22));
        assert_eq!(errno_from_name("ENOTSUP"), Some(95));
        assert_eq!(errno_from_name("EOPNOTSUPP"), Some(95));
    }

    #[test]
    fn errno_unknown() {
        assert_eq!(errno_from_name("BOGUS"), None);
    }

    #[test]
    fn resolve_errno_name_wins() {
        assert_eq!(resolve_errno(&Some("EPERM".into()), &Some(99)), Some(1));
    }

    #[test]
    fn resolve_errno_numeric_name() {
        assert_eq!(resolve_errno(&Some("42".into()), &None), Some(42));
    }

    #[test]
    fn resolve_errno_fallback_to_ret() {
        assert_eq!(resolve_errno(&None, &Some(22)), Some(22));
    }

    #[test]
    fn resolve_errno_none() {
        assert_eq!(resolve_errno(&None, &None), None);
    }

    #[test]
    fn native_arch_not_empty() {
        assert!(!native_arch().is_empty());
        assert!(!native_arch_string().is_empty());
    }
}
