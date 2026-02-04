// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]
#![deny(warnings)]

//! Module for extracting kernel binaries and modules from RPM packages.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::common::{NitroCliErrorEnum, NitroCliFailure, NitroCliResult};
use crate::new_nitro_cli_failure;

/// Kernel config options we care about
const REQUIRED_CONFIG_OPTIONS: &[&str] = &[
    "CONFIG_NSM",
    "CONFIG_VIRTIO_VSOCKETS",
    "CONFIG_VIRTIO_MMIO",
    "CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES",
];

/// Module names corresponding to config options (when built as modules)
const CONFIG_TO_MODULE: &[(&str, &str)] = &[
    ("CONFIG_NSM", "nsm"),
    ("CONFIG_VIRTIO_VSOCKETS", "vmw_vsock_virtio_transport"),
    ("CONFIG_VIRTIO_MMIO", "virtio_mmio"),
];

/// Config option value
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigValue {
    /// Built-in (=y)
    BuiltIn,
    /// Module (=m)
    Module,
    /// Not set
    NotSet,
}

/// Information about extracted kernel
#[derive(Debug)]
pub struct KernelExtractInfo {
    /// Path to kernel image (bzImage or Image)
    pub kernel_image: PathBuf,
    /// Path to kernel config
    pub kernel_config: PathBuf,
    /// List of extracted modules with their dependencies
    pub modules: Vec<ModuleInfo>,
    /// Path to modules manifest file
    pub modules_manifest: PathBuf,
}

/// Information about a kernel module
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Module name
    pub name: String,
    /// Path to the .ko file
    pub path: PathBuf,
    /// Dependencies (other module names)
    pub dependencies: Vec<String>,
}

/// Parse kernel config file and return config values
fn parse_kernel_config(config_path: &Path) -> NitroCliResult<HashMap<String, ConfigValue>> {
    let file = File::open(config_path).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to open kernel config: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    let reader = BufReader::new(file);
    let mut config = HashMap::new();

    for line in reader.lines() {
        let line = line.map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to read config line: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;

        let line = line.trim();

        // Check for "# CONFIG_XXX is not set"
        if line.starts_with("# ") && line.ends_with(" is not set") {
            let config_name = line
                .trim_start_matches("# ")
                .trim_end_matches(" is not set");
            if REQUIRED_CONFIG_OPTIONS.contains(&config_name) {
                config.insert(config_name.to_string(), ConfigValue::NotSet);
            }
            continue;
        }

        // Check for CONFIG_XXX=y or CONFIG_XXX=m
        if let Some((key, value)) = line.split_once('=') {
            if REQUIRED_CONFIG_OPTIONS.contains(&key) {
                let config_value = match value {
                    "y" => ConfigValue::BuiltIn,
                    "m" => ConfigValue::Module,
                    _ => ConfigValue::NotSet,
                };
                config.insert(key.to_string(), config_value);
            }
        }
    }

    Ok(config)
}


/// Get module dependencies using modinfo command
fn get_module_deps_from_modinfo(module_path: &Path) -> Vec<String> {
    let output = Command::new("modinfo")
        .arg("-F")
        .arg("depends")
        .arg(module_path)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let deps_str = String::from_utf8_lossy(&output.stdout);
            deps_str
                .trim()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().to_string())
                .collect()
        }
        _ => vec![],
    }
}

/// Find module path by name in the modules directory
fn find_module_path(modules_dir: &Path, module_name: &str) -> Option<PathBuf> {
    let ko_name = format!("{}.ko", module_name);
    let ko_xz_name = format!("{}.ko.xz", module_name);
    let ko_zst_name = format!("{}.ko.zst", module_name);

    find_file_recursive(modules_dir, &ko_name)
        .or_else(|| find_file_recursive(modules_dir, &ko_xz_name))
        .or_else(|| find_file_recursive(modules_dir, &ko_zst_name))
}

/// Recursively find a file by name
fn find_file_recursive(dir: &Path, filename: &str) -> Option<PathBuf> {
    if !dir.is_dir() {
        return None;
    }

    for entry in fs::read_dir(dir).ok()? {
        let entry = entry.ok()?;
        let path = entry.path();

        if path.is_dir() {
            if let Some(found) = find_file_recursive(&path, filename) {
                return Some(found);
            }
        } else if path.file_name().and_then(|n| n.to_str()) == Some(filename) {
            return Some(path);
        }
    }

    None
}

/// Extract RPM using rpm2cpio and cpio
fn extract_rpm(rpm_path: &Path, output_dir: &Path) -> NitroCliResult<()> {
    fs::create_dir_all(output_dir).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to create output directory: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    // Use rpm2cpio | cpio to extract
    let rpm2cpio = Command::new("rpm2cpio")
        .arg(rpm_path)
        .output()
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to run rpm2cpio: {e}"),
                NitroCliErrorEnum::ProcessSpawnFailure
            )
        })?;

    if !rpm2cpio.status.success() {
        return Err(new_nitro_cli_failure!(
            &format!(
                "rpm2cpio failed: {}",
                String::from_utf8_lossy(&rpm2cpio.stderr)
            ),
            NitroCliErrorEnum::ProcessSpawnFailure
        ));
    }

    let mut cpio = Command::new("cpio")
        .args(["-idm", "--no-absolute-filenames"])
        .current_dir(output_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to spawn cpio: {e}"),
                NitroCliErrorEnum::ProcessSpawnFailure
            )
        })?;

    if let Some(stdin) = cpio.stdin.as_mut() {
        stdin.write_all(&rpm2cpio.stdout).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to write to cpio stdin: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
    }

    let output = cpio.wait_with_output().map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to wait for cpio: {e}"),
            NitroCliErrorEnum::ProcessSpawnFailure
        )
    })?;

    if !output.status.success() {
        return Err(new_nitro_cli_failure!(
            &format!("cpio failed: {}", String::from_utf8_lossy(&output.stderr)),
            NitroCliErrorEnum::ProcessSpawnFailure
        ));
    }

    Ok(())
}


/// Find kernel image in extracted RPM
fn find_kernel_image(extract_dir: &Path, arch: &str) -> NitroCliResult<PathBuf> {
    let boot_dir = extract_dir.join("lib/modules");

    // Find the kernel version directory
    let version_dir = fs::read_dir(&boot_dir)
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to read modules directory: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?
        .filter_map(|e| e.ok())
        .find(|e| e.path().is_dir())
        .map(|e| e.path())
        .ok_or_else(|| {
            new_nitro_cli_failure!(
                "No kernel version directory found",
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;

    // Kernel image is typically in vmlinuz or vmlinux
    let image_name = match arch {
        "x86_64" => "vmlinuz",
        "aarch64" => "vmlinuz",
        _ => "vmlinuz",
    };

    let image_path = version_dir.join(image_name);
    if image_path.exists() {
        return Ok(image_path);
    }

    // Try alternate locations
    let boot_vmlinuz = extract_dir.join("boot").join(format!(
        "vmlinuz-{}",
        version_dir.file_name().unwrap().to_str().unwrap()
    ));
    if boot_vmlinuz.exists() {
        return Ok(boot_vmlinuz);
    }

    Err(new_nitro_cli_failure!(
        &format!("Kernel image not found in {}", extract_dir.display()),
        NitroCliErrorEnum::FileOperationFailure
    ))
}

/// Find kernel config in extracted RPM
fn find_kernel_config(extract_dir: &Path) -> NitroCliResult<PathBuf> {
    let boot_dir = extract_dir.join("lib/modules");

    // Find the kernel version directory
    let version_dir = fs::read_dir(&boot_dir)
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to read modules directory: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?
        .filter_map(|e| e.ok())
        .find(|e| e.path().is_dir())
        .map(|e| e.path())
        .ok_or_else(|| {
            new_nitro_cli_failure!(
                "No kernel version directory found",
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;

    let config_path = version_dir.join("config");
    if config_path.exists() {
        return Ok(config_path);
    }

    // Try /boot/config-VERSION
    let version_name = version_dir.file_name().unwrap().to_str().unwrap();
    let boot_config = extract_dir.join("boot").join(format!("config-{}", version_name));
    if boot_config.exists() {
        return Ok(boot_config);
    }

    Err(new_nitro_cli_failure!(
        "Kernel config not found",
        NitroCliErrorEnum::FileOperationFailure
    ))
}

/// Find modules directory in extracted RPM
fn find_modules_dir(extract_dir: &Path) -> NitroCliResult<PathBuf> {
    let modules_base = extract_dir.join("lib/modules");

    // Find the kernel version directory
    let version_dir = fs::read_dir(&modules_base)
        .map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to read modules directory: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?
        .filter_map(|e| e.ok())
        .find(|e| e.path().is_dir())
        .map(|e| e.path())
        .ok_or_else(|| {
            new_nitro_cli_failure!(
                "No kernel version directory found",
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;

    Ok(version_dir)
}

/// Decompress a module file if compressed
fn decompress_module(src: &Path, dest: &Path) -> NitroCliResult<()> {
    let src_name = src.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if src_name.ends_with(".ko.xz") {
        // Decompress with xz
        let output = Command::new("xz")
            .args(["-dk", "-c"])
            .arg(src)
            .output()
            .map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to run xz: {e}"),
                    NitroCliErrorEnum::ProcessSpawnFailure
                )
            })?;

        if !output.status.success() {
            return Err(new_nitro_cli_failure!(
                &format!("xz decompression failed: {}", String::from_utf8_lossy(&output.stderr)),
                NitroCliErrorEnum::ProcessSpawnFailure
            ));
        }

        fs::write(dest, &output.stdout).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to write decompressed module: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
    } else if src_name.ends_with(".ko.zst") {
        // Decompress with zstd
        let output = Command::new("zstd")
            .args(["-d", "-c"])
            .arg(src)
            .output()
            .map_err(|e| {
                new_nitro_cli_failure!(
                    &format!("Failed to run zstd: {e}"),
                    NitroCliErrorEnum::ProcessSpawnFailure
                )
            })?;

        if !output.status.success() {
            return Err(new_nitro_cli_failure!(
                &format!("zstd decompression failed: {}", String::from_utf8_lossy(&output.stderr)),
                NitroCliErrorEnum::ProcessSpawnFailure
            ));
        }

        fs::write(dest, &output.stdout).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to write decompressed module: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
    } else {
        // Just copy
        fs::copy(src, dest).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to copy module: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
    }

    Ok(())
}


/// Extract kernel binaries and required modules from an RPM
pub fn extract_kernel_binaries(
    rpm_path: &Path,
    output_dir: &Path,
    arch: &str,
) -> NitroCliResult<KernelExtractInfo> {
    // Create output directory
    fs::create_dir_all(output_dir).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to create output directory: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    // Create temp directory for extraction
    let temp_dir = output_dir.join("_extract_temp");
    if temp_dir.exists() {
        fs::remove_dir_all(&temp_dir).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to clean temp directory: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
    }

    eprintln!("Extracting RPM...");
    extract_rpm(rpm_path, &temp_dir)?;

    // Find kernel image
    eprintln!("Locating kernel image...");
    let kernel_image_src = find_kernel_image(&temp_dir, arch)?;
    let kernel_image_name = match arch {
        "x86_64" => "bzImage",
        "aarch64" => "Image",
        _ => "vmlinuz",
    };
    let kernel_image_dest = output_dir.join(kernel_image_name);
    fs::copy(&kernel_image_src, &kernel_image_dest).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to copy kernel image: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;
    eprintln!("  Kernel image: {}", kernel_image_dest.display());

    // Find and copy kernel config
    eprintln!("Locating kernel config...");
    let kernel_config_src = find_kernel_config(&temp_dir)?;
    let kernel_config_dest = output_dir.join("config");
    fs::copy(&kernel_config_src, &kernel_config_dest).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to copy kernel config: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;
    eprintln!("  Kernel config: {}", kernel_config_dest.display());

    // Parse kernel config to determine which modules we need
    eprintln!("Parsing kernel config...");
    let config = parse_kernel_config(&kernel_config_dest)?;

    // Report config status
    let mut modules_needed: Vec<String> = vec![];
    for option in REQUIRED_CONFIG_OPTIONS {
        let value = config.get(*option).unwrap_or(&ConfigValue::NotSet);
        let status = match value {
            ConfigValue::BuiltIn => "built-in (y)",
            ConfigValue::Module => "module (m)",
            ConfigValue::NotSet => "not set",
        };
        eprintln!("  {}: {}", option, status);

        if *value == ConfigValue::Module {
            // Find corresponding module name
            if let Some((_, module_name)) = CONFIG_TO_MODULE.iter().find(|(cfg, _)| cfg == option) {
                modules_needed.push(module_name.to_string());
            }
        }
    }

    // Find modules directory
    let modules_dir = find_modules_dir(&temp_dir)?;

    // Create modules output directory
    let modules_output_dir = output_dir.join("modules");
    if !modules_needed.is_empty() {
        fs::create_dir_all(&modules_output_dir).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to create modules directory: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
    }

    // Extract required modules and their dependencies using modinfo
    eprintln!("Extracting required modules...");
    let mut extracted_modules: Vec<ModuleInfo> = vec![];
    let mut modules_to_process: Vec<String> = modules_needed.clone();
    let mut processed_modules: HashSet<String> = HashSet::new();

    while let Some(module_name) = modules_to_process.pop() {
        if processed_modules.contains(&module_name) {
            continue;
        }
        processed_modules.insert(module_name.clone());

        if let Some(module_src) = find_module_path(&modules_dir, &module_name) {
            let module_dest = modules_output_dir.join(format!("{}.ko", module_name));
            decompress_module(&module_src, &module_dest)?;

            // Get dependencies using modinfo on the extracted module
            let dependencies = get_module_deps_from_modinfo(&module_dest);

            eprintln!("  {} (deps: {:?})", module_name, dependencies);

            // Add dependencies to processing queue
            for dep in &dependencies {
                if !processed_modules.contains(dep) {
                    modules_to_process.push(dep.clone());
                }
            }

            extracted_modules.push(ModuleInfo {
                name: module_name.clone(),
                path: module_dest,
                dependencies,
            });
        } else {
            eprintln!("  Warning: Module {} not found", module_name);
        }
    }

    // Sort modules by name for consistent output
    extracted_modules.sort_by(|a, b| a.name.cmp(&b.name));

    // Create modules manifest
    let manifest_path = output_dir.join("modules.txt");
    let mut manifest = File::create(&manifest_path).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to create modules manifest: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    writeln!(manifest, "# Kernel modules extracted for Nitro Enclaves").map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to write manifest: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;
    writeln!(manifest, "# Format: module_name: dependency1, dependency2, ...").map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to write manifest: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;
    writeln!(manifest).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to write manifest: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    // Write config status
    writeln!(manifest, "# Config options:").map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to write manifest: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;
    for option in REQUIRED_CONFIG_OPTIONS {
        let value = config.get(*option).unwrap_or(&ConfigValue::NotSet);
        let status = match value {
            ConfigValue::BuiltIn => "y (built-in)",
            ConfigValue::Module => "m (module)",
            ConfigValue::NotSet => "not set",
        };
        writeln!(manifest, "#   {}={}", option, status).map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to write manifest: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
    }
    writeln!(manifest).map_err(|e| {
        new_nitro_cli_failure!(
            &format!("Failed to write manifest: {e}"),
            NitroCliErrorEnum::FileOperationFailure
        )
    })?;

    // Write modules and dependencies
    if extracted_modules.is_empty() {
        writeln!(manifest, "# No modules needed - all required features are built-in").map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to write manifest: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
    } else {
        writeln!(manifest, "# Extracted modules:").map_err(|e| {
            new_nitro_cli_failure!(
                &format!("Failed to write manifest: {e}"),
                NitroCliErrorEnum::FileOperationFailure
            )
        })?;
        for module in &extracted_modules {
            if module.dependencies.is_empty() {
                writeln!(manifest, "{}", module.name).map_err(|e| {
                    new_nitro_cli_failure!(
                        &format!("Failed to write manifest: {e}"),
                        NitroCliErrorEnum::FileOperationFailure
                    )
                })?;
            } else {
                writeln!(manifest, "{}: {}", module.name, module.dependencies.join(", ")).map_err(|e| {
                    new_nitro_cli_failure!(
                        &format!("Failed to write manifest: {e}"),
                        NitroCliErrorEnum::FileOperationFailure
                    )
                })?;
            }
        }
    }

    // Clean up temp directory
    fs::remove_dir_all(&temp_dir).ok();

    eprintln!("\nExtraction complete:");
    eprintln!("  Kernel image: {}", kernel_image_dest.display());
    eprintln!("  Kernel config: {}", kernel_config_dest.display());
    eprintln!("  Modules manifest: {}", manifest_path.display());
    if !extracted_modules.is_empty() {
        eprintln!("  Modules directory: {}", modules_output_dir.display());
        eprintln!("  Total modules: {}", extracted_modules.len());
    }

    Ok(KernelExtractInfo {
        kernel_image: kernel_image_dest,
        kernel_config: kernel_config_dest,
        modules: extracted_modules,
        modules_manifest: manifest_path,
    })
}
