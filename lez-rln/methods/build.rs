use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Command,
};

use risc0_build::GuestOptionsBuilder;

fn main() {
    // Local (non-docker) build: docker mode's context (lez-rln/) excludes the
    // sibling lssa/spel path deps, and needs a running daemon. Local mode builds
    // the guest directly with the host risc0 toolchain, resolving path deps.
    let opts = GuestOptionsBuilder::default().build().unwrap();
    let mut map = HashMap::new();
    map.insert("logos_lez_rln_guest", opts);
    risc0_build::embed_methods_with_options(map);

    // Post-build: strip non-loadable sections (symtab/strtab/eh_frame/etc.)
    // from the user ELF inside each R0BF .bin. Deploys upload only the user
    // ELF, in 96 KiB segments, so this trims segment count rather than a
    // per-tx cap. The on-chain image_id changes (the ELF header bytes are part
    // of the first PT_LOAD segment), but the lez-rln host reads the .bin file
    // fresh at runtime via `Program::new`, so the expected program ID matches
    // the deployed bytecode automatically.
    //
    // The kernel ELF is left untouched: the program loader refuses any binary
    // whose kernel is not byte-identical to `risc0_zkos_v1compat::V1COMPAT_ELF`,
    // and it is never uploaded anyway.
    let strip = locate_llvm_strip()
        .expect("llvm-strip not found under ~/.risc0/toolchains/*/lib/rustlib/*/bin/");

    // Strip both guest build trees when present (idempotent — a stripped R0BF
    // re-strips to the same bytes):
    //   - the methods-crate local build (`cargo build`), and
    //   - the reproducible docker build (`cargo risczero build`), which is the DEPLOY artifact the
    //     host reads via `REGISTRATION_BINARY`. This one is produced by a separate invocation, so a
    //     `cargo build` after `cargo risczero build` is what strips it under the per-tx cap.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bin_dirs = [
        manifest
            .join("target/riscv-guest/logos_lez_rln_methods/logos_lez_rln_guest")
            .join("riscv32im-risc0-zkvm-elf/release"),
        manifest.join("guest/target/riscv32im-risc0-zkvm-elf/docker"),
    ];

    for bin_dir in &bin_dirs {
        for name in ["rln_registration.bin"] {
            let path = bin_dir.join(name);
            if path.exists() {
                strip_program_binary(&path, &strip);
            }
        }
    }
}

/// Find `llvm-strip` shipped with the risc0 rust toolchain. Search order:
/// 1. `$RISC0_LLVM_STRIP` if explicitly set.
/// 2. `~/.risc0/toolchains/v*-rust-*/lib/rustlib/<host-triple>/bin/llvm-strip`.
fn locate_llvm_strip() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("RISC0_LLVM_STRIP") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    let home = std::env::var("HOME").ok()?;
    let host = std::env::var("HOST").ok()?;
    let toolchains = PathBuf::from(home).join(".risc0").join("toolchains");
    let entries = std::fs::read_dir(&toolchains).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with('v') || !name.contains("-rust-") {
            continue;
        }
        let candidate = entry
            .path()
            .join("lib")
            .join("rustlib")
            .join(&host)
            .join("bin")
            .join("llvm-strip");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Strip the user ELF inside a risc0 `R0BF` binary in place. Format is:
/// `b"R0BF" | u32 version | u32 header_len | header | u32 user_len | user_elf | kernel_elf`.
/// We unpack the user ELF, run `llvm-strip --strip-all` on it, and re-pack
/// with the kernel ELF byte-for-byte unchanged. The user ELF carries
/// non-loadable sections (symtab/strtab/comment) the zkVM never maps into its
/// image, so stripping them removes deploy bytes without changing one executed
/// instruction.
fn strip_program_binary(path: &Path, strip: &Path) {
    let blob = std::fs::read(path).expect("read program binary");
    let (header, user_elf, kernel_elf) = split_r0bf(&blob, path);

    let stripped_user = strip_elf(user_elf, strip, &path.with_extension("user.elf.tmp"));

    let ver: u32 = 1;
    let mut out: Vec<u8> = Vec::with_capacity(blob.len());
    out.extend_from_slice(b"R0BF");
    out.extend_from_slice(&ver.to_le_bytes());
    out.extend_from_slice(&(header.len() as u32).to_le_bytes());
    out.extend_from_slice(header);
    out.extend_from_slice(&(stripped_user.len() as u32).to_le_bytes());
    out.extend_from_slice(&stripped_user);
    out.extend_from_slice(kernel_elf);
    std::fs::write(path, &out).expect("write stripped binary");
    println!(
        "cargo:warning=stripped {} : {} -> {} B (user {}->{})",
        path.file_name().unwrap().to_string_lossy(),
        blob.len(),
        out.len(),
        user_elf.len(),
        stripped_user.len(),
    );
}

/// Split an `R0BF` v1 blob into `(header, user_elf, kernel_elf)` slices.
fn split_r0bf<'a>(blob: &'a [u8], path: &Path) -> (&'a [u8], &'a [u8], &'a [u8]) {
    let read_u32 =
        |b: &[u8], off: usize| -> u32 { u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) };
    let mut cur = 0usize;
    assert_eq!(
        &blob[cur..cur + 4],
        b"R0BF",
        "expected R0BF magic in {path:?}"
    );
    cur += 4;
    // The parse assumes the v1 container layout; refuse anything else rather
    // than silently repacking (and version-clobbering) a future format.
    let ver = read_u32(blob, cur);
    assert_eq!(ver, 1, "unsupported R0BF version {ver} in {path:?}");
    cur += 4;
    let header_len = read_u32(blob, cur) as usize;
    cur += 4;
    let header_end = cur + header_len;
    let header = &blob[cur..header_end];
    cur = header_end;
    let user_len = read_u32(blob, cur) as usize;
    cur += 4;
    let user_elf = &blob[cur..cur + user_len];
    cur += user_len;
    let kernel_elf = &blob[cur..];
    (header, user_elf, kernel_elf)
}

/// Run `llvm-strip --strip-all` on `elf` bytes via a temp file, returning the
/// stripped bytes.
fn strip_elf(elf: &[u8], strip: &Path, tmp: &Path) -> Vec<u8> {
    std::fs::write(tmp, elf).expect("write tmp elf");
    let status = Command::new(strip)
        .args(["--strip-all", tmp.to_str().unwrap()])
        .status()
        .expect("invoke llvm-strip");
    assert!(status.success(), "llvm-strip failed on {tmp:?}");
    let stripped = std::fs::read(tmp).expect("read stripped elf");
    std::fs::remove_file(tmp).ok();
    stripped
}
