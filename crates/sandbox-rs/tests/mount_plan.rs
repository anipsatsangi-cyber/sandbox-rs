//! Functional check of the ordered mount plan inside a real, privileged
//! sandbox child (mount namespace + chroot).
//!
//! Requires root on a Linux host with user/mount namespaces; the suite is
//! ignored by default so a normal `cargo test` stays unprivileged:
//!
//!   sudo cargo test -p sandbox-rs --test mount_plan -- --ignored --nocapture

use sandbox_rs::execution::ProcessExecutor;
use sandbox_rs::{
    MountSource, MountSpec, NamespaceConfig, ProcessConfig,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn mount_ns() -> NamespaceConfig {
    NamespaceConfig {
        pid: false,
        ipc: false,
        net: false,
        mount: true,
        uts: false,
        user: false,
    }
}

/// Run `/bin/sh -c <script>` in a chroot at `root` with the given mount plan.
fn run(root: &Path, mounts: Vec<MountSpec>, script: &str) -> i32 {
    let config = ProcessConfig {
        program: "/bin/sh".to_string(),
        args: vec!["-c".to_string(), script.to_string()],
        chroot_dir: Some(root.to_string_lossy().into_owned()),
        inherit_env: false,
        env: vec![(
            "PATH".to_string(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        )],
        mounts,
        ..Default::default()
    };
    ProcessExecutor::execute(config, mount_ns())
        .expect("sandbox execution")
        .exit_status
}

fn fixture() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let collections = tmp.path().join("collections");
    fs::create_dir_all(collections.join("acme")).unwrap();
    fs::create_dir_all(collections.join("secret")).unwrap();
    fs::write(collections.join("acme/file.txt"), b"acme").unwrap();
    fs::write(collections.join("secret/file.txt"), b"secret").unwrap();
    // The chroot's own /collections must exist for the tmpfs target.
    fs::set_permissions(&collections, fs::Permissions::from_mode(0o755)).unwrap();
    tmp
}

fn mask_then_bind(root: &Path) -> Vec<MountSpec> {
    vec![
        MountSpec {
            source: MountSource::Tmpfs,
            target: "/collections".to_string(),
            read_only: false,
        },
        MountSpec {
            source: MountSource::Bind(root.join("collections/acme")),
            target: "/collections/acme".to_string(),
            read_only: true,
        },
    ]
}

#[test]
#[ignore = "needs root + mount namespaces"]
fn unmounted_child_sees_every_sibling() {
    let tmp = fixture();
    let code = run(
        tmp.path(),
        Vec::new(),
        "ls /collections | grep -qx secret && ls /collections | grep -qx acme",
    );
    assert_eq!(code, 0, "baseline child should see both collections");
}

#[test]
#[ignore = "needs root + mount namespaces"]
fn tmpfs_masks_unmapped_siblings_and_binds_mapped_ones() {
    let tmp = fixture();
    let code = run(
        tmp.path(),
        mask_then_bind(tmp.path()),
        "[ -e /collections/acme/file.txt ] || exit 10; \
         [ ! -e /collections/secret ] || exit 11; \
         ls /collections | grep -qx acme || exit 12",
    );
    assert_eq!(code, 0, "only the mapped collection should be visible");
}

#[test]
#[ignore = "needs root + mount namespaces"]
fn read_only_bind_refuses_writes() {
    let tmp = fixture();
    let code = run(
        tmp.path(),
        mask_then_bind(tmp.path()),
        "touch /collections/acme/new.txt 2>/dev/null && exit 10; exit 0",
    );
    assert_eq!(code, 0, "the mapped collection must be read-only");
}

#[test]
#[ignore = "needs root + mount namespaces"]
fn writable_bind_accepts_writes() {
    let tmp = fixture();
    let mut mounts = mask_then_bind(tmp.path());
    mounts[1].read_only = false;
    let code = run(
        tmp.path(),
        mounts,
        "touch /collections/acme/new.txt",
    );
    assert_eq!(code, 0, "a writable bind should accept writes");
}

#[test]
#[ignore = "needs root + mount namespaces"]
fn missing_bind_source_aborts_the_command() {
    let tmp = fixture();
    let mounts = vec![
        MountSpec {
            source: MountSource::Tmpfs,
            target: "/collections".to_string(),
            read_only: false,
        },
        MountSpec {
            source: MountSource::Bind(tmp.path().join("collections/missing")),
            target: "/collections/missing".to_string(),
            read_only: false,
        },
    ];
    let code = run(tmp.path(), mounts, "exit 0");
    assert_ne!(code, 0, "a failed mount must abort, never run unfiltered");
}
