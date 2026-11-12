//! Process execution within sandbox namespace
//!
//! Key changes from the original implementation:
//! - Stack size: 128KB (was 8KB)
//! - Memory leak fix: clone config into closure instead of Box::into_raw
//! - Seccomp: NO root check (seccomp only needs PR_SET_NO_NEW_PRIVS)
//! -  User namespace: child self-writes UID/GID mapping (nested userns compatible)
//! - Resource limits: applies RlimitConfig in child before execve

use sandbox_cgroup::RlimitConfig;
use sandbox_core::{Result, SandboxError};
use sandbox_namespace::NamespaceConfig;
use sandbox_seccomp::{SeccompBpf, SeccompFilter};

// use log::warn;
use nix::sched::clone;
use nix::sys::signal::Signal;
use nix::unistd::{AccessFlags, Pid, access, chdir, chroot, execve};
use std::ffi::CString;
use std::mem;
use std::os::fd::IntoRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::thread;

use crate::execution::stream::{ProcessStream, spawn_fd_reader};

/// What a mount plan entry mounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountSource {
    /// Bind an existing host path (file or directory) into the sandbox, so
    /// the child sees the host tree at `MountSpec::target`.
    Bind(PathBuf),
    /// An empty tmpfs at the target, masking whatever the sandbox root
    /// already holds there (e.g. clearing a directory of sibling entries).
    Tmpfs,
}

/// One ordered mount the sandbox applies inside its private mount
/// namespace, before chroot. Targets are absolute paths INSIDE the sandbox
/// root; they are prefixed with the chroot directory internally.
///
/// Entries apply in the order given: a caller mounts a masking tmpfs before
/// the binds that repopulate it. Sources are opened before any mount runs,
/// so a masking mount cannot change what a later bind resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountSpec {
    pub source: MountSource,
    /// Absolute path inside the sandbox root, e.g. "/collections/acme".
    pub target: String,
    /// Remount the bind read-only (the bind itself is always created
    /// read-write first; the kernel cannot strengthen a mount otherwise).
    pub read_only: bool,
}

impl MountSpec {
    /// Validate the shape. Source EXISTENCE is checked when the child applies
    /// the plan (it may live outside this build host's view).
    pub fn validate(&self) -> std::result::Result<(), String> {
        if !self.target.starts_with('/') {
            return Err(format!("mount target must be absolute: {}", self.target));
        }
        if self.target == "/" {
            return Err("mount target cannot be the sandbox root".to_string());
        }
        if self
            .target
            .split('/')
            .any(|component| component == ".." || component == ".")
        {
            return Err(format!("mount target must not contain dot components: {}", self.target));
        }
        match &self.source {
            MountSource::Bind(path) => {
                if !path.is_absolute() {
                    return Err(format!(
                        "bind source must be an absolute host path: {}",
                        path.display()
                    ));
                }
            }
            MountSource::Tmpfs => {
                if self.read_only {
                    return Err(
                        "a tmpfs mount cannot be read-only remounted; tmpfs is writable by construction"
                            .to_string(),
                    );
                }
            }
        }
        Ok(())
    }
}

/// Process execution configuration
#[derive(Debug, Clone)]
pub struct ProcessConfig {
    /// Program to execute
    pub program: String,
    /// Program arguments
    pub args: Vec<String>,
    /// Environment variables
    pub env: Vec<(String, String)>,
    /// Working directory (inside sandbox)
    pub cwd: Option<String>,
    /// Root directory for chroot
    pub chroot_dir: Option<String>,
    /// UID to run as
    pub uid: Option<u32>,
    /// GID to run as
    pub gid: Option<u32>,
    /// Seccomp filter
    pub seccomp: Option<SeccompFilter>,
    /// Resource limits (unprivileged fallback via setrlimit)
    pub rlimits: Option<RlimitConfig>,
    /// Whether to inherit the parent environment (with optional overrides)
    pub inherit_env: bool,
    /// Whether to set up user namespace UID/GID mapping
    pub use_user_namespace: bool,
    /// Host UID to map inside user namespace (None = use current process uid)
    pub host_uid: Option<u32>,
    /// Host GID to map inside user namespace (None = use current process gid)
    pub host_gid: Option<u32>,
    /// Ordered mount plan applied inside the private mount namespace, before
    /// chroot. Empty keeps the historical behavior (system paths only).
    pub mounts: Vec<MountSpec>,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            program: String::new(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            chroot_dir: None,
            uid: None,
            gid: None,
            seccomp: None,
            rlimits: None,
            inherit_env: true,
            use_user_namespace: false,
            host_uid: None,
            host_gid: None,
            mounts: Vec::new(),
        }
    }
}

impl ProcessConfig {
    /// Ensure the environment vector reflects the inherited parent environment (plus overrides)
    fn prepare_environment(&mut self) {
        if !self.inherit_env {
            return;
        }

        let overrides = mem::take(&mut self.env);
        let mut combined: Vec<(String, String)> = std::env::vars().collect();

        if overrides.is_empty() {
            self.env = combined;
            return;
        }

        for (key, value) in overrides {
            if let Some((_, existing)) = combined.iter_mut().find(|(k, _)| k == &key) {
                *existing = value;
            } else {
                combined.push((key, value));
            }
        }

        self.env = combined;
    }
}

/// Resolve a program name to an absolute path using PATH semantics.
fn resolve_program_path(
    program: &str,
    env: &[(String, String)],
) -> std::result::Result<String, String> {
    if program.contains('/') {
        return Ok(program.to_string());
    }

    const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    let path_value = env
        .iter()
        .find(|(key, _)| key == "PATH")
        .map(|(_, value)| value.as_str())
        .unwrap_or(DEFAULT_PATH);

    for entry in path_value.split(':') {
        let dir = if entry.is_empty() { "." } else { entry };
        let candidate = Path::new(dir).join(program);

        if access(&candidate, AccessFlags::X_OK).is_ok() {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }

    Err(format!("execve failed: command not found: {}", program))
}

/// Result of process execution
#[derive(Debug, Clone)]
pub struct ProcessResult {
    /// Process ID
    pub pid: Pid,
    /// Exit status
    pub exit_status: i32,
    /// Signal if killed
    pub signal: Option<i32>,
    /// Execution time in milliseconds
    pub exec_time_ms: u64,
}

/// Process executor
pub struct ProcessExecutor;

impl ProcessExecutor {
    /// Clone a child process with optional user namespace synchronization.
    ///
    /// When user namespace is enabled, creates a sync pipe so the parent can
    /// write uid_map/gid_map before the child proceeds with setup.
    fn clone_child(
        mut child_fn: Box<dyn FnMut() -> isize>,
        child_stack: &mut [u8],
        namespace_config: &NamespaceConfig,
        use_user_namespace: bool,
        host_uid: Option<u32>,
        host_gid: Option<u32>,        
    ) -> Result<Pid> {
        let flags = namespace_config.to_clone_flags();
        if use_user_namespace && namespace_config.user {
            // Compute uid/gid before the closure takes ownership
            let uid = host_uid.unwrap_or_else(|| sandbox_core::util::get_uid());
            let gid = host_gid.unwrap_or_else(|| sandbox_core::util::get_gid());
 
            // Create sync pipe for child→parent signaling
            let (sync_read, sync_write) =
                nix::unistd::pipe().map_err(|e| SandboxError::Syscall(format!("pipe: {}", e)))?;
            let sync_read_raw = sync_read.as_raw_fd();
            let sync_write_raw = sync_write.as_raw_fd();
 
            // Wrap the child function: child self-writes uid_map/gid_map,
            // then signals parent before proceeding with child_setup
            let wrapped = Box::new(move || -> isize {
                // SAFETY: raw FD operations in child process after clone
                unsafe {
                    // Close child's copy of the read end (not needed)
                    libc::close(sync_read_raw);
                }
 
                // Write setgroups(deny) ,  must happen before uid_map write
                if let Err(e) = std::fs::write("/proc/self/setgroups", "deny") {
                    eprintln!("child setgroups failed: {}", e);
                    unsafe { libc::close(sync_write_raw); }
                    return 1;
                }
 
                // Write uid_map: map host_uid → 0 inside this namespace
                let uid_map = format!("0 {} 1\n", uid);
                if let Err(e) = std::fs::write("/proc/self/uid_map", &uid_map) {
                    eprintln!("child uid_map write failed: {}", e);
                    unsafe { libc::close(sync_write_raw); }
                    return 1;
                }
 
                // Write gid_map: map host_gid → 0 inside this namespace
                let gid_map = format!("0 {} 1\n", gid);
                if let Err(e) = std::fs::write("/proc/self/gid_map", &gid_map) {
                    eprintln!("child gid_map write failed: {}", e);
                    unsafe { libc::close(sync_write_raw); }
                    return 1;
                }
 
                // Signal parent that mapping is complete
                unsafe {
                    let signal_byte: [u8; 1] = [1];
                    libc::write(
                        sync_write_raw,
                        signal_byte.as_ptr() as *const libc::c_void,
                        1,
                    );
                    libc::close(sync_write_raw);
                }
 
                child_fn()
            });
 
            let result =
                unsafe { clone(wrapped, child_stack, flags, Some(Signal::SIGCHLD as i32)) };
 
            // Parent: close our copy of the write end
            drop(sync_write);
 
            match result {
                Ok(child_pid) => {
                    // Parent waits for child to signal mapping is done
                    unsafe {
                        let mut buf = [0u8; 1];
                        libc::read(
                            sync_read.as_raw_fd(),
                            buf.as_mut_ptr() as *mut libc::c_void,
                            1,
                        );
                    }
                    drop(sync_read);
                    Ok(child_pid)
                }
                Err(e) => {
                    drop(sync_read);
                    Err(SandboxError::Syscall(format!("clone failed: {}", e)))
                }
            }
        

        // if use_user_namespace && namespace_config.user {
        //     // Create sync pipe for parent→child signaling
        //     let (sync_read, sync_write) =
        //         nix::unistd::pipe().map_err(|e| SandboxError::Syscall(format!("pipe: {}", e)))?;
        //     let sync_read_raw = sync_read.as_raw_fd();
        //     let sync_write_raw = sync_write.as_raw_fd();

        //     // Wrap the child function to wait for parent's user namespace setup
        //     let wrapped = Box::new(move || -> isize {
        //         // SAFETY: raw FD operations in child process after clone
        //         unsafe {
        //             // Close child's copy of the write end
        //             libc::close(sync_write_raw);
        //             // Wait for parent to signal (parent writes 1 byte after uid_map setup)
        //             let mut buf = [0u8; 1];
        //             libc::read(sync_read_raw, buf.as_mut_ptr() as *mut libc::c_void, 1);
        //             libc::close(sync_read_raw);
        //         }
        //         child_fn()
        //     });

        //     let result =
        //         unsafe { clone(wrapped, child_stack, flags, Some(Signal::SIGCHLD as i32)) };

        //     // Parent: close our copy of the read end
        //     drop(sync_read);

        //     match result {
        //         Ok(child_pid) => {
        //             // Write UID/GID mapping for the child's user namespace
        //             let uid = host_uid.unwrap_or_else(|| sandbox_core::util::get_uid());
        //             let gid = host_gid.unwrap_or_else(|| sandbox_core::util::get_gid());
        //             if let Err(e) =
        //                 sandbox_namespace::user_ns::setup_user_namespace(child_pid, uid, gid)
        //             {
        //                 warn!("User namespace setup failed: {}", e);
        //             }

        //             // Signal child to proceed
        //             // SAFETY: sync_write is a valid FD, writing 1 byte
        //             unsafe {
        //                 let signal_byte: [u8; 1] = [1];
        //                 libc::write(
        //                     sync_write.as_raw_fd(),
        //                     signal_byte.as_ptr() as *const libc::c_void,
        //                     1,
        //                 );
        //             }
        //             drop(sync_write);
        //             Ok(child_pid)
        //         }
        //         Err(e) => Err(SandboxError::Syscall(format!("clone failed: {}", e))),
        //     }
        } else {
            // No user namespace - clone directly
            let result =
                unsafe { clone(child_fn, child_stack, flags, Some(Signal::SIGCHLD as i32)) };
            result.map_err(|e| SandboxError::Syscall(format!("clone failed: {}", e)))
        }
    }

    /// Execute process with namespace isolation
    pub fn execute(
        mut config: ProcessConfig,
        namespace_config: NamespaceConfig,
    ) -> Result<ProcessResult> {
        let mut child_stack = vec![0u8; 131072]; // 128KB stack (was 8KB)

        config.prepare_environment();
        let use_user_ns = config.use_user_namespace;
        let host_uid = config.host_uid;
        let host_gid = config.host_gid;        

        // Move config into closure (fixes memory leak from Box::into_raw pattern)
        let mut child_config = Some(config);

        let child_pid = Self::clone_child(
            Box::new(move || Self::child_setup(child_config.take().unwrap())),
            &mut child_stack,
            &namespace_config,
            use_user_ns,
            host_uid,
            host_gid,            
        )?;

        let start = std::time::Instant::now();
        let status = wait_for_child(child_pid)?;
        let exec_time_ms = start.elapsed().as_millis() as u64;

        Ok(ProcessResult {
            pid: child_pid,
            exit_status: status,
            signal: None,
            exec_time_ms,
        })
    }

    /// Execute process with streaming output
    pub fn execute_with_stream(
        mut config: ProcessConfig,
        namespace_config: NamespaceConfig,
        enable_streams: bool,
    ) -> Result<(ProcessResult, Option<ProcessStream>)> {
        if !enable_streams {
            let result = Self::execute(config, namespace_config)?;
            return Ok((result, None));
        }

        let (stdout_read, stdout_write) = nix::unistd::pipe()
            .map_err(|e| SandboxError::Io(std::io::Error::other(format!("pipe failed: {}", e))))?;
        let (stderr_read, stderr_write) = nix::unistd::pipe()
            .map_err(|e| SandboxError::Io(std::io::Error::other(format!("pipe failed: {}", e))))?;

        let mut child_stack = vec![0u8; 131072]; // 128KB stack

        config.prepare_environment();
        let use_user_ns = config.use_user_namespace;
        let host_uid = config.host_uid;
        let host_gid = config.host_gid;        
        let stdout_write_fd = stdout_write.as_raw_fd();
        let stderr_write_fd = stderr_write.as_raw_fd();

        let mut child_config = Some(config);

        let child_pid = Self::clone_child(
            Box::new(move || {
                Self::child_setup_with_pipes(
                    child_config.take().unwrap(),
                    stdout_write_fd,
                    stderr_write_fd,
                )
            }),
            &mut child_stack,
            &namespace_config,
            use_user_ns,
            host_uid,
            host_gid,
        )?;

        // Parent: close write ends (child has copies via clone)
        drop(stdout_write);
        drop(stderr_write);

        let (stream_writer, process_stream) = ProcessStream::new();

        let tx1 = stream_writer.tx.clone();
        let tx2 = stream_writer.tx.clone();

        spawn_fd_reader(stdout_read.into_raw_fd(), false, tx1).map_err(|e| {
            SandboxError::Io(std::io::Error::other(format!("spawn reader failed: {}", e)))
        })?;
        spawn_fd_reader(stderr_read.into_raw_fd(), true, tx2).map_err(|e| {
            SandboxError::Io(std::io::Error::other(format!("spawn reader failed: {}", e)))
        })?;

        thread::spawn(move || match wait_for_child(child_pid) {
            Ok(status) => {
                let _ = stream_writer.send_exit(status, None);
            }
            Err(_) => {
                let _ = stream_writer.send_exit(1, None);
            }
        });

        let process_result = ProcessResult {
            pid: child_pid,
            exit_status: 0,
            signal: None,
            exec_time_ms: 0,
        };

        Ok((process_result, Some(process_stream)))
    }

    /// Setup child process environment.
    ///
    /// Order of operations:
    /// 1. Apply resource limits (before seccomp locks things down)
    /// 2. Chroot (if specified)
    /// 3. Chdir
    /// 4. Drop privileges (setgid/setuid)
    /// 5. Apply seccomp filter (last - irreversible lockdown before execve)
    /// 6. Execve
    fn child_setup(config: ProcessConfig) -> isize {
        let ProcessConfig {
            program,
            args,
            env,
            cwd,
            chroot_dir,
            uid,
            gid,
            seccomp,
            rlimits,
            inherit_env: _,
            use_user_namespace: _,
            host_uid: _,
            host_gid: _,
            mounts,
        } = config;

        // 1. Apply resource limits (before seccomp, which may restrict setrlimit)
        if let Some(ref rlimits) = rlimits
            && let Err(e) = rlimits.apply()
        {
            eprintln!("Failed to apply rlimits: {}", e);
            return 1;
        }

        // 2. Change root if specified
        //    Bind-mount system paths into the chroot dir first, then chroot.
        //    The child has CAP_SYS_ADMIN in the user namespace + mount namespace,
        //    so bind mounts only affect this namespace (not the host).
        if let Some(chroot_path) = &chroot_dir {
            let system_paths = [
                "/usr", "/lib", "/lib64", "/bin", "/sbin",
                "/etc", "/dev", "/proc", "/sys", "/tmp",
            ];
            for sys_path in system_paths {
                let dest = format!("{}{}", chroot_path, sys_path);
                let _ = std::fs::create_dir_all(&dest);
                let src = CString::new(sys_path).unwrap();
                let dst = CString::new(dest.as_str()).unwrap();
                let ret = unsafe {
                    libc::mount(
                        src.as_ptr(),
                        dst.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND | libc::MS_REC,
                        std::ptr::null(),
                    )
                };
                if ret != 0 {
                    // eprintln!("bind mount {} -> {} failed", sys_path, dest);
                    let err = std::io::Error::last_os_error();
                    eprintln!("bind mount {} -> {} failed: {} (errno {})", sys_path, dest, err, err.raw_os_error().unwrap_or(0));
                }
            }

            // 2b. Apply the caller's ordered mount plan. A mount failure is
            //     FATAL: running with a partial view could expose siblings the
            //     caller meant to mask. An empty plan changes nothing.
            if !mounts.is_empty()
                && let Err(e) = apply_mounts(chroot_path, &mounts)
            {
                eprintln!("mount plan failed: {}", e);
                return 1;
            }

            if let Err(e) = chroot(chroot_path.as_str()) {
                eprintln!("chroot failed: {}", e);
                return 1;
            }
        }

        // 3. Change directory
        let cwd = cwd.as_deref().unwrap_or("/");
        if let Err(e) = chdir(cwd) {
            eprintln!("chdir failed: {}", e);
            return 1;
        }

        // 4. Drop privileges if specified (no root check - fails explicitly if needed)
        if let Some(gid) = gid
            && unsafe { libc::setgid(gid) } != 0
        {
            eprintln!("setgid failed");
            return 1;
        }

        if let Some(uid) = uid
            && unsafe { libc::setuid(uid) } != 0
        {
            eprintln!("setuid failed");
            return 1;
        }

        // 5. Apply seccomp filter - NO root check!
        // Seccomp only needs PR_SET_NO_NEW_PRIVS, which works for any process.
        if let Some(filter) = &seccomp
            && let Err(e) = SeccompBpf::load(filter)
        {
            eprintln!("Failed to load seccomp: {}", e);
            return 1;
        }

        // 6. Prepare environment and execute
        let env_vars: Vec<CString> = env
            .iter()
            .map(|(k, v)| CString::new(format!("{}={}", k, v)).unwrap())
            .collect();

        let env_refs: Vec<&CString> = env_vars.iter().collect();

        let resolved_program = match resolve_program_path(&program, &env) {
            Ok(path) => path,
            Err(err) => {
                eprintln!("{}", err);
                return 1;
            }
        };

        let program_cstring = match CString::new(resolved_program) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("program name contains nul byte");
                return 1;
            }
        };

        let args_cstrings: Vec<CString> = args
            .iter()
            .map(|s| CString::new(s.clone()).unwrap_or_else(|_| CString::new("").unwrap()))
            .collect();

        let mut args_refs: Vec<&CString> = vec![&program_cstring];
        args_refs.extend(args_cstrings.iter());

        match execve(&program_cstring, &args_refs, &env_refs) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("execve failed: {}", e);
                1
            }
        }
    }

    /// Setup child process with pipe redirection
    fn child_setup_with_pipes(config: ProcessConfig, stdout_fd: i32, stderr_fd: i32) -> isize {
        // SAFETY: FDs are valid from parent and we're in a child process about to exec
        unsafe {
            if libc::dup2(stdout_fd, 1) < 0 {
                eprintln!("dup2 stdout failed");
                return 1;
            }
            if libc::dup2(stderr_fd, 2) < 0 {
                eprintln!("dup2 stderr failed");
                return 1;
            }
            _ = libc::close(stdout_fd);
            _ = libc::close(stderr_fd);
        }

        Self::child_setup(config)
    }
}

/// Apply the caller's ordered mount plan in the child, before chroot.
///
/// Targets are sandbox-absolute; each is prefixed with the chroot directory.
/// All bind sources are opened BEFORE any mount runs, so a masking tmpfs at
/// an earlier entry cannot change what a later bind resolves to. The mount
/// namespace is made private first — a shared parent namespace would receive
/// these mounts on the host.
fn apply_mounts(chroot_path: &str, mounts: &[MountSpec]) -> std::result::Result<(), String> {
    let slash = CString::new("/").unwrap();
    let ret = unsafe {
        libc::mount(
            slash.as_ptr(),
            slash.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(format!(
            "private mount propagation: {}",
            std::io::Error::last_os_error()
        ));
    }

    struct PreparedBind {
        fd: i32,
        is_dir: bool,
    }

    let mut prepared: Vec<Option<PreparedBind>> = Vec::with_capacity(mounts.len());
    for spec in mounts {
        match &spec.source {
            MountSource::Tmpfs => prepared.push(None),
            MountSource::Bind(source) => {
                let path = CString::new(source.as_os_str().as_bytes())
                    .map_err(|_| format!("bind source contains NUL: {}", source.display()))?;
                // O_PATH opens a file or directory without read access.
                let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                if fd < 0 {
                    return Err(format!(
                        "open bind source {}: {}",
                        source.display(),
                        std::io::Error::last_os_error()
                    ));
                }
                let is_dir = std::fs::metadata(source)
                    .map(|meta| meta.is_dir())
                    .unwrap_or(false);
                prepared.push(Some(PreparedBind { fd, is_dir }));
            }
        }
    }

    let result = (|| -> std::result::Result<(), String> {
        for (spec, entry) in mounts.iter().zip(prepared.iter()) {
            let dest = format!("{}{}", chroot_path.trim_end_matches('/'), spec.target);
            let target = CString::new(dest.as_str())
                .map_err(|_| format!("mount target contains NUL: {}", dest))?;

            match entry {
                None => {
                    std::fs::create_dir_all(&dest)
                        .map_err(|e| format!("mkdir {}: {}", dest, e))?;
                    let fstype = CString::new("tmpfs").unwrap();
                    let data = CString::new("mode=0755,size=4m").unwrap();
                    let ret = unsafe {
                        libc::mount(
                            fstype.as_ptr(),
                            target.as_ptr(),
                            fstype.as_ptr(),
                            libc::MS_NOSUID | libc::MS_NODEV,
                            data.as_ptr() as *const libc::c_void,
                        )
                    };
                    if ret != 0 {
                        return Err(format!(
                            "tmpfs at {}: {}",
                            spec.target,
                            std::io::Error::last_os_error()
                        ));
                    }
                }
                Some(bind) => {
                    if bind.is_dir {
                        std::fs::create_dir_all(&dest)
                            .map_err(|e| format!("mkdir {}: {}", dest, e))?;
                    } else {
                        if let Some(parent) = Path::new(&dest).parent() {
                            std::fs::create_dir_all(parent)
                                .map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
                        }
                        std::fs::OpenOptions::new()
                            .write(true)
                            .create(true)
                            .open(&dest)
                            .map_err(|e| format!("create mount target {}: {}", dest, e))?;
                    }
                    let source = CString::new(format!("/proc/self/fd/{}", bind.fd)).unwrap();
                    let bind_flags = libc::MS_BIND
                        | if bind.is_dir { libc::MS_REC } else { 0 };
                    let ret = unsafe {
                        libc::mount(
                            source.as_ptr(),
                            target.as_ptr(),
                            std::ptr::null(),
                            bind_flags,
                            std::ptr::null(),
                        )
                    };
                    if ret != 0 {
                        return Err(format!(
                            "bind at {}: {}",
                            spec.target,
                            std::io::Error::last_os_error()
                        ));
                    }
                    if spec.read_only {
                        let remount_flags = libc::MS_BIND
                            | libc::MS_REMOUNT
                            | libc::MS_RDONLY
                            | if bind.is_dir { libc::MS_REC } else { 0 };
                        let ret = unsafe {
                            libc::mount(
                                std::ptr::null(),
                                target.as_ptr(),
                                std::ptr::null(),
                                remount_flags,
                                std::ptr::null(),
                            )
                        };
                        if ret != 0 {
                            return Err(format!(
                                "read-only remount at {}: {}",
                                spec.target,
                                std::io::Error::last_os_error()
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    })();

    for bind in prepared.into_iter().flatten() {
        unsafe { libc::close(bind.fd) };
    }
    result
}

/// Wait for child process and get exit status
fn wait_for_child(pid: Pid) -> Result<i32> {
    use nix::sys::wait::{WaitStatus, waitpid};

    loop {
        match waitpid(pid, None) {
            Ok(WaitStatus::Exited(_, status)) => return Ok(status),
            Ok(WaitStatus::Signaled(_, signal, _)) => {
                return Ok(128 + signal as i32);
            }
            Ok(_) => continue,
            Err(e) => return Err(SandboxError::Syscall(format!("waitpid failed: {}", e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::{ForkResult, fork};

    #[test]
    fn mount_spec_validates_shape() {
        let bind = |target: &str, source: &str| MountSpec {
            source: MountSource::Bind(PathBuf::from(source)),
            target: target.to_string(),
            read_only: false,
        };
        assert!(bind("/collections", "/srv/root/collections").validate().is_ok());
        assert!(bind("/collections/acme", "/srv/root/collections/acme").validate().is_ok());
        // Relative targets, root, dot components and NUL are refused.
        assert!(bind("collections", "/srv/root/collections").validate().is_err());
        assert!(bind("/", "/srv/root").validate().is_err());
        assert!(bind("/collections/../secret", "/srv/root").validate().is_err());
        assert!(bind("/collections/./acme", "/srv/root").validate().is_err());
        assert!(bind("/collections", "srv/root").validate().is_err());
        // A tmpfs is writable by construction — read-only is a contradiction.
        let tmpfs = MountSpec {
            source: MountSource::Tmpfs,
            target: "/collections".to_string(),
            read_only: true,
        };
        assert!(tmpfs.validate().is_err());
        let tmpfs = MountSpec {
            read_only: false,
            ..tmpfs
        };
        assert!(tmpfs.validate().is_ok());
    }

    #[test]
    fn process_config_defaults_to_no_mount_plan() {
        assert!(ProcessConfig::default().mounts.is_empty());
    }

    #[test]
    fn test_process_config_default() {
        let config = ProcessConfig::default();
        assert!(config.program.is_empty());
        assert!(config.args.is_empty());
        assert!(config.rlimits.is_none());
        assert!(!config.use_user_namespace);
    }

    #[test]
    fn test_process_config_with_args() {
        let config = ProcessConfig {
            program: "echo".to_string(),
            args: vec!["hello".to_string(), "world".to_string()],
            ..Default::default()
        };

        assert_eq!(config.program, "echo");
        assert_eq!(config.args.len(), 2);
    }

    #[test]
    fn test_process_config_with_env() {
        let config = ProcessConfig {
            env: vec![("MY_VAR".to_string(), "my_value".to_string())],
            ..Default::default()
        };

        assert_eq!(config.env.len(), 1);
        assert_eq!(config.env[0].0, "MY_VAR");
    }

    #[test]
    fn test_process_result() {
        let result = ProcessResult {
            pid: Pid::from_raw(123),
            exit_status: 0,
            signal: None,
            exec_time_ms: 100,
        };

        assert_eq!(result.pid, Pid::from_raw(123));
        assert_eq!(result.exit_status, 0);
        assert!(result.signal.is_none());
        assert_eq!(result.exec_time_ms, 100);
    }

    #[test]
    fn test_process_result_with_signal() {
        let result = ProcessResult {
            pid: Pid::from_raw(456),
            exit_status: 0,
            signal: Some(9),
            exec_time_ms: 50,
        };

        assert!(result.signal.is_some());
        assert_eq!(result.signal.unwrap(), 9);
    }

    #[test]
    fn wait_for_child_returns_exit_status() {
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                std::process::exit(42);
            }
            Ok(ForkResult::Parent { child }) => {
                let status = wait_for_child(child).unwrap();
                assert_eq!(status, 42);
            }
            Err(e) => panic!("fork failed: {}", e),
        }
    }

    #[test]
    fn process_executor_runs_program_without_namespaces() {
        let config = ProcessConfig {
            program: "/bin/echo".to_string(),
            args: vec!["sandbox".to_string()],
            env: vec![("TEST_EXEC".to_string(), "1".to_string())],
            ..Default::default()
        };

        let namespace = NamespaceConfig {
            pid: false,
            ipc: false,
            net: false,
            mount: false,
            uts: false,
            user: false,
        };

        let result = ProcessExecutor::execute(config, namespace).unwrap();
        assert_eq!(result.exit_status, 0);
    }

    #[test]
    fn execute_with_stream_disabled() {
        let config = ProcessConfig {
            program: "/bin/echo".to_string(),
            args: vec!["test_output".to_string()],
            ..Default::default()
        };

        let namespace = NamespaceConfig {
            pid: false,
            ipc: false,
            net: false,
            mount: false,
            uts: false,
            user: false,
        };

        let (result, stream) =
            ProcessExecutor::execute_with_stream(config, namespace, false).unwrap();
        assert_eq!(result.exit_status, 0);
        assert!(stream.is_none());
    }

    #[test]
    fn execute_with_stream_enabled() {
        let config = ProcessConfig {
            program: "/bin/echo".to_string(),
            args: vec!["streamed_output".to_string()],
            ..Default::default()
        };

        let namespace = NamespaceConfig {
            pid: false,
            ipc: false,
            net: false,
            mount: false,
            uts: false,
            user: false,
        };

        let (result, stream) =
            ProcessExecutor::execute_with_stream(config, namespace, true).unwrap();
        assert_eq!(result.exit_status, 0);
        assert!(stream.is_some());
    }

    #[test]
    fn resolve_program_path_uses_env_path() {
        let env = vec![("PATH".to_string(), "/bin:/usr/bin".to_string())];
        let resolved = resolve_program_path("ls", &env).unwrap();
        assert!(
            resolved.ends_with("/ls"),
            "expected ls in path, got {}",
            resolved
        );
    }

    #[test]
    fn resolve_program_path_reports_missing_binary() {
        let env = vec![("PATH".to_string(), "/nonexistent".to_string())];
        let err = resolve_program_path("definitely_missing_cmd", &env).unwrap_err();
        assert!(err.contains("command not found"));
    }

    #[test]
    fn wait_for_child_with_signal() {
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                unsafe { libc::raise(libc::SIGTERM) };
                std::process::exit(1);
            }
            Ok(ForkResult::Parent { child }) => {
                let status = wait_for_child(child).unwrap();
                assert!(status > 0);
            }
            Err(e) => panic!("fork failed: {}", e),
        }
    }
}
