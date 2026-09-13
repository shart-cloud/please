#![cfg(unix)]

use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::bench::adapter::NativeExecution;
use crate::bench::identity::{hex_encode, sha256};
use crate::bench::model::{
    AdapterManifest, CoverageState, ProcessTelemetry, RunLimits, Surface, TrustedContext,
};
use crate::bench::protocol::{encode_case_request, AdapterMessage, HostMessage, PROTOCOL_VERSION};
use crate::bench::system::VerifiedSystem;
use crate::Result;

enum LineEvent {
    Line(Vec<u8>),
    TooLarge(Vec<u8>),
    Eof(Vec<u8>),
    Io(String),
}

#[derive(Default)]
struct StderrCapture {
    bytes: Vec<u8>,
    total: u64,
    overflow: bool,
    digest: Sha256,
}

impl StderrCapture {
    fn append(&mut self, bytes: &[u8], max: usize) {
        self.total = self.total.saturating_add(bytes.len() as u64);
        self.digest.update(bytes);
        let remaining = max.saturating_sub(self.bytes.len());
        self.bytes
            .extend_from_slice(&bytes[..bytes.len().min(remaining)]);
        self.overflow = self.total > max as u64;
    }

    fn snapshot(&self) -> StderrSnapshot {
        StderrSnapshot {
            retained: self.bytes.clone(),
            total: self.total,
            overflow: self.overflow,
            sha256: format!("{:x}", self.digest.clone().finalize()),
        }
    }
}

#[derive(Clone)]
struct StderrSnapshot {
    retained: Vec<u8>,
    total: u64,
    overflow: bool,
    sha256: String,
}

enum StderrCommand {
    Snapshot(mpsc::Sender<StderrSnapshot>),
}

struct ChildState {
    child: Child,
    stdin: ChildStdin,
    stdout: mpsc::Receiver<LineEvent>,
    stderr: Arc<Mutex<StderrCapture>>,
    stderr_control: mpsc::Sender<StderrCommand>,
    stderr_thread: Option<thread::JoinHandle<()>>,
    spawn_index: u32,
}

pub struct ProcessAdapter {
    system_id: String,
    system_digest: String,
    adapter_version: String,
    program: PathBuf,
    program_digest: String,
    args: Vec<String>,
    sandbox_command: Vec<String>,
    environment: std::collections::BTreeMap<String, String>,
    work_dir: PathBuf,
    limits: RunLimits,
    child: Option<ChildState>,
    starts: u32,
    completed: Vec<ProcessTelemetry>,
}

impl ProcessAdapter {
    pub fn new(
        system: &VerifiedSystem,
        program: &Path,
        work_dir: &Path,
        limits: RunLimits,
    ) -> Result<Self> {
        let AdapterManifest::Subprocess {
            args,
            environment,
            executable_sha256,
            sandbox_command,
            ..
        } = &system.manifest.adapter
        else {
            return Err("not a subprocess system manifest".into());
        };
        Ok(Self {
            system_id: system.manifest.system_id.clone(),
            system_digest: system.digest.clone(),
            adapter_version: system.manifest.adapter_version.clone(),
            program: program.to_path_buf(),
            program_digest: executable_sha256.clone(),
            args: args.clone(),
            sandbox_command: sandbox_command.clone(),
            environment: environment.clone(),
            work_dir: work_dir.to_path_buf(),
            limits,
            child: None,
            starts: 0,
            completed: Vec::new(),
        })
    }

    pub fn finish(mut self) -> Vec<ProcessTelemetry> {
        self.terminate();
        std::mem::take(&mut self.completed)
    }

    pub fn execute(
        &mut self,
        request_id: &str,
        surface: Surface,
        candidate: &[u8],
        candidate_sha256: &str,
        provenance: &str,
        trusted_context: Option<TrustedContext>,
    ) -> NativeExecution {
        let started = Instant::now();
        let deadline = started + Duration::from_millis(self.limits.case_timeout_ms);
        if self.child.is_none() {
            if self.starts > self.limits.max_restarts {
                return NativeExecution::unavailable("subprocess restart budget exhausted");
            }
            self.starts += 1;
            match self.spawn_child() {
                Ok(child) => self.child = Some(child),
                Err(error) => {
                    return NativeExecution::unavailable(format!(
                        "adapter startup failed: {error}"
                    ));
                }
            }
        }
        let request = match encode_case_request(
            request_id,
            surface,
            candidate,
            candidate_sha256,
            provenance,
            trusted_context.as_ref(),
        ) {
            Ok(request) if request.len() as u64 <= self.limits.max_request_bytes => request,
            Ok(_) => return NativeExecution::unavailable("case request exceeds max_request_bytes"),
            Err(error) => {
                return NativeExecution::unavailable(format!("cannot encode case request: {error}"))
            }
        };

        let child = self.child.as_mut().expect("child was started");
        match write_line_until(&mut child.stdin, &request, deadline) {
            Ok(()) => {}
            Err(DeadlineWriteError::Timeout) => {
                let (stdout, exit_status) = self.terminate_capture();
                return NativeExecution {
                    coverage: CoverageState::Timeout,
                    native: None,
                    stdout,
                    stderr: Vec::new(),
                    exit_status,
                    transport: "jsonl_subprocess",
                    elapsed: started.elapsed(),
                    runner_overhead: Duration::ZERO,
                    diagnostics: vec![
                        "adapter did not accept the request before case_timeout_ms".into()
                    ],
                };
            }
            Err(DeadlineWriteError::Io(error)) => {
                let mut outcome =
                    NativeExecution::unavailable(format!("cannot write adapter request: {error}"));
                outcome.transport = "jsonl_subprocess";
                self.terminate();
                return outcome;
            }
        }

        let event = child.stdout.recv_timeout(remaining(deadline));
        let mut output = match event {
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let (stdout, exit_status) = self.terminate_capture();
                return NativeExecution {
                    coverage: CoverageState::Timeout,
                    native: None,
                    stdout,
                    stderr: Vec::new(),
                    exit_status,
                    transport: "jsonl_subprocess",
                    elapsed: started.elapsed(),
                    runner_overhead: Duration::ZERO,
                    diagnostics: vec!["adapter exceeded case_timeout_ms".into()],
                };
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => LineEvent::Eof(Vec::new()),
            Ok(event) => event,
        };
        let response_elapsed = started.elapsed();

        let (stderr, mut runner_overhead) = measure_runner_overhead(Instant::now, || {
            stderr_snapshot(
                self.child.as_ref().expect("child remains live"),
                Duration::from_millis(100),
            )
        });
        let stderr = match stderr {
            Ok(stderr) => stderr,
            Err(error) => {
                let stdout = event_bytes(&mut output);
                self.terminate();
                return invalid(
                    response_elapsed,
                    runner_overhead,
                    stdout,
                    &format!("cannot synchronize adapter stderr: {error}"),
                );
            }
        };
        if stderr.overflow {
            let stdout = event_bytes(&mut output);
            self.terminate();
            return invalid(
                response_elapsed,
                runner_overhead,
                stdout,
                "adapter exceeded max_stderr_bytes",
            );
        }

        let line = match output {
            LineEvent::Line(line) => line,
            LineEvent::TooLarge(line) => {
                self.terminate();
                return invalid(
                    response_elapsed,
                    runner_overhead,
                    line,
                    "adapter exceeded max_stdout_bytes",
                );
            }
            LineEvent::Eof(partial) => {
                let (_, status) = self.reap_capture(deadline);
                return NativeExecution {
                    coverage: if status.as_ref().is_some_and(|status| !status.success()) {
                        CoverageState::Crashed
                    } else {
                        CoverageState::InvalidOutput
                    },
                    native: None,
                    stdout: partial,
                    stderr: Vec::new(),
                    exit_status: status.and_then(|status| status.code()),
                    transport: "jsonl_subprocess",
                    elapsed: response_elapsed,
                    runner_overhead,
                    diagnostics: vec!["adapter closed stdout without one complete response".into()],
                };
            }
            LineEvent::Io(error) => {
                self.terminate();
                return invalid(
                    response_elapsed,
                    runner_overhead,
                    Vec::new(),
                    &format!("adapter stdout failed: {error}"),
                );
            }
        };
        let parsed: AdapterMessage = match serde_json::from_slice(&line) {
            Ok(message) => message,
            Err(error) => {
                self.terminate();
                return invalid(
                    response_elapsed,
                    runner_overhead,
                    line,
                    &format!("malformed adapter response: {error}"),
                );
            }
        };
        let native = match parsed {
            AdapterMessage::Result {
                schema_version,
                request_id: response_id,
                native,
            } if schema_version == PROTOCOL_VERSION && response_id == request_id => native,
            AdapterMessage::Result { .. } => {
                self.terminate();
                return invalid(
                    response_elapsed,
                    runner_overhead,
                    line,
                    "adapter response identity mismatch",
                );
            }
            AdapterMessage::Handshake { .. } => {
                self.terminate();
                return invalid(
                    response_elapsed,
                    runner_overhead,
                    line,
                    "unexpected handshake response",
                );
            }
        };

        // A conforming sequential adapter emits exactly one line. Catch an immediate duplicate before
        // it can be mistaken for the next case; a delayed extra line is rejected by the next id check.
        let (extra, duplicate_overhead) = measure_runner_overhead(Instant::now, || {
            self.child
                .as_ref()
                .expect("child remains live")
                .stdout
                .recv_timeout(remaining(deadline).min(Duration::from_millis(2)))
        });
        runner_overhead = runner_overhead.saturating_add(duplicate_overhead);
        if let Ok(extra) = extra {
            let mut combined = line;
            combined.push(b'\n');
            combined.extend(event_bytes_owned(extra));
            self.terminate();
            return invalid(
                response_elapsed,
                runner_overhead,
                combined,
                "adapter emitted a duplicate response",
            );
        }
        let coverage = if native.abstained {
            CoverageState::Abstained
        } else {
            CoverageState::Completed
        };
        NativeExecution {
            coverage,
            native: Some(native),
            stdout: line,
            stderr: Vec::new(),
            exit_status: None,
            transport: "jsonl_subprocess",
            elapsed: response_elapsed,
            runner_overhead,
            diagnostics: Vec::new(),
        }
    }

    fn spawn_child(&mut self) -> Result<ChildState> {
        std::fs::create_dir_all(&self.work_dir)?;
        let metadata = std::fs::symlink_metadata(&self.program)?;
        crate::bench::identity::read_verified_file(
            &self.program,
            metadata.len(),
            &self.program_digest,
            256 * 1024 * 1024,
        )
        .map_err(|error| format!("staged executable digest mismatch: {error}"))?;
        let mut command = if let Some((program, arguments)) = self.sandbox_command.split_first() {
            let mut command = Command::new(program);
            command.args(arguments).arg(&self.program);
            command
        } else {
            Command::new(&self.program)
        };
        command
            .args(&self.args)
            .current_dir(&self.work_dir)
            .env_clear()
            .envs(&self.environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command.spawn()?;
        let streams = (|| -> Result<_> {
            let stdin = child.stdin.take().ok_or("adapter stdin was not piped")?;
            set_nonblocking(&stdin)?;
            let stdout = child.stdout.take().ok_or("adapter stdout was not piped")?;
            let stderr = child.stderr.take().ok_or("adapter stderr was not piped")?;
            Ok((stdin, stdout, stderr))
        })();
        let (stdin, stdout, stderr) = match streams {
            Ok(streams) => streams,
            Err(error) => {
                let _ = terminate_child(&mut child);
                return Err(error);
            }
        };
        let stderr_capture = Arc::new(Mutex::new(StderrCapture::default()));
        let (stderr_control, stderr_thread) = match spawn_stderr(
            stderr,
            Arc::clone(&stderr_capture),
            self.limits.max_stderr_bytes as usize,
        ) {
            Ok(worker) => worker,
            Err(error) => {
                let _ = terminate_child(&mut child);
                return Err(error.into());
            }
        };
        let stdout_rx = spawn_stdout(stdout, self.limits.max_stdout_bytes as usize);
        let mut state = ChildState {
            child,
            stdin,
            stdout: stdout_rx,
            stderr: stderr_capture,
            stderr_control,
            stderr_thread: Some(stderr_thread),
            spawn_index: self.starts,
        };
        let request = serde_json::to_vec(&HostMessage::handshake(
            self.system_id.clone(),
            self.system_digest.clone(),
        ))?;
        let handshake = (|| -> Result<()> {
            let deadline = Instant::now() + Duration::from_millis(self.limits.startup_timeout_ms);
            write_line_until(&mut state.stdin, &request, deadline).map_err(
                |error| -> Box<dyn std::error::Error> {
                    match error {
                        DeadlineWriteError::Timeout => {
                            "adapter did not accept the handshake before startup_timeout_ms".into()
                        }
                        DeadlineWriteError::Io(error) => {
                            format!("cannot write adapter handshake: {error}").into()
                        }
                    }
                },
            )?;
            let line = match state.stdout.recv_timeout(remaining(deadline)) {
                Ok(LineEvent::Line(line)) => line,
                Ok(_) => return Err("adapter returned no bounded handshake".into()),
                Err(_) => return Err("adapter handshake timed out or closed".into()),
            };
            let response: AdapterMessage = serde_json::from_slice(&line)?;
            match response {
                AdapterMessage::Handshake {
                    schema_version,
                    system_id,
                    system_digest,
                    adapter_version,
                } if schema_version == PROTOCOL_VERSION
                    && system_id == self.system_id
                    && system_digest == self.system_digest
                    && adapter_version == self.adapter_version => {}
                _ => return Err("adapter handshake identity mismatch".into()),
            }
            let stderr = stderr_snapshot(&state, Duration::from_millis(100))?;
            if stderr.overflow {
                return Err("adapter exceeded stderr bound during handshake".into());
            }
            Ok(())
        })();
        if let Err(error) = handshake {
            let (status, killed) = terminate_state(&mut state);
            self.record_process(state, status, killed);
            return Err(error);
        }
        Ok(state)
    }

    fn terminate(&mut self) {
        if let Some(mut state) = self.child.take() {
            let (status, killed) = terminate_state(&mut state);
            self.record_process(state, status, killed);
        }
    }

    fn terminate_capture(&mut self) -> (Vec<u8>, Option<i32>) {
        let Some(mut state) = self.child.take() else {
            return (Vec::new(), None);
        };
        let (status, killed) = terminate_state(&mut state);
        let stdout = state
            .stdout
            .recv_timeout(Duration::from_millis(50))
            .map(event_bytes_owned)
            .unwrap_or_default();
        self.record_process(state, status, killed);
        (stdout, status)
    }

    fn reap_capture(&mut self, deadline: Instant) -> (Vec<u8>, Option<std::process::ExitStatus>) {
        let Some(mut state) = self.child.take() else {
            return (Vec::new(), None);
        };
        let (status, killed) = reap_until(&mut state, deadline);
        let stdout = state
            .stdout
            .recv_timeout(Duration::from_millis(50))
            .map(event_bytes_owned)
            .unwrap_or_default();
        self.record_process(
            state,
            status.as_ref().and_then(std::process::ExitStatus::code),
            killed,
        );
        (stdout, status)
    }

    fn record_process(&mut self, mut state: ChildState, status: Option<i32>, killed: bool) {
        if let Some(thread) = state.stderr_thread.take() {
            let _ = thread.join();
        }
        let stderr = state.stderr.lock().expect("stderr lock").snapshot();
        self.completed.push(ProcessTelemetry {
            system_id: self.system_id.clone(),
            system_digest: self.system_digest.clone(),
            spawn_index: state.spawn_index,
            stderr_bytes: stderr.total,
            stderr_sha256: stderr.sha256,
            retained_stderr_sha256: sha256(&stderr.retained),
            retained_stderr_hex: hex_encode(&stderr.retained),
            stderr_overflow: stderr.overflow,
            exit_status: status,
            terminated_by_runner: killed,
        });
    }
}

impl Drop for ProcessAdapter {
    fn drop(&mut self) {
        self.terminate();
    }
}

enum DeadlineWriteError {
    Timeout,
    Io(std::io::Error),
}

fn set_nonblocking(stdin: &ChildStdin) -> std::io::Result<()> {
    set_fd_nonblocking(stdin.as_raw_fd())
}

fn set_fd_nonblocking(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn write_line_until(
    stdin: &mut ChildStdin,
    bytes: &[u8],
    deadline: Instant,
) -> std::result::Result<(), DeadlineWriteError> {
    let mut offset = 0usize;
    let mut newline = false;
    loop {
        let remaining_bytes = if offset < bytes.len() {
            &bytes[offset..]
        } else if !newline {
            b"\n"
        } else {
            return Ok(());
        };
        match stdin.write(remaining_bytes) {
            Ok(0) => {
                return Err(DeadlineWriteError::Io(std::io::Error::new(
                    ErrorKind::WriteZero,
                    "adapter stdin accepted zero bytes",
                )))
            }
            Ok(count) if offset < bytes.len() => offset += count,
            Ok(_) => newline = true,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if !wait_writable(stdin.as_raw_fd(), deadline).map_err(DeadlineWriteError::Io)? {
                    return Err(DeadlineWriteError::Timeout);
                }
            }
            Err(error) => return Err(DeadlineWriteError::Io(error)),
        }
        if Instant::now() >= deadline && (offset < bytes.len() || !newline) {
            return Err(DeadlineWriteError::Timeout);
        }
    }
}

fn wait_writable(fd: std::os::fd::RawFd, deadline: Instant) -> std::io::Result<bool> {
    loop {
        let duration = remaining(deadline);
        if duration.is_zero() {
            return Ok(false);
        }
        let timeout = duration.as_millis().saturating_add(1).min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result > 0 {
            if descriptor.revents & libc::POLLOUT != 0 {
                return Ok(true);
            }
            return Err(std::io::Error::new(
                ErrorKind::BrokenPipe,
                "adapter stdin closed while waiting to write",
            ));
        }
        if result == 0 {
            return Ok(false);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn spawn_stdout(mut stdout: impl Read + Send + 'static, max: usize) -> mpsc::Receiver<LineEvent> {
    // One delivered line plus the line currently being assembled is the complete queue bound.
    // Backpressure then reaches the child through its stdout pipe.
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut line = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            match stdout.read(&mut buffer) {
                Ok(0) => {
                    let _ = sender.send(LineEvent::Eof(line));
                    break;
                }
                Ok(count) => {
                    for byte in &buffer[..count] {
                        if *byte == b'\n' {
                            if sender
                                .send(LineEvent::Line(std::mem::take(&mut line)))
                                .is_err()
                            {
                                return;
                            }
                        } else {
                            if line.len() == max {
                                let _ = sender.send(LineEvent::TooLarge(line));
                                return;
                            }
                            line.push(*byte);
                        }
                    }
                }
                Err(error) => {
                    let _ = sender.send(LineEvent::Io(error.to_string()));
                    break;
                }
            }
        }
    });
    receiver
}

fn spawn_stderr(
    mut stderr: ChildStderr,
    capture: Arc<Mutex<StderrCapture>>,
    max: usize,
) -> std::io::Result<(mpsc::Sender<StderrCommand>, thread::JoinHandle<()>)> {
    set_fd_nonblocking(stderr.as_raw_fd())?;
    let (control_tx, control_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        loop {
            let read_state = read_stderr_once(&mut stderr, &mut buffer, &capture, max);
            let command = match control_rx.try_recv() {
                Ok(command) => Some(command),
                Err(mpsc::TryRecvError::Empty) if read_state == StderrReadState::Pending => {
                    control_rx.recv_timeout(Duration::from_millis(1)).ok()
                }
                Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => None,
            };
            if let Some(StderrCommand::Snapshot(reply)) = command {
                let mut fence_state = read_state;
                while fence_state != StderrReadState::Eof
                    && !capture.lock().expect("stderr lock").overflow
                {
                    fence_state = read_stderr_once(&mut stderr, &mut buffer, &capture, max);
                    if fence_state == StderrReadState::Pending {
                        break;
                    }
                }
                let snapshot = capture.lock().expect("stderr lock").snapshot();
                let _ = reply.send(snapshot);
                if fence_state == StderrReadState::Eof {
                    break;
                }
            } else if read_state == StderrReadState::Eof {
                break;
            }
        }
    });
    Ok((control_tx, handle))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StderrReadState {
    Data,
    Pending,
    Eof,
}

fn read_stderr_once(
    stderr: &mut ChildStderr,
    buffer: &mut [u8],
    capture: &Arc<Mutex<StderrCapture>>,
    max: usize,
) -> StderrReadState {
    loop {
        match stderr.read(buffer) {
            Ok(0) => return StderrReadState::Eof,
            Ok(count) => {
                capture
                    .lock()
                    .expect("stderr lock")
                    .append(&buffer[..count], max);
                return StderrReadState::Data;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => return StderrReadState::Pending,
            Err(_) => return StderrReadState::Eof,
        }
    }
}

fn stderr_snapshot(state: &ChildState, timeout: Duration) -> Result<StderrSnapshot> {
    let (reply_tx, reply_rx) = mpsc::channel();
    if state
        .stderr_control
        .send(StderrCommand::Snapshot(reply_tx))
        .is_err()
    {
        return Ok(state.stderr.lock().expect("stderr lock").snapshot());
    }
    reply_rx
        .recv_timeout(timeout)
        .map_err(|_| "stderr capture fence timed out".into())
}

fn event_bytes(event: &mut LineEvent) -> Vec<u8> {
    match event {
        LineEvent::Line(bytes) | LineEvent::TooLarge(bytes) | LineEvent::Eof(bytes) => {
            std::mem::take(bytes)
        }
        LineEvent::Io(_) => Vec::new(),
    }
}

fn event_bytes_owned(event: LineEvent) -> Vec<u8> {
    match event {
        LineEvent::Line(bytes) | LineEvent::TooLarge(bytes) | LineEvent::Eof(bytes) => bytes,
        LineEvent::Io(error) => error.into_bytes(),
    }
}

fn invalid(
    elapsed: Duration,
    runner_overhead: Duration,
    stdout: Vec<u8>,
    detail: &str,
) -> NativeExecution {
    NativeExecution {
        coverage: CoverageState::InvalidOutput,
        native: None,
        stdout,
        stderr: Vec::new(),
        exit_status: None,
        transport: "jsonl_subprocess",
        elapsed,
        runner_overhead,
        diagnostics: vec![detail.into()],
    }
}

fn terminate_state(state: &mut ChildState) -> (Option<i32>, bool) {
    terminate_child(&mut state.child)
}

fn terminate_child(child: &mut Child) -> (Option<i32>, bool) {
    terminate_child_with(child, &mut OsProcessGroupKiller)
}

trait ProcessGroupKiller {
    fn kill_group(&mut self, pid: i32);
}

struct OsProcessGroupKiller;

impl ProcessGroupKiller for OsProcessGroupKiller {
    fn kill_group(&mut self, pid: i32) {
        // The child starts a new process group. Killing the negative id covers descendants as well.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}

fn terminate_child_with(
    child: &mut Child,
    group_killer: &mut impl ProcessGroupKiller,
) -> (Option<i32>, bool) {
    if let Ok(Some(status)) = child.try_wait() {
        return (status.code(), false);
    }
    let pid = child.id() as i32;
    group_killer.kill_group(pid);
    let _ = child.kill();
    (child.wait().ok().and_then(|status| status.code()), true)
}

fn reap_until(
    state: &mut ChildState,
    deadline: Instant,
) -> (Option<std::process::ExitStatus>, bool) {
    loop {
        match state.child.try_wait() {
            Ok(Some(status)) => return (Some(status), false),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(remaining(deadline).min(Duration::from_millis(1)));
            }
            Ok(None) | Err(_) => {
                let (code, killed) = terminate_state(state);
                return (code.map(exit_status_from_code), killed);
            }
        }
    }
}

fn exit_status_from_code(code: i32) -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(code << 8)
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn measure_runner_overhead<T>(
    mut now: impl FnMut() -> Instant,
    operation: impl FnOnce() -> T,
) -> (T, Duration) {
    let started = now();
    let result = operation();
    let elapsed = now().saturating_duration_since(started);
    (result, elapsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::process::Command;

    #[test]
    fn overhead_clock_surrounds_only_the_runner_operation() {
        let base = Instant::now();
        let tick = Cell::new(0u64);
        let (value, overhead) = measure_runner_overhead(
            || {
                let current = tick.get();
                tick.set(current + 1);
                base + Duration::from_millis(current * 3)
            },
            || 17,
        );
        assert_eq!(value, 17);
        assert_eq!(overhead, Duration::from_millis(3));
    }

    #[test]
    fn an_already_reaped_child_is_never_signalled() {
        struct CountingKiller(u32);

        impl ProcessGroupKiller for CountingKiller {
            fn kill_group(&mut self, _pid: i32) {
                self.0 += 1;
            }
        }

        let mut child = Command::new("sh")
            .args(["-c", "exit 17"])
            .spawn()
            .expect("spawn fixture child");
        assert_eq!(child.wait().expect("reap fixture child").code(), Some(17));
        let mut killer = CountingKiller(0);
        let (status, killed) = terminate_child_with(&mut child, &mut killer);
        assert_eq!(status, Some(17));
        assert!(!killed);
        assert_eq!(killer.0, 0, "a kill syscall was requested after reap");
    }
}
