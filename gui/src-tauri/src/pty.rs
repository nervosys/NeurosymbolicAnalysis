//! The embedded terminal.
//!
//! A real PTY, not a command runner: the workbench's whole point is that you
//! rebuild and re-run without leaving the findings list, and that means the
//! shell has to behave like a shell — job control, colour, interactive prompts.

use portable_pty::{CommandBuilder, NativePtySystem, PtyPair, PtySize, PtySystem};
use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, TryRecvError, channel};

pub struct Terminal {
    pair: PtyPair,
    writer: Box<dyn Write + Send>,
    output: Receiver<Vec<u8>>,
}

impl Terminal {
    /// Start the user's default shell in `cwd`.
    pub fn spawn(cwd: &str) -> Result<Terminal, String> {
        let system = NativePtySystem::default();
        let pair = system
            .openpty(PtySize { rows: 24, cols: 100, pixel_width: 0, pixel_height: 0 })
            .map_err(|e| format!("could not open a pty: {e}"))?;

        let mut cmd = CommandBuilder::new(default_shell());
        cmd.cwd(cwd);
        // Tell the shell it is talking to a terminal that understands colour.
        cmd.env("TERM", "xterm-256color");

        pair.slave.spawn_command(cmd).map_err(|e| format!("could not start a shell: {e}"))?;

        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| format!("could not read from the pty: {e}"))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| format!("could not write to the pty: {e}"))?;

        // Reading happens on its own thread; the UI polls the channel, so a
        // silent shell never blocks a command.
        let (tx, output) = channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Ok(Terminal { pair, writer, output })
    }

    pub fn write(&mut self, data: &str) -> Result<(), String> {
        self.writer
            .write_all(data.as_bytes())
            .and_then(|_| self.writer.flush())
            .map_err(|e| e.to_string())
    }

    /// Drain everything the shell has produced since the last call.
    ///
    /// # The frontend must answer queries
    ///
    /// ConPTY opens by asking the terminal where its cursor is (`ESC [ 6 n`) and
    /// some shells will not proceed until told. A terminal emulator answers
    /// automatically — xterm.js replies through its `onData` handler, which the
    /// workbench forwards straight back to [`Terminal::write`] — so the loop
    /// closes in the GUI. Any other consumer of this API has to do the same, or
    /// the shell will appear to hang before its first prompt.
    pub fn read(&mut self) -> Result<String, String> {
        let mut out = Vec::new();
        loop {
            match self.output.try_recv() {
                Ok(chunk) => out.extend_from_slice(&chunk),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
        // The shell emits bytes, not necessarily valid UTF-8 at a chunk boundary.
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    pub fn resize(&mut self, rows: u16, cols: u16) -> Result<(), String> {
        self.pair
            .master
            .resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
            .map_err(|e| e.to_string())
    }
}

fn default_shell() -> String {
    if cfg!(windows) {
        std::env::var("COMSPEC").unwrap_or_else(|_| "powershell.exe".into())
    } else {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The embedded terminal is the GUI feature most likely to be quietly
    /// broken — a real pty, a reader thread, and a shell that has to survive
    /// being written to. None of that is exercised by launching the window.
    #[test]
    fn a_real_shell_starts_and_answers() {
        let cwd = std::env::temp_dir();
        let mut term = match Terminal::spawn(&cwd.to_string_lossy()) {
            Ok(t) => t,
            // A machine with no usable pty is a legitimate skip, not a failure.
            Err(e) => {
                eprintln!("skipping: no pty available ({e})");
                return;
            }
        };

        term.write("echo sda-pty-works\r\n").expect("writing to the shell");

        // Stand in for the terminal emulator: answer the cursor-position query
        // ConPTY opens with, exactly as xterm.js does in the workbench. Without
        // this the shell waits for a reply that never comes, which is what this
        // test found the first time it ran.
        let mut seen = String::new();
        for _ in 0..100 {
            let chunk = term.read().unwrap_or_default();
            if chunk.contains("\u{1b}[6n") {
                let _ = term.write("\u{1b}[1;1R");
            }
            seen.push_str(&chunk);
            if seen.contains("sda-pty-works") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        assert!(
            seen.contains("sda-pty-works"),
            "the shell produced no echo of the command; got: {seen:?}"
        );

        // Resizing must not take the session down.
        term.resize(40, 120).expect("resizing the pty");
        term.write("echo still-alive\r\n").expect("writing after resize");

        let mut after = String::new();
        for _ in 0..100 {
            after.push_str(&term.read().unwrap_or_default());
            if after.contains("still-alive") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(after.contains("still-alive"), "the shell died on resize; got: {after:?}");
    }

    #[test]
    fn reading_before_the_shell_speaks_is_not_an_error() {
        let cwd = std::env::temp_dir();
        if let Ok(mut term) = Terminal::spawn(&cwd.to_string_lossy()) {
            // Draining an idle terminal must return quietly rather than block.
            let _ = term.read().expect("draining an idle terminal");
        }
    }
}
