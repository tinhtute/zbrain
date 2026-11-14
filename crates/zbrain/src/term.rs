// Owner-ceremony terminal input (port of internal/cli approvalLineReader).
// The approval walk (`approval grant` and `claim approve`) reads confirmations
// from an interactive TTY without echo; a piped real stdin fails closed so the
// ceremony cannot be scripted. Tests inject a scripted prompt instead of a
// real terminal.

use std::io;

/// Source of owner confirmation lines for the grant walk.
pub trait ApprovalPrompt {
    fn read_confirmation(&mut self) -> io::Result<String>;
}

/// Real-terminal prompt backed by the `console` crate's no-echo read.
/// Construction fails closed when stdin is not an interactive terminal.
pub struct StdinPrompt;

impl StdinPrompt {
    pub fn new() -> io::Result<Self> {
        // Gate on whether stdin itself is a terminal (mirrors the Go oracle's
        // term.IsTerminal(int(stdin.Fd())) check); console's no-echo read is
        // then used for the confirmation line.
        // SAFETY: isatty takes a bare fd and performs no memory access.
        if unsafe { libc::isatty(0) } != 1 {
            return Err(io::Error::other(
                "owner approval requires an interactive terminal (TTY)",
            ));
        }
        Ok(Self)
    }
}

impl ApprovalPrompt for StdinPrompt {
    fn read_confirmation(&mut self) -> io::Result<String> {
        console::Term::stdout().read_secure_line()
    }
}

/// Scripted prompt for tests: replays prepared confirmation lines and fails
/// closed once the script is exhausted (mirrors a truncated TTY walk).
pub struct ScriptedPrompt {
    lines: Vec<String>,
    cursor: usize,
}

impl ScriptedPrompt {
    pub fn new(lines: &[&str]) -> Self {
        Self {
            lines: lines.iter().map(|line| line.to_string()).collect(),
            cursor: 0,
        }
    }
}

impl ApprovalPrompt for ScriptedPrompt {
    fn read_confirmation(&mut self) -> io::Result<String> {
        let Some(line) = self.lines.get(self.cursor) else {
            return Err(io::Error::other(
                "approval grant requires the confirmation input",
            ));
        };
        self.cursor += 1;
        Ok(line.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdin_prompt_fails_closed_without_tty() {
        // Test processes run with piped/closed stdin, never an interactive TTY.
        let err = match StdinPrompt::new() {
            Ok(_) => panic!("piped stdin must fail closed"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("owner approval requires an interactive terminal"),
            "{err}"
        );
    }

    #[test]
    fn scripted_prompt_replays_lines_then_fails_closed() {
        let mut prompt = ScriptedPrompt::new(&["abcd", "skip"]);
        assert_eq!(prompt.read_confirmation().unwrap(), "abcd");
        assert_eq!(prompt.read_confirmation().unwrap(), "skip");
        let err = prompt.read_confirmation().unwrap_err();
        assert!(
            err.to_string().contains("requires the confirmation input"),
            "{err}"
        );
    }
}
