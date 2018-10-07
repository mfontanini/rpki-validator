use std::io;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio, Output};

use rpki::uri;

#[derive(Debug, PartialEq)]
pub enum RsyncAction {
    CreateFile(PathBuf),
    ModifyFile(PathBuf),
    DeleteFile(PathBuf),
}

impl RsyncAction {
    pub fn path(&self) -> &Path {
        match self {
            RsyncAction::CreateFile(p) |
            RsyncAction::ModifyFile(p) |
            RsyncAction::DeleteFile(p) => p
        }
    }
}

#[derive(Debug)]
pub struct RsyncOutput {
    actions: Vec<RsyncAction>,
}

impl RsyncOutput {
    pub fn new(actions: Vec<RsyncAction>) -> RsyncOutput {
        RsyncOutput {
            actions
        }
    }

    pub fn actions(self) -> Vec<RsyncAction> {
        self.actions
    }
}

pub struct RsyncFetcher {
    rsync_path: String,
}

impl RsyncFetcher {
    pub fn new(rsync_path: &str) -> Self {
        RsyncFetcher {
            rsync_path: rsync_path.to_string(),
        }
    }

    pub fn fetch(&self, uri: &uri::Rsync, output_dir: &Path) -> io::Result<RsyncOutput> {
        let mut base_output = PathBuf::new();
        base_output.push(output_dir);

        let rsync_output = self.spawn_rsync(uri, output_dir)?;
        let cursor = io::Cursor::new(rsync_output.stdout);
        let actions = cursor.lines()
            .map(move |line| {
                self.parse_action(&line.unwrap(), &base_output)
            })
            .filter(|o| o.is_some())
            .map(|o| o.unwrap())
            .collect();
        Ok(RsyncOutput::new(actions))
    }

    fn parse_action(&self, action: &str, base_output: &PathBuf) -> Option<RsyncAction> {
        let mut tokens = action.split(' ');
        let changes = tokens.next().unwrap();
        let tokens : Vec<&str> = tokens.filter(|t| !t.is_empty()).collect();
        let path = base_output.join(&tokens.join(" "));
        if changes == "*deleting" {
            Some(RsyncAction::DeleteFile(path))
        }
        else if changes == ">f+++++++++" {
            Some(RsyncAction::CreateFile(path))
        }
        else if changes.starts_with(">fc") {
            Some(RsyncAction::ModifyFile(path))
        }
        else {
            None
        }
    }

    fn spawn_rsync(&self,uri: &uri::Rsync, output_dir: &Path) -> io::Result<Output> {
        let args = [
            "--delete",
            "-aic",
            &uri.to_string(),
            output_dir.to_str().unwrap()
        ];
        let mut cmd = Command::new(&self.rsync_path);
        cmd.args(&args);
        cmd.stdout(Stdio::piped());
        cmd.output()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_action() {
        let fetcher = RsyncFetcher::new("");
        assert_eq!(
            fetcher.parse_action(">f+++++++++ bleh/asd", &PathBuf::from("/tmp/")),
            Some(RsyncAction::CreateFile(PathBuf::from("/tmp/bleh/asd")))
        );
        assert_eq!(
            fetcher.parse_action(">fc.t...... bleh/asd", &PathBuf::from("/tmp/")),
            Some(RsyncAction::ModifyFile(PathBuf::from("/tmp/bleh/asd")))
        );
        assert_eq!(
            fetcher.parse_action("*deleting   bleh/asd", &PathBuf::from("/tmp/")),
            Some(RsyncAction::DeleteFile(PathBuf::from("/tmp/bleh/asd")))
        );
    }
}
