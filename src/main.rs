use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

/// Solidity source patterns that commonly deserve manual security review.
const AUDIT_PATTERNS: &[&str] = &[
    "tx.origin",
    "delegatecall",
    ".call",
    "selfdestruct",
    "assembly",
    "unchecked",
];

fn main() {
    let user_input: Vec<String> = env::args().collect();

    let parsed_input = match input_config(&user_input) {
        Ok(config) => config,

        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };

    let read_files = match read_folder(parsed_input.file_config.file_path.as_ref()) {
        Ok(files) => files,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };

    let content_in_files = match read_files_content(&read_files) {
        Ok(content) => content,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };

    audit_files(&content_in_files, parsed_input.mode, AUDIT_PATTERNS);
}

/// Recursively collects Solidity source files from a folder.
///
/// Only files with the `.sol` extension are returned. Subdirectories are
/// traversed depth-first so nested contracts are included in the scan.
fn read_folder(folder_path: &Path) -> Result<Vec<PathBuf>, io::Error> {
    let mut paths: Vec<PathBuf> = Vec::new();
    let dir_read = fs::read_dir(folder_path)?;

    for entry in dir_read {
        let path = entry?.path();
        if path.is_file() && path.extension() == Some("sol".as_ref()) {
            println!("{}", path.display());

            paths.push(path);
        } else if path.is_dir() {
            let sub_folder = read_folder(&path)?;
            paths.extend(sub_folder);
        }
    }

    Ok(paths)
}

/// CLI configuration provided by the user.
struct Config<'a> {
    /// Directory that should be searched for Solidity files.
    file_path: &'a str,
}

/// Parsed command-line input used by the scanner.
struct InputParsed<'a> {
    /// Filesystem settings for the current run.
    file_config: Config<'a>,
    /// Enables pattern matching for security-sensitive Solidity constructs.
    mode: bool,
}

/// Solidity file content paired with its original path.
struct ContentPath<'a> {
    /// Full source text loaded from disk.
    content: String,
    /// Path to the source file the content came from.
    path: &'a PathBuf,
}

/// Parses command-line arguments into the scanner configuration.
///
/// The first positional argument is treated as the folder to scan. Passing
/// `--audit-mode` enables pattern checks; otherwise the scanner only lists
/// discovered Solidity files.
fn input_config<'a>(param: &'a [String]) -> Result<InputParsed<'a>, &'static str> {
    if param.len() < 2 {
        return Err("Not enough parameters");
    }

    let file_path = match param.get(1) {
        Some(path) => path,
        None => return Err("missing file path"),
    };
    let audit_mode = param.iter().any(|arg| arg == "--audit-mode");

    let config = Config { file_path };

    let parsed = InputParsed {
        file_config: config,
        mode: audit_mode,
    };

    Ok(parsed)
}

/// Reads each discovered Solidity file into memory.
///
/// The returned entries preserve the file path so audit findings can report
/// their exact source location.
fn read_files_content<'a>(path: &'a [PathBuf]) -> Result<Vec<ContentPath<'a>>, io::Error> {
    let mut files: Vec<ContentPath> = Vec::new();

    for file_path in path {
        let read_file = fs::read_to_string(file_path)?;
        let full = ContentPath {
            content: read_file,
            path: file_path,
        };

        files.push(full);
    }

    Ok(files)
}

/// Prints Solidity files or audit warnings, depending on the selected mode.
///
/// In listing mode, each discovered `.sol` file path is printed. In audit mode,
/// each matching pattern is printed with the file path and one-based line
/// number where it appears.
fn audit_files(contents: &[ContentPath], audit_mode: bool, pattern: &[&str]) {
    for content in contents {
        if !audit_mode {
            println!("{}", content.path.display());
            continue;
        }

        for (line_number, line) in content.content.lines().enumerate() {
            for pattern in pattern {
                if line.contains(pattern) {
                    println!(
                        "[WARN] {}:{} - {}",
                        content.path.display(),
                        line_number + 1,
                        pattern
                    );
                }
            }
        }
    }
}
