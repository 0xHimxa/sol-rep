use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

fn main() {
    let patten = ["tx.origin", "delegatecall",".call","selfdestruct","assembly","unchecked"];
    println!("Hello, world!");

    let user_input: Vec<String> = env::args().collect();

    let parsed_input = match input_config(&user_input) {
        Ok(config) => config,

        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };

    let read_files = match read_folder(&parsed_input.file_config.file_path.as_ref()) {
        Ok(files) => files,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };

    let content_in_files = match files_content(&read_files) {
        Ok(content) => content,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };

    audit_files(&content_in_files, parsed_input.mode, &patten);
}

fn read_folder(_folder_path: &Path) -> Result<Vec<PathBuf>, io::Error> {
    let mut paths: Vec<PathBuf> = Vec::new();
    let dir_read = fs::read_dir(_folder_path)?;

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

struct Config<'a> {
    file_path: &'a str
}

struct InputParsed<'a> {
    file_config: Config<'a>,
    mode: bool,
}

struct ContentPath<'a> {
    content: String,
    path: &'a PathBuf,
}

fn input_config<'a>(param: &'a [String]) -> Result<InputParsed<'a>, &'static str> {
    if param.len() < 2 {
        return Err("Not enough parameters");
    }

    let file_path = match param.get(1) {
        Some(path) => path,
        None => return Err("missing file path"),
    };
    let ava_mode = param.contains(&&"--audit-mode".to_string());

    let config = Config {
        file_path: &file_path,
    };

    let parsed = InputParsed {
        file_config: config,
        mode: ava_mode,
    };

    Ok(parsed)
}

fn files_content<'a>(path: &'a [PathBuf]) -> Result<Vec<ContentPath<'a>>, io::Error> {
    let mut files: Vec<ContentPath> = Vec::new();

    for file_path in path {
        let read_file = fs::read_to_string(&file_path)?;
        let  full = ContentPath {
            content: read_file,
            path: file_path,
        };

        files.push(full);
    }

    Ok(files)
}

fn audit_files(contents: &[ContentPath], audit_mode: bool, pattern: &[&str]) {
    for content in contents {
        if !audit_mode {
            println!("{}", content.path.display());
            continue;
        }

        for (lines_num, line) in content.content.lines().enumerate() {
            for patten in pattern {
                if line.contains(patten) {
                    println!(
                        "[WARN] {}:{} - {}",
                        content.path.display(),
                        lines_num + 1,
                        patten
                    );
                }
            }
        }
    }
}
