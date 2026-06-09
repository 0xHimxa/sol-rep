use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// Solidity source patterns that commonly deserve manual security review.
const AUDIT_PATTERNS: &[&str] = &[
    //
    "tx.origin",
    "delegatecall",
    ".call",
    "selfdestruct",
    "assembly",
    "unchecked",
    // Access Control & Authorization
    "onlyOwner",     // Centralization risks
    "onlyRole",      // Role-based access control
    "initializer",   // Initialization vulnerabilities
    "initialize(",   // Unprotected initializers
    "constructor()", // Missing constructors in upgradeable contracts
    // Arithmetic & Math
    "block.timestamp", // Timestamp dependence
    "block.number",    // Block number dependence
    "blockhash",       // Blockhash predictability
    "now",             // Deprecated alias for block.timestamp
    // Reentrancy & Call Risks
    ".send(",     // Gas stipend issues (2300 gas)
    ".transfer(", // Gas stipend issues, breaks with gas changes
    ".gas(",      // Manual gas setting in calls
    ".value(",    // ETH value transfers
    // Low-level & Dangerous Patterns
    "callcode",   // Deprecated, similar to delegatecall
    "staticcall", // Low-level call variants
    "address(",   // Address casting that might fail
    "create2",    // Contract creation with predictable addresses
    // Visibility & Type Issues
    "public ",  // Public state variables (review for sensitive data)
    "external", // External functions without access control
    "payable",  // Payable functions (ETH reception risks)
    "private ", // Private variables (still visible on-chain)
    // Logic & Validation
    "require(", // Check validation completeness
    "assert(",  // Invariant checks (may consume all gas)            // Error handling patterns
    "delete ",  // Storage deletion patterns
    // Upgradeability Patterns
    "upgradeTo(",      // Upgrade risks
    "proxiable",       // Proxy patterns
    "implementation(", // Implementation address exposure
    // ERC Specific
    "approve(",      // Approval race conditions
    "transferFrom(", // Allowance risks
    "mint(",         // Unrestricted minting
    "burn(",         // Burning logic
    "_burn(",        // Internal burn
    // Oracle & External Data
    "oracle",      // Oracle manipulation
    "price",       // Price feed risks
    "getReserves", // DEX reserve manipulation
    // Gas & Economics
    "gasleft()",      // Gas manipulation
    "tx.gasprice",    // Gas price dependence
    "block.gaslimit", // Gas limit dependence
    // Randomness & Privacy
    "keccak256",        // Used for randomness (bad practice)
    "abi.encodePacked", // Hash collision risks
    "bytes.concat",     // Similar risks to encodePacked
    // Withdrawal Patterns
    ".withdraw(", // Withdrawal function without reentrancy guard
    "withdraw(",  // Alternative withdrawal pattern
    // Timelock & Delays
    "timelock",  // Delayed execution
    "onlyAfter", // Time-based restrictions
    // Modern Access Control & Upgradeability
    "_disableInitializers", // Unprotected implementation contracts
    "_grantRole",           // Privileged role assignment
    "_setupRole",           // Internal/initial role setup
    "Ownable2Step",         // Check if standard Ownable is used instead
    // Advanced Low-Level & Token Vectors
    "ecrecover",    // Signature malleability risks
    "_safeMint",    // Reentrancy vector in NFT minting
    "safeTransfer", // Ensure SafeERC20 wrappers are utilized
    // EVM Inline Assembly (Yul)
    "sstore",      // Raw storage writes (bypasses compiler safety)
    "sload",       // Raw storage reads
    "extcodesize", // Easily bypassed contract-check pattern
    // DeFi & Oracle Vectors
    "slot0",     // Uniswap V3 manipulation risk (needs TWAP)
    "flashLoan", // Flash loan execution and repayment logic
    // Context & Environmental Variables
    "_msgSender()",   // Meta-transactions (GSN/ERC2771) context
    "block.coinbase", // Miner/validator controlled environmental variable
];

/// CLI configuration provided by the user.
#[derive(Debug)]
pub struct Config<'a> {
    /// Directory that should be searched for Solidity files.
    pub file_path: &'a str,
}

/// Parsed command-line input used by the scanner.
#[derive(Debug)]
pub struct InputParsed<'a> {
    /// Filesystem settings for the current run.
    pub file_config: Config<'a>,
    /// Enables pattern matching for security-sensitive Solidity constructs.
    pub mode: bool,
}
/// Solidity file content paired with its original path.
struct ContentPath<'a> {
    /// Full source text loaded from disk.
    content: String,
    /// Path to the source file the content came from.
    path: &'a PathBuf,
}

/// A single audit pattern match found in a Solidity source file.
#[derive(Debug, PartialEq, Eq)]
struct AuditFinding {
    /// File that contains the match.
    path: PathBuf,
    /// One-based line number where the match appears.
    line_number: usize,
    /// Pattern that was found on the line.
    pattern: String,
}

impl<'a> InputParsed<'a> {
    /// Parses command-line arguments into the scanner configuration.
    ///
    /// The first positional argument is treated as the folder to scan. Passing
    /// `--audit-mode` enables pattern checks; otherwise the scanner only lists
    /// discovered Solidity files.

    pub fn new(param: &'a [String]) -> Result<InputParsed<'a>, &'static str> {
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
}

pub fn full_content_readed(parsed_input: InputParsed) {
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

        for finding in find_audit_matches(content, pattern) {
            println!(
                "[WARN] {}:{} - {}",
                finding.path.display(),
                finding.line_number,
                finding.pattern
            );
        }
    }
}

/// Finds every configured audit pattern in a single Solidity file.
///
/// This intentionally uses `line.contains()` for now. The tests document that
/// current behavior so the scanner can be safely upgraded to regex parsing and
/// comment-aware matching later.
fn find_audit_matches(content: &ContentPath, patterns: &[&str]) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    for (line_number, line) in content.content.lines().enumerate() {
        for pattern in patterns {
            if line.contains(pattern) {
                findings.push(AuditFinding {
                    path: content.path.clone(),
                    line_number: line_number + 1,
                    pattern: pattern.to_string(),
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn test_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();

        env::temp_dir().join(format!("sol_grep_{name}_{unique}"))
    }

    #[test]
    fn input_parser_requires_a_file_path() {
        let args = vec!["sol_grep".to_string()];

        let err = InputParsed::new(&args).expect_err("missing path should fail");

        assert_eq!(err, "Not enough parameters");
    }

    #[test]
    fn input_parser_reads_path_and_audit_flag() {
        let args = vec![
            "sol_grep".to_string(),
            "contracts".to_string(),
            "--audit-mode".to_string(),
        ];

        let parsed = InputParsed::new(&args).expect("valid cli args should parse");

        assert_eq!(parsed.file_config.file_path, "contracts");
        assert!(parsed.mode);
    }

    #[test]
    fn input_parser_defaults_to_listing_mode_without_audit_flag() {
        let args = vec!["sol_grep".to_string(), "contracts".to_string()];

        let parsed = InputParsed::new(&args).expect("valid cli args should parse");

        assert_eq!(parsed.file_config.file_path, "contracts");
        assert!(!parsed.mode);
    }

    #[test]
    fn read_folder_recursively_returns_only_solidity_files() {
        let root = test_dir("read_folder");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).expect("test directory should be created");

        let root_sol = root.join("Root.sol");
        let nested_sol = nested.join("Nested.sol");
        let ignored_file = root.join("notes.txt");

        fs::write(&root_sol, "contract Root {}").expect("root solidity file should be written");
        fs::write(&nested_sol, "contract Nested {}")
            .expect("nested solidity file should be written");
        fs::write(ignored_file, "not solidity").expect("ignored file should be written");

        let mut files = read_folder(&root).expect("folder should be readable");
        files.sort();

        assert_eq!(files, vec![root_sol, nested_sol]);

        fs::remove_dir_all(root).expect("test directory should be removed");
    }

    #[test]
    fn read_files_content_preserves_file_paths_and_contents() {
        let root = test_dir("read_files_content");
        fs::create_dir_all(&root).expect("test directory should be created");

        let first = root.join("First.sol");
        let second = root.join("Second.sol");
        fs::write(&first, "contract First {}").expect("first file should be written");
        fs::write(&second, "contract Second {}").expect("second file should be written");
        let files = vec![first.clone(), second.clone()];

        let contents = read_files_content(&files).expect("files should be readable");

        assert_eq!(contents.len(), 2);
        assert_eq!(contents[0].path, &first);
        assert_eq!(contents[0].content, "contract First {}");
        assert_eq!(contents[1].path, &second);
        assert_eq!(contents[1].content, "contract Second {}");

        fs::remove_dir_all(root).expect("test directory should be removed");
    }

    #[test]
    fn find_audit_matches_reports_patterns_with_one_based_line_numbers() {
        let path = PathBuf::from("contracts/Risky.sol");
        let source = r#"contract Risky {
    function run(address target) external payable {
        target.delegatecall("");
        require(msg.sender == tx.origin);
    }
}"#;
        let content = ContentPath {
            content: source.to_string(),
            path: &path,
        };

        let findings = find_audit_matches(&content, &["delegatecall", "tx.origin", "payable"]);

        assert_eq!(
            findings,
            vec![
                AuditFinding {
                    path: path.clone(),
                    line_number: 2,
                    pattern: "payable".to_string(),
                },
                AuditFinding {
                    path: path.clone(),
                    line_number: 3,
                    pattern: "delegatecall".to_string(),
                },
                AuditFinding {
                    path,
                    line_number: 4,
                    pattern: "tx.origin".to_string(),
                },
            ]
        );
    }

    #[test]
    fn find_audit_matches_documents_current_contains_limitations() {
        let path = PathBuf::from("contracts/Comments.sol");
        let source = r#"contract Comments {
    // TODO: review tx.origin risk if this is ever added
    function split(address target) external {
        require(tx
            .origin == msg.sender);
    }
}"#;
        let content = ContentPath {
            content: source.to_string(),
            path: &path,
        };

        let findings = find_audit_matches(&content, &["tx.origin"]);

        assert_eq!(
            findings,
            vec![AuditFinding {
                path,
                line_number: 2,
                pattern: "tx.origin".to_string(),
            }]
        );
    }
}
