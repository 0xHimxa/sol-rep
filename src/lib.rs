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
    println!("path to read,{}", parsed_input.file_config.file_path);
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

mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_input_parsing() {
        let input_var = [
            "contract".to_string(),
            "sol_grip".to_string(),
            "--audit-mode".to_string(),
        ];
        let parsed = InputParsed::new(&input_var);
        let value = match &parsed {
            Ok(config) => config,
            Err(e) => {
                println!("Error: {}", e);
                return;
            }
        };
        println!("path: {}", value.file_config.file_path);
        assert_eq!(value.file_config.file_path, "sol_grip");
        assert!(value.mode);

        assert!(parsed.is_ok());
    }

    #[test]
    fn test_input_fail_no_argument() {
        let input_var = ["contract".to_string()];
        let parsed = InputParsed::new(&input_var);

        assert!(parsed.is_err());
    }

    #[test]
    fn test_read_folder_no_sol_files() {
        let temp_dir = tempdir().unwrap();

        let path = temp_dir.path().join("text.txt");
        let content = "void main() {}";
        let mut createPath = std::fs::File::create(&path).unwrap();
        createPath.write_all(content.as_bytes()).unwrap();

        let result = read_folder(temp_dir.path()).unwrap();
        assert!(result.len() == 0);
    }

    #[test]
    fn test_deep_file_read() {
        let temp_dir = tempdir().unwrap();
        let root_dir = temp_dir.path();

        let path = temp_dir.path().join("text.sol");
        let content = "void main() {}";
        let mut createPath = std::fs::File::create(&path).unwrap();
        createPath.write_all(content.as_bytes()).unwrap();

        //first deep

        let f_deep = temp_dir.path().join("deep");
        std::fs::create_dir(&f_deep).unwrap();
        let f_path = f_deep.join("f.sol");
        let f_content = "void main() {}";
        let mut f_createPath = std::fs::File::create(&f_path).unwrap();
        f_createPath.write_all(f_content.as_bytes()).unwrap();

        // second deep deeo

        let s_deep = f_deep.join("second_deep");
        std::fs::create_dir(&s_deep).unwrap();
        let s_path = s_deep.join("s.sol");
        let s_content = "void main() {}";
        let mut f_createPath = std::fs::File::create(&s_path).unwrap();
        f_createPath.write_all(s_content.as_bytes()).unwrap();

        let result = read_folder(root_dir).unwrap();
        assert!(
            result.iter().any(|p| p.ends_with("s.sol")),
            "Could not find s.sol in {:?}",
            result
        );
        assert!(
            result.iter().any(|p| p.ends_with("f.sol")),
            "Could not find f.sol in {:?}",
            result
        );
        assert!(
            result.iter().any(|p| p.ends_with("text.sol")),
            "Could not find text.sol in {:?}",
            result
        );

        assert!(result.len() == 3);
    }







#[test]
fn test_read_files_content_multiple_files() {
    let temp_dir = tempdir().unwrap();
    
    // Create test files with content
    let file1_path = temp_dir.path().join("test1.sol");
    let content1 = "contract Test1 { \n  function test() public {}\n}";
    let mut file = File::create(&file1_path).unwrap();
    file.write_all(content1.as_bytes()).unwrap();
    
    let file2_path = temp_dir.path().join("test2.sol");
    let content2 = "contract Test2 { \n  address owner;\n}";
    let mut file = File::create(&file2_path).unwrap();
    file.write_all(content2.as_bytes()).unwrap();
    
    // Create vector of paths
    let paths = vec![file1_path, file2_path];
    
    // Test the function
    let result = read_files_content(&paths).unwrap();
    
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].content, content1);
    assert_eq!(result[1].content, content2);
    assert_eq!(result[0].path.file_name().unwrap(), "test1.sol");
    assert_eq!(result[1].path.file_name().unwrap(), "test2.sol");
}






#[test]
fn test_read_files_content_with_invalid_file() {
    let temp_dir = tempdir().unwrap();
    
    let valid_path = temp_dir.path().join("valid.sol");
    let mut file = File::create(&valid_path).unwrap();
    file.write_all(b"contract Valid {}").unwrap();
    
    let invalid_path = temp_dir.path().join("does_not_exist.sol");
    
    let paths = vec![valid_path, invalid_path];
    
    // Should return error because one file doesn't exist
    let result = read_files_content(&paths);
    assert!(result.is_err());
}




}
