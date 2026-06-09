use std::{ fs, io,
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
    "onlyOwner",           // Centralization risks
    "onlyRole",            // Role-based access control
    "initializer",         // Initialization vulnerabilities
    "initialize(",         // Unprotected initializers
    "constructor()",       // Missing constructors in upgradeable contracts
    
    // Arithmetic & Math
    "block.timestamp",     // Timestamp dependence
    "block.number",        // Block number dependence
    "blockhash",           // Blockhash predictability
    "now",                 // Deprecated alias for block.timestamp
    
    // Reentrancy & Call Risks
    ".send(",              // Gas stipend issues (2300 gas)
    ".transfer(",          // Gas stipend issues, breaks with gas changes
    ".gas(" ,              // Manual gas setting in calls
    ".value(",             // ETH value transfers
    
    // Low-level & Dangerous Patterns
    "callcode",            // Deprecated, similar to delegatecall
    "staticcall",          // Low-level call variants
    "address(",            // Address casting that might fail
    "create2",             // Contract creation with predictable addresses
    
    // Visibility & Type Issues
    "public ",             // Public state variables (review for sensitive data)
    "external",            // External functions without access control
    "payable",             // Payable functions (ETH reception risks)
    "private ",            // Private variables (still visible on-chain)
    
    // Logic & Validation
    "require(",            // Check validation completeness
    "assert(",             // Invariant checks (may consume all gas)            // Error handling patterns
    "delete ",             // Storage deletion patterns
    
    // Upgradeability Patterns
    "upgradeTo(",          // Upgrade risks
    "proxiable",           // Proxy patterns
    "implementation(",     // Implementation address exposure
    
    // ERC Specific
    "approve(",            // Approval race conditions
    "transferFrom(",       // Allowance risks
    "mint(",               // Unrestricted minting
    "burn(",               // Burning logic
    "_burn(",              // Internal burn
    
    // Oracle & External Data
    "oracle",              // Oracle manipulation
    "price",               // Price feed risks
    "getReserves",         // DEX reserve manipulation
    
    // Gas & Economics
    "gasleft()",           // Gas manipulation
    "tx.gasprice",         // Gas price dependence
    "block.gaslimit",      // Gas limit dependence
    
    // Randomness & Privacy
    "keccak256",           // Used for randomness (bad practice)
    "abi.encodePacked",    // Hash collision risks
    "bytes.concat",        // Similar risks to encodePacked
    
    // Withdrawal Patterns
    ".withdraw(",          // Withdrawal function without reentrancy guard
    "withdraw(",           // Alternative withdrawal pattern
    
    // Timelock & Delays
    "timelock",            // Delayed execution
    "onlyAfter",           // Time-based restrictions



    // Modern Access Control & Upgradeability
    "_disableInitializers",   // Unprotected implementation contracts
    "_grantRole",             // Privileged role assignment
    "_setupRole",             // Internal/initial role setup
    "Ownable2Step",           // Check if standard Ownable is used instead

    // Advanced Low-Level & Token Vectors
    "ecrecover",              // Signature malleability risks
    "_safeMint",              // Reentrancy vector in NFT minting
    "safeTransfer",           // Ensure SafeERC20 wrappers are utilized

    // EVM Inline Assembly (Yul)
    "sstore",                 // Raw storage writes (bypasses compiler safety)
    "sload",                  // Raw storage reads
    "extcodesize",            // Easily bypassed contract-check pattern

    // DeFi & Oracle Vectors
    "slot0",                  // Uniswap V3 manipulation risk (needs TWAP)
    "flashLoan",              // Flash loan execution and repayment logic
    
    // Context & Environmental Variables
    "_msgSender()",           // Meta-transactions (GSN/ERC2771) context
    "block.coinbase",         // Miner/validator controlled environmental variable
];




/// CLI configuration provided by the user.
pub struct Config<'a> {
    /// Directory that should be searched for Solidity files.
    pub file_path: &'a str,
}

/// Parsed command-line input used by the scanner.
pub struct InputParsed<'a> {
    /// Filesystem settings for the current run.
   pub  file_config: Config<'a>,
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











 impl<'a> InputParsed<'a>{
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




pub fn full_content_readed(parsed_input:InputParsed) {


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
