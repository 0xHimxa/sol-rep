So far, the code makes sense and is getting the job done.

I really need to handle errors gracefully and the current revert that I allowed.


**TODO**: Switch from line.contains() to Regular Expressions (Regex) to prevent formatting variations (like extra spaces, tabs, or newlines) from bypassing the scanner, and to stop the tool from incorrectly flagging patterns hidden inside safe code comments.

The issue is that the scanner currently checks each source line with simple
substring matching. That makes it easy to understand, but it also means the
tool does not really understand Solidity syntax yet. A risky expression like
`tx.origin` can be missed if it is split across multiple lines, while the same
text inside a comment can still be reported as a warning.

This matters because a security scanner should help reduce review blind spots.
False negatives are dangerous because risky code can pass without being shown
to the auditor. False positives also matter because too many noisy warnings can
make real issues easier to ignore.



need to write test for it , when i learned i completed ready rust ch13 i will comeback and change some stuff.


need to add text explaining the issue and why it matters
