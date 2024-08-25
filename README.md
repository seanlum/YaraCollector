# YaraCollector
A tool for assembling large quantities of Yara rule files into a single scanner, and scanning a list of files 

## Notes
- This program has not implemented the following features yet. If you would like to contribute, open a pull request.
  - Multi-threaded / Multi-core programming. Was thinking of using `concurrent.futures`
  - Implement using a single rule file switch. Should allow multiple switches of the same name to submit multiple single files.
  - De-duping scanned files. For now all paths are converted to absolute paths and filtered. However, it is still possible to scan the same file twice.
  - Test output files and validate data joining with the `tail` command to read all file outputs to one file and compare with stdout as default.
  
