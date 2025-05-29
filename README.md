# Hide&Lock: Secure File & Directory Encryption Tool 🔒

A powerful command-line tool for securely encrypting and managing sensitive files and directories with session support and advanced file utilities.

## ⚠️ Important Disclaimer
**We are not responsible for any data loss.** While Hide&Lock is designed to be secure and reliable:
- Always keep backups of important files before locking them
- Store your master keys in a safe place
- Be careful with sensitive directories
- Data loss might occur due to:
  - Forgetting passwords or master keys
  - System crashes during encryption/decryption
  - Improper use of force options (-r)
  - Accidental deletion of configuration

## Features ✨

- 🔐 Strong AES256 encryption
- 📁 Session-based file management
- 🔑 Master key recovery system
- ⚡ Temporary and permanent unlocking options 
- 🛡️ Sensitive directory protection
- 🎯 Simple and intuitive interface
- 🔄 Multiple session support with separate passwords
- ⚙️ Session management tools
- 📅 **NEW: Timestamp manipulation** - Modify file/folder creation and modification dates
- 🕐 **NEW: Batch timestamp operations** - Update multiple files at once
- 📋 **NEW: Timestamp copying** - Copy timestamps between files

## Installation 🚀

```bash
# Clone the repository
git clone https://github.com/ishaq2321/hide-and-lock.git

# Navigate to the directory
cd hide-and-lock

# Make the script executable
chmod +x lock.sh
```

## Quick Start 🎯

```bash
# Basic usage
./lock.sh                    # Start normally
./lock.sh -s Photos          # Start with session 'Photos'
./lock.sh -h                 # Show help menu
```

## Usage Examples 💡

### Basic Operations
```bash
# Lock a directory
./lock.sh
> Choose option 1
> Enter path: /path/to/folder

# Unlock a directory
./lock.sh
> Choose option 2
> Select ID and unlock type

# Timestamp manipulation
./lock.sh
> Choose option 4
> Various timestamp operations available
```

### Timestamp Manipulation Examples
```bash
# View current timestamps
./lock.sh
> Option 4 -> Option 1
> Enter file path

# Set specific timestamps
./lock.sh
> Option 4 -> Option 2
> Enter timestamps in various formats:
  - "2023-12-25 15:30:00"
  - "2023-12-25"
  - "2 days ago"
  - "last week"

# Copy timestamps from another file
./lock.sh
> Option 4 -> Option 3
> Specify source and target files

# Batch operations
./lock.sh
> Option 4 -> Option 4
> Update multiple files with same timestamp
```

## Advanced Usage 💡

### Session Management
```bash
# Create/access a session
./lock.sh -s Photos         # Work with Photos session
./lock.sh -s Documents      # Work with Documents session

# Delete a session
./lock.sh --delete-session  # Interactive session deletion

# Each session has:
- Independent password
- Unique master key
- Separate locked items
- Isolated configuration
```

### Security Options
```bash
# Force lock sensitive directories
./lock.sh -r -k <key> /path/to/sensitive

# Recover using master key
./lock.sh -m <master-key>

# Delete configuration
./lock.sh --delete-config

# Show version info
./lock.sh -v
```

## Command Line Options 📝

```bash
Options:
  -h, --help         Show help message
  -m KEY            Recover using master key
  -r                Force lock sensitive directories
  -k KEY            Provide current key for operations
  -s SESSION        Specify session name (e.g., Photos, Documents)
  -v, --version     Show program version and author information
  --delete-session  Delete a specific session (interactive)
  --delete-config   Delete configuration (requires password)
```

## Timestamp Manipulation Features 📅

### Supported Date Formats
- **ISO Format**: `2023-12-25 15:30:00`
- **Date Only**: `2023-12-25`
- **Relative**: `2 days ago`, `last week`, `yesterday`
- **Natural**: `Dec 25 2023`, `Christmas 2023`

### Operations Available
1. **View Timestamps** - Display current access, modify, and change times
2. **Set Specific Times** - Manually set access and modification times
3. **Copy Timestamps** - Copy timestamps from one file to another
4. **Batch Operations** - Update multiple files/directories at once
5. **Reset to Current** - Update timestamps to current time

### Use Cases
- **Privacy**: Remove traces of when files were accessed/modified
- **Organization**: Set consistent timestamps for related files
- **Forensics**: Analyze or modify file timeline information
- **Backup Restoration**: Maintain original timestamps after restoration

## Tips & Best Practices 💪

1. **Session Management:**
   - Create separate sessions for different types of data
   - Use meaningful session names
   - Keep track of master keys for each session
   - Regularly backup session configurations

2. **Data Safety:**
   - Never delete configuration directories manually
   - Always use --delete-session for removing sessions
   - Keep master keys in a secure, separate location
   - Test unlocking before deleting original files

3. **Sensitive Directories:**
   - Check sensitive_dirs.txt for protected locations
   - Use -r flag carefully with sensitive directories
   - Create sessions away from system directories

4. **Timestamp Operations:**
   - Always verify timestamps after modification
   - Be careful with batch operations on system files
   - Keep backups before major timestamp changes
   - Use relative dates for convenience ("2 days ago")

## Contributing 🤝

Contributions are welcome! Please feel free to submit pull requests.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a pull request

## Coming for Windows in the next version.

## Contact 📞

For support, feature requests, or issues:
- 📧 Email: andmynameiskhan@gmail.com
- 🌐 GitHub Issues: [Create an issue](https://github.com/ishaq2321/hide-and-lock/issues)

## License 📄

This project is licensed under the MIT See the [LICENSE](LICENSE) file for details.

---

> **Note:** This tool is for legitimate use only. Always respect privacy and data protection laws.
