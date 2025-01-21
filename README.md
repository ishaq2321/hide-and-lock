# Hide&Lock: Secure File & Directory Encryption Tool 🔒

A powerful command-line tool for securely encrypting and managing sensitive files and directories with session support.

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
./lock.sh                     # Start normally
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

## Security Features 🛡️

- AES256 encryption
- Session isolation
- Password hashing
- Master key recovery
- Immutable configuration
- Temporary unlock support

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

## Troubleshooting 🔧

Common issues and solutions:

1. **Access Denied:**
   - Verify correct password
   - Check file permissions
   - Ensure proper directory access

2. **Session Issues:**
   - Confirm session name
   - Check session directory exists
   - Verify session permissions

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

- 📱 Phone: +36 70 574 4971
- 📧 Email: andmynameiskhan@gmail.com
- 🌐 GitHub Issues: [Create an issue](https://github.com/ishaq2321/hide-and-lock/issues)

## License 📄

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

---

Made with ❤️ by Muhammad Ishaq Khan

> **Note:** This tool is for legitimate use only. Always respect privacy and data protection laws.
