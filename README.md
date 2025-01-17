# Hide&Lock: Secure File & Directory Encryption Tool 🔒

A powerful command-line tool for securely encrypting and managing sensitive files and directories with session support.

## Features ✨

- 🔐 Strong AES256 encryption
- 📁 Session-based file management
- 🔑 Master key recovery system
- ⚡ Temporary and permanent unlocking options 
- 🛡️ Sensitive directory protection
- 🎯 Simple and intuitive interface

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

### Session Management
```bash
# Create/access a session
./lock.sh -s Documents       # Work with Documents session
./lock.sh -s Photos         # Work with Photos session

# Each session maintains separate:
- Passwords
- Master keys
- Locked items
```

### Security Options
```bash
# Force lock sensitive directories
./lock.sh -r -k <key> /path/to/sensitive

# Recover using master key
./lock.sh -m <master-key>
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
  -h, --help     Show help message
  -m KEY         Recover using master key
  -r             Force lock sensitive directories
  -k KEY         Provide current key
  -s SESSION     Specify session name
```

## Tips & Best Practices 💪

1. **Always Remember:**
   - Keep master keys safe
   - Use strong passwords
   - Backup important files

2. **Session Usage:**
   - Create separate sessions for different purposes
   - Use meaningful session names
   - Don't share session passwords

3. **Security:**
   - Avoid locking system directories
   - Keep sensitive files separate
   - Regular password changes

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

## Contact 📞

For support, feature requests, or issues:

- 📱 Phone: +36 70 574 4971
- 📧 Email: andmynameiskhan@gmail.com
- 🌐 GitHub Issues: [Create an issue](https://github.com/ishaq2321/hide-and-lock/issues)

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Made with ❤️ by [Your Name]

> **Note:** This tool is for legitimate use only. Always respect privacy and data protection laws.
