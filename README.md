# hide_and_lock

`hide_and_lock` is a secure file/folder encryption tool that allows you to lock and unlock sensitive directories with a password. It uses GPG for encryption and provides additional features such as password recovery and secure deletion of the configuration directory.

## Features

- Lock and unlock files and directories with a password
- Support for sensitive directories
- Password recovery using a master key
- Secure deletion of the configuration directory with password verification
- Change password functionality

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/ishaq2321/hide_and_lock.git
    cd hide_and_lock
    ```

2. Make the scripts executable:

    ```bash
    chmod +x lock.sh delete_secure_lock.sh
    ```

## Usage

### Locking and Unlocking Items

To lock a new item:

```bash
./lock.sh
```

Follow the on-screen instructions to lock a new item.

To unlock an item:

```bash
./lock.sh
```

Follow the on-screen instructions to unlock an item.

### Changing Password

To change the password:

```bash
./lock.sh
```

Select the option to change the password and follow the on-screen instructions.

### Deleting Configuration Directory

To securely delete the configuration directory:

```bash
./delete_secure_lock.sh
```

You will be prompted to enter your password to confirm the deletion.

## Command Line Options

- `-h, --help`: Show the help message
- `-m <key>`: Recover access using the master key
- `-r`: Force lock sensitive directories
- `-k <key>`: Provide the current key for operations

## Examples

Start the program normally:

```bash
./lock.sh
```

Recover access using the master key:

```bash
./lock.sh -m <key>
```

Force lock a sensitive directory:

```bash
./lock.sh -r /path -k <current key>
```

## Sensitive Directories

The following directories are considered sensitive and are not recommended to be locked:

```
/
/bin
/boot
/dev
/etc
/home
/lib
/lib64
/media
/mnt
/opt
/proc
/root
/run
/sbin
/srv
/sys
/tmp
/usr
/var
/home/ishaq2321/Desktop
/home/ishaq2321/Downloads
/home/ishaq2321/Documents
/home/ishaq2321/Music
/home/ishaq2321/Pictures
/home/ishaq2321/Videos
```

## License

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Contact

For any questions or support, please contact [ishaq2321](https://github.com/ishaq2321).
