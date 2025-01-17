#!/bin/bash

CONFIG_DIR="$HOME/.config/secure_lock"
PASSWORD_FILE="$CONFIG_DIR/.password_hash"

# Function to hash a password
hash_password() {
    echo -n "$1" | sha256sum | awk '{print $1}'
}

# Check if the configuration directory exists
if [ ! -d "$CONFIG_DIR" ]; then
    echo "Configuration directory does not exist."
    exit 1
fi

# Prompt for password
echo -n "Enter your password to confirm deletion: "
read -s entered_password
echo

# Verify password
stored_hash=$(cat "$PASSWORD_FILE")
entered_hash=$(hash_password "$entered_password")

if [ "$entered_hash" == "$stored_hash" ]; then
    echo "Password verified. Deleting configuration directory..."
    rm -rf "$CONFIG_DIR"
    echo "Configuration directory deleted."
else
    echo "Incorrect password. Deletion aborted."
    exit 1
fi
