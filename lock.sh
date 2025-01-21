#!/bin/bash

# Hide&Lock: Secure File & Directory Encryption Tool
# Author: Muhammad Ishaq Khan
# Contact: andmynameiskhan@gmail.com
# Version: 1.2.0

CONFIG_DIR="$HOME/.config/secure_lock"
CONFIG_FILE="$CONFIG_DIR/settings"
PASSWORD_FILE="$CONFIG_DIR/.password_hash"
METADATA_FILE="$CONFIG_DIR/items.log"
MASTER_KEY_FILE="$CONFIG_DIR/.master_key"
RECOVERY_SCRIPT="$CONFIG_DIR/password_recovery.sh"
USER_KEY_FILE="$CONFIG_DIR/.user_key"
SCRIPT_DIR=$(dirname "$(realpath "$0")")
SENSITIVE_DIRS_FILE="$SCRIPT_DIR/sensitive_dirs.txt"

# Add session-specific variables near the top with other configs
SESSION_NAME=""
BASE_SESSION_DIR="$HOME/.config/secure_lock_sessions"

# Create config directory if it doesn't exist
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# Initialize metadata file if it doesn't exist
touch "$METADATA_FILE"
chmod 600 "$METADATA_FILE"

declare -a TEMP_UNLOCKED_ITEMS

# Add GPG options
GPG_OPTS="--cipher-algo AES256 --batch --yes --no-tty --quiet"

CURRENT_PASSWORD=""
MASTER_KEY_USED=false
FORCE_LOCK=false
LOCK_PATH=""

# Add color codes near the top
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Add new variable near the top with other configs
RECOVERY_PASSWORD_FILE="$CONFIG_DIR/.recovery_password"

# Add new function to validate metadata entries
function validate_metadata() {
    local temp_file="$METADATA_FILE.tmp"
    local valid_entries=0
    
    # Clear temporary file
    > "$temp_file"
    
    # Check each entry
    while IFS='|' read -r name path created locked size || [ -n "$name" ]; do
        local encrypted_file="$CONFIG_DIR/$name.gpg"
        # Only keep entries that have corresponding encrypted files
        if [ -f "$encrypted_file" ]; then
            echo "$name|$path|$created|$locked|$size" >> "$temp_file"
            ((valid_entries++))
        fi
    done < "$METADATA_FILE"
    
    # Replace original with validated entries
    mv "$temp_file" "$METADATA_FILE"
    chmod 600 "$METADATA_FILE"
    
    return $valid_entries
}

# Modified add_lock_entry function
function add_lock_entry() {
    local target="$1"
    local name=$(basename "$target")
    
    # Check if item is already locked
    while IFS='|' read -r existing_name existing_path _ _ _ || [ -n "$existing_name" ]; do
        if [ "$existing_path" == "$target" ] || [ "$existing_name" == "$name" ]; then
            echo "Error: This item is already locked or a similar name exists!"
            return 1
        fi
    done < "$METADATA_FILE"
    
    local created=$(stat -c %y "$target" 2>/dev/null || echo "N/A")
    local locked=$(date "+%Y-%m-%d %H:%M:%S")
    local size=$(du -sh "$target" 2>/dev/null | cut -f1)
    echo "$name|$target|$created|$locked|$size" >> "$METADATA_FILE"
}

# Simplified encryption function to use only the password
encrypt_with_password() {
    local input_file="$1"
    local output_file="$2"
    local password="$3"
    
    echo "Encrypting with password..."
    # Encrypt with password
    if ! gpg $GPG_OPTS --passphrase-fd 3 --symmetric --output "$output_file" 3<<< "$password" < "$input_file"; then
        echo "Error: Failed to encrypt with password"
        return 1
    fi
    
    return 0
}

# Simplified decryption function to use only the password
decrypt_with_password() {
    local input_file="$1"
    local output_file="$2"
    local password="$3"
    
    echo "Decrypting with password..."
    # Try decryption with password
    if gpg $GPG_OPTS --passphrase-fd 3 --decrypt --output "$output_file" 3<<< "$password" < "$input_file"; then
        return 0
    fi
    
    echo "Error: Failed to decrypt with password"
    return 1
}

# Updated function to check if a directory is sensitive
is_sensitive_directory() {
    local dir="$1"
    # Normalize the path (remove trailing slash if exists)
    dir="${dir%/}/"
    # Expand $HOME variable in the input path
    dir="${dir/\$HOME/$HOME}"
    dir="${dir/\~/$HOME}"
    
    while IFS= read -r sensitive_dir || [ -n "$sensitive_dir" ]; do
        # Skip empty lines and comments
        [[ -z "$sensitive_dir" || "$sensitive_dir" =~ ^[[:space:]]*# ]] && continue
        
        # Expand $HOME variable in the sensitive directory path
        sensitive_dir="${sensitive_dir/\$HOME/$HOME}"
        sensitive_dir="${sensitive_dir/\~/$HOME}"
        
        # Normalize the sensitive directory path
        sensitive_dir="${sensitive_dir%/}/"
        
        if [[ "$dir" == "$sensitive_dir" ]]; then
            return 0
        fi
    done < "$SENSITIVE_DIRS_FILE"
    return 1
}

# Modified lock_item function to handle sensitive directories
function lock_item() {
    local source_path="$1"
    local source_name=$(basename "$source_path")
    local encrypted_file="$CONFIG_DIR/$source_name.gpg"
    local is_relock=${2:-false}  # New parameter for re-locking
    
    # Check for sensitive directories
    if is_sensitive_directory "$source_path" && [ "$FORCE_LOCK" = false ]; then
        echo -e "${RED}Error: You are trying to lock a folder marked as sensitive.${NC}"
        echo -e "${YELLOW}If you really want to lock this folder, use the -r option:${NC}"
        echo -e "${YELLOW}Example: ./lock.sh -r -k <current key> \"$source_path\"${NC}"
        return 1
    fi
    
    # Skip "already locked" check if this is a re-lock operation
    if [ "$is_relock" != "true" ] && [ -f "$encrypted_file" ]; then
        echo "Error: An item with this name is already locked!"
        return 1
    fi
    
    # Check if source exists
    if [ ! -e "$source_path" ]; then
        echo "Error: Source path does not exist!"
        return 1
    fi
    
    # Create temporary file for tar output
    local temp_tar=$(mktemp)
    
    # Create archive first
    tar czf "$temp_tar" -C "$(dirname "$source_path")" "$(basename "$source_path")" || {
        rm -f "$temp_tar"
        echo "Error: Failed to create archive!"
        return 1
    }
    
    # Encrypt the archive
    if encrypt_with_password "$temp_tar" "$encrypted_file" "$CURRENT_PASSWORD"; then
        local gpg_status=0
    else
        local gpg_status=1
    fi
    
    # Clean up temp file
    rm -f "$temp_tar"
    
    if [ $gpg_status -eq 0 ]; then
        if [ "$is_relock" != "true" ]; then
            if add_lock_entry "$source_path"; then
                rm -rf "$source_path"
                echo "Successfully locked $source_name"
                return 0
            else
                rm -f "$encrypted_file"
                return 1
            fi
        else
            rm -rf "$source_path"
            echo "Successfully re-locked $source_name"
            return 0
        fi
    else
        echo "Encryption failed with status: $gpg_status"
        rm -f "$encrypted_file"
        return 1
    fi
}

# Modified unlock_item function - improve error handling
function unlock_item() {
    local encrypted_file="$1"
    local target_dir="$2"
    local original_path="$3"
    
    # Check if encrypted file exists
    if [ ! -f "$encrypted_file" ]; then
        echo "Error: Encrypted file not found!"
        return 1
    fi
    
    # Create target directory if it doesn't exist
    mkdir -p "$target_dir"
    
    # Create temporary files
    local temp_dec=$(mktemp)
    
    # Try decryption with current password
    if decrypt_with_password "$encrypted_file" "$temp_dec" "$CURRENT_PASSWORD" 2>/tmp/gpg_error; then
        # Extract from temporary file
        (cd "$target_dir" && tar xzf "$temp_dec") 2>/tmp/tar_error
        local status=$?
        rm -f "$temp_dec" /tmp/tar_error
        [ $status -eq 0 ] && return 0
    fi
    
    echo "Decryption failed. Invalid password or corrupted file."
    echo "GPG Error: $(cat /tmp/gpg_error)"
    rm -f "$temp_dec" /tmp/tar_error /tmp/gpg_error
    return 1
}

# Add array to track temporarily unlocked items
declare -a TEMP_UNLOCKED_ITEMS

# Modified cleanup function to handle re-locking properly
function cleanup() {
    if [ ${#TEMP_UNLOCKED_ITEMS[@]} -gt 0 ]; then
        echo -e "\nRe-locking temporarily unlocked items..."
        for item in "${TEMP_UNLOCKED_ITEMS[@]}"; do
            IFS='|' read -r name path created locked size <<< "$item"
            if [ -e "$path" ]; then
                echo "Re-locking: $path"
                # Pass true as second parameter to indicate this is a re-lock
                if lock_item "$path" true; then
                    echo "Successfully re-locked: $path"
                else
                    echo "Warning: Failed to re-lock: $path"
                fi
            fi
        done
        echo "Cleanup complete!"
    fi
    exit 0
}

# Set trap for cleanup on exit
trap cleanup EXIT

# Function to hash a password
hash_password() {
    echo -n "$1" | sha256sum | awk '{print $1}'
}

# Add new functions for master key handling
generate_master_key() {
    # Generate a random 32-character master key
    openssl rand -hex 16 > "$MASTER_KEY_FILE"
    chmod 600 "$MASTER_KEY_FILE"
    echo -e "\n${YELLOW}  ╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}  ║                     ${RED}! IMPORTANT !${YELLOW}                         ║${NC}"
    echo -e "${YELLOW}  ║ ${GREEN}Your master key is: $(cat "$MASTER_KEY_FILE")${YELLOW}      ║${NC}"
    echo -e "${YELLOW}  ║ Store this key in a secure location for password recovery ║${NC}"
    echo -e "${YELLOW}  ╚═══════════════════════════════════════════════════════════╝${NC}\n"
}

# Add function to generate and store user key
generate_user_key() {
    echo -n "$CURRENT_PASSWORD" > "$USER_KEY_FILE"
    chmod 600 "$USER_KEY_FILE"
}

# Add function to retrieve user key
get_user_key() {
    cat "$USER_KEY_FILE"
}

# Updated help menu function
show_help() {
    echo "Usage: $(basename "$0") [OPTION]"
    echo "Secure file/folder encryption tool"
    echo
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -m KEY         Recover access using master key"
    echo "  -r             Force lock sensitive directories"
    echo "  -k KEY         Provide current key for operations"
    echo "  -s SESSION     Specify session name (e.g., Photos, Documents)"
    echo
    echo "Examples:"
    echo "  $(basename "$0")              Start the program normally"
    echo "  $(basename "$0") -m <key>     Recover access using master key"
    echo "  $(basename "$0") -r /path -k <current key>  Force lock sensitive directory"
    echo "  $(basename "$0") -s Photos    Start the program with session 'Photos'"
    echo
    echo "To clean all data and start fresh:"
    # echo "  rm -rf $CONFIG_DIR"
}

# Add command line argument handling (add this before the main script logic)
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -m)
            shift
            if [ -z "$1" ]; then
                echo "Error: Master key required"
                exit 1
            fi
            if [ "$1" == "$(cat "$MASTER_KEY_FILE")" ]; then
                CURRENT_PASSWORD=$(get_user_key)
                MASTER_KEY_USED=true
                echo "Master key verified successfully"
                echo -e "${YELLOW}Your key is: ${GREEN}$CURRENT_PASSWORD${NC}"
                echo "Press Enter to exit..."
                read
                exit 0
            else
                echo "Invalid master key"
                exit 1
            fi
            shift
            ;;
        -r)
            FORCE_LOCK=true
            shift
            ;;
        -k)
            shift
            if [ -z "$1" ]; then
                echo "Error: Key required"
                exit 1
            fi
            entered_key="$1"
            stored_key=$(get_user_key)
            if [ "$entered_key" != "$stored_key" ]; then
                echo "Error: Invalid key"
                exit 1
            fi
            CURRENT_PASSWORD="$1"
            shift
            ;;
        -s|--session)
            shift
            if [ -z "$1" ]; then
                echo "Error: Session name required"
                exit 1
            fi
            SESSION_NAME="$1"
            # Set config paths for session
            CONFIG_DIR="$BASE_SESSION_DIR/$SESSION_NAME/config"
            CONFIG_FILE="$CONFIG_DIR/settings"
            PASSWORD_FILE="$CONFIG_DIR/.password_hash"
            METADATA_FILE="$CONFIG_DIR/items.log"
            MASTER_KEY_FILE="$CONFIG_DIR/.master_key"
            USER_KEY_FILE="$CONFIG_DIR/.user_key"
            shift
            ;;
        -v|--version)
            echo "Hide&Lock version 1.2.0"
            echo "Author: Muhammad Ishaq Khan"
            echo "Contact: andmynameiskhan@gmail.com"
            exit 0
            ;;
        --delete-config)
            echo -n "Enter your password to confirm deletion: "
            read -s entered_password
            echo
            stored_hash=$(cat "$PASSWORD_FILE")
            entered_hash=$(hash_password "$entered_password")

            # Added user confirmation prompt
            if [ "$entered_hash" == "$stored_hash" ]; then
                echo -n "Are you sure you want to delete $CONFIG_DIR? [y/N]: "
                read confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    echo "Password verified. Deleting configuration directory..."
                    rm -rf "$CONFIG_DIR"
                    echo "Configuration directory deleted."
                    exit 0
                else
                    echo "Deletion aborted."
                    exit 1
                fi
            else
                echo "Incorrect password. Deletion aborted."
                exit 1
            fi
            ;;
        *)
            if [ "$FORCE_LOCK" = true ]; then
                LOCK_PATH="$1"
                shift
            else
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
            fi
            ;;
    esac
done

if [ "$FORCE_LOCK" = true ] && [ -n "$LOCK_PATH" ]; then
    if [ -z "$CURRENT_PASSWORD" ]; then
        echo "Error: Key required"
        exit 1
    fi
    lock_item "$LOCK_PATH"
    exit $?
fi

# Remove the first-time setup section completely and replace with simple directory check
if [ ! -d "$CONFIG_DIR" ]; then
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    touch "$METADATA_FILE"
    chmod 600 "$METADATA_FILE"

    # Call protect_config_directory here
    protect_config_directory
fi

# Password setup
if [ ! -f "$PASSWORD_FILE" ]; then
    echo "First-time setup - Password Creation"
    echo -n "Enter a new password: "
    read -s new_password
    echo
    echo -n "Confirm the new password: "
    read -s confirm_password
    echo

    if [ "$new_password" == "$confirm_password" ]; then
        hash_password "$new_password" > "$PASSWORD_FILE"
        chmod 600 "$PASSWORD_FILE"
        echo -e "${GREEN}Password set successfully!${NC}"
        
        # Generate master key on first password setup
        if [ ! -f "$MASTER_KEY_FILE" ]; then
            generate_master_key
            echo "Press Enter to continue..."
            read
        fi
        
        # Set CURRENT_PASSWORD to the new password
        CURRENT_PASSWORD="$new_password"
        
        # Generate and store user key
        generate_user_key
    else
        echo -e "${RED}Passwords do not match. Exiting.${NC}"
        exit 1
    fi
fi

# Verify password if master key was not used
if [ "$MASTER_KEY_USED" = false ]; then
    echo -n "Enter your password: "
    read -s entered_password
    echo

    stored_hash=$(cat "$PASSWORD_FILE")
    entered_hash=$(hash_password "$entered_password")

    # Update the password verification section
    if [ "$entered_hash" == "$stored_hash" ];then
        CURRENT_PASSWORD="$entered_password"
        echo "Password verified successfully"  # Debug information
    else
        echo "Incorrect password. Access denied!"
        exit 1
    fi
fi

# Add initialization check after password verification
function initialize_session() {
    # Validate existing metadata and clean up invalid entries
    echo "Validating locked items..."
    validate_metadata
    local valid_count=$?
    
    if ( $valid_count -eq 0 ); then
        echo "No valid locked items found."
    else
        echo "Found $valid_count valid locked items."
    fi
}

# Add this after password verification
initialize_session

# Add function to change password
change_password() {
    echo -n "Enter current password: "
    read -s old_password
    echo
    
    old_hash=$(hash_password "$old_password")
    if [ "$old_hash" != "$(cat "$PASSWORD_FILE")" ];then
        echo -e "${RED}Incorrect current password!${NC}"
        return 1
    fi
    
    echo -n "Enter new password: "
    read -s new_password
    echo
    echo -n "Confirm new password: "
    read -s confirm_password
    echo
    
    if [ "$new_password" == "$confirm_password" ];then
        # Migrate encrypted files to new password
        local temp_dir=$(mktemp -d)
        local migration_failed=0
        local migrated_count=0
        
        echo -e "${YELLOW}Migrating encrypted files...${NC}"
        
        # Process each encrypted file
        while IFS='|' read -r name path created locked size || [ -n "$name" ];do
            local encrypted_file="$CONFIG_DIR/$name.gpg"
            local temp_dec="$temp_dir/$name"
            
            echo "Processing: $name"
            
            # Try to decrypt with old password
            if decrypt_with_password "$encrypted_file" "$temp_dec" "$old_password";then
                # Re-encrypt with new password
                if encrypt_with_password "$temp_dec" "$encrypted_file.new" "$new_password";then
                    mv "$encrypted_file.new" "$encrypted_file"
                    ((migrated_count++))
                    echo -e "${GREEN}Successfully migrated: $name${NC}"
                else
                    echo -e "${RED}Failed to re-encrypt: $name${NC}"
                    migration_failed=1
                fi
            else
                echo -e "${RED}Failed to decrypt: $name${NC}"
                migration_failed=1
            fi
            rm -f "$temp_dec"
        done < "$METADATA_FILE"
        
        # Clean up
        rm -rf "$temp_dir"
        
        if [ $migration_failed -eq 0 ];then
            # Update password file
            hash_password "$new_password" > "$PASSWORD_FILE"
            chmod 600 "$PASSWORD_FILE"
            
            # Update current session password
            CURRENT_PASSWORD="$new_password"
            
            # Generate new master key
            generate_master_key
            
            # Generate and store new user key
            generate_user_key
            
            echo -e "${GREEN}Password changed successfully!${NC}"
        else
            echo -e "${RED}Failed to migrate some files. Password unchanged.${NC}"
            return 1
        fi
    else
        echo -e "${RED}Passwords do not match!${NC}"
        return 1
    fi
}

# Updated menu function
show_menu() {
    clear
    echo "=== Secure Lock Menu ==="
    echo "1. Lock new item"
    echo "2. Unlock item"
    echo "3. Change password"
    echo "4. Exit"
    echo "Choose an option (1-4): "
}

# Remove change_password function

# Modified handle_unlock function to better track temporary items and support multiple IDs
function handle_unlock() {
    echo "=== Locked Items ==="
    echo "ID  | Name | Size | Created | Locked Date"
    echo "----------------------------------------"
    awk -F'|' '{printf "%-3d | %-20s | %-6s | %-19s | %s\n", NR, $1, $5, $3, $4}' "$METADATA_FILE"
    
    echo -n "Enter IDs to unlock (comma-separated, 0 to cancel): "
    read ids
    [ "$ids" = "0" ] && return
    
    # Split IDs by comma and trim spaces
    IFS=',' read -r -a id_array <<< "$ids"
    for i in "${!id_array[@]}";do
        id_array[$i]=$(echo "${id_array[$i]}" | xargs)
    done
    
    echo "1. Temporary unlock (until program exit)"
    echo "2. Permanent unlock"
    echo -n "Choose unlock type (1-2): "
    read unlock_type
    
    for id in "${id_array[@]}";do
        local line=$(sed "${id}!d" "$METADATA_FILE")
        if [ -n "$line" ];then
            IFS='|' read -r name path created locked size <<< "$line"
            ENCRYPTED_FILE="$CONFIG_DIR/$name.gpg"
            local target_dir=$(dirname "$path")
            
            echo "Unlocking $name..."
            if [ "$unlock_type" = "1" ];then
                if unlock_item "$ENCRYPTED_FILE" "$target_dir" "$path";then
                    TEMP_UNLOCKED_ITEMS+=("$name|$path|$created|$locked|$size")
                    echo "Successfully unlocked at: $path (temporary)"
                else
                    echo "Failed to unlock item!"
                fi
            elif [ "$unlock_type" = "2" ];then
                if unlock_item "$ENCRYPTED_FILE" "$target_dir" "$path";then
                    rm "$ENCRYPTED_FILE"
                    sed -i "${id}d" "$METADATA_FILE"
                    echo "Successfully unlocked at: $path (permanent)"
                else
                    echo "Failed to unlock item!"
                fi
            fi
        else
            echo "Invalid ID: $id"
        fi
    done
}

# Modified main menu loop
while true;do
    show_menu
    read choice
    case $choice in
        1)  # Lock new item
            # Enable tab-completion with read -e
            read -e -p "Enter folder path: " folder_path
            
            if [ -z "$folder_path" ];then
                echo "Error: No path provided"
                continue
            fi
            
            folder_path=$(realpath "$folder_path" 2>/dev/null)
            if [ -e "$folder_path" ];then
                echo "Locking: $folder_path"
                if lock_item "$folder_path";then
                    echo "Item locked successfully!"
                else
                    echo "Failed to lock item!"
                fi
            else
                echo "Invalid path: $folder_path"
            fi
            ;;
        2)  # Unlock item
            handle_unlock
            ;;
        3)  # Change password
            change_password
            ;;
        4)  # Exit
            cleanup
            ;;
        *)
            echo "Invalid option!"
            ;;
    esac
    echo
    read -p "Press Enter to continue..."
done

function protect_config_directory() {
    echo "Protecting configuration directory with immutable attribute..."
    # Check if running with sudo privileges
    if [[ $EUID -ne 0 ]];then
        echo "Warning: You may need sudo privileges to set the immutable bit."
    fi
    sudo chattr +i "$CONFIG_DIR" || echo "Warning: Failed to set immutable attribute."
}


