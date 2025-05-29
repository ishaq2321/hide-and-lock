#!/bin/bash

# Hide&Lock: Secure File & Directory Encryption Tool
# Author: Muhammad Ishaq Khan
# Contact: andmynameiskhan@gmail.com
# Version: 1.4.0

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
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Add new variable near the top with other configs
RECOVERY_PASSWORD_FILE="$CONFIG_DIR/.recovery_password"

# Define ALL functions at the start
function protect_config_directory() {
    echo "Protecting configuration directory with immutable attribute..."
    if [[ $EUID -ne 0 ]]; then
        echo "Warning: You may need sudo privileges to set the immutable bit."
    fi
    sudo chattr +i "$CONFIG_DIR" || echo "Warning: Failed to set immutable attribute."
}

function validate_password() {
    local password="$1"
    if [ -z "$password" ] || [ ${#password} -lt 4 ]; then
        echo -e "${RED}Error: Password must be at least 4 characters long${NC}"
        return 1
    fi
    return 0
}

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

# Add these functions near the top with other function definitions
get_master_key() {
    if [ -f "$1" ]; then
        cat "$1"
        return 0
    fi
    return 1
}

function find_session_by_master_key() {
    local input_key="$1"
    # Search all session directories
    for session_folder in "$BASE_SESSION_DIR"/*; do
        [ -d "$session_folder" ] || continue
        local possible_key_file="$session_folder/config/.master_key"
        if [ -f "$possible_key_file" ]; then
            local possible_key
            possible_key=$(cat "$possible_key_file")
            if [ "$input_key" == "$possible_key" ]; then
                echo "$(basename "$session_folder")"
                return 0
            fi
        fi
    done
    return 1
}

# Updated help menu function
show_help() {
    echo "Usage: $(basename "$0") [OPTION]"
    echo "Secure file/folder encryption tool"
    echo
    echo "Options:"
    echo "  -h, --help         Show this help message"
    echo "  -m KEY            Recover access using master key"
    echo "  -r                Force lock sensitive directories"
    echo "  -k KEY            Provide current key for operations"
    echo "  -s SESSION        Specify session name (e.g., Photos, Documents)"
    echo "  -v, --version     Show program version and author information"
    echo "  --delete-session  Delete a specific session (interactive)"
    echo "  --delete-config   Delete configuration (requires password)"
    echo
    echo "Examples:"
    echo "  $(basename "$0")              Start the program normally"
    echo "  $(basename "$0") -m <key>     Recover access using master key"
    echo "  $(basename "$0") -r /path -k <current key>  Force lock sensitive directory"
    echo "  $(basename "$0") -s Photos    Start the program with session 'Photos'"
    echo "  $(basename "$0") --delete-session  Delete an existing session"
    echo
    echo "To clean all data and start fresh:"
    #echo "  rm -rf $CONFIG_DIR  # WARNING: Deletes all data, use with caution!"
}

# Add command line argument handling (add this before the main script logic)
# Add command line argument handling section
setup_session_paths() {
    local session_name="$1"
    BASE_SESSION_DIR="$HOME/.config/secure_lock_sessions"
    CONFIG_DIR="$BASE_SESSION_DIR/$session_name/config"
    CONFIG_FILE="$CONFIG_DIR/settings"
    PASSWORD_FILE="$CONFIG_DIR/.password_hash"
    METADATA_FILE="$CONFIG_DIR/items.log"
    MASTER_KEY_FILE="$CONFIG_DIR/.master_key"
    USER_KEY_FILE="$CONFIG_DIR/.user_key"

    # Create directory structure with proper permissions
    if [ ! -d "$BASE_SESSION_DIR" ]; then
        if ! mkdir -p "$BASE_SESSION_DIR"; then
            echo -e "${RED}Error: Could not create base session directory${NC}"
            exit 1
        fi
        chmod 700 "$BASE_SESSION_DIR"
    fi

    if [ ! -d "$CONFIG_DIR" ]; then
        if ! mkdir -p "$CONFIG_DIR"; then
            echo -e "${RED}Error: Could not create config directory${NC}"
            exit 1
        fi
        chmod 700 "$CONFIG_DIR"
    fi

    # Initialize required files with proper permissions
    for file in "$PASSWORD_FILE" "$METADATA_FILE" "$MASTER_KEY_FILE" "$USER_KEY_FILE"; do
        if ! touch "$file" 2>/dev/null; then
            echo -e "${RED}Error: Could not create file: $file${NC}"
            exit 1
        fi
        chmod 600 "$file"
    done
}

function delete_session() {
    echo "Available sessions:"
    local sessions=()
    local index=1

    for session_folder in "$BASE_SESSION_DIR"/*; do
        [ -d "$session_folder" ] || continue
        local session_name
        session_name=$(basename "$session_folder")
        echo "$index) $session_name"
        sessions+=("$session_name")
        ((index++))
    done

    echo -n "Select a session to delete (number): "
    read selection
    local chosen="${sessions[$((selection-1))]}"
    if [ -z "$chosen" ]; then
        echo "Invalid selection."
        return 1
    fi

    echo -n "Enter the key for session '$chosen': "
    read -s entered_key
    echo

    local chosen_user_key="$BASE_SESSION_DIR/$chosen/config/.user_key"
    if [ ! -f "$chosen_user_key" ]; then
        echo "User key not found for session '$chosen'."
        return 1
    fi

    local stored_key
    stored_key=$(cat "$chosen_user_key")
    if [ "$stored_key" != "$entered_key" ]; then
        echo "Invalid key. Deletion aborted."
        return 1
    fi

    rm -rf "$BASE_SESSION_DIR/$chosen"
    echo "Session '$chosen' deleted successfully."
}

# First pass - handle session setup
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--session)
            shift
            if [ -z "$1" ]; then
                echo "Error: Session name required"
                exit 1
            fi
            SESSION_NAME="$1"
            setup_session_paths "$SESSION_NAME"
            shift
            ;;
        *)
            break
            ;;
    esac
done

# Second pass - handle other arguments with correct paths
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
            
            if [ ! -f "$MASTER_KEY_FILE" ] || [ "$1" != "$(cat "$MASTER_KEY_FILE")" ]; then
                echo "Master key not found for current session, searching all sessions..."
                found_session=$(find_session_by_master_key "$1")
                if [ -z "$found_session" ]; then
                    echo "Invalid master key"
                    exit 1
                else
                    echo "Found matching session: $found_session"
                    SESSION_NAME="$found_session"
                    # Reconfigure paths for the found session
                    setup_session_paths "$SESSION_NAME"
                    if [ ! -f "$USER_KEY_FILE" ]; then
                        echo "Error: User key file not found in session $found_session"
                        exit 1
                    fi
                fi
            fi
            
            # If we reach here, the master key is valid; proceed with user key
            CURRENT_PASSWORD=$(cat "$USER_KEY_FILE")
            MASTER_KEY_USED=true
            echo "Master key verified successfully"
            echo -e "${YELLOW}Your key is: ${GREEN}$CURRENT_PASSWORD${NC}"
            echo "Press Enter to exit..."
            read
            exit 0
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
            
            # Set session-specific paths
            BASE_SESSION_DIR="$HOME/.config/secure_lock_sessions"
            CONFIG_DIR="$BASE_SESSION_DIR/$SESSION_NAME/config"
            CONFIG_FILE="$CONFIG_DIR/settings"
            PASSWORD_FILE="$CONFIG_DIR/.password_hash"
            METADATA_FILE="$CONFIG_DIR/items.log"
            MASTER_KEY_FILE="$CONFIG_DIR/.master_key"
            USER_KEY_FILE="$CONFIG_DIR/.user_key"
            
            # Create fresh session directory if it doesn't exist
            if [ ! -d "$CONFIG_DIR" ]; then
                echo -e "${YELLOW}Creating new session: $SESSION_NAME${NC}"
                mkdir -p "$CONFIG_DIR"
                chmod 700 "$CONFIG_DIR"
                touch "$METADATA_FILE"
                chmod 600 "$METADATA_FILE"
                
                # Since this is a new session, we'll need new password and master key
                PASSWORD_FILE_EXISTS=0
            else
                echo -e "${GREEN}Resuming session: $SESSION_NAME${NC}"
                PASSWORD_FILE_EXISTS=1
            fi
            shift
            ;;
        -v|--version)
            echo "Hide&Lock version 1.4.0"
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
        --delete-session)
            delete_session
            exit 0
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

    protect_config_directory
fi

# Password setup
if [ ! -f "$PASSWORD_FILE" ] || [ ! -s "$PASSWORD_FILE" ]; then
    if [ -n "$SESSION_NAME" ]; then
        echo -e "${YELLOW}First-time setup for session: $SESSION_NAME${NC}"
    else
        echo "First-time setup - Password Creation"
    fi
    
    while true; do
        echo -n "Enter a new password: "
        read -s new_password
        echo
        
        if ! validate_password "$new_password"; then
            continue
        fi
        
        echo -n "Confirm the new password: "
        read -s confirm_password
        echo

        if [ "$new_password" == "$confirm_password" ]; then
            # Write password hash with error checking
            if ! hash_password "$new_password" > "$PASSWORD_FILE"; then
                echo -e "${RED}Error: Could not write password hash${NC}"
                exit 1
            fi
            
            echo -e "${GREEN}Password set successfully!${NC}"
            
            # Set current password before generating keys
            CURRENT_PASSWORD="$new_password"
            
            # Generate master key with error checking
            if ! openssl rand -hex 16 > "$MASTER_KEY_FILE"; then
                echo -e "${RED}Error: Could not generate master key${NC}"
                exit 1
            fi
            
            # Generate and store user key with error checking
            if ! echo -n "$CURRENT_PASSWORD" > "$USER_KEY_FILE"; then
                echo -e "${RED}Error: Could not store user key${NC}"
                exit 1
            fi
            
            # Display master key
            if [ -f "$MASTER_KEY_FILE" ]; then
                echo -e "\n${YELLOW}  ╔═══════════════════════════════════════════════════════════╗${NC}"
                echo -e "${YELLOW}  ║                     ${RED}! IMPORTANT !${YELLOW}                         ║${NC}"
                echo -e "${YELLOW}  ║ ${GREEN}Your master key is: $(cat "$MASTER_KEY_FILE")${YELLOW}      ║${NC}"
                echo -e "${YELLOW}  ║ Store this key in a secure location for password recovery ║${NC}"
                echo -e "${YELLOW}  ╚═══════════════════════════════════════════════════════════╝${NC}\n"
            else
                echo -e "${RED}Warning: Could not read master key${NC}"
            fi
            
            echo "Press Enter to continue..."
            read
            break
        else
            echo -e "${RED}Passwords do not match. Try again.${NC}"
        fi
    done
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

# Add new timestamp manipulation functions
function validate_date_format() {
    local date_input="$1"
    
    # Check various date formats
    if date -d "$date_input" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

function format_timestamp() {
    local date_input="$1"
    # Convert to standard format: YYYY-MM-DD HH:MM:SS
    date -d "$date_input" "+%Y-%m-%d %H:%M:%S"
}

function set_file_timestamps() {
    local target_path="$1"
    local access_time="$2"
    local modify_time="$3"
    local create_time="$4"  # Note: creation time requires special handling
    
    if [ ! -e "$target_path" ]; then
        echo -e "${RED}Error: Path does not exist: $target_path${NC}"
        return 1
    fi
    
    # Set access and modification times
    if [ -n "$access_time" ] && [ -n "$modify_time" ]; then
        local access_formatted=$(date -d "$access_time" "+%Y%m%d%H%M.%S")
        local modify_formatted=$(date -d "$modify_time" "+%Y%m%d%H%M.%S")
        
        # Use touch command to set both times
        if touch -t "$modify_formatted" "$target_path" && \
           touch -a -t "$access_formatted" "$target_path"; then
            echo -e "${GREEN}Successfully updated timestamps for: $target_path${NC}"
            return 0
        else
            echo -e "${RED}Failed to update timestamps${NC}"
            return 1
        fi
    fi
    
    # Handle individual timestamp changes
    if [ -n "$access_time" ]; then
        local access_formatted=$(date -d "$access_time" "+%Y%m%d%H%M.%S")
        if touch -a -t "$access_formatted" "$target_path"; then
            echo -e "${GREEN}Successfully updated access time${NC}"
        else
            echo -e "${RED}Failed to update access time${NC}"
            return 1
        fi
    fi
    
    if [ -n "$modify_time" ]; then
        local modify_formatted=$(date -d "$modify_time" "+%Y%m%d%H%M.%S")
        if touch -t "$modify_formatted" "$target_path"; then
            echo -e "${GREEN}Successfully updated modification time${NC}"
        else
            echo -e "${RED}Failed to update modification time${NC}"
            return 1
        fi
    fi
    
    return 0
}

function show_current_timestamps() {
    local target_path="$1"
    
    if [ ! -e "$target_path" ]; then
        echo -e "${RED}Error: Path does not exist${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}Current timestamps for: $target_path${NC}"
    echo "=================================="
    
    # Get detailed timestamp information
    local access_time=$(stat -c %x "$target_path" 2>/dev/null)
    local modify_time=$(stat -c %y "$target_path" 2>/dev/null)
    local change_time=$(stat -c %z "$target_path" 2>/dev/null)
    
    echo -e "${GREEN}Access Time:${NC}     $access_time"
    echo -e "${GREEN}Modify Time:${NC}     $modify_time"
    echo -e "${GREEN}Change Time:${NC}     $change_time"
    
    # Show in human-readable format as well
    echo
    echo -e "${YELLOW}Human-readable format:${NC}"
    ls -la "$target_path"
}

function handle_timestamp_manipulation() {
    clear
    echo "=== Timestamp Manipulation ==="
    echo "1. View current timestamps"
    echo "2. Set specific timestamps"
    echo "3. Set timestamps from another file"
    echo "4. Batch timestamp operations"
    echo "5. Reset to current time"
    echo "6. Back to main menu"
    echo -n "Choose option (1-6): "
    read ts_choice
    
    case $ts_choice in
        1)  # View timestamps
            read -e -p "Enter file/folder path: " target_path
            if [ -n "$target_path" ]; then
                target_path=$(realpath "$target_path" 2>/dev/null)
                show_current_timestamps "$target_path"
            fi
            ;;
        2)  # Set specific timestamps
            read -e -p "Enter file/folder path: " target_path
            if [ -z "$target_path" ]; then
                echo -e "${RED}No path provided${NC}"
                return
            fi
            
            target_path=$(realpath "$target_path" 2>/dev/null)
            show_current_timestamps "$target_path"
            echo
            
            echo "Enter new timestamps (leave empty to keep current):"
            echo "Formats: 'YYYY-MM-DD HH:MM:SS', 'YYYY-MM-DD', '2 days ago', 'last week', etc."
            
            read -p "Access time: " new_access
            read -p "Modification time: " new_modify
            
            # Validate dates if provided
            if [ -n "$new_access" ] && ! validate_date_format "$new_access"; then
                echo -e "${RED}Invalid access time format${NC}"
                return
            fi
            
            if [ -n "$new_modify" ] && ! validate_date_format "$new_modify"; then
                echo -e "${RED}Invalid modification time format${NC}"
                return
            fi
            
            set_file_timestamps "$target_path" "$new_access" "$new_modify"
            ;;
        3)  # Copy timestamps from another file
            read -e -p "Enter target file/folder path: " target_path
            read -e -p "Enter source file/folder path (to copy timestamps from): " source_path
            
            if [ -z "$target_path" ] || [ -z "$source_path" ]; then
                echo -e "${RED}Both paths are required${NC}"
                return
            fi
            
            target_path=$(realpath "$target_path" 2>/dev/null)
            source_path=$(realpath "$source_path" 2>/dev/null)
            
            if [ ! -e "$source_path" ]; then
                echo -e "${RED}Source path does not exist${NC}"
                return
            fi
            
            # Use touch with reference file
            if touch -r "$source_path" "$target_path"; then
                echo -e "${GREEN}Successfully copied timestamps from $source_path to $target_path${NC}"
            else
                echo -e "${RED}Failed to copy timestamps${NC}"
            fi
            ;;
        4)  # Batch operations
            echo "Batch Timestamp Operations"
            echo "1. Set timestamps for all files in directory"
            echo "2. Set timestamps for files matching pattern"
            echo -n "Choose (1-2): "
            read batch_choice
            
            case $batch_choice in
                1)  # All files in directory
                    read -e -p "Enter directory path: " dir_path
                    if [ ! -d "$dir_path" ]; then
                        echo -e "${RED}Invalid directory${NC}"
                        return
                    fi
                    
                    read -p "Enter modification time: " batch_time
                    if ! validate_date_format "$batch_time"; then
                        echo -e "${RED}Invalid time format${NC}"
                        return
                    fi
                    
                    echo -n "Include subdirectories? (y/N): "
                    read include_sub
                    
                    local find_opts="-maxdepth 1"
                    if [[ "$include_sub" =~ ^[Yy]$ ]]; then
                        find_opts=""
                    fi
                    
                    local count=0
                    while IFS= read -r -d '' file; do
                        if set_file_timestamps "$file" "" "$batch_time"; then
                            ((count++))
                        fi
                    done < <(find "$dir_path" $find_opts -type f -print0)
                    
                    echo -e "${GREEN}Updated timestamps for $count files${NC}"
                    ;;
                2)  # Pattern matching
                    read -e -p "Enter directory path: " dir_path
                    read -p "Enter file pattern (e.g., *.txt, *.jpg): " pattern
                    read -p "Enter modification time: " batch_time
                    
                    if [ ! -d "$dir_path" ] || ! validate_date_format "$batch_time"; then
                        echo -e "${RED}Invalid directory or time format${NC}"
                        return
                    fi
                    
                    local count=0
                    for file in "$dir_path"/$pattern; do
                        if [ -f "$file" ]; then
                            if set_file_timestamps "$file" "" "$batch_time"; then
                                ((count++))
                            fi
                        fi
                    done
                    
                    echo -e "${GREEN}Updated timestamps for $count files${NC}"
                    ;;
            esac
            ;;
        5)  # Reset to current time
            read -e -p "Enter file/folder path: " target_path
            if [ -n "$target_path" ]; then
                target_path=$(realpath "$target_path" 2>/dev/null)
                if touch "$target_path"; then
                    echo -e "${GREEN}Reset timestamps to current time${NC}"
                else
                    echo -e "${RED}Failed to reset timestamps${NC}"
                fi
            fi
            ;;
        6)  # Back to main menu
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
}

# Add folder color customization functions
function detect_desktop_environment() {
    if [ "$XDG_CURRENT_DESKTOP" ]; then
        echo "$XDG_CURRENT_DESKTOP" | tr '[:upper:]' '[:lower:]'
    elif [ "$DESKTOP_SESSION" ]; then
        echo "$DESKTOP_SESSION" | tr '[:upper:]' '[:lower:]'
    elif command -v gnome-shell >/dev/null 2>&1; then
        echo "gnome"
    elif command -v plasmashell >/dev/null 2>&1; then
        echo "kde"
    elif command -v xfce4-session >/dev/null 2>&1; then
        echo "xfce"
    elif command -v mate-session >/dev/null 2>&1; then
        echo "mate"
    elif command -v cinnamon >/dev/null 2>&1; then
        echo "cinnamon"
    else
        echo "unknown"
    fi
}

function get_folder_color_presets() {
    cat << 'EOF'
1|Red|#FF0000|folder-red
2|Green|#00FF00|folder-green
3|Blue|#0000FF|folder-blue
4|Yellow|#FFFF00|folder-yellow
5|Orange|#FFA500|folder-orange
6|Purple|#800080|folder-violet
7|Pink|#FFC0CB|folder-pink
8|Brown|#A52A2A|folder-brown
9|Gray|#808080|folder-grey
10|Black|#000000|folder-black
11|Cyan|#00FFFF|folder-cyan
12|Magenta|#FF00FF|folder-magenta
13|Lime|#32CD32|folder-green
14|Navy|#000080|folder-blue
15|Maroon|#800000|folder-red
EOF
}

function set_folder_color_gnome() {
    local folder_path="$1"
    local color_name="$2"
    local hex_color="$3"
    
    # Check if gio is available
    if ! command -v gio >/dev/null 2>&1; then
        echo -e "${RED}Error: gio command not found. Cannot set folder color in GNOME.${NC}"
        return 1
    fi
    
    # First clear any existing custom settings
    gio set "$folder_path" -d metadata::custom-icon-name 2>/dev/null || true
    gio set "$folder_path" -d metadata::emblems 2>/dev/null || true
    
    # Set folder color using gio with proper icon name
    if gio set "$folder_path" metadata::custom-icon-name "$color_name" 2>/dev/null; then
        echo -e "${GREEN}Successfully set folder color to $color_name${NC}"
        return 0
    else
        # Try alternative method with emblem
        if gio set "$folder_path" metadata::emblems "$color_name" 2>/dev/null; then
            echo -e "${GREEN}Successfully set folder emblem to $color_name${NC}"
            return 0
        else
            echo -e "${RED}Failed to set folder color in GNOME${NC}"
            return 1
        fi
    fi
}

function set_folder_color_kde() {
    local folder_path="$1"
    local color_name="$2"
    local hex_color="$3"
    
    # Create .directory file for KDE
    local directory_file="$folder_path/.directory"
    
    # Create or update .directory file with proper structure
    cat > "$directory_file" << EOF
[Desktop Entry]
Icon=$color_name
Type=Directory
Name=$(basename "$folder_path")
EOF
    
    if [ -f "$directory_file" ]; then
        echo -e "${GREEN}Successfully created KDE folder color configuration${NC}"
        return 0
    else
        echo -e "${RED}Failed to create KDE folder color configuration${NC}"
        return 1
    fi
}

function set_folder_color_xfce() {
    local folder_path="$1"
    local color_name="$2"
    local hex_color="$3"
    
    # XFCE uses Thunar custom actions and desktop files
    local desktop_file="$folder_path/.directory"
    
    cat > "$desktop_file" << EOF
[Desktop Entry]
Icon=$color_name
Type=Directory
Name=$(basename "$folder_path")
EOF
    
    if [ -f "$desktop_file" ]; then
        echo -e "${GREEN}Successfully set XFCE folder icon to $color_name${NC}"
        # Try to refresh Thunar if running
        if command -v thunar >/dev/null 2>&1; then
            killall thunar 2>/dev/null || true
            sleep 1
            thunar "$folder_path" 2>/dev/null &
        fi
        return 0
    else
        echo -e "${RED}Failed to set XFCE folder color${NC}"
        return 1
    fi
}

function set_folder_color_generic() {
    local folder_path="$1"
    local color_name="$2"
    local hex_color="$3"
    
    # Create a .folder_color file for future reference
    local color_file="$folder_path/.folder_color"
    
    cat > "$color_file" << EOF
# Folder color configuration
# Set by Hide&Lock tool
COLOR_NAME=$color_name
HEX_COLOR=$hex_color
TIMESTAMP=$(date)
EOF
    
    # Try to create a desktop entry file
    local desktop_file="$folder_path/.directory"
    cat > "$desktop_file" << EOF
[Desktop Entry]
Icon=$color_name
Type=Directory
Name=$(basename "$folder_path")
EOF
    
    if [ -f "$color_file" ] && [ -f "$desktop_file" ]; then
        echo -e "${GREEN}Successfully created generic folder color configuration${NC}"
        echo -e "${YELLOW}Note: Color may not be visible in all file managers${NC}"
        return 0
    else
        echo -e "${RED}Failed to create folder color configuration${NC}"
        return 1
    fi
}

function apply_folder_color() {
    local folder_path="$1"
    local color_name="$2"
    local hex_color="$3"
    local de=$(detect_desktop_environment)
    
    echo -e "${YELLOW}Detected desktop environment: $de${NC}"
    
    case "$de" in
        *gnome*|*ubuntu*)
            set_folder_color_gnome "$folder_path" "$color_name" "$hex_color"
            ;;
        *kde*|*plasma*)
            set_folder_color_kde "$folder_path" "$color_name" "$hex_color"
            ;;
        *xfce*)
            set_folder_color_xfce "$folder_path" "$color_name" "$hex_color"
            ;;
        *mate*|*cinnamon*)
            set_folder_color_generic "$folder_path" "$color_name" "$hex_color"
            ;;
        *)
            echo -e "${YELLOW}Unknown desktop environment, using generic method${NC}"
            set_folder_color_generic "$folder_path" "$color_name" "$hex_color"
            ;;
    esac
}

function validate_hex_color() {
    local hex="$1"
    # Remove # if present
    hex="${hex#'#'}"
    
    # Check if it's a valid 6-digit hex color
    if [[ "$hex" =~ ^[0-9A-Fa-f]{6}$ ]]; then
        return 0
    else
        return 1
    fi
}

function show_color_preview() {
    local color_name="$1"
    local hex_color="$2"
    
    echo -e "${YELLOW}Color Preview:${NC}"
    echo "Name: $color_name"
    echo "Hex: $hex_color"
    
    # Try to show color preview if terminal supports it
    if [ "$TERM" != "dumb" ]; then
        # Convert hex to RGB for terminal display
        local r=$((16#${hex_color:1:2}))
        local g=$((16#${hex_color:3:2}))
        local b=$((16#${hex_color:5:2}))
        
        echo -e "\033[48;2;${r};${g};${b}m    \033[0m <- Color sample"
    fi
}

function reset_folder_color() {
    local folder_path="$1"
    local de=$(detect_desktop_environment)
    
    echo -e "${YELLOW}Resetting folder color for: $folder_path${NC}"
    
    case "$de" in
        *gnome*|*ubuntu*)
            if command -v gio >/dev/null 2>&1; then
                # Method 1: Delete all custom metadata attributes
                gio set "$folder_path" -d metadata::custom-icon-name 2>/dev/null || true
                gio set "$folder_path" -d metadata::emblems 2>/dev/null || true
                
                # Method 2: Clear any lingering metadata
                gio set "$folder_path" metadata::custom-icon-name '' 2>/dev/null || true
                gio set "$folder_path" metadata::emblems '' 2>/dev/null || true
                
                # Method 3: Force refresh by setting and then removing
                gio set "$folder_path" metadata::custom-icon-name 'folder' 2>/dev/null || true
                sleep 0.2
                gio set "$folder_path" -d metadata::custom-icon-name 2>/dev/null || true
                
                echo -e "${GREEN}Reset GNOME folder metadata${NC}"
                
                # Try to refresh nautilus
                if command -v nautilus >/dev/null 2>&1; then
                    killall nautilus 2>/dev/null || true
                    sleep 1
                    nautilus --no-desktop 2>/dev/null &
                    echo -e "${CYAN}Restarted Nautilus file manager${NC}"
                fi
            fi
            ;;
        *kde*|*plasma*)
            # Remove .directory file completely for KDE
            rm -f "$folder_path/.directory"
            
            # Try to refresh dolphin
            if command -v dolphin >/dev/null 2>&1; then
                killall dolphin 2>/dev/null || true
                echo -e "${CYAN}Refreshed Dolphin file manager${NC}"
            fi
            echo -e "${GREEN}Reset KDE folder to default${NC}"
            ;;
        *xfce*)
            # Remove .directory file completely for XFCE
            rm -f "$folder_path/.directory"
            
            # Try to refresh Thunar
            if command -v thunar >/dev/null 2>&1; then
                killall thunar 2>/dev/null || true
                sleep 1
                thunar "$folder_path" 2>/dev/null &
                echo -e "${CYAN}Refreshed Thunar file manager${NC}"
            fi
            echo -e "${GREEN}Reset XFCE folder to default${NC}"
            ;;
        *mate*|*cinnamon*|*)
            # For generic environments, remove all custom files
            rm -f "$folder_path/.directory"
            rm -f "$folder_path/.folder_color"
            
            # Try to refresh caja (MATE) or nemo (Cinnamon)
            if command -v caja >/dev/null 2>&1; then
                killall caja 2>/dev/null || true
            elif command -v nemo >/dev/null 2>&1; then
                killall nemo 2>/dev/null || true
            fi
            echo -e "${GREEN}Removed custom folder configuration files${NC}"
            ;;
    esac
    
    # Always remove our custom color file
    rm -f "$folder_path/.folder_color"
    
    echo -e "${GREEN}Folder color reset to default successfully${NC}"
    echo -e "${YELLOW}Note: File manager has been refreshed. Changes should be visible immediately.${NC}"
}

function batch_set_folder_colors() {
    local base_dir="$1"
    local color_name="$2"
    local hex_color="$3"
    local include_subdirs="$4"
    
    echo -e "${YELLOW}Batch setting folder colors...${NC}"
    
    local find_opts="-maxdepth 1"
    if [[ "$include_subdirs" =~ ^[Yy]$ ]]; then
        find_opts=""
    fi
    
    local count=0
    while IFS= read -r -d '' folder; do
        if [ -d "$folder" ] && [ "$folder" != "$base_dir" ]; then
            echo "Processing: $folder"
            if apply_folder_color "$folder" "$color_name" "$hex_color"; then
                ((count++))
            fi
        fi
    done < <(find "$base_dir" $find_opts -type d -print0)
    
    echo -e "${GREEN}Applied color to $count folders${NC}"
}

function handle_folder_color_customization() {
    clear
    echo "=== Folder Color Customization ==="
    echo "1. Set folder color from presets"
    echo "2. Set custom folder color"
    echo "3. Reset folder color to default"
    echo "4. Batch color operations"
    echo "5. View current folder color"
    echo "6. Back to main menu"
    echo -n "Choose option (1-6): "
    read color_choice
    
    case $color_choice in
        1)  # Preset colors
            echo -e "${YELLOW}Available Color Presets:${NC}"
            echo "=================================="
            get_folder_color_presets | while IFS='|' read -r num name hex icon; do
                echo "$num. $name ($hex)"
            done
            echo
            
            read -p "Select color number (1-15): " preset_num
            read -e -p "Enter folder path: " folder_path
            
            if [ -z "$folder_path" ] || [ ! -d "$folder_path" ]; then
                echo -e "${RED}Invalid folder path${NC}"
                return
            fi
            
            # Get selected color
            local selected_color=$(get_folder_color_presets | grep "^$preset_num|")
            if [ -z "$selected_color" ]; then
                echo -e "${RED}Invalid color selection${NC}"
                return
            fi
            
            IFS='|' read -r _ color_name hex_color icon_name <<< "$selected_color"
            folder_path=$(realpath "$folder_path" 2>/dev/null)
            
            show_color_preview "$color_name" "$hex_color"
            echo -n "Apply this color? (y/N): "
            read confirm
            
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                apply_folder_color "$folder_path" "$icon_name" "$hex_color"
            fi
            ;;
            
        2)  # Custom color
            read -e -p "Enter folder path: " folder_path
            read -p "Enter color name: " custom_name
            read -p "Enter hex color (e.g., #FF5733): " custom_hex
            
            if [ -z "$folder_path" ] || [ ! -d "$folder_path" ]; then
                echo -e "${RED}Invalid folder path${NC}"
                return
            fi
            
            if [ -z "$custom_name" ]; then
                echo -e "${RED}Color name required${NC}"
                return
            fi
            
            if ! validate_hex_color "$custom_hex"; then
                echo -e "${RED}Invalid hex color format. Use #RRGGBB${NC}"
                return
            fi
            
            folder_path=$(realpath "$folder_path" 2>/dev/null)
            show_color_preview "$custom_name" "$custom_hex"
            
            echo -n "Apply this custom color? (y/N): "
            read confirm
            
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                apply_folder_color "$folder_path" "folder-custom" "$custom_hex"
                
                # Save custom color info
                local color_file="$folder_path/.folder_color"
                cat >> "$color_file" << EOF
CUSTOM_NAME=$custom_name
EOF
            fi
            ;;
            
        3)  # Reset color
            read -e -p "Enter folder path to reset: " folder_path
            
            if [ -z "$folder_path" ] || [ ! -d "$folder_path" ]; then
                echo -e "${RED}Invalid folder path${NC}"
                return
            fi
            
            folder_path=$(realpath "$folder_path" 2>/dev/null)
            echo -n "Reset folder color to default? (y/N): "
            read confirm
            
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                reset_folder_color "$folder_path"
                echo -e "${CYAN}Folder has been reset to default appearance${NC}"
            fi
            ;;
            
        4)  # Batch operations
            echo "Batch Color Operations"
            echo "1. Set same color for all folders in directory"
            echo "2. Reset all folder colors in directory"
            echo -n "Choose (1-2): "
            read batch_choice
            
            case $batch_choice in
                1)  # Batch set color
                    read -e -p "Enter base directory: " base_dir
                    if [ ! -d "$base_dir" ]; then
                        echo -e "${RED}Invalid directory${NC}"
                        return
                    fi
                    
                    echo -e "${YELLOW}Select color:${NC}"
                    get_folder_color_presets | while IFS='|' read -r num name hex icon; do
                        echo "$num. $name ($hex)"
                    done
                    
                    read -p "Select color number (1-15): " preset_num
                    echo -n "Include subdirectories? (y/N): "
                    read include_sub
                    
                    local selected_color=$(get_folder_color_presets | grep "^$preset_num|")
                    if [ -z "$selected_color" ]; then
                        echo -e "${RED}Invalid color selection${NC}"
                        return
                    fi
                    
                    IFS='|' read -r _ color_name hex_color icon_name <<< "$selected_color"
                    batch_set_folder_colors "$base_dir" "$icon_name" "$hex_color" "$include_sub"
                    ;;
                    
                2)  # Batch reset
                    read -e -p "Enter base directory: " base_dir
                    if [ ! -d "$base_dir" ]; then
                        echo -e "${RED}Invalid directory${NC}"
                        return
                    fi
                    
                    echo -n "Include subdirectories? (y/N): "
                    read include_sub
                    
                    echo -n "Are you sure you want to reset all folder colors in this directory? (y/N): "
                    read confirm_batch
                    
                    if [[ ! "$confirm_batch" =~ ^[Yy]$ ]]; then
                        echo "Operation cancelled."
                        return
                    fi
                    
                    local find_opts="-maxdepth 1"
                    if [[ "$include_sub" =~ ^[Yy]$ ]]; then
                        find_opts=""
                    fi
                    
                    local count=0
                    while IFS= read -r -d '' folder; do
                        if [ -d "$folder" ] && [ "$folder" != "$base_dir" ]; then
                            echo "Resetting: $(basename "$folder")"
                            reset_folder_color "$folder"
                            ((count++))
                        fi
                    done < <(find "$base_dir" $find_opts -type d -print0)
                    
                    echo -e "${GREEN}Reset colors for $count folders${NC}"
                    echo -e "${CYAN}All folders have been reset to default appearance${NC}"
                    ;;
            esac
            ;;
            
        5)  # View current color
            read -e -p "Enter folder path: " folder_path
            
            if [ -z "$folder_path" ] || [ ! -d "$folder_path" ]; then
                echo -e "${RED}Invalid folder path${NC}"
                return
            fi
            
            folder_path=$(realpath "$folder_path" 2>/dev/null)
            local color_file="$folder_path/.folder_color"
            
            if [ -f "$color_file" ]; then
                echo -e "${YELLOW}Current folder color configuration:${NC}"
                echo "=================================="
                cat "$color_file"
            else
                echo -e "${YELLOW}No custom color set for this folder${NC}"
            fi
            ;;
            
        6)  # Back to main menu
            return
            ;;
            
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
}

# Add the missing handle_unlock function
function handle_unlock() {
    clear
    echo "=== Unlock Items ==="
    
    # Check if there are any locked items
    if [ ! -s "$METADATA_FILE" ]; then
        echo "No locked items found."
        return
    fi
    
    echo "Locked items:"
    echo "============="
    local index=1
    while IFS='|' read -r name path created locked size || [ -n "$name" ]; do
        echo "$index. $name (Original: $path) [Size: $size]"
        ((index++))
    done < "$METADATA_FILE"
    
    echo
    read -p "Enter item number to unlock: " item_num
    
    # Validate input
    if ! [[ "$item_num" =~ ^[0-9]+$ ]] || [ "$item_num" -lt 1 ]; then
        echo -e "${RED}Invalid selection${NC}"
        return
    fi
    
    # Get the selected item
    local current_index=1
    local selected_name=""
    local selected_path=""
    
    while IFS='|' read -r name path created locked size || [ -n "$name" ]; do
        if [ "$current_index" -eq "$item_num" ]; then
            selected_name="$name"
            selected_path="$path"
            break
        fi
        ((current_index++))
    done < "$METADATA_FILE"
    
    if [ -z "$selected_name" ]; then
        echo -e "${RED}Invalid selection${NC}"
        return
    fi
    
    echo "Selected: $selected_name"
    echo "1. Unlock permanently"
    echo "2. Unlock temporarily"
    read -p "Choose unlock type (1-2): " unlock_type
    
    local encrypted_file="$CONFIG_DIR/$selected_name.gpg"
    local target_dir=$(dirname "$selected_path")
    
    case $unlock_type in
        1)  # Permanent unlock
            if unlock_item "$encrypted_file" "$target_dir" "$selected_path"; then
                # Remove from metadata
                grep -v "^$selected_name|" "$METADATA_FILE" > "$METADATA_FILE.tmp"
                mv "$METADATA_FILE.tmp" "$METADATA_FILE"
                # Remove encrypted file
                rm -f "$encrypted_file"
                echo -e "${GREEN}Item unlocked permanently${NC}"
            else
                echo -e "${RED}Failed to unlock item${NC}"
            fi
            ;;
        2)  # Temporary unlock
            if unlock_item "$encrypted_file" "$target_dir" "$selected_path"; then
                # Add to temporary unlock tracking
                local item_info="$selected_name|$selected_path|$created|$locked|$size"
                TEMP_UNLOCKED_ITEMS+=("$item_info")
                echo -e "${GREEN}Item unlocked temporarily (will be re-locked on exit)${NC}"
            else
                echo -e "${RED}Failed to unlock item${NC}"
            fi
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
}

# Updated menu function
show_menu() {
    clear
    if [ -n "$SESSION_NAME" ]; then
        echo "=== Secure Lock Menu (Session: $SESSION_NAME) ==="
    else
        echo "=== Secure Lock Menu ==="
    fi
    echo "1. Lock new item"
    echo "2. Unlock item"
    echo "3. Change password"
    echo "4. Timestamp manipulation"
    echo "5. Folder color customization"
    echo "6. Exit"
    echo "Choose an option (1-6): "
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
        4)  # Timestamp manipulation
            handle_timestamp_manipulation
            ;;
        5)  # Folder color customization
            handle_folder_color_customization
            ;;
        6)  # Exit
            cleanup
            ;;
        *)
            echo "Invalid option!"
            ;;
    esac
    echo
    read -p "Press Enter to continue..."
done


