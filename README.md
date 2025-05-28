# VPN Profile Validator

A GUI application for validating VPN profiles using Nmap as a backend. This tool helps you verify the accessibility of VPN endpoints by scanning specified IP addresses, protocols, and ports.

## Features

- Load and parse CSV files containing VPN profile information
- Display scan targets in a table format
- Real-time scanning with Nmap
- Two scan modes: Slow (sequential) and Aggressive (concurrent)
- Configurable timeout per scan
- Real-time logging of scan progress
- Export scan results to CSV
- Clean, responsive UI

## Requirements

- Python 3.13 or higher
- Nmap installed on your system
- Required Python packages (install using `pip install -r requirements.txt`):
  - PyQt6
  - python-nmap
  - pandas

## Installation

1. Ensure you have Python 3.13+ installed

2. Install Nmap on your system:
   - Windows:
     1. Download the latest Nmap installer from https://nmap.org/download.html
     2. Run the installer as administrator
     3. During installation:
        - Choose "Custom" installation
        - Make sure "Add Nmap to PATH" is checked
        - Install to the default location (C:\Program Files\Nmap)
     4. After installation, restart your computer to ensure PATH changes take effect
     5. Verify installation by opening Command Prompt and typing `nmap --version`
   
   - Linux: `sudo apt-get install nmap` (Ubuntu/Debian) or equivalent for your distribution
   - macOS: `brew install nmap` (using Homebrew)

3. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   python vpn_validator.py
   ```

2. Prepare your CSV file with the following format:
   ```
   IP,PROTOCOL,PORT
   192.168.1.1,TCP,443
   10.0.0.1,UDP,1194
   ```

3. Use the application:
   - Click "Load CSV" to load your VPN profile data
   - Select scan mode (Slow/Aggressive)
   - Set timeout value (in seconds)
   - Click "Start Scan" to begin validation
   - Monitor progress in the log window
   - Export results using the "Export Results" button

## Notes

- The "Slow" mode scans one target at a time, while "Aggressive" mode scans multiple targets concurrently
- Default timeout is 30 seconds per scan
- Scan results show the port state (open, closed, filtered, etc.)
- The application requires Nmap to be installed and accessible in your system PATH

## Troubleshooting

If you encounter issues:
1. Ensure Nmap is properly installed and accessible from the command line
   - Windows: Open Command Prompt and type `nmap --version`
   - If not found, try these steps:
     1. Uninstall Nmap
     2. Download the latest installer
     3. Run installer as administrator
     4. Check "Add Nmap to PATH" during installation
     5. Restart your computer
2. Check that all required Python packages are installed
3. Verify your CSV file format is correct
4. Check the log window for detailed error messages
5. If you see "Nmap not found" error:
   - Make sure Nmap is installed in one of these locations:
     - C:\Program Files\Nmap
     - C:\Program Files (x86)\Nmap
   - Or add Nmap's installation directory to your system PATH manually 