# SVA Validator

A powerful network port scanning and validation tool built with Python and PyQt6, utilizing Nmap for accurate port scanning.

## Features

- **User-Friendly Interface**: Modern GUI built with PyQt6
- **CSV Import/Export**: Load target lists from CSV and export results
- **Multiple Scan Modes**:
  - Slow Mode: Sequential scanning for minimal network impact
  - Aggressive Mode: Parallel scanning for faster results
- **Real-time Results**: Live updates with color-coded status indicators
- **Advanced Filtering**: Filter results by IP, protocol, port, and status
- **Comprehensive Logging**: Optional detailed logging for debugging
- **Progress Tracking**: Real-time progress updates and scan status
- **Error Handling**: Robust error handling and crash recovery

## Requirements

- Python 3.6 or higher
- PyQt6
- python-nmap
- Nmap (must be installed on your system)

## Installation

1. **Install Nmap**:
   - Download Nmap from [https://nmap.org/download.html](https://nmap.org/download.html)
   - Run the installer as administrator
   - During installation:
     - Choose 'Custom' installation
     - Check 'Add Nmap to PATH'
     - Install to default location
   - Restart your computer

2. **Install Python Dependencies**:
   ```bash
   pip install PyQt6 python-nmap
   ```

3. **Clone or Download**:
   ```bash
   git clone [repository-url]
   cd sva-validator
   ```

## Usage

1. **Start the Application**:
   ```bash
   python sva_validator.py
   ```

2. **Load Target List**:
   - Click "Load CSV" to import your target list
   - CSV format should be: `IP,Protocol,Port`
   - Example:
     ```
     192.168.1.1,TCP,80
     192.168.1.2,UDP,53
     ```

3. **Configure Scan**:
   - Select scan mode (Slow/Aggressive)
   - Enable logging if needed
   - Click "Start Scan"

4. **Monitor Results**:
   - View real-time scan results in the table
   - Use filters to focus on specific results
   - Export results using "Export Results" button

## CSV Format

The application expects a CSV file with the following format:
```
IP,Protocol,Port
192.168.1.1,TCP,80
192.168.1.2,UDP,53
```

## Scan Modes

- **Slow Mode**: Scans one target at a time, minimizing network impact
- **Aggressive Mode**: Scans multiple targets simultaneously (up to 20 parallel scans)

## Status Indicators

- 🟢 **Open**: Port is open and accepting connections
- 🟡 **Closed**: Port is closed
- 🟡 **Filtered**: Port is filtered (firewall)
- 🔴 **Error**: Scan encountered an error
- 🔴 **Stopped**: Scan was manually stopped
- ⚪ **Pending**: Scan not yet started

## Logging

- Enable logging through the GUI checkbox
- Logs are saved to `app.log`
- Crash logs are saved to `crash_log.txt`

## Error Handling

The application includes comprehensive error handling:
- Automatic crash logging
- Graceful error recovery
- User-friendly error messages
- Detailed logging for debugging

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Powered by Nmap © 1996–2025 Insecure.Com LLC
- Built with PyQt6
- Uses python-nmap for Nmap integration 