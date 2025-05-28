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

- **Slow Mode**: 
  - Scans one target at a time
  - Updates results in real-time
  - Uses polite timing template (-T2)
  - Adds delays between probes
  - Minimizes network impact
- **Aggressive Mode**: 
  - Scans up to 20 targets simultaneously
  - Updates results in batches (every 10 results)
  - Uses normal timing template (-T3)
  - No delays between probes
  - Maximum scanning speed

### Nmap Timing Templates

Nmap uses timing templates (-T0 through -T5) to control scan speed and stealth:

- **-T0 (Paranoid)**: Extremely slow, one probe at a time, 5 minutes between probes
- **-T1 (Sneaky)**: Very slow, one probe at a time, 15 seconds between probes
- **-T2 (Polite)**: Slow, one probe at a time, 400ms between probes
- **-T3 (Normal)**: Default speed, parallel probes, no delays
- **-T4 (Aggressive)**: Fast, parallel probes, no delays, reduced timeouts
- **-T5 (Insane)**: Very fast, parallel probes, no delays, minimal timeouts

Our application uses:
- **Slow Mode**: -T2 (Polite) for minimal network impact
- **Aggressive Mode**: -T3 (Normal) for balanced speed and reliability

## Controls

- **Start/Stop Button**: 
  - Toggles between Start and Stop states
  - Green when ready to start
  - Red when scanning
  - Automatically resets when scan completes
- **Load CSV**: Import target list
- **Clear Table**: Remove all results
- **Export Results**: Save scan results to CSV
- **Enable Logging**: Toggle detailed logging

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