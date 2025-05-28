import sys
import csv
import nmap
import os
import subprocess
import time
import traceback
import logging
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem,
                            QComboBox, QSpinBox, QLabel, QTextEdit, QFileDialog,
                            QHeaderView, QMessageBox, QLineEdit, QCheckBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QMutex, QMutexLocker

# Constants
DEFAULT_SCAN_TIMEOUT = 30  # seconds
MAX_CSV_ROWS = 10000  # Maximum number of rows in CSV (memory usage: ~3.5 MB for 10000 rows)
MAX_PARALLEL_SCANS = 20  # Maximum number of concurrent scans in aggressive mode
SCAN_START_DELAY = 0.5  # Delay between starting scans in seconds

# Set up logging
logging.basicConfig(
    filename='app.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_crash(error_msg):
    """Log crash information to a file."""
    try:
        logging.critical(f"CRASH: {error_msg}")
        logging.critical(f"Traceback:\n{traceback.format_exc()}")
        
        with open('crash_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*50}\n")
            f.write(f"Crash occurred at: {datetime.now()}\n")
            f.write(f"Error: {error_msg}\n")
            f.write(f"Traceback:\n{traceback.format_exc()}\n")
            f.write(f"{'='*50}\n")
    except Exception as e:
        # If we can't log to file, try to write to a new file
        try:
            with open('crash_log_emergency.txt', 'w', encoding='utf-8') as f:
                f.write(f"Failed to write to crash_log.txt: {str(e)}\n")
                f.write(f"Original error: {error_msg}\n")
                f.write(f"Traceback:\n{traceback.format_exc()}\n")
        except:
            pass  # If all logging fails, we can't do anything

class ExceptionHandler:
    def __init__(self, app):
        self.app = app
        sys.excepthook = self.handle_exception
        logging.info("Exception handler initialized")

    def handle_exception(self, exc_type, exc_value, exc_traceback):
        """Handle uncaught exceptions."""
        error_msg = f"Uncaught exception: {exc_type.__name__}: {str(exc_value)}"
        logging.critical(error_msg)
        
        # Try to show error in GUI if possible
        try:
            QMessageBox.critical(None, "Application Error", 
                               f"An error occurred and the application needs to close.\n\n"
                               f"Error: {error_msg}")
        except:
            pass
        
        # Exit the application
        self.app.quit()

def find_nmap_path():
    """Find Nmap executable in common Windows installation locations."""
    possible_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        os.path.join(os.environ.get('PROGRAMFILES', ''), 'Nmap', 'nmap.exe'),
        os.path.join(os.environ.get('PROGRAMFILES(X86)', ''), 'Nmap', 'nmap.exe'),
        # Add the Nmap directory to PATH if found
        os.path.join(os.environ.get('PROGRAMFILES', ''), 'Nmap'),
        os.path.join(os.environ.get('PROGRAMFILES(X86)', ''), 'Nmap')
    ]
    
    # First check for nmap.exe
    for path in possible_paths:
        if os.path.exists(path) and path.endswith('nmap.exe'):
            # Add the Nmap directory to PATH
            nmap_dir = os.path.dirname(path)
            if nmap_dir not in os.environ['PATH']:
                os.environ['PATH'] = nmap_dir + os.pathsep + os.environ['PATH']
            return path
    
    # If nmap.exe not found, check for Nmap directory
    for path in possible_paths:
        if os.path.exists(path) and os.path.isdir(path):
            nmap_exe = os.path.join(path, 'nmap.exe')
            if os.path.exists(nmap_exe):
                # Add the Nmap directory to PATH
                if path not in os.environ['PATH']:
                    os.environ['PATH'] = path + os.pathsep + os.environ['PATH']
                return nmap_exe
    
    return None

def verify_nmap_installation():
    """Verify Nmap installation and return detailed status."""
    nmap_path = find_nmap_path()
    if not nmap_path:
        return False, "Nmap not found in standard installation locations."
    
    try:
        # Try to run nmap --version
        result = subprocess.run([nmap_path, '--version'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        if result.returncode == 0:
            return True, f"Nmap found at: {nmap_path}\nVersion: {result.stdout.splitlines()[0]}"
        else:
            return False, f"Nmap found but failed to run: {result.stderr}"
    except Exception as e:
        return False, f"Error running Nmap: {str(e)}"

class ScanWorker(QThread):
    progress = pyqtSignal(str)
    scan_complete = pyqtSignal(str, str, str, str)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, target, protocol, port, timeout):
        super().__init__()
        self.target = target
        self.protocol = protocol
        self.port = port
        self.timeout = timeout
        self.nmap_path = find_nmap_path()
        self.start_time = None
        self._is_running = True
        self._nm = None
        self._scan_completed = False
        self._mutex = QMutex()
        logging.debug(f"ScanWorker initialized for {target}:{port}/{protocol}")

    def stop(self):
        """Safely stop the worker."""
        with QMutexLocker(self._mutex):
            if not self._is_running:
                return
                
            logging.debug(f"Stopping scan for {self.target}:{self.port}/{self.protocol}")
            self._is_running = False
            
            if not self._scan_completed:
                try:
                    self.scan_complete.emit(self.target, self.protocol, self.port, 'stopped')
                except RuntimeError:
                    pass
            
            # Don't terminate, just let the thread finish naturally
            self._nm = None

    def is_running(self):
        """Thread-safe check if worker is running."""
        with QMutexLocker(self._mutex):
            return self._is_running

    def run(self):
        try:
            if not self.is_running():
                return

            logging.debug(f"Starting scan for {self.target}:{self.port}/{self.protocol}")

            if not self.nmap_path:
                raise Exception("Nmap not found. Please install Nmap and ensure it's in your PATH or in a standard installation directory.")
            
            self.start_time = time.time()
            
            # Set the Nmap path for the scanner
            self._nm = nmap.PortScanner()
            self._nm.scan_command = f'"{self.nmap_path}"'
            
            # Verify Nmap is working
            try:
                test_scan = self._nm.scan('127.0.0.1', arguments='-sn')
                if not test_scan:
                    raise Exception("Nmap test scan failed")
            except Exception as e:
                raise Exception(f"Nmap verification failed: {str(e)}")
            
            if not self.is_running():
                return

            # Use TCP connect scan (-sT) for TCP and UDP scan (-sU) for UDP
            scan_type = '-sT' if self.protocol.upper() == 'TCP' else '-sU'
            
            # Add scan parameters
            scan_args = (
                f'{scan_type} '           # TCP connect scan or UDP scan
                f'-p{self.port} '         # Port to scan
                f'--host-timeout {self.timeout}s '  # Overall timeout
                f'--max-rtt-timeout {self.timeout*1000}ms '  # Maximum RTT timeout
                f'--min-rtt-timeout {self.timeout*100}ms '   # Minimum RTT timeout
                f'--max-retries 2 '       # Reduce retries for faster results
                f'--version-intensity 0 ' # Skip version detection
                f'--max-scan-delay 0 '    # No delay between probes
                f'-T4 '                   # Aggressive timing template
                f'--reason '              # Show reason for port state
            )
            
            try:
                self.progress.emit(f"Scanning {self.target}:{self.port}/{self.protocol}")
                logging.debug(f"Starting Nmap scan with args: {scan_args}")
                
                scan_result = self._nm.scan(self.target, arguments=scan_args)
                logging.debug(f"Scan result: {scan_result}")
            except Exception as e:
                if self.is_running():
                    raise Exception(f"Scan failed: {str(e)}")
                return
            
            if not self.is_running():
                return

            with QMutexLocker(self._mutex):
                if self.target in self._nm.all_hosts():
                    # Get the protocol-specific results
                    protocol_key = self.protocol.lower()
                    if protocol_key in self._nm[self.target]:
                        # Get the port info directly from the scan results
                        port_info = self._nm[self.target][protocol_key].get(int(self.port), {})
                        state = port_info.get('state', 'unknown')
                        
                        elapsed = time.time() - self.start_time
                        self.progress.emit(
                            f"Scan completed for {self.target}:{self.port}/{self.protocol} - "
                            f"State: {state} (took {elapsed:.1f}s)"
                        )
                        logging.debug(f"Scan completed: {self.target}:{self.port}/{self.protocol} - State: {state}")
                        self._scan_completed = True
                        self.scan_complete.emit(self.target, self.protocol, self.port, state)
                    else:
                        self.progress.emit(f"No results for {self.target}:{self.port}/{self.protocol}")
                        self._scan_completed = True
                        self.scan_complete.emit(self.target, self.protocol, self.port, 'filtered')
                else:
                    self.progress.emit(f"Host {self.target} not responding")
                    self._scan_completed = True
                    self.scan_complete.emit(self.target, self.protocol, self.port, 'filtered')
                
        except Exception as e:
            if self.is_running():  # Only emit error if we're still running
                elapsed = time.time() - self.start_time if self.start_time else 0
                error_msg = f"Error scanning {self.target}:{self.port}/{self.protocol} after {elapsed:.1f}s: {str(e)}"
                logging.error(error_msg)
                try:
                    self.progress.emit(error_msg)
                    self.error.emit(error_msg)
                    self._scan_completed = True
                    self.scan_complete.emit(self.target, self.protocol, self.port, 'error')
                except RuntimeError:
                    pass
        finally:
            if self.is_running():
                try:
                    self.finished.emit()
                except RuntimeError:
                    pass
            self._nm = None
            logging.debug(f"Scan worker finished for {self.target}:{self.port}/{self.protocol}")

class SVAValidator(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SVA Validator")
        self.setMinimumSize(1000, 600)
        
        # Initialize logging state
        self.logging_enabled = False
        self.setup_logging()
        
        # Initialize thread-safe variables
        self._scan_mutex = QMutex()
        self._is_scanning = False
        self._scan_workers = []
        
        # Initialize data storage with dictionary for faster lookups
        self.scan_data = {}  # Changed from list to dict for O(1) lookups
        self.current_scan_index = 0
        self.scan_timeout_timer = QTimer()
        self.scan_timeout_timer.timeout.connect(self.check_scan_timeout)
        
        # Initialize filter debounce timer
        self.filter_timer = QTimer()
        self.filter_timer.setSingleShot(True)
        self.filter_timer.timeout.connect(self._apply_filters)
        
        # Check for Nmap installation
        nmap_ok, nmap_status = verify_nmap_installation()
        if not nmap_ok:
            QMessageBox.critical(
                self,
                "Nmap Not Found",
                f"Nmap installation check failed:\n\n{nmap_status}\n\n"
                "Please follow these steps:\n"
                "1. Download Nmap from https://nmap.org/download.html\n"
                "2. Run the installer as administrator\n"
                "3. During installation:\n"
                "   - Choose 'Custom' installation\n"
                "   - Check 'Add Nmap to PATH'\n"
                "   - Install to default location\n"
                "4. Restart your computer\n"
                "5. Restart this application"
            )
        
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Create controls
        controls_layout = QHBoxLayout()
        
        # Load CSV button
        self.load_btn = QPushButton("Load CSV")
        self.load_btn.clicked.connect(self.load_csv)
        controls_layout.addWidget(self.load_btn)
        
        # Scan mode selection
        self.scan_mode = QComboBox()
        self.scan_mode.addItems(["Slow", "Aggressive"])
        controls_layout.addWidget(QLabel("Scan Mode:"))
        controls_layout.addWidget(self.scan_mode)
        
        # Start scan button
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        controls_layout.addWidget(self.scan_btn)
        
        # Stop scan button
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        controls_layout.addWidget(self.stop_btn)
        
        # Clear table button
        self.clear_btn = QPushButton("Clear Table")
        self.clear_btn.clicked.connect(self.clear_table)
        controls_layout.addWidget(self.clear_btn)
        
        # Export results button
        self.export_btn = QPushButton("Export Results")
        self.export_btn.clicked.connect(self.export_results)
        controls_layout.addWidget(self.export_btn)
        
        # Enable logging checkbox
        self.enable_logging_cb = QCheckBox("Enable Logging")
        self.enable_logging_cb.setChecked(False)
        self.enable_logging_cb.stateChanged.connect(self.toggle_logging)
        controls_layout.addWidget(self.enable_logging_cb)
        
        layout.addLayout(controls_layout)
        
        # Create filter controls
        filter_layout = QHBoxLayout()
        
        # IP filter
        filter_layout.addWidget(QLabel("Filter by IP:"))
        self.ip_filter = QLineEdit()
        self.ip_filter.setPlaceholderText("Enter IP or partial IP")
        self.ip_filter.textChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.ip_filter)
        
        # Protocol filter
        filter_layout.addWidget(QLabel("Filter by Protocol:"))
        self.protocol_filter = QComboBox()
        self.protocol_filter.addItems(["All", "TCP", "UDP"])
        self.protocol_filter.currentTextChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.protocol_filter)
        
        # Port filter
        filter_layout.addWidget(QLabel("Filter by Port:"))
        self.port_filter = QLineEdit()
        self.port_filter.setPlaceholderText("Enter port number")
        self.port_filter.textChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.port_filter)
        
        # Status filter
        filter_layout.addWidget(QLabel("Filter by Status:"))
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "Open", "Closed", "Filtered", "Error", "Stopped"])
        self.status_filter.currentTextChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.status_filter)
        
        filter_layout.addStretch()
        layout.addLayout(filter_layout)
        
        # Create table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["IP", "Protocol", "Port", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSortingEnabled(True)  # Enable sorting
        self.table.setAlternatingRowColors(True)  # Alternate row colors for better readability
        layout.addWidget(self.table)
        
        # Create log window
        self.log_window = QTextEdit()
        self.log_window.setReadOnly(True)
        self.log_window.setMaximumHeight(150)
        layout.addWidget(self.log_window)
        
        # Add Nmap credit line
        credit_label = QLabel("Powered by Nmap © 1996–2025 Insecure.Com LLC — https://nmap.org — Licensed under the Nmap Public Source License")
        credit_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = credit_label.font()
        font.setPointSize(7)  # Set small font size
        credit_label.setFont(font)
        layout.addWidget(credit_label)
        
        self.log("Application started. Ready to load CSV file.")
        if nmap_ok:
            self.log(nmap_status)
        else:
            self.log(f"WARNING: {nmap_status}")

    @property
    def is_scanning(self):
        with QMutexLocker(self._scan_mutex):
            return self._is_scanning

    @is_scanning.setter
    def is_scanning(self, value):
        with QMutexLocker(self._scan_mutex):
            self._is_scanning = value

    @property
    def scan_workers(self):
        with QMutexLocker(self._scan_mutex):
            return self._scan_workers

    @scan_workers.setter
    def scan_workers(self, value):
        with QMutexLocker(self._scan_mutex):
            self._scan_workers = value

    def setup_logging(self):
        """Set up or disable logging based on current state."""
        if self.logging_enabled:
            logging.basicConfig(
                filename='app.log',
                level=logging.DEBUG,
                format='%(asctime)s - %(levelname)s - %(message)s'
            )
        else:
            # Disable all logging
            logging.disable(logging.CRITICAL)

    def toggle_logging(self, state):
        """Toggle file logging on/off."""
        self.logging_enabled = state == Qt.CheckState.Checked.value
        self.setup_logging()
        if self.logging_enabled:
            self.log("Logging enabled")
        else:
            self.log_window.append("[System] Logging disabled")

    def log(self, message):
        """Log a message to both the log window and the log file if enabled."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        
        # Update GUI
        self.log_window.append(log_message)
        
        # Log to file if enabled
        if self.logging_enabled:
            logging.info(message)

    def check_scan_timeout(self):
        """Check for any scans that have exceeded the timeout."""
        if not self.is_scanning:
            self.scan_timeout_timer.stop()
            return

        current_time = time.time()
        for worker in self.scan_workers:
            if worker.isRunning() and worker.start_time:
                elapsed = current_time - worker.start_time
                if elapsed > DEFAULT_SCAN_TIMEOUT:
                    self.log(f"Scan timeout for {worker.target}:{worker.port}/{worker.protocol} after {elapsed:.1f}s")
                    worker.stop()
                    self.scan_complete.emit(worker.target, worker.protocol, worker.port, 'timeout')

    def load_csv(self):
        try:
            file_name, _ = QFileDialog.getOpenFileName(
                self, "Open CSV File", "", "CSV Files (*.csv)")
            
            if file_name:
                with open(file_name, 'r') as file:
                    reader = csv.reader(file)
                    self.scan_data = {}  # Reset to empty dict
                    self.table.setRowCount(0)
                    
                    row_count = 0
                    for row in reader:
                        if len(row) == 3:
                            if row_count >= MAX_CSV_ROWS:
                                QMessageBox.warning(
                                    self,
                                    "CSV Size Warning",
                                    f"The CSV file contains more than {MAX_CSV_ROWS} rows.\n"
                                    f"Only the first {MAX_CSV_ROWS} rows will be processed."
                                )
                                break
                                
                            ip, protocol, port = row
                            key = f"{ip}:{protocol}:{port}"  # Create unique key
                            self.scan_data[key] = {
                                'ip': ip,
                                'protocol': protocol.upper(),
                                'port': port,
                                'status': 'Pending',
                                'row': row_count  # Store row index
                            }
                            
                            self.table.insertRow(row_count)
                            self.table.setItem(row_count, 0, QTableWidgetItem(ip))
                            self.table.setItem(row_count, 1, QTableWidgetItem(protocol.upper()))
                            self.table.setItem(row_count, 2, QTableWidgetItem(port))
                            self.table.setItem(row_count, 3, QTableWidgetItem('Pending'))
                            row_count += 1
                    
                    self.log(f"Loaded {len(self.scan_data)} targets from CSV")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load CSV: {str(e)}")

    def start_scan(self):
        if not self.scan_data:
            QMessageBox.warning(self, "Warning", "Please load a CSV file first")
            return
        
        if self.is_scanning:
            return
        
        self.is_scanning = True
        self.scan_btn.setEnabled(False)
        self.load_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.scan_workers = []
        self.current_scan_index = 0
        
        # Start timeout checker
        self.scan_timeout_timer.start(1000)  # Check every second
        
        try:
            if self.scan_mode.currentText() == "Aggressive":
                # Start scans in batches
                active_workers = 0
                for key, data in self.scan_data.items():
                    if not self.is_scanning:
                        break
                        
                    # Wait if we've reached the maximum number of parallel scans
                    while active_workers >= MAX_PARALLEL_SCANS and self.is_scanning:
                        active_workers = sum(1 for w in self.scan_workers if w.isRunning())
                        if active_workers >= MAX_PARALLEL_SCANS:
                            time.sleep(0.1)
                    
                    if not self.is_scanning:
                        break
                        
                    worker = ScanWorker(
                        data['ip'],
                        data['protocol'],
                        data['port'],
                        DEFAULT_SCAN_TIMEOUT
                    )
                    worker.progress.connect(self.log)
                    worker.scan_complete.connect(self.update_scan_result)
                    worker.finished.connect(self.check_scan_completion)
                    worker.error.connect(self.handle_scan_error)
                    worker.start()
                    self.scan_workers.append(worker)
                    active_workers += 1
                    
                    time.sleep(SCAN_START_DELAY)
            else:
                # Start first scan in slow mode
                self.start_next_slow_scan()
            
            self.log("Scan started")
        except Exception as e:
            self.log(f"Error starting scan: {str(e)}")
            self.stop_scan()

    def start_next_slow_scan(self):
        if self.current_scan_index >= len(self.scan_data):
            self.check_scan_completion()
            return
        
        # Get data from dictionary using list of keys
        key = list(self.scan_data.keys())[self.current_scan_index]
        data = self.scan_data[key]
        
        worker = ScanWorker(
            data['ip'],
            data['protocol'],
            data['port'],
            DEFAULT_SCAN_TIMEOUT
        )
        worker.progress.connect(self.log)
        worker.scan_complete.connect(self.update_scan_result)
        worker.finished.connect(self.start_next_slow_scan)
        worker.start()
        self.scan_workers.append(worker)
        self.current_scan_index += 1

    def update_scan_result(self, ip, protocol, port, status):
        """Update scan result in the table with optimized lookup."""
        key = f"{ip}:{protocol}:{port}"
        if key in self.scan_data:
            row = self.scan_data[key]['row']
            self.scan_data[key]['status'] = status
            
            # Update status with colored and bold text
            status_item = QTableWidgetItem(status)
            font = status_item.font()
            font.setBold(True)
            status_item.setFont(font)
            
            # Set text color based on status
            if status.lower() == 'open':
                status_item.setForeground(Qt.GlobalColor.green)
            elif status.lower() in ['closed', 'filtered']:
                status_item.setForeground(Qt.GlobalColor.yellow)
            elif status.lower() in ['error', 'stopped']:
                status_item.setForeground(Qt.GlobalColor.red)
            else:
                status_item.setForeground(Qt.GlobalColor.black)
            
            self.table.setItem(row, 3, status_item)
            
            # Trigger filter update with debounce
            self.filter_timer.start(100)  # 100ms debounce

    def check_scan_completion(self):
        """Check if all scans are complete and update UI accordingly."""
        try:
            if all(worker.isFinished() for worker in self.scan_workers):
                self.scan_btn.setEnabled(True)
                self.load_btn.setEnabled(True)
                self.stop_btn.setEnabled(False)
                self.is_scanning = False
                self.scan_timeout_timer.stop()
                self.log("All scans completed")
        except Exception as e:
            self.log(f"Error checking scan completion: {str(e)}")
            self.stop_scan()

    def handle_scan_error(self, error_msg):
        """Handle scan errors."""
        self.log(f"Scan error: {error_msg}")
        # Don't stop the scan on individual errors, just log them

    def export_results(self):
        if not self.scan_data:
            QMessageBox.warning(self, "Warning", "No data to export")
            return
        
        try:
            file_name, _ = QFileDialog.getSaveFileName(
                self, "Save Results", "", "CSV Files (*.csv)")
            
            if file_name:
                with open(file_name, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(['IP', 'Protocol', 'Port', 'Status'])
                    
                    for key, data in self.scan_data.items():
                        writer.writerow([
                            data['ip'],
                            data['protocol'],
                            data['port'],
                            data['status']
                        ])
                
                self.log(f"Results exported to {file_name}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export results: {str(e)}")

    def stop_scan(self):
        """Stop all ongoing scans."""
        if not self.is_scanning:
            return
            
        self.log("Stopping all scans...")
        with QMutexLocker(self._scan_mutex):
            # First stop all workers
            for worker in self._scan_workers:
                if worker.isRunning():
                    worker.stop()
            
            # Then wait for them to finish
            for worker in self._scan_workers:
                if worker.isRunning():
                    worker.wait()
            
            # Finally clear the list
            self._scan_workers = []
        
        self.is_scanning = False
        self.scan_btn.setEnabled(True)
        self.load_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.scan_timeout_timer.stop()
        self.log("All scans stopped")

    def clear_table(self):
        """Clear all results from the table."""
        self.table.setRowCount(0)
        self.scan_data = {}
        self.log("Table cleared")

    def apply_filters(self):
        """Debounced filter application."""
        self.filter_timer.start(100)  # 100ms debounce

    def _apply_filters(self):
        """Apply all active filters to the table."""
        status_filter = self.status_filter.currentText()
        protocol_filter = self.protocol_filter.currentText()
        ip_filter = self.ip_filter.text().strip()
        port_filter = self.port_filter.text().strip()
        
        # Show all rows first
        for row in range(self.table.rowCount()):
            self.table.setRowHidden(row, False)
        
        # Apply filters
        for key, data in self.scan_data.items():
            row = data['row']
            should_hide = False
            
            # IP filter
            if ip_filter and ip_filter not in data['ip']:
                should_hide = True
            
            # Protocol filter
            if not should_hide and protocol_filter != "All" and data['protocol'] != protocol_filter:
                should_hide = True
            
            # Port filter
            if not should_hide and port_filter and port_filter not in data['port']:
                should_hide = True
            
            # Status filter
            if not should_hide and status_filter != "All" and data['status'].lower() != status_filter.lower():
                should_hide = True
            
            self.table.setRowHidden(row, should_hide)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    # Set up global exception handler
    handler = ExceptionHandler(app)
    window = SVAValidator()
    window.show()
    sys.exit(app.exec()) 