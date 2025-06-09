from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit,
                               QTableWidget, QTableWidgetItem, QMessageBox, QLabel, QDialog,
                               QProgressBar, QHBoxLayout, QTabWidget)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QColor, QBrush, QIcon, QMovie
import sys
import psutil
import win32api
import win32process
import win32con
import time
import socket

# Configuration
KEYWORDS = ["Keylogger", "logger", "keyboard", "hook"]
SUSPICIOUS_DLLS = ["pynput", "pyHook", "keyboard", "ctypes"]
WHITE_LIST = ["python.exe", "explorer.exe", "D-LoGGer.exe", "D-LoGGer", "pycharm.exe", "pycharm", "python312",
              "vscode.exe", "discord.exe", "systemsettings.exe", "sihost.exe", "widgets.exe",
              "loggerDetection.py", "loggerDetection.exe", "LOGGERDETECTION.exe"]


DARK_THEME = {
    # "background": "#1E1E1E",  # Darker background
    "background": "#000000",  # Darker background
    "foreground": "#FFFFFF",  # White text for better contrast
    "accent": "#4CAF50",      # Green accent for highlights
    "button": "#1c7fb0",      # Dark button color
    "button_hover": "#094a75", # Lighter button color on hover
    "table_header": "#2A2A2A", # Dark gray for table headers
    "table_row": "#2E2E2E",    # Dark gray for table rows
    "table_alternate": "#3A3A3A", # Slightly lighter for alternate rows
    "log_background": "#2E2E2E", # Dark background for logs
    "log_foreground": "#575656", # Light gray for log text
}

class KeyloggerScanner(QThread):
    update_log = Signal(str, str)
    update_processes = Signal(list, bool)
    stop_signal = Signal()

    def __init__(self):
        super().__init__()
        self.running = False

    def run(self):
        self.running = True
        self.update_log.emit(f"<span style='font-size:16px; font-weight:bold; '>🔍 --> Scanning for suspicious processes...</span>", "cyan")
        suspicious_processes = self.detect_suspicious_processes()
        hooked = self.key_hooked()
        self.update_processes.emit(suspicious_processes, hooked)

        if suspicious_processes and hooked:
            # self.update_log.emit("🚨🚨 KEYLOGGER DETECTED !!! Monitoring network activity...", "red")
            self.update_log.emit(f"<span style='font-weight:bold; font-size:15px;'> 🚨🚨 KEYLOGGER DETECTED !!! Monitoring network activity...</span>",
            "red")
            self.monitor_network_activity(suspicious_processes)
        else:
            self.update_log.emit(f"<span style=' font-size:15px; font-weight:bold;'>✅ NO KEYLOGGER detected. You're SAFE ! </span>", "lightgreen")

    def get_loaded_modules(self, pid):
        try:
            hProcess = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
            modules = win32process.EnumProcessModules(hProcess)
            return [win32process.GetModuleFileNameEx(hProcess, mod) for mod in modules]
        except Exception:
            return []

    def detect_suspicious_processes(self):
        detected_processes = []

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            if not self.running:
                return []
            try:
                pid, name = proc.info['pid'], proc.info['name'].lower()
                if any(white.lower() in name for white in WHITE_LIST):
                    continue

                if any(k in name for k in KEYWORDS):
                    detected_processes.append((pid, name, "N/A"))
                    continue
                loaded_modules = self.get_loaded_modules(pid)
                for module in loaded_modules:
                    if any(s in module.lower() for s in SUSPICIOUS_DLLS):
                        if not any(white in name for white in WHITE_LIST):
                            detected_processes.append((pid, name, module))
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return detected_processes

    def key_hooked(self):
        import ctypes

        WH_KEYBOARD_LL = 13
        WH_JOURNALRECORD = 0

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        hook_libraries = [
            "pynput", "keyboard", "pyhook", "_ctypes", "inputhook",
            "jni.dll", "awt.dll", "hook.dll"
        ]

        hooked_detected = False

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                loaded_modules = self.get_loaded_modules(proc.pid)
                for module in loaded_modules:
                    if any(lib in module.lower() for lib in hook_libraries):
                        message = f"💡 A module Found (it could be Legit Process): {module} (PID: {proc.pid}) — CROSS-CHECKING is Recommended!"
                        self.update_log.emit(message, "orange")
                        hooked_detected = True
            except Exception:
                continue

        def try_hook(hook_id):
            try:
                hook = user32.SetWindowsHookExW(hook_id, None, kernel32.GetModuleHandleW(None), 0)
                if hook:
                    user32.UnhookWindowsHookEx(hook)
                    return True
                return False
            except Exception:
                return False

        hooks_to_check = {
            "WH_KEYBOARD_LL": try_hook(WH_KEYBOARD_LL),
            "WH_JOURNALRECORD": try_hook(WH_JOURNALRECORD)
        }

        return hooked_detected or any(hooks_to_check.values())

    def monitor_network_activity(self, detected_processes):
        import collections
        import datetime

        THRESHOLD_COUNT = 10
        TIME_WINDOW = 300

        active_processes = {pid: name for pid, name, _ in detected_processes}
        network_tracker = collections.defaultdict(lambda: collections.defaultdict(list))

        self.update_log.emit(f"<span style='font-weight:bold; font-size:15px; '>🛰️ Monitoring OUTGOING Network Activity to unknown servers...</span>", "lightgreen")

        def is_private_ip(ip):
            return (ip.startswith("10.") or
                    ip.startswith("192.168.") or
                    ip.startswith("172.16.") or ip.startswith("172.17.") or
                    ip.startswith("172.18.") or ip.startswith("172.19.") or
                    ip.startswith("172.20.") or ip.startswith("172.21.") or
                    ip.startswith("172.22.") or ip.startswith("172.23.") or
                    ip.startswith("172.24.") or ip.startswith("172.25.") or
                    ip.startswith("172.26.") or ip.startswith("172.27.") or
                    ip.startswith("172.28.") or ip.startswith("172.29.") or
                    ip.startswith("172.30.") or ip.startswith("172.31.") or
                    ip == "127.0.0.1" or ip == "::1")

        while self.running:
            current_time = time.time()

            for conn in psutil.net_connections(kind='inet'):
                if not self.running:
                    return
                try:
                    pid = conn.pid
                    if pid in active_processes and conn.raddr and conn.status == psutil.CONN_ESTABLISHED and self.running:

                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port

                        if is_private_ip(remote_ip):
                            continue

                        network_tracker[pid][remote_ip].append(current_time)

                        timestamps = network_tracker[pid][remote_ip]
                        network_tracker[pid][remote_ip] = [t for t in timestamps if current_time - t <= TIME_WINDOW]

                        timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        try:
                            host = socket.gethostbyaddr(remote_ip)[0]
                        except socket.herror:
                            host = remote_ip

                        connection_msg = (f"[{timestamp_str}] Suspicious Process {active_processes[pid]} (PID: {pid}) "
                                          f"sent data to {host} ({remote_ip}:{remote_port})")
                        self.update_log.emit(connection_msg, "red")

                        # Trigger alert
                        if len(network_tracker[pid][remote_ip]) >= THRESHOLD_COUNT:
                            alert_msg = (f"🚨 ALERT! {active_processes[pid]} (PID: {pid}) has sent data "
                                         f"{len(network_tracker[pid][remote_ip])} times within 5 minutes "
                                         f"to {remote_ip}. Continuous sending detected!")
                            self.update_log.emit(alert_msg, "maroon")
                            network_tracker[pid][remote_ip].clear()

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    continue

            time.sleep(0.5)

        self.stop_signal.emit()

class ProgressDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(" Detecting...")
        self.setFixedSize(400, 160)
        self.setModal(True)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 15, 15, 15)

        self.label = QLabel("Scanning for Keylogger...")
        self.label.setStyleSheet("background-color:#d18ca1; color: #deb8d2; font-size: 15px; font-weight: bold;")
        self.label.setAlignment(Qt.AlignCenter)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #ffffff;
                border: 2px solid #fcfcfc;
                text-align: center;
                font-weight: bold;
                color: #3bc936;
                height: 22px;
            }
            QLabel {
                background-color: #f5d5d5;
                
            }

            QProgressBar::chunk {
                background-color: qlineargradient(
                    x1: 0, y1: 0, x2: 1, y2: 0,
                    stop: 0 #66ccff,
                    stop: 0.5 #196dc2,
                    stop: 1 #007acc
                );
                border-radius: 10px;
                width: 20px;
                margin: 1px;
            }
        """)

        layout.addWidget(self.label)
        layout.addWidget(self.progress_bar)
        self.setStyleSheet("""
                   QDialog {
                       background-color: #fad4ee;
                   }
               """)

    def update_status(self, message, color):
         self.label.setText(message)
         self.label.setStyleSheet(f"color: {color}; background-color:#fffcfe; font-size: 14px; font-weight: bold;")
         self.progress_bar.hide()

    def reset(self):
        self.label.setText("Scanning for Keylogger...")
        self.label.setStyleSheet("color: #424041; background-color:#fffcfe; font-size: 15px; font-weight: bold;")
        self.progress_bar.show()

class KeyloggerAlertDialog(QDialog):
    def __init__(self, process_name, pid, parent=None):
        super().__init__(parent)

        self.setWindowTitle("🚨 Keylogger Detected")
        self.setFixedSize(400, 180)
        self.setModal(True)
        self.setStyleSheet("""

            QDialog {

                background-color: white;  
                border: 2px solid #cc0000;  /* Red border */

            }

            QLabel {

                color: #cc0000;  /* Red text color */
                background0color: #f5d5d5;
                font-size: 16px;  /* Increase font size */
                font-weight: bold;

            }

        """)

        layout = QVBoxLayout(self)

        layout.setSpacing(15)


        message = QLabel(f"🚨 Keylogger Detected:\n\n🔍 Process: {process_name}\n\nDo you want to Terminate it?")

        message.setWordWrap(True)
        message.setAlignment(Qt.AlignCenter)
        layout.addWidget(message)
        button_layout = QHBoxLayout()
        self.yes_button = QPushButton("Terminate")
        self.yes_button.setObjectName("yesButton")
        self.no_button = QPushButton("Ignore")
        self.no_button.setObjectName("noButton")
        self.yes_button.clicked.connect(self.accept)
        self.no_button.clicked.connect(self.reject)
        button_layout.addWidget(self.yes_button)
        button_layout.addWidget(self.no_button)
        layout.addLayout(button_layout)


class KeyloggerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.progress_dialog = ProgressDialog(self)
        self.setWindowTitle("D-LoGGer : Keylogger Detection System")
        self.setGeometry(200, 200, 1000, 600)
        self.setup_ui()
        self.setup_styles()

    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        self.tabs = QTabWidget()
        self.tabs.setFixedHeight(560)

        self.tabs.setStyleSheet("""

                QTabWidget::pane {

                    border: 2px solid #4CAF50;  /* Border color for the tab widget */

                }

                QTabBar::tab {

                    background: #2E2E2E; 

                    color: #FFFFFF;  

                    font-size: 16px;  

                }

                QTabBar::tab:hover {

                    background: #4CAF50;

                    color: #FFFFFF; 

                }

                QTabBar::tab:selected {

                    background: #1E1E1E;  

                    color: #FFFFFF;  

                }

            """)
        layout.addWidget(self.tabs)

        # Tab 1: Scan Control
        self.scan_tab = QWidget()
        self.setup_scan_tab()
        self.tabs.addTab(self.scan_tab, "Scan Control")

        # Tab 2: Detection Results
        self.results_tab = QWidget()
        self.setup_results_tab()
        self.tabs.addTab(self.results_tab, "Detection Results")

        # Scanner Thread
        self.scanner_thread = KeyloggerScanner()
        self.scanner_thread.update_log.connect(self.append_log)
        self.scanner_thread.update_processes.connect(self.update_process_table)
        self.scanner_thread.stop_signal.connect(self.on_scan_stopped)

    def setup_scan_tab(self):
        layout = QVBoxLayout()
        self.scan_tab.setLayout(layout)

        self.status_label = QLabel(f"<span style=' font-size:19px; color:whitesmoke; font-family:Times; '>Click ' START SCAN ' to check for KEYLOGGERS </span>")
        layout.addWidget(self.status_label)

        self.gif_label = QLabel(self)
        self.movie = QMovie("scanner1.gif")
        self.gif_label.setMovie(self.movie)
        layout.addWidget(self.gif_label)

        button_layout = QHBoxLayout()

        # Start Scan Button
        self.scan_button = QPushButton("START Scan")
        self.scan_button.setIcon(QIcon("grn.png"))
        self.scan_button.setFixedSize(170, 170)
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        self.scan_button.setCursor(Qt.PointingHandCursor)
        self.scan_button.setStyleSheet("""

                QPushButton {

                    border-radius: 80px;  
                    font-size: 18px;  
                    padding: 10px;

                }
            """)
        self.stop_button = QPushButton("STOP Scan")
        self.stop_button.setIcon(QIcon("stop_icon.png"))
        self.stop_button.setFixedSize(170, 170)
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        self.stop_button.setCursor(Qt.PointingHandCursor)
        self.stop_button.setStyleSheet("""

                        QPushButton {

                            border-radius: 80px;  
                            font-size: 18px;  
                            padding: 10px;
                            

                        }

                    """)

        button_layout.setAlignment(Qt.AlignCenter)

        button_layout.setContentsMargins(0, 20, 20, 20)
        button_layout.setSpacing(40)

        layout.addLayout(button_layout)

    def setup_results_tab(self):
        layout = QVBoxLayout()
        self.results_tab.setLayout(layout)

        # Process Table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(4)
        self.process_table.setHorizontalHeaderLabels(["PID", "Process Name", "FILE_Path", "Action"])
        self.process_table.setStyleSheet("QTableWidget { font-size: 13px;color:red; font-family:Times }")
        layout.addWidget(self.process_table)

        # Log Output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)

    def setup_styles(self):
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {DARK_THEME["background"]};
                color: {DARK_THEME["foreground"]};
                font-family: Calibri ;
            }}
            QPushButton {{
                background-color: {DARK_THEME["button"]};
                color: white;
                border-radius: 5px;
                padding: 10px;
                font-size: 14px;
            }}
            QPushButton:hover {{
                background-color: {DARK_THEME["button_hover"]};
            }}
            QPushButton:disabled {{
                background-color: #8c8b8b;
            }}
            QTableWidget {{
                background-color: {DARK_THEME["table_row"]};
                color: {DARK_THEME["foreground"]};
                border: 1px solid {DARK_THEME["accent"]};
            }}
            QHeaderView::section {{
                background-color: {DARK_THEME["table_header"]};
                color: {DARK_THEME["foreground"]};
                padding: 6px;
            }}
            QTextEdit {{
                background-color: {DARK_THEME["log_background"]};
                color: {DARK_THEME["log_foreground"]};
                border: 1px solid {DARK_THEME["accent"]};
            }}
        """)

    def start_scan(self):
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_dialog.reset()
        self.progress_dialog.show()
        self.scanner_thread.running = True
        self.scanner_thread.start()

        self.movie.start()

    def stop_scan(self):
        self.scanner_thread.running = False
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        self.movie.stop()

    def on_scan_stopped(self):
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        self.movie.stop()

    def append_log(self, message, color=DARK_THEME["foreground"]):
        self.log_output.append(f'<span style="color:{color};">{message}</span>')
        self.log_output.verticalScrollBar().setValue(self.log_output.verticalScrollBar().maximum())

        if "NO KEYLOGGER detected" in message:
            self.progress_dialog.update_status("✅ No 'KEYLOGGER' detected. You are SAFE!", "green")
            self.movie.stop()
            QTimer.singleShot(2000, lambda: (
                self.progress_dialog.close(),
                self.status_label.setText(f"<span style='font-size:20px; color:lightgreen; font-weight:bold;'>✅ SCAN COMPLETE... No threats found. Click on <span style='color:white;'>' Detection Results '</span> for more clear analysis !!!  </span>"),
                self.scan_button.setEnabled(True),
                self.stop_button.setEnabled(False)
            ))
        elif "KEYLOGGER DETECTED" in message:
            self.progress_dialog.update_status(f"<span style=' font-size:15px; font-weight:bold; '>🚨 Keylogger detected , KILL IT !!! </span>","red")
            self.movie.stop()
            QTimer.singleShot(2000, self.progress_dialog.close)

    def update_process_table(self, process_list, hooked):
        self.process_table.setRowCount(len(process_list))
        self.active_keylogger_pids = set(pid for pid, _, _ in process_list)

        for row, (pid, name, module) in enumerate(process_list):
            self.process_table.setItem(row, 0, QTableWidgetItem(str(pid)))
            self.process_table.setItem(row, 1, QTableWidgetItem(name))
            self.process_table.setItem(row, 2, QTableWidgetItem(module))

            self.process_table.item(row, 1).setForeground(QBrush(QColor("red")))
            self.process_table.item(row, 2).setForeground(QBrush(QColor("red")))

            if row % 2 == 0:
                for col in range(3):
                    self.process_table.item(row, col).setBackground(QBrush(QColor("#f2f2f2")))

            terminate_btn = QPushButton("Kill")
            terminate_btn.setStyleSheet(
                "background-color: #9c0606; color: white; font-weight: bold; border-radius: 3px;")
            terminate_btn.setCursor(Qt.PointingHandCursor)
            terminate_btn.clicked.connect(lambda _, r=row, p=pid, n=name: self.terminate_process(r, p, n))
            self.process_table.setCellWidget(row, 3, terminate_btn)

        if process_list and hooked:
            self.status_label.setText(
                "<span style='font-size:20px; color:red; '>🚨 KEYLOGGER FOUND !! Click on <span style='color:white; font-weight:bold; '>'Detection Results'</span> for more details and <span style='color:white; font-weight:bold;'> 'KILL' </span>.</span>"
            )
        else:
            self.status_label.setText(
                "<span style='font-size:20px; color:green; font-weight:bold;'> -->> ✅ SCAN COMPLETE <<-- </span>"
            )
        self.process_table.resizeColumnsToContents()

        # self.status_label.setText(f"<span style='font-size:16px; color:green; font-weight:bold;'>✅ --> SCAN COMPLETE <-- </span>")
        # self.process_table.resizeColumnsToContents()

    def terminate_process(self, row, pid, name):
        try:
            process = psutil.Process(pid)
            process.terminate()
            self.append_log(
                f"<span style='font-weight:bold; font-size:15px; font-family:Arial;'> <span style='color:white; '>' {name} '</span> keylogger has been TERMINATED SUCCESSFULLY !!!</span>",
                "green")
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("✅ Termination Successful")
            msg_box.setText(f"The keylogger process \"{name}\" was terminated successfully.")
            msg_box.setIcon(QMessageBox.Information)
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec()

            self.process_table.removeRow(row)

            if pid in self.active_keylogger_pids:
                self.active_keylogger_pids.remove(pid)

            if not self.active_keylogger_pids:
                self.scanner_thread.running = False
                self.status_label.setText(f"<span style='font-size:15px; '>✅ No more suspicious activity detected.</span>")
                if self.progress_dialog.isVisible():
                    self.progress_dialog.close()

                self.scan_button.setEnabled(True)
                self.stop_button.setEnabled(False)
        except psutil.NoSuchProcess:
            self.append_log(f"⚠️ Process {name} (PID: {pid}) no longer exists.", "orange")
        except Exception as e:
            self.append_log(f"⚠️ Failed to terminate {name} (PID: {pid}): {e}", "red")

def path(rPath):
    import os
    basePath=getattr(sys,'_MEIPASS',os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(basePath,rPath)


if __name__ == "__main__":
    app = QApplication([])
    window = KeyloggerGUI()
    icon_path = path("cyber3.ico")
    window.setWindowIcon(QIcon(icon_path))
    window.show()
    sys.exit(app.exec())



