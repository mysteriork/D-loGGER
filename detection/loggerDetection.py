
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit,
                               QTableWidget, QTableWidgetItem, QMessageBox ,QLabel,QDialog, QProgressBar,QHBoxLayout)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QColor, QBrush, QIcon
import sys
import psutil
import win32api
import win32process
import win32con
import time
import socket


keywords = ["Keylogger", "logger", "keyboard", "hook"]
SUSPICIOUS_DLLS = ["pynput", "pyHook", "keyboard", "ctypes"]
WHITE_LIST = ["python.exe", "explorer.exe","D-LoGGer.exe","D-LoGGer", "pycharm.exe","pycharm","python312", "vscode.exe", "discord.exe", "systemsettings.exe","sihost.exe","widgets.exe","loggerDetection.py","loggerDetection.exe","LOGGERDETECTION.exe"]

class KeyloggerScanner(QThread):
    update_log = Signal(str, str)
    update_processes = Signal(list, bool)
    stop_signal = Signal()

    def __init__(self):
        super().__init__()
        self.running = False

    def run(self):
        self.running = True
        self.update_log.emit("🔍 --> Scanning for suspicious processes...", "blue")
        suspicious_processes = self.detect_suspicious_processes()
        hooked = self.key_hooked()
        self.update_processes.emit(suspicious_processes, hooked)

        if suspicious_processes and hooked:
            self.update_log.emit("🚨🚨 KEYLOGGER DETECTED !!! Monitoring network activity...", "maroon")
            self.monitor_network_activity(suspicious_processes)
        else:
            self.update_log.emit("✅ NO KEYLOGGER detected. You're SAFE !", "green")

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

                if any(k in name for k in keywords):
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

        # Retain fallback hook detection
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

        self.update_log.emit("🛰️ Monitoring outgoing network activity to unknown servers...", "blue")

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
                        self.update_log.emit(connection_msg, "crimson")

                        # Trigger alert
                        if len(network_tracker[pid][remote_ip]) >= THRESHOLD_COUNT:
                            alert_msg = (f"🚨 ALERT! {active_processes[pid]} (PID: {pid}) has sent data "
                                         f"{len(network_tracker[pid][remote_ip])} times within 5 minutes "
                                         f"to {remote_ip}. Continuous sending detected!")
                            self.update_log.emit(alert_msg, "maroon")
                            # Optional: clear to avoid spamming
                            network_tracker[pid][remote_ip].clear()

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    continue

            time.sleep(0.5)

        self.stop_signal.emit()

class ProgressDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(" 🔍 Detecting...")
        self.setFixedSize(400, 160)
        self.setModal(True)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)

        self.label = QLabel("Scanning for Keylogger...")
        self.label.setStyleSheet("color: #333; font-size: 14px; font-weight: bold;")
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
         self.label.setStyleSheet(f"color: {color}; font-size: 14px; font-weight: bold;")
         self.progress_bar.hide()

    def reset(self):
        self.label.setText("Scanning for Keylogger...")
        self.label.setStyleSheet("color: #615e5f; font-size: 15px; font-weight: bold;")
        self.progress_bar.show()

class KeyloggerAlertDialog(QDialog):
    def __init__(self, process_name, pid, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🚨 Keylogger Detected")
        self.setFixedSize(400, 180)
        self.setModal(True)
        self.setStyleSheet("""
            QDialog {
                background-color: #fff0f0;
                border: 2px solid #cc0000;

            }
            QLabel {
                color: #990000;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton {
                padding: 6px 12px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton#yesButton {
                background-color: #cc0000;
                color: white;
            }
            QPushButton#noButton {
                background-color: #dddddd;
                color: #333;
            }
            QPushButton#yesButton:hover {
                background-color: #990000;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        message = QLabel(f"Suspicious process detected:\n\n🔍 Process: {process_name}\n\n\nDo you want to Terminate it ?")
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
        self.progress_dialog=ProgressDialog(self)
        self.setWindowTitle("  D-loGGer :  Keylogger Detection System")
        self.setGeometry(200, 200, 900, 450)
        layout = QVBoxLayout()

        self.setStyleSheet("""
            QWidget { background-color: #f5f5f5; color: #333; font-family: Arial; }
            QLabel { font-size: 14px; font-weight: bold; }
            QPushButton { background-color: #008CBA; color: white; border-radius: 5px; padding: 6px; }
            QPushButton:hover { background-color: #005f8b; }
            QPushButton:disabled { background-color: #cccccc; }
            QTextEdit { background-color: white; color: black; font-family: Consolas; border: 1px solid #ddd; }
            QTableWidget { background-color: white; color: black; border: 1px solid gray; }
            QHeaderView::section { background-color: #e0e0e0; color: black; font-weight: bold; }
        """)

        self.status_label = QLabel("Click 'Start Scan' to check for keyloggers.")
        layout.addWidget(self.status_label)

        self.scan_button = QPushButton("START Scan")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)

        self.stop_button = QPushButton("STOP Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        layout.addWidget(self.stop_button)

        self.process_table = QTableWidget()
        self.process_table.setColumnCount(4)
        self.process_table.setHorizontalHeaderLabels(["PID", "Process Name", "FILE_Path", "Action"])
        layout.addWidget(self.process_table)
        self.active_keylogger_pids = set()

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)

        self.setLayout(layout)
        self.scanner_thread = KeyloggerScanner()
        self.scanner_thread.update_log.connect(self.append_log)
        self.scanner_thread.update_processes.connect(self.update_process_table)
        self.scanner_thread.stop_signal.connect(self.on_scan_stopped)

    def start_scan(self):

        self.status_label.setText("🔄 Scanning...")
        self.log_output.clear()
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        self.progress_dialog.reset()
        self.progress_dialog.show()

        self.scanner_thread.running = True
        self.scanner_thread.start()

    def stop_scan(self):

        self.scanner_thread.running = False
        self.status_label.setText("🛑 Scan Stopped!")
        self.scan_button.setEnabled(True)   # Re-enable START button
        self.stop_button.setEnabled(False)  # Disable STOP button

    def on_scan_stopped(self):

        self.progress_dialog.close()
        self.status_label.setText("🛑 Scan Stopped!")
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def append_log(self, message, color="black"):
        self.log_output.append(f'<span style="color:{color};">{message}</span>')
        self.log_output.verticalScrollBar().setValue(self.log_output.verticalScrollBar().maximum())

        if "NO KEYLOGGER detected" in message:
            self.progress_dialog.update_status("✅ No 'KEYLOGGER' detected. You are SAFE!", "green")
            QTimer.singleShot(2000, lambda: (
                self.progress_dialog.close(),
                self.status_label.setText("✅ Scan complete. No threats found."),
                self.scan_button.setEnabled(True),
                self.stop_button.setEnabled(False)
            ))
        elif "KEYLOGGER DETECTED" in message:
            self.progress_dialog.update_status("🚨 Keylogger detected , TERMINATE IT !", "red")
            QTimer.singleShot(2000, self.progress_dialog.close)

    # def update_process_table(self, process_list, _):
    #     self.process_table.setRowCount(len(process_list))
    #     if process_list:
    #         for pid, name, _ in process_list:
    #             dialog = KeyloggerAlertDialog(name, pid, self)
    #             user_choice = dialog.exec()
    #
    #             if user_choice == QDialog.Accepted:
    #                 try:
    #                     psutil.Process(pid).terminate()
    #                     self.append_log(f"🛡️ Terminated {name}", "green")
    #                 except Exception as e:
    #                     self.append_log(f"⚠️ Failed to terminate {name} (PID: {pid}): {e}", "red")
    #
    #
    #     for row, (pid, name, module) in enumerate(process_list):
    #         self.process_table.setItem(row, 0, QTableWidgetItem(str(pid)))
    #         self.process_table.setItem(row, 1, QTableWidgetItem(name))
    #         self.process_table.setItem(row, 2, QTableWidgetItem(module))
    #         self.process_table.item(row, 1).setForeground(QBrush(QColor("red")))
    #         self.process_table.item(row, 2).setForeground(QBrush(QColor("darkred")))
    #
    #         if row % 2 == 0:
    #             for col in range(3):
    #                 self.process_table.item(row, col).setBackground(QBrush(QColor("#f2f2f2")))
    #     self.process_table.resizeColumnToContents(2)
    #     self.status_label.setText("✅ --> Scan Complete <-- ")
    def update_process_table(self, process_list, _):
        self.process_table.setRowCount(len(process_list))
        self.active_keylogger_pids = set(pid for pid, _, _ in process_list)

        for row, (pid, name, module) in enumerate(process_list):
            self.process_table.setItem(row, 0, QTableWidgetItem(str(pid)))
            self.process_table.setItem(row, 1, QTableWidgetItem(name))
            self.process_table.setItem(row, 2, QTableWidgetItem(module))

            self.process_table.item(row, 1).setForeground(QBrush(QColor("red")))
            self.process_table.item(row, 2).setForeground(QBrush(QColor("darkred")))

            # Alternate row color
            if row % 2 == 0:
                for col in range(3):
                    self.process_table.item(row, col).setBackground(QBrush(QColor("#f2f2f2")))

            terminate_btn = QPushButton("Terminate")
            terminate_btn.setStyleSheet(
                "background-color: #9c0606; color: white; font-weight: bold; border-radius: 3px;")
            terminate_btn.setCursor(Qt.PointingHandCursor)
            terminate_btn.clicked.connect(lambda _, r=row, p=pid, n=name: self.terminate_process(r, p, n))
            self.process_table.setCellWidget(row, 3, terminate_btn)

        self.status_label.setText("✅ --> SCAN COMPLETE <-- ")
        self.process_table.resizeColumnsToContents()

    def terminate_process(self, row, pid, name):
        try:
            psutil.Process(pid).terminate()
            self.append_log(
                f"<span style='font-weight:bold; font-size:14px;'> {name} keylogger has been TERMINATED SUCCESSFULLY !!!</span>",
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
                self.status_label.setText("✅ No more suspicious activity detected.")
                if self.progress_dialog.isVisible():
                    self.progress_dialog.close()

                self.scan_button.setEnabled(True)
                self.stop_button.setEnabled(False)
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
