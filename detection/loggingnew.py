# D L O G G E R ----- DETECTION SYSTEM ---- SIMPLE #####


import psutil
# import ctypes
# import win32api
# import win32process
# import win32con
# import time
# import socket
#
# keywords=["Keylogger","logger","keyboard","hook"]
# SUSPICIOUS_DLLS = ["pynput", "pyHook", "keyboard", "ctypes"]
# WHITE_LIST = ["python.exe", "pycharm.exe", "vscode.exe"]
# LOG_FILE = "suspicious_network_activity.log"
#
#
# def get_loaded_modules(pid):
#
#     try:
#         hProcess = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
#         modules = win32process.EnumProcessModules(hProcess)
#         loaded_modules = [win32process.GetModuleFileNameEx(hProcess, mod) for mod in modules]
#         return loaded_modules
#     except Exception:
#         return []
#
#
# def detect_suspicious_processes():
#
#     Suspi_Found = False
#     detected_processes = []
#
#     for proc in psutil.process_iter(['pid', 'name', 'exe']):
#         try:
#             pid = proc.info['pid']
#             name = proc.info['name'].lower()
#
#             if name in WHITE_LIST:
#                 continue
#
#             if name in keywords:
#                 Suspi_Found=True
#                 detected_processes.append((pid, name))
#                 continue
#
#
#             loaded_modules = get_loaded_modules(pid)
#             for module in loaded_modules:
#                 if any(suspicious in module.lower() for suspicious in SUSPICIOUS_DLLS):
#                     print(f" --->> Suspicious Process Detected: {name} (PID: {pid}) using {module}")
#                     Suspi_Found = True
#                     detected_processes.append((pid, name))
#
#         except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
#             continue
#
#     return Suspi_Found, detected_processes
#
#
# def key_hooked():
#     WH_KEYBOARD_LL = 13
#     WH_JOURNALRECORD = 0
#
#     user32 = ctypes.windll.user32
#     kernel32 = ctypes.windll.kernel32
#
#
#     hook_libraries = [
#         "pynput", "keyboard", "pyhook", "_ctypes", "inputhook",
#         "user32.dll", "msvcrt.dll", "win32u.dll", "jni.dll", "awt.dll", "hook.dll"
#     ]
#
#
#     for proc in psutil.process_iter(['pid', 'name']):
#         try:
#             loaded_modules = get_loaded_modules(proc.pid)
#             for module in loaded_modules:
#                 if any(lib in module.lower() for lib in hook_libraries):
#                     print(f"💡 A module detected ( it could be Legit Process ): {module} (PID: {proc.pid}) CROSS-CHECKING is Recommended !!! ")
#                     return True
#         except Exception:
#             continue
#
#     def try_hook(hook_id):
#         try:
#             hook = user32.SetWindowsHookExW(hook_id, None, kernel32.GetModuleHandleW(None), 0)
#             if hook:
#                 user32.UnhookWindowsHookEx(hook)
#                 return True
#             return False
#         except Exception:
#             return False
#
#     # Retain fallback hook detection
#     hooks_to_check = {
#         "WH_KEYBOARD_LL": try_hook(WH_KEYBOARD_LL),
#         "WH_JOURNALRECORD": try_hook(WH_JOURNALRECORD)
#     }
#
#     return any(hooks_to_check.values())
#
# def monitor_network_activity(detected_processes):
#
#     print(f" Monitoring network activity of flagged processes {detected_processes}...")
#
#     activeProcess={pid:name for pid,name in detected_processes}
#
#     while True:
#         for conn in psutil.net_connections(kind='inet'):
#             try:
#                 pid = conn.pid
#                 if pid and any(dpid == pid for dpid, _ in detected_processes):
#                     proc_name=activeProcess[pid]
#                     remote_ip = conn.raddr.ip if conn.raddr else "UNKNOWN"
#                     remote_port = conn.raddr.port if conn.raddr else "UNKNOWN"
#                     try:
#                         host=socket.gethostbyaddr(remote_ip)[0]
#                     except socket.herror:
#                         host=remote_ip
#
#                     if remote_ip not in ["127.0.0.1", "localhost"]:
#                         log_message =  (f" Suspicious network activity detected! "
#                                        f"Process: {proc_name} (PID: {pid}) "
#                                        f"is sending data to {host} ({remote_ip}):{remote_port}")
#                         print(log_message)
#                         with open(LOG_FILE, "w") as log:
#                             log.write(log_message + "\n")
#
#             except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
#                 continue
#
#         time.sleep(2)
#
#
# def main():
#     Suspicious, detected_processes = detect_suspicious_processes()
#     hooked = key_hooked()
#
#     if Suspicious and hooked :
#         print("--> KEYLOGGER FOUND SUCCESSFULLY !!! 🚨")
#         monitor_network_activity(detected_processes)
#     else:
#         print("--> No keylogger detected . RELAX ")
#
#
# if __name__ == "__main__":
#     main()
#
# import sys