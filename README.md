## DOWNLOAD THE TOOL 
https://github.com/mysteriork/D-loGGER/releases/download/v1.0.0/setup_dlogger.exe

# 🛡️ D-LoGGer – Keylogger & spyware Detection System

**D-LoGGer** is a Python-based desktop application that simulates and detects stealth Keyloggers and Spywares . Designed with a user-friendly GUI using PySide6, this project aims to bridge the gap between technical malware behavior and practical end-user protection.

---

## 🧩 Project Structure

- **Detection Module**: Behavior-based scanner to detect suspicious processes using keyboard hooks, sensitive API access, and outbound traffic analysis with live process termination.

---

## 🔐 Features

### Defensive Component (D-LoGGer Detection System)
- Real-time monitoring of running processes
- Detection of keyboard hooks and suspicious modules
- Network traffic analysis for unauthorized outbound connections
- Displays server IPs, ports, and transferred data
- One-click termination of flagged processes
- Modern PySide6-based GUI

---

## 🛠️ Technologies Used

- **Language:** Python
- **GUI Framework:** PySide6
- **Key Libraries:**  
  - Detection: `psutil`, `ctypes`, `win32api`, `socket`, `requests`  
  - Keylogger: `pynput`, `mss`, `pygetwindow`, `base64`
- **Packaging:** PyInstaller (for `.exe` generation)
- **OS Support:** Windows only

---

## 🧪 Testing and Results

- Tested across multiple scenarios: local keylogger, packed executables, offline loggers, RATs, and whitelisted tools
- Achieved **100% detection rate** in 9 malicious scenarios
- **0% false positives** across all legitimate test cases
- Real-time process and network behavior monitoring validated against real-world threat patterns

---

## 🚀 How to Run

1. Clone the repository:
   ```bash
   https://github.com/mysteriork/D-loGGER/new/main

## SNAPSHOTS :
1) UI .
   
![Screenshot 2025-04-14 170202](https://github.com/user-attachments/assets/8c1c1dcd-4b29-4d5c-a897-dca912241864)

2) SCANNING PHASE .
   ![Screenshot 2025-04-14 170215](https://github.com/user-attachments/assets/cac1cbea-7150-47e7-80ed-465e464c7ba6)

3) MALWARE MESSAGE .
![Screenshot 2025-04-14 213131](https://github.com/user-attachments/assets/72a853cc-9e8b-4a49-81d7-8acf91880fcc)

4) MALWARE DETAILS .
![Screenshot 2025-04-14 213151](https://github.com/user-attachments/assets/cdb46b7b-9c69-45fb-bfd7-46c8d6dc70b9)

📄 License

This project is licensed under the MIT License. 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change. 📧 callmerachit145@gmail.com

Created by @mysteriork -- RACHIT KUMAR

For inquiries, open an issue or drop a message via GitHub.
