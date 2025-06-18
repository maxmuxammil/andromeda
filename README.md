

   ___   _  _____  ___  ____  __  __________  ___ 
  / _ | / |/ / _ \/ _ \/ __ \/  |/  / __/ _ \/ _ |
 / __ |/    / // / , _/ /_/ / /|_/ / _// // / __ |
/_/ |_/_/|_/____/_/|_|\____/_/  /_/___/____/_/ |_|.py

Android APK Security Analyzer - Max Muxammil
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# APK Security Analyzer

A simple Python script that performs static analysis on Android APK files to identify potential security issues such as deeplinks, hardcoded secrets, URLs, Firebase references, and more.

---

## 🧠 Features

- Extracts and displays:
  - Secrets (e.g., Passwords, API keys, Tokens)
  - URLs
  - Firebase Instances
  - Base64-encoded strings
  - Deeplinks
- Dark/light HTML report generation

---

## 🚀 Getting Started

### 📦 Prerequisites

Make sure you have the following installed:

- Python 3.7+
- `pip` package manager

### 🔧 Installation

```bash
git clone https://github.com/maxmuxammil/andromeda.git
cd andromeda
pip3 install -r requirements.txt
