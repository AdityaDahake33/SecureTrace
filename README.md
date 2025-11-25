# SecureTrace – Automated Network Intrusion Detection & Response

## 📌 Overview
SecureTrace is an automated Intrusion Detection & Response system built using **Snort**, **Python**, **n8n workflow automation**, and a **React-based Admin Panel**. It continuously monitors network traffic, detects malicious behavior, triggers automated workflows, blocks attacker IPs, and notifies administrators instantly.

This project aims to provide a lightweight, open-source, and fully automated security pipeline suitable for small businesses, home labs, and academic environments.

---

## 🚀 Features
- **Real-time traffic monitoring using Snort (Ubuntu)**
- **Automated attack detection via Python log parser**
- **Instant workflow execution in n8n**
- **Automatic IP blocking (e.g., UFW/Firewall rules)**
- **Admin alerting via a custom dashboard**
- **Fully local setup (no external APIs required)**

---

## 🏗️ System Architecture
1. **Snort** monitors the network and generates alerts.
2. A **Python script** reads Snort logs and forwards suspicious events to n8n via webhook.
3. **n8n workflow** processes alerts, stores logs, blocks the attacker IP, and forwards the alert.
4. **Admin Panel (React Website)** displays all alerts in real time.

---

## 🛠️ Installation & Setup Guide
Follow these steps to set up the entire SecureTrace system.

---

## 1️⃣ Install Ubuntu
Download and install Ubuntu (recommended: Ubuntu 20.04 or 22.04).

---

## 2️⃣ Install Snort on Ubuntu
Follow the Snort installation guide provided here:
👉 **https://adityadahake33.github.io/code-alpha-Task4/**

This guide includes:
- Installing dependencies
- Setting up Snort
- Testing Snort rules

---

## 3️⃣ Clone & Run the Python Log Forwarder
This script reads Snort logs and sends alerts to n8n.

### Clone the Repository
```bash
git clone https://github.com/AdityaDahake33/SecureTrace
cd SecureTrace
```

### Run the Script
```bash
python3 snort_forwarder.py
```

This script will automatically forward alerts to:
```
http://localhost:5678/webhook/securetrace
```

Make sure n8n is running.

---

## 4️⃣ Install n8n (one‑line install command)
Run this command:
```bash
npx n8n
```
This will start n8n on:
```
http://localhost:5678/
```

---

## 5️⃣ Import the n8n Workflow
Your GitHub includes the workflow JSON. Import it into your n8n editor.

Workflow actions include:
- Receiving alerts from Python
- Saving them into a database or JSON
- Blocking attacker IP
- Sending alerts to the frontend

---

## 6️⃣ Install & Configure the Admin Dashboard
You may use your custom React dashboard or any frontend.

Current working dashboard:
👉 **https://react-project-office-task-pud3.vercel.app/**

This dashboard receives alerts directly from n8n.

If using your GitHub frontend:
```bash
git clone <your-frontend-url>
npm install
npm start
```

Then configure your API endpoint to match n8n output.

---

## 🧪 How to Use SecureTrace
1. Make sure Snort is running.
2. Ensure Python forwarder is active.
3. Start n8n.
4. Trigger some attacks or normal traffic.
5. Watch for real‑time alerts in the dashboard.

---

## 📌 Example Alert Flow
- Snort detects **SQL Injection attempt**.
- Python script sends alert JSON to n8n.
- n8n:
  - Blocks attacker IP
  - Stores alert
  - Sends alert to Admin Panel
- Admin sees notification instantly.

---

## 📈 Future Scope
- Add ML-based anomaly detection
- Add real‑time graphs and analytics
- Integrate with SIEM tools
- Extend support for Suricata
- Cloud-based deployment options

---

## 🎯 Conclusion
SecureTrace provides a powerful yet lightweight automated intrusion detection pipeline using open-source tools. It eliminates manual monitoring, accelerates incident response, and ensures administrators stay informed in real time.

A simple, powerful, and scalable security workflow for modern networks.

---

## 👨‍💻 Developer
**Aditya Dahake**
GitHub: https://github.com/AdityaDahake33

