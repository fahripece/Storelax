# Storelax — Self-Hosted IT Inventory

A lightweight, self-hosted inventory management system for IT teams. No cloud required, no subscriptions, no nonsense. Runs on any machine with Python.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![Flask](https://img.shields.io/badge/Flask-2%2B-lightgrey) ![SQLite](https://img.shields.io/badge/Database-SQLite-green) ![License](https://img.shields.io/badge/License-MIT-yellow)

## 🚀 Features

* **Asset & Quantity Tracking:** Track serialized assets (Check Out/In) or consumables (Stock Levels).
* **Smart Hardware Specs:** Fields for CPU, RAM, and Storage auto-appear for "PC" or "Server" categories.
* **Dual-User Auth:** Built-in Admin (full control) and Worker (check-in/out only) roles.
* **Barcode Scanner Support:** USB HID scanners work out of the box (Press F2).
* **Financials & Tax:** Track Unit Cost vs. Sale Price with live profit margin calculations.
* **Low Stock Alerts:** Visual red-row alerts and a live navigation badge for reordering.
* **Audit Log:** Every action is permanently recorded with technician names.
* **No Infrastructure:** Uses SQLite (one file). Zero database server setup required.

---

## 📦 Quick Start

1. Setup and Run
   $ git clone https://github.com/yourusername/storelax.git
   $ cd storelax
   $ pip install flask openpyxl
   $ python app.py

2. Access Storelax
   Open your browser to http://localhost:5000
   * Default Admin: admin / admin123
   * Default Worker: worker / worker123

---

## ⌨️ Keyboard Shortcuts & Scanner

| Key | Action |
| :--- | :--- |
| F2 | Toggle Barcode Scanner bar / Focus search |
| Esc | Close modals or scanner bar |

**Scanner Modes:**
* Look Up: Find an item by serial, model, or SKU.
* Check Out: Scan to check out; prompts for name and job reference.
* Check In: Scan to return an item instantly.

---

## 📋 Item & Logic Schema

Storelax uses logic-based fields to keep the UI clean:
* Serialized Asset: Serial = Required + Qty = None.
* Consumable: Serial = None + Qty = Integer.
* Tax Mandate: Save button remains disabled until "Tax Paid" (Yes/No) is selected.
* Owner Validation: Triggers a confirmation pop-up if an Owner is assigned to a record.

---

## 🛠️ Deployment (Production)

For a permanent office install (e.g., Raspberry Pi or Windows Server):
$ pip install flask gunicorn
$ gunicorn -w 2 -b 0.0.0.0:5000 "app:app"

---

## ⚖️ License

**Personal & Internal Use Only.**

Storelax is free to use for personal projects, internal business operations, and non-commercial IT environments. 
* Prohibited: You may not commercialize this software, sell it as a service (SaaS), or include it in paid distributions without explicit permission from the author.

---
*Developed for IT Directors and Service Managers who value efficiency.*

---

## 📂 Configuration Files

### .gitignore
__pycache__/
*.py[cod]
inventory.db
.env
venv/
.DS_Store

### requirements.txt
Flask==3.0.0
openpyxl==3.1.2
