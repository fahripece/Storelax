# Storelax — Self-Hosted IT Inventory

A lightweight, self-hosted inventory management system for IT teams. No cloud required, no subscriptions, no nonsense. Runs on any machine with Python.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![Flask](https://img.shields.io/badge/Flask-2%2B-lightgrey) ![SQLite](https://img.shields.io/badge/Database-SQLite-green) ![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Features

- **Asset tracking** — Serialized items with check out / check in (name & job reference)
- **Quantity tracking** — Consumables with add / remove / set stock levels
- **Barcode scanner support** — USB HID scanners work out of the box (press F2)
- **Audit log** — Every action is permanently recorded and cannot be edited
- **Categories** — Color-coded, fully customizable
- **Shelf locations** — Numeric shelf assignments per item
- **Search & filter** — By name, serial, model, SKU, shelf, category, or status
- **No database server** — Uses SQLite, zero infrastructure needed
- **No authentication** — Designed for trusted internal networks

---

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/storelax.git
cd storelax

# 2. Install dependencies
pip install flask

# 3. Run
python app.py
```

Open **http://localhost:5000** in your browser.  
To access from other machines on the network: `http://<this-pc-ip>:5000`

---

## Customizing the Demo Data

On first run, the app creates two default users and five default product types. No categories or items are seeded — it starts completely empty so you can build your own inventory from scratch.  
To pre-load items before first run (optional):

1. Delete `inventory.db` (recreated automatically on next run)
2. Edit the `CATEGORIES` and `ITEMS` lists near the top of `app.py`
3. Restart — the new data seeds automatically

Or skip seeding entirely and add everything through the UI.

### Item format

```python
ITEMS = [
    # (name, model, serial, sku, category, shelf, qty)

    # Serialized asset — tracked individually, checked out/in:
    ("LAPTOP", "ThinkPad-X1", "SN123456", None, "Workstations", 2, None),

    # Consumable — tracked by quantity, not by serial:
    ("CAT6 PATCH 6FT", "CAT6-6", None, "C-001", "Consumables", 5, 50),
]
```

- `serial="..."` + `qty=None` → serialized asset (checkout / checkin)
- `serial=None` + `qty=integer` → consumable (quantity tracked)

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `F2` | Toggle barcode scanner bar |
| `/` | Focus search |
| `Esc` | Close modals / scanner |

---

## Scanner Modes

Press **F2** to open the scan bar. Three modes:

- **Look Up** — Find an item by serial, model, or SKU
- **Check Out** — Scan to check out; prompts for name and job reference
- **Check In** — Scan to return an item

Any USB HID barcode scanner (the default for most scanners) works without configuration.

---

## Project Structure

```
storelax/
├── app.py              # Flask app — all routes, DB logic, seed data
├── inventory.db        # SQLite database (auto-created, gitignored)
├── README.md
└── templates/
    ├── base.html       # Sidebar, nav, shared styles
    ├── inventory.html  # Main inventory view
    └── audit.html      # Audit log view
```

---

## Deploying on a Local Server

For a more permanent install (e.g. a Raspberry Pi or office PC):

```bash
pip install flask gunicorn
gunicorn -w 2 -b 0.0.0.0:5000 "app:app"
```

Use a systemd service or `screen` session to keep it running after logout.

---

## Security Notes

- This app has **no authentication**. It is intended for use on a trusted internal LAN.
- To expose it beyond your network, put it behind a reverse proxy (nginx / Caddy) with HTTP Basic Auth or your own login system.
- The audit log is append-only and cannot be modified through the UI.

---

## License

MIT — do whatever you want with it.
