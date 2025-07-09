# Flask Base App - Setup Guide

This guide will walk you step by step through setting up the Flask Base App with login, user management, and role-based access.

---

## 📦 Prerequisites

- Python 3.11+ installed
- MySQL installed and running
- Git (optional but recommended)

---

## 🛠️ Step-by-Step Setup Instructions

### 1. Clone or Download the Repository

If using Git:
```bash
git clone https://github.com/yourusername/flask-base-app.git
cd flask-base-app
```

Or manually extract the ZIP folder into a directory.

---

### 2. Create a Virtual Environment and Activate It

```bash
python -m venv venv
venv\Scripts\activate     # Windows
# OR
source venv/bin/activate   # macOS/Linux
```

---

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Set Up MySQL Database

Create a new MySQL database using a tool like MySQL Workbench or CLI:

```sql
CREATE DATABASE my_base_app;
```

---

### 5. Configure Environment Variables

Create a `.env` file in the root directory:

```
DB_USER=root
DB_PASSWORD=yourpassword
DB_HOST=localhost
DB_NAME=my_base_app
SECRET_KEY=your-secret-key
```

Replace `yourpassword` and `your-secret-key` as needed.

---

### 6. Initialize the Database with Alembic

Set your Flask app environment variable:
```bash
$env:FLASK_APP="run.py"      # PowerShell (Windows)
# OR
export FLASK_APP=run.py      # macOS/Linux
```

Then run:
```bash
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

This will create the `users` table in your database.

---

### 7. Insert a Super Admin User

Use Python to generate a hashed password:
```python
from werkzeug.security import generate_password_hash
print(generate_password_hash("admin"))
```

Then use this SQL (replace the hash with yours):
```sql
INSERT INTO users (name, username, password, role, created_at)
VALUES ('Admin', 'admin', 'your_hashed_password_here', 'super_admin', NOW());
```

---

### 8. Run the App

```bash
python run.py
```

Visit `http://localhost:5000` in your browser and log in with:
```
Username: admin
Password: admin
```

---

## ✅ Features

- Login/logout
- Role-based dashboard
- Super admin user management (`/users`)
- AdminLTE-ready UI structure

---

## 🧪 Troubleshooting

- If `flask db` gives circular import error, ensure `db` is in `extensions.py`.
- If you get `No such command "db"`, make sure `FLASK_APP=run.py` is set correctly.

---

## 🧹 Optional

- Add AdminLTE assets to `app/static/adminlte/`
- Build your own modules using this as a foundation

---

Happy developing 🚀

