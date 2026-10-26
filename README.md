# 🛡️ SentinelCLI

> **Scan it before you click it.**

An interactive command-line security tool that lets users check suspicious links and passwords, while giving the security team a mini to analyze reports, manage investigations, and detect phishing campaigns.

---

## 📖 Overview

Every day, people receive suspicious links by email and SMS. Most of them don't know if a link is safe, and the security team doesn't know that five different users received links from **the same attacker**.

**SentinelCLI** solves both problems:

- **Users** scan links and passwords and get a clear result with advice.
- **Every scan is saved as a report** for the security team.
- **The admin** analyzes the reports, manages cases, and gets **automatic alerts** when different reports come from the same source.

All checks use **real, live data** from public security APIs.

---

## ✨ Features

### 👤 For Users
- 🔑 **Password Leak Check:** checks if a password appeared in known data breaches, **without ever sending the password** (k-Anonymity).
- 🔍 **URL Investigation:** combines a reputation check (URLhaus malware database) with a live website inspection (SSL certificate, DNS records, uptime) into one **risk score**.
- 🛡️ **Safety first:** if a link is already known as malicious, the program **does not contact it**.
- 📜 **My Scans:** a history of the user's own scans.

### 🔐 For the Admin
- 📥 **All Reports:** every user's reports, with filters (high risk, by user, by type) and full details.
- 📁 **Cases:** create, list, search, edit (title, status, notes, linked reports) and delete investigations.
- 🔗 **Threat Correlation:** automatically detects **campaigns**: reports from different users that share the same IP address, the same URL, similar domain names, or the same threat tag.
- 📊 **Dashboard:** statistics, charts, top reporters, top threat tags and leaked-password rate.
- 📄 **Export:** saves a case report or a full security summary as a text file.

---

## 📋 User Stories

**As a user, I should be able to:**
- Check if my password has been leaked, without sending it over the internet.
- Investigate a suspicious URL and get a clear risk score with advice.
- Be protected from contacting links that are already known as malicious.
- See the history of my own scans.

**As an admin, I should be able to:**
- Log in securely with a hashed password, with a limit on failed attempts.
- View all users' reports, filter them, and open the details of any report.
- Create, list, search, edit and delete cases.
- Link reports to a case, add notes, and change its status (open / investigating / closed).
- Get alerted when different reports come from the same source, and turn the alert into a case.
- View a dashboard with statistics about all reports.
- Export a case report or a full summary as a file.

---

## ⚙️ Installation

**1. Clone the repository**
```bash
git clone https://github.com/JZL9/UNIT-PROJECT-1.git
cd UNIT-PROJECT-1
```

**2. Create and activate a virtual environment**
```bash
python -m venv venv
venv\Scripts\activate          # Windows (PowerShell)
source venv/Scripts/activate   # Windows (Git Bash)
source venv/bin/activate       # macOS / Linux
```

**3. Install the requirements**
```bash
pip install -r requirements.txt
```

**4. Add your free URLhaus API key**
- Get a free key from [auth.abuse.ch](https://auth.abuse.ch/).
- Copy `.env.example` to a new file called `.env` and put your key inside:
```
URLHAUS_AUTH_KEY=your_key_here
```

**5. Run the program**
```bash
python main.py
```

> The first time you choose **Admin**, the program asks you to create the admin account.

---

## 🖥️ Usage

When the program starts, choose who you are:

```
═════ WHO ARE YOU? ═════
[1] 👤 User   — scan links & passwords
[2] 🔐 Admin  — analyze reports & cases
[0] Exit
```

### 👤 User menu
| Option | What it does |
|---|---|
| `1` Check Password Leak | Type a password (hidden with `*`) to see if it was leaked |
| `2` Investigate URL | Type a link like `example.com` to get a full investigation and risk score. Type `back` to return |
| `3` My Scans | Show a table of all your scans |
| `0` Back | Return to the first screen |

### 🔐 Admin menu
| Option | What it does |
|---|---|
| `1` All Reports | Filter reports, then type a report ID to see its details |
| `2` Cases | New / List / Search / Edit / Delete cases |
| `3` Correlation Alerts | See detected campaigns and turn one into a case |
| `4` Dashboard | Statistics and charts about all reports |
| `5` Export Report | Save a case report or a full summary to the `reports/` folder |
| `0` Logout | Return to the first screen |

> 💡 Every menu checks your input: wrong choices, empty text or invalid links are rejected with a clear message, and you can try again.

---

## 🧠 How the Risk Score Works

The APIs give **facts**; SentinelCLI turns them into a score with clear rules:

| Red flag | Points |
|---|---|
| Invalid / expired / fake SSL certificate | +40 |
| Raw IP address inst