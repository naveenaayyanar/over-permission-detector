# 🛡️ PermGuard AI — Over-Permission Detection System

**Guided by:** Dr. R. Saranya  
**Presented by:** Mohamed Nazeer Afsal M (23BDC034)

---

## 📁 Project Structure

```
over-permission-detector/
├── index.html              # Landing page + Login/Register
├── css/
│   └── main.css            # Complete stylesheet
├── js/
│   ├── auth.js             # Authentication logic
│   ├── app.js              # Landing page animations
│   └── dashboard.js        # Core AI analysis engine
└── pages/
    └── dashboard.html      # Main app dashboard
```

---

## 🚀 How to Run

1. **Extract** the ZIP file to a folder
2. **Open** `index.html` in any modern web browser (Chrome, Firefox, Edge)
3. **Login** using demo credentials below

> ⚠️ No server or installation required — runs entirely in the browser!

---

## 🔑 Demo Credentials

| Role  | Email             | Password   |
|-------|-------------------|------------|
| User  | user@demo.com     | demo123    |
| Admin | admin@demo.com    | admin123   |

Or click **"Demo User"** / **"Demo Admin"** buttons on the login page.

---

## 🧩 System Modules

1. **User Authentication** — Secure login & register, role-based access
2. **APK Upload** — Drag & drop APK upload with format validation
3. **Permission Extraction** — Identifies & classifies all permissions (Normal/Dangerous/Special)
4. **AI Analysis Engine** — Detects unnecessary permissions & suspicious combinations
5. **Risk Assessment** — Scores apps 0–100, classifies as Safe/Medium/High Risk
6. **Reports & Visualization** — Charts, dashboards, PDF/HTML/JSON download

---

## 🛠️ Technologies

- **Frontend:** HTML5, CSS3, JavaScript (ES6+)
- **Charts:** Canvas API (custom pie charts)
- **PDF Export:** jsPDF (CDN)
- **Storage:** localStorage (simulating Supabase)
- **Fonts:** Google Fonts (Syne, Space Mono, Inter)

---

## 📊 AI Detection Logic

The AI engine:
- Matches uploaded APK permissions against a **permission database** of 25+ Android permissions
- Compares permissions to **expected permissions** for the app's category
- Detects **6 suspicious combinations** (e.g., Camera+Microphone, Read+Send SMS)
- Computes a **risk score** based on: high-risk permissions, medium-risk permissions, special permissions, and suspicious combos

---

*PermGuard AI — Protecting user privacy through intelligent permission analysis*
