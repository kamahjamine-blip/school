# 🏫 BrightPath Academy — Full Stack School Management System

> Node.js 22 · SQLite (built-in) · M-Pesa Daraja · JWT Auth · Zero npm dependencies
> Private Primary School System — Nairobi, Kenya

---

## ⚡ Quick Start

```bash
# 1. Unzip
unzip brightpath_academy_fullstack.zip
cd brightpath

# 2. Check Node version (22+ required)
node --version      # must say v22.x.x or higher

# 3. Start — NO npm install needed
node start.js

# 4. Open in browser
#   http://localhost:3000          School Website
#   http://localhost:3000/admin    Admin CMS Portal
#   http://localhost:3000/portal   Parent Portal
```

---

## 🔑 Demo Login Credentials

| Role    | Email                                 | Password     |
|---------|---------------------------------------|--------------|
| Admin   | admin@brightpathacademy.co.ke         | Admin@2025   |
| Teacher | gachieng@brightpathacademy.co.ke      | Teacher@2025 |
| Parent  | wanjiru.kariuki@gmail.com             | Parent@2025  |
| Parent  | david.muthoni@gmail.com               | Parent@2025  |
| Parent  | asha.odhiambo@gmail.com               | Parent@2025  |

---

## 📁 Project Structure

```
brightpath/
├── server/
│   └── index.js         Complete backend — HTTP server, DB, all routes (~700 lines)
├── public/
│   ├── index.html        Public school website
│   ├── admin.html        Admin CMS dashboard
│   ├── portal.html       Parent portal (M-Pesa, results, attendance)
│   └── uploads/          File upload storage
├── test.js               28 automated tests — all passing
├── start.js              Production startup script
├── .env.example          All environment variables documented
└── package.json          npm scripts, zero dependencies
```

---

## 🌐 Full API Reference

### Authentication
```
POST  /api/auth/login              Login → JWT token
POST  /api/auth/register           Create user account
GET   /api/auth/me                 Get current user            [JWT]
PUT   /api/auth/change-password    Change password             [JWT]
```

### Students
```
GET   /api/students                List — admin sees all, parent sees own  [JWT]
POST  /api/students                Create new student                      [Admin/Teacher]
GET   /api/students/:id            Student detail                          [JWT]
PUT   /api/students/:id            Update student                          [Admin/Teacher]
GET   /api/students/:id/results    Exam results (filter by term/year)      [JWT]
POST  /api/students/:id/results    Record exam result                      [Admin/Teacher]
GET   /api/students/:id/attendance Attendance log + summary                [JWT]
POST  /api/students/:id/attendance Record attendance                       [Admin/Teacher]
```

### M-Pesa (Safaricom Daraja)
```
POST  /api/mpesa/initiate          Initiate STK Push                       [JWT]
POST  /api/mpesa/callback          Safaricom result callback               [Public]
GET   /api/mpesa/status/:id        Poll payment status                     [JWT]
GET   /api/mpesa/history           Parent payment history                  [JWT]
```

### Admissions
```
POST  /api/admissions              Submit application (public form)        [Public]
GET   /api/admissions              List all applications                   [Admin]
PUT   /api/admissions/:id          Update status / review                  [Admin]
```

### Content Management
```
GET   /api/news                    Published articles                      [Public]
POST  /api/news                    Create article                          [Admin]
PUT   /api/news/:id                Update article                          [Admin]
DELETE /api/news/:id               Delete article                          [Admin]
GET   /api/events                  Public events calendar                  [Public]
POST  /api/events                  Create event                            [Admin]
DELETE /api/events/:id             Delete event                            [Admin]
GET   /api/notices                 Notices (filtered by role)              [JWT]
POST  /api/notices                 Send notice to audience                 [Admin]
POST  /api/enquiries               Submit contact form                     [Public]
GET   /api/enquiries               View all enquiries                      [Admin]
PUT   /api/enquiries/:id/read      Mark as read                            [Admin]
GET   /api/fees                    Fee structure                           [Public]
POST  /api/fees                    Set fee entry                           [Admin]
GET   /api/users                   List users by role                      [Admin]
GET   /api/dashboard/stats         Full dashboard statistics               [Admin]
GET   /api/health                  Health check                            [Public]
```

---

## 💚 M-Pesa Integration Guide

### Payment Flow
```
1. Parent selects child & amount in portal
2. POST /api/mpesa/initiate → Safaricom sends PIN prompt to parent's phone
3. Parent enters M-Pesa PIN on their phone
4. Safaricom calls POST /api/mpesa/callback with result
5. Portal polls /api/mpesa/status/:id every 4s → shows live confirmation
```

### Sandbox Mode (Default — No Credentials Needed)
Payments auto-complete after 6 seconds. Perfect for demos and development.

### Going Live with Real M-Pesa
1. Register at [developer.safaricom.co.ke](https://developer.safaricom.co.ke)
2. Create a **Lipa Na M-Pesa Online** app → get credentials
3. Complete Safaricom's Go-Live process to get production keys
4. Set in `.env`:
```env
MPESA_CONSUMER_KEY=your_production_key
MPESA_CONSUMER_SECRET=your_production_secret
MPESA_PASSKEY=your_passkey
MPESA_SHORTCODE=your_paybill_or_till
MPESA_CALLBACK_URL=https://yourdomain.co.ke/api/mpesa/callback
MPESA_ENV=production
```
> The callback URL must be public HTTPS. Use [ngrok](https://ngrok.com) for local dev: `ngrok http 3000`

---

## 🗄️ Database Schema (SQLite, 11 Tables)

| Table | Purpose |
|-------|---------|
| `users` | Admins, teachers, parents with hashed passwords |
| `students` | Student registry linked to parent accounts |
| `fee_structure` | Per-grade, per-term fee breakdown (tuition/lunch/transport) |
| `payments` | M-Pesa and cash payments with receipt numbers |
| `admissions` | Online applications (pending→accepted/rejected/waitlisted) |
| `news` | CMS articles with draft/published/pinned state |
| `events` | School calendar events |
| `results` | Exam marks per student, subject, term, year |
| `attendance` | Daily register (present/absent/late/excused) |
| `notices` | Broadcast announcements by audience |
| `enquiries` | Contact form submissions |

---

## 🔒 Security

| Feature | Implementation |
|---------|---------------|
| Passwords | `crypto.scryptSync` — 64-byte key, 16-byte random salt |
| Tokens | HMAC-SHA256 JWT, 7-day expiry, `node:crypto` only |
| Role guards | admin / teacher / parent enforced per route |
| Rate limiting | 200 req/min per IP, in-memory |
| SQL injection | Parameterised queries throughout |
| Zero deps | No supply chain risk — only Node.js built-ins |

---

## 🚀 Deployment

### Option A — Railway (Recommended)
```
Connect GitHub → New Project → Deploy
Start Command: node start.js
Node Version:  22
Set env vars in Railway dashboard
```

### Option B — Render / Fly.io
```
Build: (none)
Start: node start.js
Node:  22
```

### Option C — VPS (Ubuntu + PM2)
```bash
npm i -g pm2
pm2 start start.js --name brightpath --node-args="--experimental-sqlite"
pm2 startup && pm2 save
# Add Nginx → proxy_pass http://127.0.0.1:3000
```

### Option D — cPanel Shared Hosting
- Upload via FTP
- cPanel Node.js App Manager → Startup file: `start.js`, Node version: 22

---

## 🧪 Tests

```bash
node --experimental-sqlite test.js
```
28 tests covering:
- Crypto: password hashing, JWT sign/verify, tamper detection, expiry
- Database: CRUD, foreign keys, unique constraints, aggregations
- Route Logic: slugify, grade letters, phone formatter, admission numbers, rate limiter
- M-Pesa: payload validation, checkout ID uniqueness, callback parsing
- Security: role guards, expired tokens, empty token rejection

---

## 📱 Feature Summary

### 🌐 Public Website
- School information, CBC programmes, facilities
- Online admissions application form
- Contact / enquiry form
- News articles & events calendar
- Fee structure display
- Fully responsive

### 🔧 Admin CMS Portal (`/admin`)
- Dashboard: students, revenue (today/month/total), pending admissions, unread enquiries
- Student registry with search and add
- Teacher account management
- Enter exam results by subject, term, exam type
- Payment history with M-Pesa receipts
- Fee structure management per grade/term
- Review admissions: accept / reject / waitlist
- Publish/draft news articles, manage events
- Send notices to all / parents / teachers
- View and mark contact enquiries

### 👨‍👩‍👧 Parent Portal (`/portal`)
- Children overview with enrolment info
- Exam results with grade letters (A–E) and term averages
- Attendance log with present/absent/late summary and rate %
- M-Pesa STK Push with live fee breakdown per grade
- Real-time payment status polling
- Full payment history with M-Pesa receipt numbers
- School notices filtered by audience

---

## 🔮 Future Features to Add

```
□ SMS via Africa's Talking API
□ Email via Nodemailer + Gmail App Password
□ WhatsApp Business API notifications
□ PDF report cards and fee statements (pdfkit)
□ Bulk attendance marking by class/stream
□ Teacher lesson planner
□ NEMIS integration (Kenya national education data)
□ Bank transfer (Equity/KCB) integration
□ React Native mobile app for parents
□ Multi-branch / franchise mode
```

---

*BrightPath Academy · Westlands Road, Nairobi · KNEC Reg. KNY/2005/0234*
*Node.js 22 · SQLite · Zero Dependencies · M-Pesa Daraja API*
