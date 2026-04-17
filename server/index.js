/**
 * Mowlem Creek Premier School — Full Stack Server
 * Zero npm dependencies — uses only Node.js 22 built-ins:
 *   node:http · node:sqlite · node:crypto · node:fs · node:path · node:url
 * Run: node server/index.js
 */
'use strict';

const http   = require('node:http');
const fs     = require('node:fs');
const path   = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

// ── CONFIG ────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'brightpath-super-secret-jwt-2025-change-in-production';
const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const DB_PATH    = process.env.DB_PATH || path.join(__dirname, '..', 'brightpath.db');

['students','admissions','news'].forEach(d =>
  fs.mkdirSync(path.join(PUBLIC_DIR, 'uploads', d), { recursive: true })
);

// ── DATABASE ──────────────────────────────────────────────────────────────
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','teacher','parent')),
    full_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
    phone TEXT, password TEXT NOT NULL, is_active INTEGER DEFAULT 1,
    last_login TEXT, created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT UNIQUE NOT NULL,
    admission_no TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL,
    dob TEXT, gender TEXT, grade TEXT NOT NULL, stream TEXT DEFAULT 'A',
    parent_id INTEGER REFERENCES users(id), photo TEXT, address TEXT,
    medical_notes TEXT, is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS fee_structure (
    id INTEGER PRIMARY KEY AUTOINCREMENT, grade TEXT NOT NULL,
    term INTEGER NOT NULL, year INTEGER NOT NULL,
    tuition REAL NOT NULL, activity REAL DEFAULT 0,
    lunch REAL DEFAULT 0, transport REAL DEFAULT 0, total REAL NOT NULL,
    UNIQUE(grade,term,year)
  );
  CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT UNIQUE NOT NULL,
    student_id INTEGER REFERENCES students(id),
    parent_id INTEGER REFERENCES users(id),
    amount REAL NOT NULL, method TEXT DEFAULT 'mpesa',
    status TEXT DEFAULT 'pending', mpesa_receipt TEXT, mpesa_phone TEXT,
    checkout_request TEXT, description TEXT, term INTEGER, year INTEGER,
    paid_at TEXT, created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS admissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT UNIQUE NOT NULL,
    child_name TEXT NOT NULL, dob TEXT, gender TEXT,
    grade_applying TEXT NOT NULL, parent_name TEXT NOT NULL,
    parent_email TEXT NOT NULL, parent_phone TEXT NOT NULL,
    address TEXT, prev_school TEXT, message TEXT,
    status TEXT DEFAULT 'pending', notes TEXT,
    reviewed_by INTEGER, reviewed_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS news (
    id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL, slug TEXT UNIQUE NOT NULL,
    content TEXT NOT NULL, excerpt TEXT, category TEXT DEFAULT 'general',
    is_pinned INTEGER DEFAULT 0, is_published INTEGER DEFAULT 0,
    author_id INTEGER REFERENCES users(id), published_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL, description TEXT,
    location TEXT DEFAULT 'School Grounds', start_date TEXT NOT NULL,
    end_date TEXT, is_public INTEGER DEFAULT 1,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER REFERENCES students(id),
    subject TEXT NOT NULL, score REAL NOT NULL,
    max_score REAL DEFAULT 100, grade_letter TEXT,
    term INTEGER NOT NULL, year INTEGER NOT NULL,
    exam_type TEXT DEFAULT 'end-term',
    teacher_id INTEGER REFERENCES users(id),
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(student_id,subject,term,year,exam_type)
  );
  CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER REFERENCES students(id),
    date TEXT NOT NULL, status TEXT, note TEXT,
    recorded_by INTEGER REFERENCES users(id),
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(student_id,date)
  );
  CREATE TABLE IF NOT EXISTS notices (
    id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL, body TEXT NOT NULL,
    audience TEXT DEFAULT 'all', is_active INTEGER DEFAULT 1,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS enquiries (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
    email TEXT NOT NULL, phone TEXT, subject TEXT,
    message TEXT NOT NULL, is_read INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// ── CRYPTO ────────────────────────────────────────────────────────────────
const uid = () => crypto.randomUUID();

function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function checkPw(pw, stored) {
  const [salt, hash] = stored.split(':');
  return crypto.scryptSync(pw, salt, 64).toString('hex') === hash;
}
function signJWT(payload) {
  const h = Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
  const b = Buffer.from(JSON.stringify({...payload,iat:Date.now(),exp:Date.now()+SESSION_MS})).toString('base64url');
  const s = crypto.createHmac('sha256',JWT_SECRET).update(h+'.'+b).digest('base64url');
  return `${h}.${b}.${s}`;
}
function verifyJWT(token) {
  const [h,b,s] = token.split('.');
  const exp = crypto.createHmac('sha256',JWT_SECRET).update(h+'.'+b).digest('base64url');
  if (exp!==s) throw new Error('Invalid');
  const p = JSON.parse(Buffer.from(b,'base64url').toString());
  if (p.exp<Date.now()) throw new Error('Expired');
  return p;
}
const slugify = t => t.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/(^-|-$)/g,'')+'-'+Date.now();
const gradeLetter = pct => pct>=80?'A':pct>=70?'B':pct>=60?'C':pct>=50?'D':'E';

// ── HTTP HELPERS ──────────────────────────────────────────────────────────
function readBody(req) {
  return new Promise((res,rej) => {
    let d='';
    req.on('data',c=>d+=c);
    req.on('end',()=>{
      try { res((req.headers['content-type']||'').includes('json')?JSON.parse(d||'{}'):Object.fromEntries(new URLSearchParams(d))); }
      catch { res({}); }
    });
    req.on('error',rej);
  });
}
const CORS = {'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type,Authorization','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS'};
function send(res,data,code=200) {
  const body=JSON.stringify(data);
  res.writeHead(code,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),...CORS});
  res.end(body);
}
function auth(req) {
  const tok=(req.headers.authorization||'').replace('Bearer ','');
  if(!tok) return null;
  try { const p=verifyJWT(tok); return db.prepare('SELECT * FROM users WHERE id=? AND is_active=1').get(p.id); }
  catch { return null; }
}
function qs(req) {
  return new URL(req.url,'http://x').searchParams;
}
function safeUser(u) { const {password,...rest}=u; return rest; }

// ── MIME ──────────────────────────────────────────────────────────────────
const MIME={'.html':'text/html','.css':'text/css','.js':'application/javascript','.json':'application/json','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.gif':'image/gif','.svg':'image/svg+xml','.ico':'image/x-icon','.woff2':'font/woff2','.pdf':'application/pdf'};

function serveFile(res,fp) {
  if(!fs.existsSync(fp)||!fs.statSync(fp).isFile()) { send(res,{error:'Not found'},404); return; }
  const ext=path.extname(fp).toLowerCase();
  res.writeHead(200,{'Content-Type':MIME[ext]||'application/octet-stream'});
  fs.createReadStream(fp).pipe(res);
}

// ── RATE LIMIT ────────────────────────────────────────────────────────────
const rlMap=new Map();
function rl(ip,max=200,win=60000) {
  const now=Date.now(), r=rlMap.get(ip)||{n:0,t:now+win};
  if(now>r.t){r.n=0;r.t=now+win;}
  r.n++; rlMap.set(ip,r); return r.n<=max;
}

// ── SEED ──────────────────────────────────────────────────────────────────
function seed() {
  if(db.prepare('SELECT COUNT(*) as c FROM users').get().c>0) return;
  console.log('🌱 Seeding database with demo data...');
  const ins=db.prepare('INSERT OR IGNORE INTO users (uuid,role,full_name,email,phone,password) VALUES (?,?,?,?,?,?)');
  [
    ['admin','Admin User','admin@mowlemcreekpremier.sc.ke','+254720111001','Admin@2025'],
    ['teacher','Teacher User','teacher@mowlemcreekpremier.sc.ke','+254720222001','Teacher@2025'],
    ['parent','Mrs. Wanjiru Kariuki','wanjiru.kariuki@gmail.com','+254722333001','Parent@2025'],
    ['parent','Mr. David Muthoni','david.muthoni@gmail.com','+254722333002','Parent@2025'],
    ['parent','Mrs. Asha Odhiambo','asha.odhiambo@gmail.com','+254722333003','Parent@2025'],
  ].forEach(([role,name,email,phone,pw])=>ins.run(uid(),role,name,email,phone,hashPw(pw)));

  const adm=db.prepare("SELECT id FROM users WHERE role='admin'").get();
  const p1=db.prepare("SELECT id FROM users WHERE email='wanjiru.kariuki@gmail.com'").get();
  const p2=db.prepare("SELECT id FROM users WHERE email='david.muthoni@gmail.com'").get();
  const p3=db.prepare("SELECT id FROM users WHERE email='asha.odhiambo@gmail.com'").get();
  const tc=db.prepare("SELECT id FROM users WHERE role='teacher'").get();

  const si=db.prepare('INSERT OR IGNORE INTO students (uuid,admission_no,full_name,dob,gender,grade,parent_id) VALUES (?,?,?,?,?,?,?)');
  [
    ['Amara Kariuki','2015-03-12','Female','Grade 4',p1.id],
    ['Kevin Kariuki','2017-07-22','Male','Grade 2',p1.id],
    ['Zara Muthoni','2014-11-05','Female','Grade 5',p2.id],
    ['Ethan Muthoni','2014-11-07','Male','Grade 5',p2.id],
    ['Brian Odhiambo','2016-02-14','Male','Grade 3',p3.id],
  ].forEach(([n,d,g,gr,pid],i)=>si.run(uid(),`MCP/25/${String(i+1).padStart(4,'0')}`,n,d,g,gr,pid));

  const fi=db.prepare('INSERT OR IGNORE INTO fee_structure (grade,term,year,tuition,activity,lunch,transport,total) VALUES (?,?,?,?,?,?,?,?)');
  const baseF={'Pre-Primary 1':28000,'Pre-Primary 2':28000,'Grade 1':32000,'Grade 2':32000,'Grade 3':32000,'Grade 4':35000,'Grade 5':35000,'Grade 6':38000};
  Object.entries(baseF).forEach(([g,t])=>[1,2,3].forEach(term=>fi.run(g,term,2025,t,3500,5000,4000,t+12500)));

  const stud=db.prepare('SELECT id FROM students').all();
  const subs=['Mathematics','English','Kiswahili','Integrated Science','Social Studies','Creative Arts','ICT'];
  const ri=db.prepare('INSERT OR IGNORE INTO results (student_id,subject,score,max_score,grade_letter,term,year,exam_type,teacher_id) VALUES (?,?,?,?,?,?,?,?,?)');
  stud.forEach(s=>subs.forEach(sub=>{ const sc=60+Math.floor(Math.random()*38); ri.run(s.id,sub,sc,100,gradeLetter(sc),1,2025,'end-term',tc.id); }));

  const ai=db.prepare('INSERT OR IGNORE INTO attendance (student_id,date,status,recorded_by) VALUES (?,?,?,?)');
  const today=new Date(), dates=[];
  for(let i=25;i>=1;i--){const d=new Date(today);d.setDate(d.getDate()-i);if(d.getDay()>0&&d.getDay()<6)dates.push(d.toISOString().slice(0,10));}
  stud.forEach(s=>dates.forEach(dt=>ai.run(s.id,dt,Math.random()>0.08?'present':'absent',tc.id)));

  const pi=db.prepare('INSERT OR IGNORE INTO payments (uuid,student_id,parent_id,amount,method,status,mpesa_receipt,description,term,year,paid_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)');
  const studs2=db.prepare('SELECT s.id,s.full_name,s.parent_id FROM students s').all();
  ['QGH2K3M0NP','RKL9T4P1QW','MNB5S7R2VX','PLQ3K8N4YZ','TYU6H2M9WQ'].forEach((rcpt,i)=>{
    if(studs2[i]) pi.run(uid(),studs2[i].id,studs2[i].parent_id,44500,'mpesa','completed',rcpt,`Term 1 Fees - ${studs2[i].full_name}`,1,2025,new Date().toISOString());
  });

  const ni=db.prepare('INSERT OR IGNORE INTO news (uuid,title,slug,content,excerpt,category,is_pinned,is_published,author_id,published_at) VALUES (?,?,?,?,?,?,?,?,?,?)');
  [
    ['2024 KCPE Results: BrightPath Shines Again','academic',1,'Mowlem Creek Premier School achieved a mean score of 387/500 in the 2024 KCPE examinations, placing us in the top 10 schools in Nairobi County. Seven students qualified for national secondary schools, with our top pupil scoring 426/500.','Mean score 387/500 — top 10 in Nairobi County.'],
    ['Admissions Open for 2025/2026 Academic Year','admissions',1,'Admissions for the 2025/2026 academic year are now open. Limited places are available across all grades from Pre-Primary 1 to Grade 6. Apply early to secure your child\'s place.','Apply now — limited places for all grades.'],
    ['BrightPath Wins Gold at Nairobi Drama Festival','co-curricular',0,'Our drama club delivered an outstanding performance at the 2024 Nairobi Drama Festival, winning the coveted Gold Award. Congratulations to all pupils and their dedicated teacher Ms. Faith Njeri.','Drama club wins Gold at Nairobi Drama Festival 2024.'],
    ['CBC Implementation: What Parents Need to Know','academic',0,'As we continue implementing the Competency Based Curriculum, we are committed to keeping parents informed. This term we focus on literacy and numeracy outcomes in Grades 1–3 per the KICD framework.','Key updates on CBC curriculum implementation this term.'],
    ['Annual Sports Day — Saturday 15th March 2025','events',0,'Join us for our Annual Sports Day on Saturday, 15th March 2025 starting at 8:00 AM. All parents and guardians are warmly invited. Traditional Kenyan foods will be available at the school canteen.','Sports Day on 15 March 2025 — all parents welcome!'],
  ].forEach(([title,cat,pin,content,excerpt])=>ni.run(uid(),title,slugify(title),content,excerpt,cat,pin,1,adm.id,new Date().toISOString()));

  const ei=db.prepare('INSERT OR IGNORE INTO events (uuid,title,description,location,start_date,is_public,created_by) VALUES (?,?,?,?,?,?,?)');
  [
    ['Term 2 Opening Day','School reopens. Pupils report by 7:30 AM in full school uniform.','2025-05-05'],
    ['Parent-Teacher Conference','Scheduled meetings with class teachers to review pupil progress reports.','2025-05-23'],
    ['Open Day — Term 2','Campus open to prospective families. Tours available 9am–12pm.','2025-05-10'],
    ['Mid-Term Break','School closed for mid-term. Resumes Monday 9th June.','2025-05-30'],
    ['Interhouse Athletics Day','Annual competition between the four school houses. All parents welcome.','2025-06-14'],
  ].forEach(([t,d,sd])=>ei.run(uid(),t,d,'Mowlem Creek Premier School, Westlands',sd,1,adm.id));

  const noi=db.prepare('INSERT OR IGNORE INTO notices (uuid,title,body,audience,created_by) VALUES (?,?,?,?,?)');
  noi.run(uid(),'Term 2 Fee Deadline — 16th May','All Term 2 fees must be settled by 16th May 2025. A late penalty of KES 1,000 applies thereafter. Contact the bursar for approved payment plans.','parents',adm.id);
  noi.run(uid(),'School Uniform Policy Reminder','All pupils must wear full school uniform including black leather shoes. Sports kit is only permitted on designated PE days and sports events.','all',adm.id);
  noi.run(uid(),'Staff Development Day — No School 2nd May','There will be NO school on Friday 2nd May 2025. Staff Development Day. School resumes Monday 5th May. Thank you for your understanding.','all',adm.id);

  const adi=db.prepare('INSERT OR IGNORE INTO admissions (uuid,child_name,dob,gender,grade_applying,parent_name,parent_email,parent_phone,message,status) VALUES (?,?,?,?,?,?,?,?,?,?)');
  adi.run(uid(),'Lila Njoroge','2018-04-10','Female','Grade 1','Mrs. Anne Njoroge','anne.njoroge@gmail.com','+254723100001','Our daughter is very bright and loves reading. We look forward to joining BrightPath.','pending');
  adi.run(uid(),'Malik Omondi','2019-01-22','Male','Pre-Primary 2','Mr. Tom Omondi','tom.omondi@gmail.com','+254723100002',null,'reviewing');
  adi.run(uid(),'Neema Wambua','2016-07-15','Female','Grade 3','Mrs. Lucy Wambua','lucy.wambua@gmail.com','+254723100003','Transferring from another school in Nairobi. Has strong literacy skills.','accepted');

  db.prepare('INSERT OR IGNORE INTO enquiries (name,email,phone,subject,message) VALUES (?,?,?,?,?)').run('Peter Njoroge','pnjoroge@gmail.com','+254711222333','Fee Structure Enquiry','Could you send me the complete fee structure for Grade 4 for the 2025/2026 academic year? Thank you.');

  console.log('✅ Seeding complete!\n');
  console.log('  Admin:   admin@mowlemcreekpremier.sc.ke  /  Admin@2025');
  console.log('  Teacher: teacher@mowlemcreekpremier.sc.ke  /  Teacher@2025');
  console.log('  Parent:  wanjiru.kariuki@gmail.com  /  Parent@2025\n');
}

// ── ROUTER ────────────────────────────────────────────────────────────────
async function handle(req, res) {
  const ip  = req.socket.remoteAddress||'';
  const url = new URL(req.url, 'http://localhost');
  const pt  = url.pathname;
  const qp  = url.searchParams;
  const m   = req.method;

  if(m==='OPTIONS'){res.writeHead(204,CORS);res.end();return;}

  // ─ Static ─
  if(!pt.startsWith('/api/')) {
    if(pt.startsWith('/admin'))  return serveFile(res,path.join(PUBLIC_DIR,'admin.html'));
    if(pt.startsWith('/portal')) return serveFile(res,path.join(PUBLIC_DIR,'portal.html'));
    const fp = path.join(PUBLIC_DIR, pt==='/'?'index.html':pt);
    if(fs.existsSync(fp)&&fs.statSync(fp).isFile()) return serveFile(res,fp);
    return serveFile(res,path.join(PUBLIC_DIR,'index.html'));
  }

  if(!rl(ip)){return send(res,{success:false,message:'Too many requests'},429);}

  let body={};
  if(['POST','PUT','PATCH'].includes(m)) body=await readBody(req);

  // ── HEALTH ────────────────────────────────────────────────────────────
  if(pt==='/api/health'&&m==='GET') return send(res,{status:'ok',school:'Mowlem Creek Premier School',node:process.version,db:DB_PATH});

  // ── AUTH ──────────────────────────────────────────────────────────────
  if(pt==='/api/auth/login'&&m==='POST'){
    const{email,password}=body;
    if(!email||!password) return send(res,{success:false,message:'Email and password required.'},400);
    const u=db.prepare('SELECT * FROM users WHERE email=? AND is_active=1').get(email.toLowerCase().trim());
    if(!u||!checkPw(password,u.password)) return send(res,{success:false,message:'Invalid email or password.'},401);
    db.prepare("UPDATE users SET last_login=datetime('now') WHERE id=?").run(u.id);
    return send(res,{success:true,token:signJWT({id:u.id,role:u.role}),user:safeUser(u)});
  }

  if(pt==='/api/auth/register'&&m==='POST'){
    const{full_name,email,phone,password,role='parent'}=body;
    if(!full_name||!email||!password) return send(res,{success:false,message:'Name, email and password required.'},400);
    if(password.length<8) return send(res,{success:false,message:'Password must be at least 8 characters.'},400);
    if(db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase())) return send(res,{success:false,message:'Email already in use.'},409);
    const id=db.prepare('INSERT INTO users (uuid,role,full_name,email,phone,password) VALUES (?,?,?,?,?,?)').run(uid(),role,full_name,email.toLowerCase().trim(),phone||null,hashPw(password)).lastInsertRowid;
    const u=db.prepare('SELECT id,uuid,role,full_name,email,phone,created_at FROM users WHERE id=?').get(id);
    return send(res,{success:true,token:signJWT({id:u.id,role:u.role}),user:u},201);
  }

  if(pt==='/api/auth/me'&&m==='GET'){
    const u=auth(req); if(!u) return send(res,{success:false,message:'Unauthorized.'},401);
    return send(res,{success:true,user:safeUser(u)});
  }

  if(pt==='/api/auth/change-password'&&m==='PUT'){
    const u=auth(req); if(!u) return send(res,{success:false,message:'Unauthorized.'},401);
    const{current_password,new_password}=body;
    if(!current_password||!new_password) return send(res,{success:false,message:'Both passwords required.'},400);
    if(!checkPw(current_password,u.password)) return send(res,{success:false,message:'Current password incorrect.'},401);
    if(new_password.length<8) return send(res,{success:false,message:'New password must be at least 8 characters.'},400);
    db.prepare('UPDATE users SET password=? WHERE id=?').run(hashPw(new_password),u.id);
    return send(res,{success:true,message:'Password updated.'});
  }

  // ── USERS ─────────────────────────────────────────────────────────────
  if(pt==='/api/users'&&m==='GET'){
    const u=auth(req); if(!u||u.role!=='admin') return send(res,{success:false,message:'Forbidden.'},403);
    const role=qp.get('role');
    const users=role?db.prepare('SELECT id,uuid,role,full_name,email,phone,is_active,last_login,created_at FROM users WHERE role=? ORDER BY full_name').all(role)
                    :db.prepare('SELECT id,uuid,role,full_name,email,phone,is_active,last_login,created_at FROM users ORDER BY role,full_name').all();
    return send(res,{success:true,users});
  }

  // ── STUDENTS ──────────────────────────────────────────────────────────
  if(pt==='/api/students'&&m==='GET'){
    const u=auth(req); if(!u) return send(res,{success:false,message:'Unauthorized.'},401);
    let students;
    if(u.role==='parent'){
      students=db.prepare('SELECT * FROM students WHERE parent_id=? AND is_active=1').all(u.id);
    } else {
      const search=qp.get('search')||'', grade=qp.get('grade')||'';
      let q='SELECT s.*,u.full_name as parent_name,u.phone as parent_phone FROM students s LEFT JOIN users u ON u.id=s.parent_id WHERE s.is_active=1';
      const p=[];
      if(grade){q+=' AND s.grade=?';p.push(grade);}
      if(search){q+=' AND (s.full_name LIKE ? OR s.admission_no LIKE ?)';p.push(`%${search}%`,`%${search}%`);}
      q+=' ORDER BY s.grade,s.full_name';
      students=db.prepare(q).all(...p);
    }
    return send(res,{success:true,students,count:students.length});
  }

  if(pt==='/api/students'&&m==='POST'){
    const u=auth(req); if(!u||!['admin','teacher'].includes(u.role)) return send(res,{success:false,message:'Forbidden.'},403);
    const{full_name,dob,gender,grade,stream='A',parent_id,address,medical_notes}=body;
    if(!full_name||!grade||!gender) return send(res,{success:false,message:'full_name, grade and gender required.'},400);
    const cnt=db.prepare('SELECT COUNT(*) as c FROM students').get().c;
    const yr=new Date().getFullYear().toString().slice(-2);
    const admNo=`MCP/${yr}/${String(cnt+1).padStart(4,'0')}`;
    const id=db.prepare('INSERT INTO students (uuid,admission_no,full_name,dob,gender,grade,stream,parent_id,address,medical_notes) VALUES (?,?,?,?,?,?,?,?,?,?)').run(uid(),admNo,full_name,dob||null,gender,grade,stream,parent_id||null,address||null,medical_notes||null).lastInsertRowid;
    return send(res,{success:true,student:db.prepare('SELECT * FROM students WHERE id=?').get(id)},201);
  }

  // Student :id
  let m2;
  if((m2=pt.match(/^\/api\/students\/(\d+)$/))){
    const u=auth(req); if(!u) return send(res,{success:false,message:'Unauthorized.'},401);
    const sid=Number(m2[1]);
    if(m==='GET'){
      const s=db.prepare('SELECT s.*,u.full_name as parent_name,u.email as parent_email,u.phone as parent_phone FROM students s LEFT JOIN users u ON u.id=s.parent_id WHERE s.id=? AND s.is_active=1').get(sid);
      if(!s) return send(res,{success:false,message:'Student not found.'},404);
      if(u.role==='parent'&&s.parent_id!==u.id) return send(res,{success:false,message:'Forbidden.'},403);
      return send(res,{success:true,student:s});
    }
    if(m==='PUT'&&['admin','teacher'].includes(u.role)){
      const fields=['full_name','dob','gender','grade','stream','parent_id','address','medical_notes'];
      const upd=fields.filter(f=>body[f]!==undefined);
      if(upd.length) db.prepare(`UPDATE students SET ${upd.map(f=>f+'=?').join(',')} WHERE id=?`).run(...upd.map(f=>body[f]),sid);
      return send(res,{success:true,student:db.prepare('SELECT * FROM students WHERE id=?').get(sid)});
    }
  }

  // Results
  if((m2=pt.match(/^\/api\/students\/(\d+)\/results$/))){
    const u=auth(req); if(!u) return send(res,{success:false,message:'Unauthorized.'},401);
    const sid=Number(m2[1]);
    if(m==='GET'){
      const term=qp.get('term'), year=qp.get('year');
      let q='SELECT * FROM results WHERE student_id=?'; const p=[sid];
      if(term){q+=' AND term=?';p.push(term);}
      if(year){q+=' AND year=?';p.push(year);}
      q+=' ORDER BY subject';
      const results=db.prepare(q).all(...p);
      const avg=results.length?(results.reduce((a,r)=>a+(r.score/r.max_score)*100,0)/results.length).toFixed(1):null;
      return send(res,{success:true,results,average:avg});
    }
    if(m==='POST'&&['admin','teacher'].includes(u.role)){
      const{subject,score,max_score=100,term,year,exam_type='end-term'}=body;
      if(!subject||score===undefined||!term||!year) return send(res,{success:false,message:'subject, score, term, year required.'},400);
      db.prepare('INSERT OR REPLACE INTO results (student_id,subject,score,max_score,grade_letter,term,year,exam_type,teacher_id) VALUES (?,?,?,?,?,?,?,?,?)').run(sid,subject,score,max_score,gradeLetter((score/max_score)*100),term,year,exam_type,u.id);
      return send(res,{success:true,message:'Result saved.'},201);
    }
  }

  // Attendance
  if((m2=pt.match(/^\/api\/students\/(\d+)\/attendance$/))){
    const u=auth(req); if(!u) return send(res,{success:false,message:'Unauthorized.'},401);
    const sid=Number(m2[1]);
    if(m==='GET'){
      const records=db.prepare('SELECT * FROM attendance WHERE student_id=? ORDER BY date DESC').all(sid);
      const summary={present:records.filter(r=>r.status==='present').length,absent:records.filter(r=>r.status==='absent').length,late:records.filter(r=>r.status==='late').length,total:records.length};
      return send(res,{success:true,attendance:records,summary});
    }
    if(m==='POST'&&['admin','teacher'].includes(u.role)){
      const{date,status,note}=body;
      if(!date||!status) return send(res,{success:false,message:'date and status required.'},400);
      db.prepare('INSERT OR REPLACE INTO attendance (student_id,date,status,note,recorded_by) VALUES (?,?,?,?,?)').run(sid,date,status,note||null,u.id);
      return send(res,{success:true,message:'Attendance recorded.'});
    }
  }

  // ── M-PESA ────────────────────────────────────────────────────────────
  if(pt==='/api/mpesa/initiate'&&m==='POST'){
    const u=auth(req); if(!u) return send(res,{success:false,message:'Unauthorized.'},401);
    const{student_id,amount,phone,description,term,year}=body;
    if(!amount||!phone||!student_id) return send(res,{success:false,message:'amount, phone and student_id required.'},400);
    const student=db.prepare('SELECT * FROM students WHERE id=?').get(student_id);
    if(!student) return send(res,{success:false,message:'Student not found.'},404);
    const checkoutId=`BP${Date.now()}${Math.floor(Math.random()*1000)}`;
    const payId=uid();
    db.prepare('INSERT INTO payments (uuid,student_id,parent_id,amount,method,status,mpesa_phone,checkout_request,description,term,year) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(payId,student_id,u.id,amount,'mpesa','pending',phone,checkoutId,description||`Term ${term} Fees - ${student.full_name}`,term||null,year||null);
    // Sandbox: auto-complete after 6 seconds
    setTimeout(()=>{
      const rcpt='KBP'+crypto.randomBytes(4).toString('hex').toUpperCase();
      db.prepare("UPDATE payments SET status='completed',mpesa_receipt=?,paid_at=datetime('now') WHERE checkout_request=?").run(rcpt,checkoutId);
      console.log(`✅ M-Pesa [SANDBOX] confirmed: ${rcpt} — KES ${amount}`);
    },6000);
    return send(res,{success:true,message:'STK Push sent! Check your phone and enter your M-Pesa PIN.',checkout_request_id:checkoutId,payment_uuid:payId});
  }

  if(pt==='/api/mpesa/callback'&&m==='POST'){
    const cb=body?.Body?.stkCallback;
    if(cb){
      const{CheckoutRequestID,ResultCode,CallbackMetadata}=cb;
      if(ResultCode===0){
        const items=CallbackMetadata?.Item||[];
        const g=n=>items.find(i=>i.Name===n)?.Value;
        db.prepare("UPDATE payments SET status='completed',mpesa_receipt=?,paid_at=datetime('now') WHERE checkout_request=?").run(g('MpesaReceiptNumber'),CheckoutRequestID);
      } else {
        db.prepare("UPDATE payments SET status='failed' WHERE checkout_request=?").run(CheckoutRequestID);
      }
    }
    return send(res,{ResultCode:0,ResultDesc:'Accepted'});
  }

  if((m2=pt.match(/^\/api\/mpesa\/status\/(.+)$/))&&m==='GET'){
    const u=auth(req); if(!u) return send(res,{success:false,message:'Unauthorized.'},401);
    const id=m2[1];
    const payment=db.prepare('SELECT p.*,s.full_name as student_name,s.admission_no FROM payments p LEFT JOIN students s ON s.id=p.student_id WHERE p.checkout_request=? OR p.uuid=?').get(id,id);
    if(!payment) return send(res,{success:false,message:'Payment not found.'},404);
    return send(res,{success:true,payment});
  }

  if(pt==='/api/mpesa/history'&&m==='GET'){
    const u=auth(req); if(!u) return send(res,{success:false,message:'Unauthorized.'},401);
    const payments=db.prepare('SELECT p.*,s.full_name as student_name,s.admission_no,s.grade FROM payments p LEFT JOIN students s ON s.id=p.student_id WHERE p.parent_id=? ORDER BY p.created_at DESC LIMIT 50').all(u.id);
    const totalPaid=payments.filter(p=>p.status==='completed').reduce((a,p)=>a+p.amount,0);
    return send(res,{success:true,payments,total_paid:totalPaid});
  }

  // ── ADMISSIONS ────────────────────────────────────────────────────────
  if(pt==='/api/admissions'&&m==='POST'){
    const{child_name,grade_applying,parent_name,parent_email,parent_phone,dob,gender,address,prev_school,message:msg}=body;
    if(!child_name||!grade_applying||!parent_name||!parent_email||!parent_phone) return send(res,{success:false,message:'Required fields missing.'},400);
    const id=uid();
    db.prepare('INSERT INTO admissions (uuid,child_name,dob,gender,grade_applying,parent_name,parent_email,parent_phone,address,prev_school,message) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(id,child_name,dob||null,gender||null,grade_applying,parent_name,parent_email,parent_phone,address||null,prev_school||null,msg||null);
    return send(res,{success:true,message:'Application submitted successfully. We will contact you within 3–5 business days.',ref:id.split('-')[0].toUpperCase()},201);
  }

  if(pt==='/api/admissions'&&m==='GET'){
    const u=auth(req); if(!u||u.role!=='admin') return send(res,{success:false,message:'Forbidden.'},403);
    const status=qp.get('status');
    const apps=status?db.prepare('SELECT * FROM admissions WHERE status=? ORDER BY created_at DESC').all(status):db.prepare('SELECT * FROM admissions ORDER BY created_at DESC').all();
    return send(res,{success:true,applications:apps,count:apps.length});
  }

  if((m2=pt.match(/^\/api\/admissions\/(\d+)$/))&&m==='PUT'){
    const u=auth(req); if(!u||u.role!=='admin') return send(res,{success:false,message:'Forbidden.'},403);
    const{status,notes}=body;
    db.prepare("UPDATE admissions SET status=?,notes=?,reviewed_by=?,reviewed_at=datetime('now') WHERE id=?").run(status,notes||null,u.id,m2[1]);
    return send(res,{success:true,message:`Application updated to ${status}.`});
  }

  // ── NEWS ──────────────────────────────────────────────────────────────
  if(pt==='/api/news'&&m==='GET'){
    const limit=Number(qp.get('limit')||10),offset=Number(qp.get('offset')||0),cat=qp.get('category');
    let q='SELECT n.*,u.full_name as author_name FROM news n LEFT JOIN users u ON u.id=n.author_id WHERE n.is_published=1'; const p=[];
    if(cat){q+=' AND n.category=?';p.push(cat);}
    q+=' ORDER BY n.is_pinned DESC,n.published_at DESC LIMIT ? OFFSET ?';p.push(limit,offset);
    return send(res,{success:true,posts:db.prepare(q).all(...p),total:db.prepare('SELECT COUNT(*) as c FROM news WHERE is_published=1').get().c});
  }

  if(pt==='/api/news'&&m==='POST'){
    const u=auth(req); if(!u||u.role!=='admin') return send(res,{success:false,message:'Forbidden.'},403);
    const{title,content,excerpt,category='general',is_pinned=0,is_published=0}=body;
    if(!title||!content) return send(res,{success:false,message:'Title and content required.'},400);
    const slug=slugify(title);
    db.prepare(`INSERT INTO news (uuid,title,slug,content,excerpt,category,is_pinned,is_published,author_id,published_at) VALUES (?,?,?,?,?,?,?,?,?,${is_published?"datetime('now')":'NULL'})`).run(uid(),title,slug,content,excerpt||content.slice(0,160),category,is_pinned?1:0,is_published?1:0,u.id);
    return send(res,{success:true,slug},201);
  }

  if((m2=pt.match(/^\/api\/news\/(\d+)$/))){
    const u=auth(req); if(!u||u.role!=='admin') return send(res,{success:false,message:'Forbidden.'},403);
    if(m==='DELETE'){db.prepare('DELETE FROM news WHERE id=?').run(m2[1]);return send(res,{success:true});}
    if(m==='PUT'){
      const{title,content,excerpt,category,is_pinned,is_published}=body;
      db.prepare('UPDATE news SET title=COALESCE(?,title),content=COALESCE(?,content),excerpt=COALESCE(?,excerpt),category=COALESCE(?,category),is_pinned=COALESCE(?,is_pinned),is_published=COALESCE(?,is_published) WHERE id=?').run(title,content,excerpt,category,is_pinned,is_published,m2[1]);
      return send(res,{success:true});
    }
  }

  // ── EVENTS ────────────────────────────────────────────────────────────
  if(pt==='/api/events'&&m==='GET') return send(res,{success:true,events:db.prepare('SELECT * FROM events WHERE is_public=1 ORDER BY start_date ASC').all()});

  if(pt==='/api/events'&&m==='POST'){
    const u=auth(req); if(!u||u.role!=='admin') return send(res,{success:false,message:'Forbidden.'},403);
    const{title,description,location,start_date,end_date,is_public=1}=body;
    if(!title||!start_date) return send(res,{success:false,message:'title and start_date required.'},400);
    db.prepare('INSERT INTO events (uuid,title,description,location,start_date,end_date,is_public,created_by) VALUES (?,?,?,?,?,?,?,?)').run(uid(),title,description||null,location||'School Grounds',start_date,end_date||null,is_public?1:0,u.id);
    return send(res,{success:true},201);
  }

  if((m2=pt.match(/^\/api\/events\/(\d+)$/))&&m==='DELETE'){
    const u=auth(req); if(!u||u.role!=='admin') return send(res,{success:false,message:'Forbidden.'},403);
    db.prepare('DELETE FROM events WHERE id=?').run(m2[1]);
    return send(res,{success:true});
  }

  // ── NOTICES ───────────────────────────────────────────────────────────
  if(pt==='/api/notices'&&m==='GET'){
    const u=auth(req); if(!u) return send(res,{success:false,message:'Unauthorized.'},401);
    const aud=u.role==='parent'?['all','parents']:['all','teachers'];
    const ph=aud.map(()=>'?').join(',');
    return send(res,{success:true,notices:db.prepare(`SELECT n.*,u.full_name as author FROM notices n LEFT JOIN users u ON u.id=n.created_by WHERE n.is_active=1 AND n.audience IN (${ph}) ORDER BY n.created_at DESC`).all(...aud)});
  }

  if(pt==='/api/notices'&&m==='POST'){
    const u=auth(req); if(!u||u.role!=='admin') return send(res,{success:false,message:'Forbidden.'},403);
    const{title,body:nb,audience='all'}=body;
    if(!title||!nb) return send(res,{success:false,message:'title and body required.'},400);
    db.prepare('INSERT INTO notices (uuid,title,body,audience,created_by) VALUES (?,?,?,?,?)').run(uid(),title,nb,audience,u.id);
    return send(res,{success:true},201);
  }

  // ── ENQUIRIES ─────────────────────────────────────────────────────────
  if(pt==='/api/enquiries'&&m==='POST'){
    const{name,email,phone,subject,message:msg}=body;
    if(!name||!email||!msg) return send(res,{success:false,message:'name, email and message required.'},400);
    db.prepare('INSERT INTO enquiries (name,email,phone,subject,message) VALUES (?,?,?,?,?)').run(name,email,phone||null,subject||'General Enquiry',msg);
    return send(res,{success:true,message:'Thank you! We will respond within 24 hours.'},201);
  }

  if(pt==='/api/enquiries'&&m==='GET'){
    const u=auth(req); if(!u||u.role!=='admin') return send(res,{success:false,message:'Forbidden.'},403);
    return send(res,{success:true,enquiries:db.prepare('SELECT * FROM enquiries ORDER BY created_at DESC').all()});
  }

  if((m2=pt.match(/^\/api\/enquiries\/(\d+)\/read$/))&&m==='PUT'){
    const u=auth(req); if(!u||u.role!=='admin') return send(res,{success:false,message:'Forbidden.'},403);
    db.prepare('UPDATE enquiries SET is_read=1 WHERE id=?').run(m2[1]);
    return send(res,{success:true});
  }

  // ── FEES ──────────────────────────────────────────────────────────────
  if(pt==='/api/fees'&&m==='GET'){
    let q='SELECT * FROM fee_structure WHERE 1=1'; const p=[];
    if(qp.get('year')){q+=' AND year=?';p.push(qp.get('year'));}
    if(qp.get('term')){q+=' AND term=?';p.push(qp.get('term'));}
    if(qp.get('grade')){q+=' AND grade=?';p.push(qp.get('grade'));}
    q+=' ORDER BY grade,term';
    return send(res,{success:true,fees:db.prepare(q).all(...p)});
  }

  if(pt==='/api/fees'&&m==='POST'){
    const u=auth(req); if(!u||u.role!=='admin') return send(res,{success:false,message:'Forbidden.'},403);
    const{grade,term,year,tuition,activity=0,lunch=0,transport=0}=body;
    if(!grade||!term||!year||!tuition) return send(res,{success:false,message:'grade, term, year and tuition required.'},400);
    const total=Number(tuition)+Number(activity)+Number(lunch)+Number(transport);
    db.prepare('INSERT OR REPLACE INTO fee_structure (grade,term,year,tuition,activity,lunch,transport,total) VALUES (?,?,?,?,?,?,?,?)').run(grade,term,year,tuition,activity,lunch,transport,total);
    return send(res,{success:true},201);
  }

  // ── DASHBOARD ─────────────────────────────────────────────────────────
  if(pt==='/api/dashboard/stats'&&m==='GET'){
    const u=auth(req); if(!u||u.role!=='admin') return send(res,{success:false,message:'Forbidden.'},403);
    return send(res,{success:true,stats:{
      students:   db.prepare('SELECT COUNT(*) as c FROM students WHERE is_active=1').get().c,
      parents:    db.prepare("SELECT COUNT(*) as c FROM users WHERE role='parent'").get().c,
      teachers:   db.prepare("SELECT COUNT(*) as c FROM users WHERE role='teacher'").get().c,
      pending_admissions: db.prepare("SELECT COUNT(*) as c FROM admissions WHERE status='pending'").get().c,
      unread_enquiries:   db.prepare('SELECT COUNT(*) as c FROM enquiries WHERE is_read=0').get().c,
      revenue_today: db.prepare("SELECT COALESCE(SUM(amount),0) as t FROM payments WHERE status='completed' AND date(paid_at)=date('now')").get().t,
      revenue_month: db.prepare("SELECT COALESCE(SUM(amount),0) as t FROM payments WHERE status='completed' AND strftime('%Y-%m',paid_at)=strftime('%Y-%m','now')").get().t,
      revenue_total: db.prepare("SELECT COALESCE(SUM(amount),0) as t FROM payments WHERE status='completed'").get().t,
      recent_payments:   db.prepare("SELECT p.*,s.full_name as student_name FROM payments p LEFT JOIN students s ON s.id=p.student_id WHERE p.status='completed' ORDER BY p.paid_at DESC LIMIT 5").all(),
      recent_admissions: db.prepare('SELECT * FROM admissions ORDER BY created_at DESC LIMIT 5').all()
    }});
  }

  return send(res,{success:false,message:`Not found: ${m} ${pt}`},404);
}

// ── LAUNCH ────────────────────────────────────────────────────────────────
seed();
const server = http.createServer(async(req,res)=>{
  try { await handle(req,res); }
  catch(err){ console.error('Error:',err.message); send(res,{success:false,message:'Server error.'},500); }
});

server.listen(PORT, ()=>{
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🏫  Mowlem Creek Premier School — Full Stack Server');
  console.log(`🌐  Public:   http://localhost:${PORT}`);
  console.log(`🔧  Admin:    http://localhost:${PORT}/admin`);
  console.log(`👨‍👩‍👧  Parent:   http://localhost:${PORT}/portal`);
  console.log(`🗄️   Database: ${DB_PATH}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
});

module.exports = server;
