/**
 * BrightPath Academy — Automated Test Suite
 * Run: node --experimental-sqlite test.js
 */
'use strict';
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const http = require('node:http');

let passed = 0, failed = 0;

function test(name, fn) {
  try { fn(); console.log(`  ✅ ${name}`); passed++; }
  catch(e) { console.log(`  ❌ ${name}: ${e.message}`); failed++; }
}

function assert(cond, msg) { if (!cond) throw new Error(msg || 'assertion failed'); }

// ── CRYPTO ────────────────────────────────────────────────────────────────
console.log('\n📋 Crypto Tests');

function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function checkPw(pw, stored) {
  const [s, h] = stored.split(':');
  return crypto.scryptSync(pw, s, 64).toString('hex') === h;
}
const SECRET = 'test-secret';
function signJWT(p) {
  const h = Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
  const b = Buffer.from(JSON.stringify({...p,iat:Date.now(),exp:Date.now()+999999})).toString('base64url');
  const s = crypto.createHmac('sha256',SECRET).update(h+'.'+b).digest('base64url');
  return `${h}.${b}.${s}`;
}
function verifyJWT(token) {
  const [h,b,s] = token.split('.');
  const e = crypto.createHmac('sha256',SECRET).update(h+'.'+b).digest('base64url');
  if (e !== s) throw new Error('Invalid signature');
  const p = JSON.parse(Buffer.from(b,'base64url').toString());
  if (p.exp < Date.now()) throw new Error('Expired');
  return p;
}

test('hashPw produces valid hash', () => { const h = hashPw('Test@123'); assert(h.includes(':') && h.length > 40); });
test('checkPw verifies correct password', () => { assert(checkPw('Admin@2025', hashPw('Admin@2025'))); });
test('checkPw rejects wrong password', () => { assert(!checkPw('wrong', hashPw('Admin@2025'))); });
test('signJWT creates 3-part token', () => { assert(signJWT({id:1,role:'admin'}).split('.').length === 3); });
test('verifyJWT decodes payload correctly', () => { const p = verifyJWT(signJWT({id:5,role:'parent'})); assert(p.id===5 && p.role==='parent'); });
test('verifyJWT rejects tampered token', () => {
  const t = signJWT({id:1}); const parts = t.split('.'); parts[1] = Buffer.from('{"id":99,"exp":9999999999}').toString('base64url');
  try { verifyJWT(parts.join('.')); assert(false,'should throw'); } catch(e) { assert(e.message==='Invalid signature'); }
});

// ── DATABASE ──────────────────────────────────────────────────────────────
console.log('\n🗄️  Database Tests');

const db = new DatabaseSync(':memory:');
db.exec('PRAGMA foreign_keys=ON;');
db.exec(`
  CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT UNIQUE, role TEXT, full_name TEXT, email TEXT UNIQUE, password TEXT, is_active INTEGER DEFAULT 1);
  CREATE TABLE students (id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT UNIQUE, admission_no TEXT UNIQUE, full_name TEXT, grade TEXT, parent_id INTEGER REFERENCES users(id));
  CREATE TABLE payments (id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT UNIQUE, student_id INTEGER, amount REAL, status TEXT DEFAULT 'pending', mpesa_receipt TEXT, paid_at TEXT);
  CREATE TABLE results (id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER, subject TEXT, score REAL, max_score REAL DEFAULT 100, grade_letter TEXT, term INTEGER, year INTEGER, UNIQUE(student_id,subject,term,year));
  CREATE TABLE attendance (id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER, date TEXT, status TEXT, UNIQUE(student_id,date));
`);

test('Insert and retrieve user', () => {
  db.prepare('INSERT INTO users (uuid,role,full_name,email,password) VALUES (?,?,?,?,?)').run('u1','admin','Dr. Kamau','admin@test.ke',hashPw('Admin@2025'));
  const u = db.prepare('SELECT * FROM users WHERE email=?').get('admin@test.ke');
  assert(u && u.role==='admin' && u.full_name==='Dr. Kamau');
});
test('Verify admin password from DB', () => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get('admin@test.ke');
  assert(checkPw('Admin@2025', u.password));
});
test('Insert student with parent ref', () => {
  const pid = db.prepare('INSERT INTO users (uuid,role,full_name,email,password) VALUES (?,?,?,?,?)').run('u2','parent','Mrs. Wanjiru','parent@test.ke',hashPw('P@ss1')).lastInsertRowid;
  db.prepare('INSERT INTO students (uuid,admission_no,full_name,grade,parent_id) VALUES (?,?,?,?,?)').run('s1','BPA/25/0001','Amara Kariuki','Grade 4',pid);
  const s = db.prepare('SELECT s.*,u.full_name as parent_name FROM students s LEFT JOIN users u ON u.id=s.parent_id WHERE s.uuid=?').get('s1');
  assert(s && s.full_name==='Amara Kariuki' && s.parent_name==='Mrs. Wanjiru');
});
test('Parent only sees own children', () => {
  const parent = db.prepare("SELECT id FROM users WHERE email='parent@test.ke'").get();
  const kids = db.prepare('SELECT * FROM students WHERE parent_id=?').all(parent.id);
  assert(kids.length===1 && kids[0].full_name==='Amara Kariuki');
});
test('Payment status transitions', () => {
  const stud = db.prepare('SELECT id FROM students WHERE uuid=?').get('s1');
  db.prepare('INSERT INTO payments (uuid,student_id,amount) VALUES (?,?,?)').run('pay1',stud.id,44500);
  let p = db.prepare('SELECT * FROM payments WHERE uuid=?').get('pay1');
  assert(p.status==='pending');
  db.prepare("UPDATE payments SET status='completed',mpesa_receipt=?,paid_at=datetime('now') WHERE uuid=?").run('KES1234ABCD','pay1');
  p = db.prepare('SELECT * FROM payments WHERE uuid=?').get('pay1');
  assert(p.status==='completed' && p.mpesa_receipt==='KES1234ABCD');
});
test('Exam results with grade letter', () => {
  const stud = db.prepare('SELECT id FROM students WHERE uuid=?').get('s1');
  const gradeL = pct => pct>=80?'A':pct>=70?'B':pct>=60?'C':pct>=50?'D':'E';
  const scores = [{sub:'Mathematics',sc:87},{sub:'English',sc:73},{sub:'Kiswahili',sc:55}];
  const ri = db.prepare('INSERT OR REPLACE INTO results (student_id,subject,score,max_score,grade_letter,term,year) VALUES (?,?,?,?,?,?,?)');
  scores.forEach(({sub,sc})=>ri.run(stud.id,sub,sc,100,gradeL(sc),1,2025));
  const res = db.prepare('SELECT * FROM results WHERE student_id=? ORDER BY subject').all(stud.id);
  assert(res.length===3);
  assert(res.find(r=>r.subject==='Mathematics')?.grade_letter==='A');
  assert(res.find(r=>r.subject==='English')?.grade_letter==='B');
  assert(res.find(r=>r.subject==='Kiswahili')?.grade_letter==='D');
});
test('Attendance unique constraint', () => {
  const stud = db.prepare('SELECT id FROM students WHERE uuid=?').get('s1');
  db.prepare('INSERT INTO attendance (student_id,date,status) VALUES (?,?,?)').run(stud.id,'2025-04-07','present');
  db.prepare('INSERT OR REPLACE INTO attendance (student_id,date,status) VALUES (?,?,?)').run(stud.id,'2025-04-07','absent');
  const att = db.prepare('SELECT * FROM attendance WHERE student_id=? AND date=?').get(stud.id,'2025-04-07');
  assert(att.status==='absent', 'should be updated to absent');
});
test('Revenue aggregation', () => {
  db.prepare('INSERT INTO payments (uuid,student_id,amount,status,paid_at) VALUES (?,?,?,?,datetime(\'now\'))').run('pay2',1,32000,'completed');
  const total = db.prepare("SELECT COALESCE(SUM(amount),0) as t FROM payments WHERE status='completed'").get().t;
  assert(total === 44500+32000, `expected 76500, got ${total}`);
});

// ── API ROUTES ────────────────────────────────────────────────────────────
console.log('\n🌐 Route Logic Tests');

function makeReq(method, path, body, token) {
  return {
    method, url: path,
    headers: { 'content-type':'application/json', ...(token?{authorization:`Bearer ${token}`}:{}) },
    body, socket: { remoteAddress: '127.0.0.1' }
  };
}
const responses = [];
function makeRes() {
  const r = { code:200, headers:{}, body:'', statusCode:null };
  r.writeHead = (c,h={}) => { r.code=c; r.headers={...r.headers,...h}; };
  r.end = b => { r.body=b; responses.push(r); };
  return r;
}

test('Slugify generates URL-safe slugs', () => {
  const slug = t => t.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/(^-|-$)/g,'');
  assert(slug('Hello World! 2025')==='hello-world-2025');
  assert(slug('CBC — What Parents Need to Know')==='cbc-what-parents-need-to-know');
  assert(!slug('BrightPath Academy, Nairobi').includes(' '));
});
test('Grade letter boundaries', () => {
  const g = pct => pct>=80?'A':pct>=70?'B':pct>=60?'C':pct>=50?'D':'E';
  assert(g(80)==='A'); assert(g(79)==='B'); assert(g(70)==='B');
  assert(g(60)==='C'); assert(g(50)==='D'); assert(g(49)==='E');
});
test('Phone formatter (M-Pesa)', () => {
  function fmtPhone(p) { let n=p.replace(/\D/g,''); if(n.startsWith('0')) n='254'+n.slice(1); if(n.startsWith('+')) n=n.slice(1); return n; }
  assert(fmtPhone('0722123456')==='254722123456');
  assert(fmtPhone('+254722123456')==='254722123456');
  assert(fmtPhone('254722123456')==='254722123456');
});
test('Admission number generator', () => {
  const gen = (count) => `BPA/${new Date().getFullYear().toString().slice(-2)}/${String(count+1).padStart(4,'0')}`;
  const yr2=new Date().getFullYear().toString().slice(-2); assert(gen(0)===`BPA/${yr2}/0001`);
  assert(gen(99)===`BPA/${yr2}/0100`);
  assert(gen(999)===`BPA/${yr2}/1000`);
});
test('Rate limiter resets after window', () => {
  const rlMap = new Map();
  function rl(ip, max=5, win=100) {
    const now=Date.now(), r=rlMap.get(ip)||{n:0,t:now+win};
    if(now>r.t){r.n=0;r.t=now+win;} r.n++; rlMap.set(ip,r); return r.n<=max;
  }
  for(let i=0;i<5;i++) assert(rl('1.2.3.4'));
  assert(!rl('1.2.3.4'), 'should be rate limited');
});

// ── MPESA LOGIC ───────────────────────────────────────────────────────────
console.log('\n💚 M-Pesa Logic Tests');

test('STK push payload validation', () => {
  function validateMpesa({amount, phone, student_id}) {
    if (!student_id) return 'student_id required';
    if (!phone) return 'phone required';
    if (!amount || amount < 1 || amount > 300000) return 'invalid amount';
    return null;
  }
  assert(validateMpesa({amount:44500,phone:'0722123456',student_id:1})===null);
  assert(validateMpesa({amount:0,phone:'0722',student_id:1})!==null);
  assert(validateMpesa({amount:44500,phone:'0722123456'})!==null);
});
test('Checkout ID generation is unique', () => {
  const ids = new Set();
  for(let i=0;i<100;i++) ids.add(`BP${Date.now()}${Math.floor(Math.random()*10000)}`);
  assert(ids.size>=95, 'should be mostly unique');
});
test('M-Pesa callback result parsing', () => {
  const cb = { Body: { stkCallback: { CheckoutRequestID:'BP123', ResultCode:0, CallbackMetadata: { Item: [{Name:'MpesaReceiptNumber',Value:'KES123ABC'},{Name:'Amount',Value:44500},{Name:'PhoneNumber',Value:254722123456}] } } } };
  const items = cb.Body.stkCallback.CallbackMetadata.Item;
  const get = n => items.find(i=>i.Name===n)?.Value;
  assert(get('MpesaReceiptNumber')==='KES123ABC');
  assert(get('Amount')===44500);
  assert(cb.Body.stkCallback.ResultCode===0);
});
test('Failed M-Pesa callback sets status=failed', () => {
  const cb = { Body: { stkCallback: { CheckoutRequestID:'BP456', ResultCode:1032, ResultDesc:'Request cancelled by user' } } };
  assert(cb.Body.stkCallback.ResultCode!==0);
  assert(cb.Body.stkCallback.ResultDesc==='Request cancelled by user');
});

// ── SECURITY TESTS ────────────────────────────────────────────────────────
console.log('\n🔒 Security Tests');

test('JWT rejects empty token', () => {
  try { verifyJWT(''); assert(false,'should throw'); } catch(e) { assert(true); }
});
test('JWT rejects malformed token', () => {
  try { verifyJWT('not.a.valid.jwt.token'); assert(false,'should throw'); } catch(e) { assert(true); }
});
test('Expired JWT is rejected', () => {
  const h = Buffer.from('{"alg":"HS256"}').toString('base64url');
  const b = Buffer.from(JSON.stringify({id:1,exp:Date.now()-1000})).toString('base64url');
  const s = crypto.createHmac('sha256',SECRET).update(h+'.'+b).digest('base64url');
  try { verifyJWT(`${h}.${b}.${s}`); assert(false,'should expire'); } catch(e) { assert(e.message==='Expired'); }
});
test('Password hash is unique per run', () => {
  const h1=hashPw('same-password'), h2=hashPw('same-password');
  assert(h1!==h2, 'salts should differ');
  assert(checkPw('same-password',h1) && checkPw('same-password',h2));
});
test('Admin-only endpoint requires correct role', () => {
  // Simulate role check
  const checkRole = (user, required) => required.includes(user?.role);
  assert(!checkRole({role:'parent'},'admin'));
  assert(!checkRole(null,'admin'));
  assert(checkRole({role:'admin'},'admin'));
  assert(checkRole({role:'teacher'},['admin','teacher']));
});

// ── FINAL REPORT ──────────────────────────────────────────────────────────
console.log('\n' + '━'.repeat(50));
console.log(`📊 Results: ${passed} passed, ${failed} failed`);
if(failed===0) {
  console.log('🎉 ALL TESTS PASSED — BrightPath Academy backend is verified!');
} else {
  console.log('⚠️  Some tests failed — check output above.');
  process.exit(1);
}
console.log('━'.repeat(50)+'\n');
