const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const production = process.env.NODE_ENV === 'production';
if (production && !process.env.SESSION_SECRET) throw new Error('SESSION_SECRET must be set in production.');
const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'darkzone.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
 email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 bio TEXT NOT NULL DEFAULT '', is_admin INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS posts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 body TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'عام', is_announcement INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS likes (
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(user_id, post_id)
);
CREATE TABLE IF NOT EXISTS comments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE, body TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reports (
 id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE, reason TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(reporter_id, post_id)
);
`);
// Safe schema upgrades for installations created by the earlier DARKZONE version.
const userCols = db.prepare('PRAGMA table_info(users)').all().map(x => x.name);
if (!userCols.includes('bio')) db.exec("ALTER TABLE users ADD COLUMN bio TEXT NOT NULL DEFAULT ''");
if (!userCols.includes('is_admin')) db.exec('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0');
const postCols = db.prepare('PRAGMA table_info(posts)').all().map(x => x.name);
if (!postCols.includes('category')) db.exec("ALTER TABLE posts ADD COLUMN category TEXT NOT NULL DEFAULT 'عام'");
if (!postCols.includes('is_announcement')) db.exec('ALTER TABLE posts ADD COLUMN is_announcement INTEGER NOT NULL DEFAULT 0');
if (process.env.ADMIN_EMAIL) db.prepare('UPDATE users SET is_admin=1 WHERE email=?').run(process.env.ADMIN_EMAIL.trim().toLowerCase());

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '30kb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({ name: 'darkzone.sid', secret: process.env.SESSION_SECRET || 'local-development-secret-change-me', resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: 'lax', secure: production, maxAge: 7 * 86400000 } }));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });
const writeLimiter = rateLimit({ windowMs: 60 * 1000, limit: 15, standardHeaders: 'draft-7', legacyHeaders: false });
const clean = v => typeof v === 'string' ? v.trim() : '';
const getUser = req => req.session.userId ? db.prepare('SELECT id, username, email, bio, is_admin, created_at FROM users WHERE id=?').get(req.session.userId) || null : null;
function auth(req,res,next){ if(!getUser(req)) return res.status(401).json({error:'سجّل الدخول أولاً.'}); next(); }
function admin(req,res,next){ const u=getUser(req); if(!u || !u.is_admin) return res.status(403).json({error:'هذه الميزة للإدارة فقط.'}); next(); }
function postShape(postId, viewerId){
 return db.prepare(`SELECT p.id,p.body,p.category,p.is_announcement,p.created_at,u.id user_id,u.username,u.bio,
 (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) likes_count,
 (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) comments_count,
 EXISTS(SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=?) liked
 FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=?`).get(viewerId || 0, postId);
}
app.get('/api/me',(req,res)=>res.json({user:getUser(req)}));
app.post('/api/register',authLimiter,async(req,res)=>{
 const username=clean(req.body.username), email=clean(req.body.email).toLowerCase(), password=typeof req.body.password==='string'?req.body.password:'';
 if(!/^[\p{L}\p{N}_-]{3,20}$/u.test(username)) return res.status(400).json({error:'اسم المستخدم يجب أن يكون 3–20 حرفاً أو رقماً.'});
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:'اكتب بريداً إلكترونياً صحيحاً.'});
 if(password.length<10||password.length>72) return res.status(400).json({error:'كلمة المرور يجب أن تكون 10 أحرف على الأقل.'});
 try { const hash=await bcrypt.hash(password,12); const adminFlag=process.env.ADMIN_EMAIL && email===process.env.ADMIN_EMAIL.trim().toLowerCase()?1:0;
 const r=db.prepare('INSERT INTO users(username,email,password_hash,is_admin) VALUES(?,?,?,?)').run(username,email,hash,adminFlag); req.session.userId=r.lastInsertRowid; res.status(201).json({user:getUser(req)});
 } catch(e){ if(String(e.code).includes('SQLITE_CONSTRAINT')) return res.status(409).json({error:'اسم المستخدم أو البريد مستخدم بالفعل.'}); res.status(500).json({error:'حدث خطأ غير متوقع.'}); }
});
app.post('/api/login',authLimiter,async(req,res)=>{const email=clean(req.body.email).toLowerCase(),password=typeof req.body.password==='string'?req.body.password:'';const u=db.prepare('SELECT * FROM users WHERE email=?').get(email);if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:'بيانات الدخول غير صحيحة.'});req.session.userId=u.id;res.json({user:getUser(req)});});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>{res.clearCookie('darkzone.sid');res.json({ok:true});}));
app.get('/api/posts',(req,res)=>{const q=clean(req.query.q).slice(0,60),cat=clean(req.query.category);const rows=db.prepare(`SELECT p.id FROM posts p JOIN users u ON u.id=p.user_id WHERE (?='' OR p.body LIKE ? OR u.username LIKE ?) AND (?='' OR p.category=?) ORDER BY p.is_announcement DESC,p.id DESC LIMIT 100`).all(q,`%${q}%`,`%${q}%`,cat,cat);res.json({posts:rows.map(x=>postShape(x.id,getUser(req)?.id))});});
app.post('/api/posts',auth,writeLimiter,(req,res)=>{const body=clean(req.body.body),category=clean(req.body.category)||'عام';const allowed=['عام','ألعاب','تقنية','نقاش','إعلانات'];if(!body||body.length>1000)return res.status(400).json({error:'المنشور يجب أن يكون بين 1 و1000 حرف.'});if(!allowed.includes(category))return res.status(400).json({error:'القسم غير صحيح.'});const r=db.prepare('INSERT INTO posts(user_id,body,category) VALUES(?,?,?)').run(req.session.userId,body,category);res.status(201).json({post:postShape(r.lastInsertRowid,req.session.userId)});});
app.post('/api/posts/:id/like',auth,writeLimiter,(req,res)=>{const id=Number(req.params.id);if(!db.prepare('SELECT id FROM posts WHERE id=?').get(id))return res.status(404).json({error:'المنشور غير موجود.'});const exists=db.prepare('SELECT 1 FROM likes WHERE user_id=? AND post_id=?').get(req.session.userId,id);if(exists)db.prepare('DELETE FROM likes WHERE user_id=? AND post_id=?').run(req.session.userId,id);else db.prepare('INSERT INTO likes(user_id,post_id) VALUES(?,?)').run(req.session.userId,id);res.json({liked:!exists,likes_count:db.prepare('SELECT COUNT(*) n FROM likes WHERE post_id=?').get(id).n});});
app.get('/api/posts/:id/comments',(req,res)=>{const id=Number(req.params.id);const comments=db.prepare('SELECT c.id,c.body,c.created_at,u.username FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id ASC LIMIT 100').all(id);res.json({comments});});
app.post('/api/posts/:id/comments',auth,writeLimiter,(req,res)=>{const id=Number(req.params.id),body=clean(req.body.body);if(!db.prepare('SELECT id FROM posts WHERE id=?').get(id))return res.status(404).json({error:'المنشور غير موجود.'});if(!body||body.length>400)return res.status(400).json({error:'التعليق يجب أن يكون بين 1 و400 حرف.'});const r=db.prepare('INSERT INTO comments(user_id,post_id,body) VALUES(?,?,?)').run(req.session.userId,id,body);res.status(201).json({comment:db.prepare('SELECT c.id,c.body,c.created_at,u.username FROM comments c JOIN users u ON u.id=c.user_id WHERE c.id=?').get(r.lastInsertRowid)});});
app.post('/api/posts/:id/report',auth,writeLimiter,(req,res)=>{const id=Number(req.params.id),reason=clean(req.body.reason).slice(0,200)||'محتوى غير مناسب';try{db.prepare('INSERT INTO reports(reporter_id,post_id,reason) VALUES(?,?,?)').run(req.session.userId,id,reason);res.status(201).json({ok:true});}catch(e){if(String(e.code).includes('SQLITE_CONSTRAINT'))return res.status(409).json({error:'سبق وأبلغت عن هذا المنشور.'});res.status(500).json({error:'تعذر إرسال البلاغ.'});}});
app.get('/api/users/:id',(req,res)=>{const u=db.prepare('SELECT id,username,bio,created_at FROM users WHERE id=?').get(Number(req.params.id));if(!u)return res.status(404).json({error:'العضو غير موجود.'});u.posts_count=db.prepare('SELECT COUNT(*) n FROM posts WHERE user_id=?').get(u.id).n;res.json({user:u});});
app.put('/api/profile',auth,writeLimiter,(req,res)=>{const bio=clean(req.body.bio);if(bio.length>180)return res.status(400).json({error:'النبذة لا تتجاوز 180 حرفاً.'});db.prepare('UPDATE users SET bio=? WHERE id=?').run(bio,req.session.userId);res.json({user:getUser(req)});});
app.get('/api/admin/stats',auth,admin,(req,res)=>res.json({users:db.prepare('SELECT COUNT(*) n FROM users').get().n,posts:db.prepare('SELECT COUNT(*) n FROM posts').get().n,reports:db.prepare('SELECT COUNT(*) n FROM reports').get().n}));
app.get('/api/admin/reports',auth,admin,(req,res)=>res.json({reports:db.prepare(`SELECT r.id,r.reason,r.created_at,p.id post_id,p.body,u.username reporter FROM reports r JOIN posts p ON p.id=r.post_id JOIN users u ON u.id=r.reporter_id ORDER BY r.id DESC LIMIT 100`).all()}));
app.post('/api/admin/announce/:id',auth,admin,(req,res)=>{const id=Number(req.params.id);db.prepare('UPDATE posts SET is_announcement=CASE WHEN is_announcement=1 THEN 0 ELSE 1 END WHERE id=?').run(id);res.json({post:postShape(id,getUser(req).id)});});
app.delete('/api/admin/posts/:id',auth,admin,(req,res)=>{db.prepare('DELETE FROM posts WHERE id=?').run(Number(req.params.id));db.prepare('DELETE FROM reports WHERE post_id=?').run(Number(req.params.id));res.json({ok:true});});
app.delete('/api/admin/reports/:id',auth,admin,(req,res)=>{db.prepare('DELETE FROM reports WHERE id=?').run(Number(req.params.id));res.json({ok:true});});
app.use(express.static(path.join(__dirname,'public')));
app.get('*',(_req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`DARKZONE running on port ${PORT}`));
