// ═══════════════════════════════════════════════════════
// EventPilot Backend — server.js (MySQL / Bluehost)
// ═══════════════════════════════════════════════════════
require('dotenv').config();

const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const mysql      = require('mysql2/promise');
const rateLimit  = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

// ── MySQL Connection Pool ─────────────────────────────────
const db = mysql.createPool({
  host:     process.env.DB_HOST,
  port:     process.env.DB_PORT || 3306,
  user:     process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  charset: 'utf8mb4',
});

db.getConnection()
  .then(c => { console.log('✅ MySQL Connected'); c.release(); })
  .catch(e => console.error('❌ MySQL Error:', e.message));

// ── Express ───────────────────────────────────────────────
const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: '*', methods: ['GET','POST'], credentials: true }
});

app.use(cors({ origin: '*' }));
app.use(express.json());
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// ── Helpers ───────────────────────────────────────────────
const sign   = (id) => jwt.sign({ userId: id }, process.env.JWT_SECRET, { expiresIn: '30d' });
const verify = (req, res, next) => {
  const t = req.headers.authorization?.replace('Bearer ', '');
  if (!t) return res.status(401).json({ error: 'غير مصرح' });
  try { req.user = jwt.verify(t, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'جلسة منتهية' }); }
};
const code = () => {
  const n = String(Math.floor(Math.random()*9000)+1000);
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let p = '';
  for (let i=0;i<4;i++) p += c[Math.floor(Math.random()*c.length)];
  return `EP-${n}-${p}`;
};
const dist = (a,b,c,d) => {
  const R=6371000, dL=(c-a)*Math.PI/180, dG=(d-b)*Math.PI/180;
  const x=Math.sin(dL/2)**2+Math.cos(a*Math.PI/180)*Math.cos(c*Math.PI/180)*Math.sin(dG/2)**2;
  return R*2*Math.atan2(Math.sqrt(x),Math.sqrt(1-x));
};

// ══════════════════════════════════════════════════════════
// API Routes
// ══════════════════════════════════════════════════════════
app.get('/', (_,res) => res.json({ status:'✅ EventPilot API Running', version:'1.0.0' }));

// تسجيل
app.post('/api/auth/register', async (req,res) => {
  try {
    const { name, phone, password } = req.body;
    if (!name||!phone||!password) return res.status(400).json({ error:'جميع الحقول مطلوبة' });
    if (password.length<6) return res.status(400).json({ error:'كلمة المرور 6 أحرف على الأقل' });
    const id   = uuidv4();
    const hash = await bcrypt.hash(password, 10);
    await db.execute('INSERT INTO users (id,name,phone,password) VALUES (?,?,?,?)',[id,name,phone,hash]);
    res.status(201).json({ user:{id,name,phone,package:'free'}, token:sign(id) });
  } catch(e) {
    if (e.code==='ER_DUP_ENTRY') return res.status(409).json({ error:'رقم الجوال مسجّل مسبقاً' });
    res.status(500).json({ error:'حدث خطأ' });
  }
});

// دخول
app.post('/api/auth/login', async (req,res) => {
  try {
    const { phone, password } = req.body;
    const [r] = await db.execute('SELECT * FROM users WHERE phone=?',[phone]);
    if (!r[0]||!await bcrypt.compare(password,r[0].password))
      return res.status(401).json({ error:'رقم الجوال أو كلمة المرور خاطئة' });
    await db.execute('UPDATE users SET last_seen=NOW() WHERE id=?',[r[0].id]);
    const { password:_, ...u } = r[0];
    res.json({ user:u, token:sign(r[0].id) });
  } catch(e) { res.status(500).json({ error:'حدث خطأ' }); }
});

// بياناتي
app.get('/api/auth/me', verify, async (req,res) => {
  const [r] = await db.execute('SELECT id,name,phone,avatar,package FROM users WHERE id=?',[req.user.userId]);
  res.json(r[0]||null);
});

// إنشاء مجموعة
app.post('/api/groups/create', verify, async (req,res) => {
  try {
    const { name, eventName, eventLoc, safeRadius=100 } = req.body;
    const id=uuidv4(), c=code();
    await db.execute(
      'INSERT INTO groups (id,code,name,event_name,event_loc,creator_id,safe_radius) VALUES (?,?,?,?,?,?,?)',
      [id,c,name,eventName,eventLoc,req.user.userId,safeRadius]
    );
    await db.execute('INSERT INTO group_members (id,group_id,user_id,role) VALUES (?,?,?,?)',
      [uuidv4(),id,req.user.userId,'leader']);
    res.status(201).json({ id,code:c,name,event_name:eventName,safe_radius:safeRadius });
  } catch(e) { res.status(500).json({ error:'خطأ في الإنشاء' }); }
});

// انضمام
app.post('/api/groups/join', verify, async (req,res) => {
  try {
    const { code:c, role='member' } = req.body;
    const [g] = await db.execute('SELECT * FROM groups WHERE code=? AND is_active=1',[c.toUpperCase()]);
    if (!g[0]) return res.status(404).json({ error:'الكود غير صحيح أو منتهي' });
    try {
      await db.execute('INSERT INTO group_members (id,group_id,user_id,role) VALUES (?,?,?,?)',
        [uuidv4(),g[0].id,req.user.userId,role]);
    } catch(e2) {
      if (e2.code==='ER_DUP_ENTRY') return res.status(409).json({ error:'أنت بالفعل في هذه المجموعة' });
      throw e2;
    }
    res.json(g[0]);
  } catch(e) { res.status(500).json({ error:'حدث خطأ' }); }
});

// أعضاء المجموعة
app.get('/api/groups/:id/members', verify, async (req,res) => {
  const [r] = await db.execute(`
    SELECT gm.role,gm.joined_at,u.id,u.name,u.avatar,u.last_seen,
           ml.latitude,ml.longitude,ml.battery,ml.status,ml.updated_at
    FROM group_members gm
    JOIN users u ON u.id=gm.user_id
    LEFT JOIN member_locations ml ON ml.user_id=gm.user_id
    WHERE gm.group_id=?`,[req.params.id]);
  res.json(r);
});

// مجموعاتي
app.get('/api/groups/my', verify, async (req,res) => {
  const [r] = await db.execute(`
    SELECT g.*,gm.role AS my_role FROM group_members gm
    JOIN groups g ON g.id=gm.group_id
    WHERE gm.user_id=? AND g.is_active=1 ORDER BY g.created_at DESC`,[req.user.userId]);
  res.json(r);
});

// تنبيهات
app.get('/api/groups/:id/alerts', verify, async (req,res) => {
  const [r] = await db.execute(`
    SELECT a.*,u.name AS user_name,u.avatar FROM alerts a
    LEFT JOIN users u ON u.id=a.user_id
    WHERE a.group_id=? ORDER BY a.created_at DESC LIMIT 50`,[req.params.id]);
  res.json(r);
});

// ══════════════════════════════════════════════════════════
// Socket.io
// ══════════════════════════════════════════════════════════
const live = new Map();

io.use(async (socket,next) => {
  try {
    const d = jwt.verify(socket.handshake.auth?.token, process.env.JWT_SECRET);
    const [r] = await db.execute('SELECT id,name,avatar FROM users WHERE id=?',[d.userId]);
    if (!r[0]) return next(new Error('غير موجود'));
    Object.assign(socket,{ userId:r[0].id, userName:r[0].name, userAvatar:r[0].avatar });
    next();
  } catch { next(new Error('غير مصرح')); }
});

io.on('connection', socket => {
  console.log(`✅ ${socket.userName}`);

  socket.on('join_group', async ({ groupId }) => {
    const [m] = await db.execute('SELECT role FROM group_members WHERE group_id=? AND user_id=?',[groupId,socket.userId]);
    if (!m[0]) return socket.emit('error',{message:'لست عضواً في هذه المجموعة'});
    Object.assign(socket,{ groupId, userRole:m[0].role });
    socket.join(`group:${groupId}`);
    socket.to(`group:${groupId}`).emit('member_joined',{userId:socket.userId,name:socket.userName,avatar:socket.userAvatar,role:m[0].role});
    const snap=[];
    for (const [id,l] of live) if(l.groupId===groupId) snap.push({userId:id,...l});
    socket.emit('locations_snapshot',snap);
  });

  socket.on('location_update', async ({ latitude,longitude,accuracy,battery }) => {
    if (!socket.groupId) return;
    const l={groupId:socket.groupId,name:socket.userName,avatar:socket.userAvatar,latitude,longitude,accuracy,battery,updatedAt:new Date().toISOString()};
    live.set(socket.userId,l);
    io.to(`group:${socket.groupId}`).emit('location_updated',{userId:socket.userId,...l});

    const now=Date.now();
    if (!socket.lastSave||now-socket.lastSave>10000) {
      socket.lastSave=now;
      const [g]=await db.execute('SELECT safe_radius FROM groups WHERE id=?',[socket.groupId]);
      const r=g[0]?.safe_radius||100;
      let status='safe';
      for(const [,loc] of live) if(loc.groupId===socket.groupId&&loc.role==='leader'){const d2=dist(latitude,longitude,loc.latitude,loc.longitude);if(d2>r*1.5)status='danger';else if(d2>r)status='warning';break;}
      await db.execute(`INSERT INTO member_locations (id,user_id,group_id,latitude,longitude,accuracy,battery,status) VALUES (?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE latitude=?,longitude=?,accuracy=?,battery=?,status=?,updated_at=NOW()`,
        [uuidv4(),socket.userId,socket.groupId,latitude,longitude,accuracy||0,battery||100,status,latitude,longitude,accuracy||0,battery||100,status]);
      if(status==='danger'){
        const msg=`⚠️ ${socket.userName} تجاوز نطاق الأمان`;
        await db.execute('INSERT INTO alerts (id,group_id,user_id,type,message) VALUES (?,?,?,?,?)',[uuidv4(),socket.groupId,socket.userId,'danger',msg]);
        io.to(`group:${socket.groupId}`).emit('safety_alert',{type:'danger',userId:socket.userId,name:socket.userName,message:msg});
      }
    }
  });

  socket.on('sos_send', async ({ latitude,longitude }) => {
    if(!socket.groupId) return;
    const id=uuidv4(), msg=`🆘 ${socket.userName} أرسل نداء استغاثة!`;
    await db.execute('INSERT INTO sos_events (id,sender_id,group_id,latitude,longitude) VALUES (?,?,?,?,?)',[id,socket.userId,socket.groupId,latitude,longitude]);
    await db.execute('INSERT INTO alerts (id,group_id,user_id,type,message) VALUES (?,?,?,?,?)',[uuidv4(),socket.groupId,socket.userId,'sos',msg]);
    io.to(`group:${socket.groupId}`).emit('sos_received',{sosId:id,senderId:socket.userId,name:socket.userName,avatar:socket.userAvatar,latitude,longitude,message:msg});
  });

  socket.on('sos_respond', async ({ sosId }) => {
    await db.execute('INSERT IGNORE INTO sos_responders (sos_id,user_id) VALUES (?,?)',[sosId,socket.userId]).catch(()=>{});
    io.to(`group:${socket.groupId}`).emit('sos_response',{sosId,responderId:socket.userId,name:socket.userName,avatar:socket.userAvatar});
  });

  socket.on('sos_cancel', async ({ sosId }) => {
    if(sosId) await db.execute('UPDATE sos_events SET status="cancelled",resolved_at=NOW() WHERE id=? AND sender_id=?',[sosId,socket.userId]);
    io.to(`group:${socket.groupId}`).emit('sos_cancelled',{userId:socket.userId,name:socket.userName});
  });

  socket.on('update_radius', async ({ radius }) => {
    if(!socket.groupId||socket.userRole!=='leader') return;
    await db.execute('UPDATE groups SET safe_radius=? WHERE id=?',[radius,socket.groupId]);
    io.to(`group:${socket.groupId}`).emit('radius_updated',{radius});
  });

  socket.on('disconnect', async () => {
    live.delete(socket.userId);
    if(socket.groupId) socket.to(`group:${socket.groupId}`).emit('member_left',{userId:socket.userId,name:socket.userName});
    await db.execute('UPDATE member_locations SET status="offline" WHERE user_id=?',[socket.userId]).catch(()=>{});
    await db.execute('UPDATE users SET last_seen=NOW() WHERE id=?',[socket.userId]).catch(()=>{});
  });
});

const PORT=process.env.PORT||3001;
server.listen(PORT,()=>console.log(`🚀 EventPilot on port ${PORT}`));
