require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');

// ── Supabase ──────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── Express ───────────────────────────────────────────────
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET','POST'] }
});
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use('/api/', rateLimit({ windowMs: 15*60*1000, max: 100 }));

// ── Helpers ───────────────────────────────────────────────
const sign = (id) => jwt.sign({ userId: id }, process.env.JWT_SECRET, { expiresIn: '30d' });
const auth = (req, res, next) => {
  const t = req.headers.authorization?.replace('Bearer ', '');
  if (!t) return res.status(401).json({ error: 'غير مصرح' });
  try { req.user = jwt.verify(t, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'جلسة منتهية' }); }
};
const genCode = () => {
  const n = String(Math.floor(Math.random()*9000)+1000);
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let p = '';
  for(let i=0;i<4;i++) p += c[Math.floor(Math.random()*c.length)];
  return `EP-${n}-${p}`;
};
const haversine = (a,b,c,d) => {
  const R=6371000, dL=(c-a)*Math.PI/180, dG=(d-b)*Math.PI/180;
  const x=Math.sin(dL/2)**2+Math.cos(a*Math.PI/180)*Math.cos(c*Math.PI/180)*Math.sin(dG/2)**2;
  return R*2*Math.atan2(Math.sqrt(x),Math.sqrt(1-x));
};

// ══════════════════════════════════════════════════════════
// REST API
// ══════════════════════════════════════════════════════════
app.get('/', (_, res) => res.json({ status: '✅ EventPilot API Running', version: '1.0.0' }));

// تسجيل
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, password } = req.body;
    if (!name||!phone||!password) return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    if (password.length < 6) return res.status(400).json({ error: 'كلمة المرور 6 أحرف على الأقل' });
    const hash = await bcrypt.hash(password, 10);
    const { data, error } = await supabase.from('users').insert({ name, phone, password: hash }).select('id,name,phone,package').single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'رقم الجوال مسجّل مسبقاً' });
      throw error;
    }
    res.status(201).json({ user: data, token: sign(data.id) });
  } catch(e) { console.error(e); res.status(500).json({ error: 'حدث خطأ' }); }
});

// دخول
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    const { data: user } = await supabase.from('users').select('*').eq('phone', phone).single();
    if (!user || !await bcrypt.compare(password, user.password))
      return res.status(401).json({ error: 'رقم الجوال أو كلمة المرور خاطئة' });
    await supabase.from('users').update({ last_seen: new Date() }).eq('id', user.id);
    const { password: _, ...safe } = user;
    res.json({ user: safe, token: sign(user.id) });
  } catch(e) { res.status(500).json({ error: 'حدث خطأ' }); }
});

// بياناتي
app.get('/api/auth/me', auth, async (req, res) => {
  const { data } = await supabase.from('users').select('id,name,phone,avatar,package').eq('id', req.user.userId).single();
  res.json(data);
});

// إنشاء مجموعة
app.post('/api/groups/create', auth, async (req, res) => {
  try {
    const { name, eventName, eventLoc, safeRadius = 100 } = req.body;
    const code = genCode();
    const { data: group, error } = await supabase.from('groups').insert({
      code, name, event_name: eventName, event_loc: eventLoc,
      creator_id: req.user.userId, safe_radius: safeRadius
    }).select().single();
    if (error) throw error;
    await supabase.from('group_members').insert({ group_id: group.id, user_id: req.user.userId, role: 'leader' });
    res.status(201).json(group);
  } catch(e) { res.status(500).json({ error: 'خطأ في الإنشاء' }); }
});

// انضمام
app.post('/api/groups/join', auth, async (req, res) => {
  try {
    const { code, role = 'member' } = req.body;
    const { data: group } = await supabase.from('groups').select('*').eq('code', code.toUpperCase()).eq('is_active', true).single();
    if (!group) return res.status(404).json({ error: 'الكود غير صحيح أو منتهي' });
    const { error } = await supabase.from('group_members').insert({ group_id: group.id, user_id: req.user.userId, role });
    if (error?.code === '23505') return res.status(409).json({ error: 'أنت بالفعل في هذه المجموعة' });
    res.json(group);
  } catch(e) { res.status(500).json({ error: 'حدث خطأ' }); }
});

// أعضاء المجموعة
app.get('/api/groups/:id/members', auth, async (req, res) => {
  const { data } = await supabase.from('group_members').select('role,joined_at,users(id,name,avatar,last_seen),member_locations(latitude,longitude,battery,status,updated_at)').eq('group_id', req.params.id);
  res.json(data || []);
});

// مجموعاتي
app.get('/api/groups/my', auth, async (req, res) => {
  const { data } = await supabase.from('group_members').select('role,groups(*)').eq('user_id', req.user.userId);
  res.json(data?.map(r => ({ ...r.groups, myRole: r.role })) || []);
});

// تنبيهات
app.get('/api/groups/:id/alerts', auth, async (req, res) => {
  const { data } = await supabase.from('alerts').select('*,users(name,avatar)').eq('group_id', req.params.id).order('created_at', { ascending: false }).limit(50);
  res.json(data || []);
});

// ══════════════════════════════════════════════════════════
// Socket.io
// ══════════════════════════════════════════════════════════
const live = new Map();

io.use(async (socket, next) => {
  try {
    const d = jwt.verify(socket.handshake.auth?.token, process.env.JWT_SECRET);
    const { data: u } = await supabase.from('users').select('id,name,avatar').eq('id', d.userId).single();
    if (!u) return next(new Error('غير موجود'));
    Object.assign(socket, { userId: u.id, userName: u.name, userAvatar: u.avatar });
    next();
  } catch { next(new Error('غير مصرح')); }
});

io.on('connection', socket => {
  console.log(`✅ ${socket.userName} connected`);

  socket.on('join_group', async ({ groupId }) => {
    const { data: m } = await supabase.from('group_members').select('role').eq('group_id', groupId).eq('user_id', socket.userId).single();
    if (!m) return socket.emit('error', { message: 'لست عضواً في هذه المجموعة' });
    Object.assign(socket, { groupId, userRole: m.role });
    socket.join(`group:${groupId}`);
    socket.to(`group:${groupId}`).emit('member_joined', { userId: socket.userId, name: socket.userName, avatar: socket.userAvatar, role: m.role });
    const snap = [];
    for (const [id, l] of live) if (l.groupId === groupId) snap.push({ userId: id, ...l });
    socket.emit('locations_snapshot', snap);
  });

  socket.on('location_update', async ({ latitude, longitude, accuracy, battery }) => {
    if (!socket.groupId) return;
    const l = { groupId: socket.groupId, name: socket.userName, avatar: socket.userAvatar, latitude, longitude, accuracy, battery, updatedAt: new Date().toISOString() };
    live.set(socket.userId, l);
    io.to(`group:${socket.groupId}`).emit('location_updated', { userId: socket.userId, ...l });

    const now = Date.now();
    if (!socket.lastSave || now - socket.lastSave > 10000) {
      socket.lastSave = now;
      const { data: g } = await supabase.from('groups').select('safe_radius').eq('id', socket.groupId).single();
      const radius = g?.safe_radius || 100;
      let status = 'safe';
      for (const [, loc] of live) {
        if (loc.groupId === socket.groupId && loc.role === 'leader') {
          const d = haversine(latitude, longitude, loc.latitude, loc.longitude);
          if (d > radius * 1.5) status = 'danger';
          else if (d > radius) status = 'warning';
          break;
        }
      }
      await supabase.from('member_locations').upsert({ user_id: socket.userId, group_id: socket.groupId, latitude, longitude, accuracy: accuracy||0, battery: battery||100, status, updated_at: new Date() }, { onConflict: 'user_id' });
      if (status === 'danger') {
        const msg = `⚠️ ${socket.userName} تجاوز نطاق الأمان`;
        await supabase.from('alerts').insert({ group_id: socket.groupId, user_id: socket.userId, type: 'danger', message: msg });
        io.to(`group:${socket.groupId}`).emit('safety_alert', { type: 'danger', userId: socket.userId, name: socket.userName, message: msg });
      }
    }
  });

  socket.on('sos_send', async ({ latitude, longitude }) => {
    if (!socket.groupId) return;
    const msg = `🆘 ${socket.userName} أرسل نداء استغاثة!`;
    const { data: sos } = await supabase.from('sos_events').insert({ sender_id: socket.userId, group_id: socket.groupId, latitude, longitude }).select().single();
    await supabase.from('alerts').insert({ group_id: socket.groupId, user_id: socket.userId, type: 'sos', message: msg });
    io.to(`group:${socket.groupId}`).emit('sos_received', { sosId: sos?.id, senderId: socket.userId, name: socket.userName, avatar: socket.userAvatar, latitude, longitude, message: msg });
  });

  socket.on('sos_respond', async ({ sosId }) => {
    await supabase.from('sos_responders').upsert({ sos_id: sosId, user_id: socket.userId }).catch(() => {});
    io.to(`group:${socket.groupId}`).emit('sos_response', { sosId, responderId: socket.userId, name: socket.userName, avatar: socket.userAvatar });
  });

  socket.on('sos_cancel', async ({ sosId }) => {
    if (sosId) await supabase.from('sos_events').update({ status: 'cancelled', resolved_at: new Date() }).eq('id', sosId).eq('sender_id', socket.userId);
    io.to(`group:${socket.groupId}`).emit('sos_cancelled', { userId: socket.userId, name: socket.userName });
  });

  socket.on('update_radius', async ({ radius }) => {
    if (!socket.groupId || socket.userRole !== 'leader') return;
    await supabase.from('groups').update({ safe_radius: radius }).eq('id', socket.groupId);
    io.to(`group:${socket.groupId}`).emit('radius_updated', { radius });
  });

  socket.on('disconnect', async () => {
    live.delete(socket.userId);
    if (socket.groupId) socket.to(`group:${socket.groupId}`).emit('member_left', { userId: socket.userId, name: socket.userName });
    await supabase.from('member_locations').update({ status: 'offline' }).eq('user_id', socket.userId).catch(() => {});
    await supabase.from('users').update({ last_seen: new Date() }).eq('id', socket.userId).catch(() => {});
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log(`🚀 EventPilot on port ${PORT}`));
