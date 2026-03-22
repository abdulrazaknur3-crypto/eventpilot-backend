require('dotenv').config();
const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const rateLimit  = require('express-rate-limit');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY, { auth:{ persistSession:false } });
const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: process.env.FRONTEND_URL||'*', methods:['GET','POST'] },
  pingTimeout:60000, pingInterval:25000, transports:['websocket','polling'],
});

app.use(cors({ origin: process.env.FRONTEND_URL||'*' }));
app.use(express.json({ limit:'1mb' }));
app.use('/api/auth/',    rateLimit({ windowMs:15*60*1000, max:20,  message:{ error:'كثير من المحاولات' } }));
app.use('/api/',         rateLimit({ windowMs:15*60*1000, max:300, message:{ error:'تجاوزت الحد' } }));

const sign = (id) => jwt.sign({ userId:id }, process.env.JWT_SECRET, { expiresIn:'30d' });
const auth = (req,res,next) => {
  const t = req.headers.authorization?.replace('Bearer ','');
  if (!t) return res.status(401).json({ error:'غير مصرح' });
  try { req.user = jwt.verify(t, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error:'جلسة منتهية' }); }
};
const genCode = () => {
  const n=String(Math.floor(Math.random()*9000)+1000);
  const c='ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; let p='';
  for(let i=0;i<4;i++) p+=c[Math.floor(Math.random()*c.length)];
  return `EP-${n}-${p}`;
};
const haversine = (a,b,c,d) => {
  const R=6371000,dL=(c-a)*Math.PI/180,dG=(d-b)*Math.PI/180;
  const x=Math.sin(dL/2)**2+Math.cos(a*Math.PI/180)*Math.cos(c*Math.PI/180)*Math.sin(dG/2)**2;
  return R*2*Math.atan2(Math.sqrt(x),Math.sqrt(1-x));
};

const PKG = {
  free:      { maxMembers:5,   trackHistory:false, analyticsRetention:1  },
  family:    { maxMembers:10,  trackHistory:true,  analyticsRetention:7  },
  pro:       { maxMembers:50,  trackHistory:true,  analyticsRetention:30 },
  enterprise:{ maxMembers:500, trackHistory:true,  analyticsRetention:90 },
};

const PLANS = {
  family:      { price:29,  label:'عائلي',          months:1  },
  family_year: { price:249, label:'عائلي سنوي',      months:12 },
  pro:         { price:79,  label:'احترافي',         months:1  },
  pro_year:    { price:699, label:'احترافي سنوي',    months:12 },
};

async function logEvent(groupId, userId, eventType, metadata={}) {
  await supabase.from('analytics_events').insert({
    group_id:eventId, user_id:userId, event_type:eventType,
    metadata:JSON.stringify(metadata), created_at:new Date(),
  }).catch(()=>{});
}

// ── Health ──────────────────────────────────────────────────────────────────
app.get('/', (_,res) => res.json({ status:'✅ EventPilot API v2.0', uptime:Math.round(process.uptime()) }));

// ── Auth ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req,res) => {
  try {
    const { name, phone, password, avatar='👤' } = req.body;
    if (!name||!phone||!password) return res.status(400).json({ error:'جميع الحقول مطلوبة' });
    const hash = await bcrypt.hash(password, 10);
    const { data, error } = await supabase.from('users')
      .insert({ name:name.trim(), phone:phone.trim(), password:hash, avatar, package:'free' })
      .select('id,name,phone,avatar,package').single();
    if (error) {
      if (error.code==='23505') return res.status(409).json({ error:'رقم الجوال مسجّل مسبقاً' });
      throw error;
    }
    res.status(201).json({ user:data, token:sign(data.id) });
  } catch(e) { console.error('[register]',e.message); res.status(500).json({ error:'حدث خطأ' }); }
});

app.post('/api/auth/login', async (req,res) => {
  try {
    const { phone, password } = req.body;
    const { data:user } = await supabase.from('users').select('*').eq('phone',phone.trim()).single();
    if (!user||!await bcrypt.compare(password,user.password))
      return res.status(401).json({ error:'رقم الجوال أو كلمة المرور خاطئة' });
    await supabase.from('users').update({ last_seen:new Date() }).eq('id',user.id);
    const { password:_,...safe } = user;
    res.json({ user:safe, token:sign(user.id) });
  } catch(e) { res.status(500).json({ error:'حدث خطأ' }); }
});

app.get('/api/auth/me', auth, async (req,res) => {
  const { data } = await supabase.from('users')
    .select('id,name,phone,avatar,package,subscription_end,created_at')
    .eq('id',req.user.userId).single();
  res.json({ ...data, limits:PKG[data?.package]||PKG.free });
});

// ── Groups ────────────────────────────────────────────────────────────────────
app.post('/api/groups/create', auth, async (req,res) => {
  try {
    const { name, eventName, eventLoc, safeRadius=100, leaderLat, leaderLng } = req.body;
    if (!name) return res.status(400).json({ error:'اسم المجموعة مطلوب' });
    const code = genCode();
    const { data:group, error } = await supabase.from('groups').insert({
      code, name:name.trim(), event_name:eventName, event_loc:eventLoc,
      creator_id:req.user.userId, safe_radius:safeRadius,
      leader_lat:leaderLat, leader_lng:leaderLng, is_active:true,
    }).select().single();
    if (error) throw error;
    await supabase.from('group_members').insert({ group_id:group.id, user_id:req.user.userId, role:'leader' });
    res.status(201).json({ ...group, myRole:'leader' });
  } catch(e) { console.error('[create]',e.message); res.status(500).json({ error:'خطأ في الإنشاء' }); }
});

app.post('/api/groups/join', auth, async (req,res) => {
  try {
    const { code, role='member' } = req.body;
    const { data:group } = await supabase.from('groups').select('*').eq('code',code.toUpperCase().trim()).eq('is_active',true).single();
    if (!group) return res.status(404).json({ error:'الكود غير صحيح أو المجموعة منتهية' });
    const { data:creator } = await supabase.from('users').select('package').eq('id',group.creator_id).single();
    const pkg = PKG[creator?.package]||PKG.free;
    const { count } = await supabase.from('group_members').select('*',{count:'exact',head:true}).eq('group_id',group.id);
    if (count >= pkg.maxMembers)
      return res.status(403).json({ error:`المجموعة ممتلئة (${pkg.maxMembers} أعضاء) — ترقية الباقة مطلوبة` });
    const { error } = await supabase.from('group_members').insert({ group_id:group.id, user_id:req.user.userId, role });
    if (error?.code==='23505') return res.status(409).json({ error:'أنت بالفعل في هذه المجموعة' });
    res.json({ ...group, myRole:role });
  } catch(e) { console.error('[join]',e.message); res.status(500).json({ error:'حدث خطأ' }); }
});

app.get('/api/groups/:id/members', auth, async (req,res) => {
  const { data } = await supabase.from('group_members')
    .select('role,joined_at,users(id,name,avatar,last_seen),member_locations(latitude,longitude,battery,status,updated_at)')
    .eq('group_id',req.params.id);
  res.json(data||[]);
});

app.get('/api/groups/my', auth, async (req,res) => {
  const { data } = await supabase.from('group_members')
    .select('role,groups(id,code,name,safe_radius,is_active,created_at,event_loc,event_name)')
    .eq('user_id',req.user.userId);
  const groups = await Promise.all((data||[]).map(async r => {
    if (!r.groups) return null;
    const { count } = await supabase.from('group_members').select('*',{count:'exact',head:true}).eq('group_id',r.groups.id);
    return { ...r.groups, myRole:r.role, member_count:count||0 };
  }));
  res.json(groups.filter(Boolean));
});

app.post('/api/groups/:id/locations/batch', auth, async (req,res) => {
  try {
    const { locations } = req.body;
    if (!Array.isArray(locations)||!locations.length) return res.json({ ok:true, saved:0 });
    const last = locations[locations.length-1];
    await supabase.from('member_locations').upsert({
      user_id:req.user.userId, group_id:req.params.id,
      latitude:last.latitude, longitude:last.longitude,
      accuracy:last.accuracy||0, battery:last.battery||100,
      status:'safe', updated_at:new Date(),
    },{ onConflict:'user_id' });
    res.json({ ok:true, saved:locations.length });
  } catch(e) { res.status(500).json({ error:'خطأ' }); }
});

// ── Payments ──────────────────────────────────────────────────────────────────
app.post('/api/payments/initiate', auth, async (req,res) => {
  try {
    const { plan } = req.body;
    const p = PLANS[plan];
    if (!p) return res.status(400).json({ error:'الباقة غير موجودة' });
    const ref = `EP-${Date.now()}-${req.user.userId.slice(0,8)}`;
    await supabase.from('payments').insert({ user_id:req.user.userId, plan, amount:p.price, currency:'SAR', status:'pending', reference:ref });

    if (process.env.MOYASAR_API_KEY) {
      const r = await fetch('https://api.moyasar.com/v1/payments', {
        method:'POST',
        headers:{ 'Content-Type':'application/json', 'Authorization':'Basic '+Buffer.from(process.env.MOYASAR_API_KEY+':').toString('base64') },
        body: JSON.stringify({ amount:p.price*100, currency:'SAR', description:`EventPilot - باقة ${p.label}`,
          callback_url:`${process.env.BACKEND_URL||'https://web-production-fc375.up.railway.app'}/api/payments/callback`,
          source:{ type:'creditcard' }, metadata:{ userId:req.user.userId, plan, ref } }),
      });
      const d = await r.json();
      if (d.id) {
        await supabase.from('payments').update({ provider_id:d.id }).eq('reference',ref);
        return res.json({ url:d.source?.transaction_url, ref, provider:'moyasar' });
      }
    }

    res.json({ ref, plan, amount:p.price, label:p.label, months:p.months,
      message:'تواصل معنا على واتساب لإتمام الدفع',
      whatsapp:`https://wa.me/966500000000?text=${encodeURIComponent(`طلب اشتراك ${p.label} - REF: ${ref}`)}`,
      provider:'manual' });
  } catch(e) { res.status(500).json({ error:'خطأ في الدفع' }); }
});

app.post('/api/payments/callback', async (req,res) => {
  try {
    const { id, status, metadata } = req.body;
    if (status!=='paid') { await supabase.from('payments').update({ status:'failed' }).eq('provider_id',id); return res.json({ ok:true }); }
    const { userId, plan } = metadata||{};
    if (!userId||!plan) return res.status(400).json({ error:'missing' });
    const p = PLANS[plan]; const pkg = plan.replace('_year','');
    const end = new Date(); end.setMonth(end.getMonth()+(p?.months||1));
    await supabase.from('users').update({ package:pkg, subscription_end:end }).eq('id',userId);
    await supabase.from('payments').update({ status:'paid', paid_at:new Date() }).eq('provider_id',id);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/payments/activate', auth, async (req,res) => {
  try {
    const { targetUserId, plan, adminKey } = req.body;
    if (adminKey!==process.env.ADMIN_KEY) return res.status(403).json({ error:'غير مصرح' });
    const p = PLANS[plan]; const pkg = plan.replace('_year','');
    const end = new Date(); end.setMonth(end.getMonth()+(p?.months||1));
    await supabase.from('users').update({ package:pkg, subscription_end:end }).eq('id',targetUserId);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('/api/payments/status', auth, async (req,res) => {
  const { data:u } = await supabase.from('users').select('package,subscription_end').eq('id',req.user.userId).single();
  const active = u?.subscription_end ? new Date(u.subscription_end)>new Date() : u?.package==='free';
  res.json({ package:u?.package||'free', active, expires:u?.subscription_end, limits:PKG[u?.package]||PKG.free });
});

// ── Analytics ─────────────────────────────────────────────────────────────────
app.get('/api/analytics/group/:id', auth, async (req,res) => {
  try {
    const gid = req.params.id;
    const { data:mem } = await supabase.from('group_members').select('role').eq('group_id',gid).eq('user_id',req.user.userId).single();
    if (mem?.role!=='leader') return res.status(403).json({ error:'للقائد فقط' });

    const [mRes, aRes, sRes] = await Promise.all([
      supabase.from('group_members').select('role,joined_at,users(name,avatar,last_seen),member_locations(status,battery,latitude,longitude,updated_at)').eq('group_id',gid),
      supabase.from('alerts').select('type,message,created_at').eq('group_id',gid).order('created_at',{ascending:false}).limit(100),
      supabase.from('sos_events').select('sender_id,created_at,status').eq('group_id',gid).limit(50),
    ]);

    const members = mRes.data||[], alerts = aRes.data||[], sos = sRes.data||[];
    const now = Date.now();
    const online = members.filter(m=>m.member_locations?.updated_at&&(now-new Date(m.member_locations.updated_at).getTime())<5*60*1000);
    const alertsByHour = {};
    alerts.forEach(a=>{ const h=new Date(a.created_at).getHours(); alertsByHour[h]=(alertsByHour[h]||0)+1; });

    res.json({
      summary:{ totalMembers:members.length, onlineNow:online.length, totalAlerts:alerts.length,
        dangerAlerts:alerts.filter(a=>a.type==='danger').length, sosEvents:sos.length },
      members:members.map(m=>({ name:m.users?.name, avatar:m.users?.avatar, role:m.role,
        status:m.member_locations?.status, battery:m.member_locations?.battery,
        lastSeen:m.users?.last_seen, locationAt:m.member_locations?.updated_at })),
      alerts:alerts.slice(0,20), alertsByHour, sosEvents:sos,
      lowBattery:members.filter(m=>m.member_locations?.battery<20).map(m=>({ name:m.users?.name, battery:m.member_locations?.battery })),
      heatmapPoints:members.filter(m=>m.member_locations?.latitude).map(m=>({
        lat:m.member_locations.latitude, lng:m.member_locations.longitude,
        weight:m.member_locations.status==='danger'?3:1 })),
    });
  } catch(e) { console.error('[analytics]',e.message); res.status(500).json({ error:'خطأ' }); }
});

app.get('/api/analytics/me', auth, async (req,res) => {
  try {
    const { data:grps } = await supabase.from('group_members').select('role,group_id,groups(name,code,created_at,is_active)').eq('user_id',req.user.userId).eq('role','leader');
    const stats = await Promise.all((grps||[]).map(async r => {
      const gid = r.group_id;
      const [{ count:mc },{ count:ac },{ count:sc }] = await Promise.all([
        supabase.from('group_members').select('*',{count:'exact',head:true}).eq('group_id',gid),
        supabase.from('alerts').select('*',{count:'exact',head:true}).eq('group_id',gid),
        supabase.from('sos_events').select('*',{count:'exact',head:true}).eq('group_id',gid),
      ]);
      return { ...r.groups, members:mc, alerts:ac, sos:sc };
    }));
    const { data:u } = await supabase.from('users').select('package,subscription_end,created_at').eq('id',req.user.userId).single();
    res.json({ account:{ package:u?.package, expires:u?.subscription_end, since:u?.created_at, limits:PKG[u?.package]||PKG.free },
      groups:stats, totals:{ groups:stats.length, members:stats.reduce((s,g)=>s+g.members,0),
      alerts:stats.reduce((s,g)=>s+g.alerts,0), sos:stats.reduce((s,g)=>s+g.sos,0) } });
  } catch(e) { res.status(500).json({ error:'خطأ' }); }
});

// ── Socket.io ─────────────────────────────────────────────────────────────────
const live = new Map();

io.use(async (socket,next) => {
  try {
    const d = jwt.verify(socket.handshake.auth?.token, process.env.JWT_SECRET);
    const { data:u } = await supabase.from('users').select('id,name,avatar').eq('id',d.userId).single();
    if (!u) return next(new Error('غير موجود'));
    Object.assign(socket, { userId:u.id, userName:u.name, userAvatar:u.avatar });
    next();
  } catch { next(new Error('غير مصرح')); }
});

io.on('connection', socket => {
  console.log(`✅ ${socket.userName} connected`);

  socket.on('join_group', async ({ groupId }) => {
    const { data:m } = await supabase.from('group_members').select('role').eq('group_id',groupId).eq('user_id',socket.userId).single();
    if (!m) return socket.emit('error',{ message:'لست عضواً' });
    Object.assign(socket,{ groupId, userRole:m.role });
    socket.join(`group:${groupId}`);
    socket.to(`group:${groupId}`).emit('member_joined',{ userId:socket.userId, name:socket.userName, avatar:socket.userAvatar, role:m.role });
    const snap=[]; for(const [id,l] of live) if(l.groupId===groupId) snap.push({ userId:id,...l });
    socket.emit('locations_snapshot',snap);
  });

  socket.on('location_update', async ({ latitude, longitude, accuracy, battery }) => {
    if (!socket.groupId||typeof latitude!=='number') return;
    const loc={ groupId:socket.groupId, name:socket.userName, avatar:socket.userAvatar, role:socket.userRole,
      latitude, longitude, accuracy:accuracy||10, battery:battery||100, updatedAt:new Date().toISOString() };
    live.set(socket.userId, loc);
    io.to(`group:${socket.groupId}`).emit('location_updated',{ userId:socket.userId,...loc });

    const now=Date.now();
    if (!socket.lastSave||now-socket.lastSave>10000) {
      socket.lastSave=now;
      try {
        const { data:g } = await supabase.from('groups').select('safe_radius').eq('id',socket.groupId).single();
        const radius=g?.safe_radius||100; let status='safe', dist=0;
        for(const [,l] of live) {
          if(l.groupId===socket.groupId&&l.role==='leader'&&l.latitude) {
            dist=haversine(latitude,longitude,l.latitude,l.longitude);
            if(dist>radius*1.5) status='danger'; else if(dist>radius) status='warning'; break;
          }
        }
        await supabase.from('member_locations').upsert({ user_id:socket.userId, group_id:socket.groupId,
          latitude, longitude, accuracy:accuracy||0, battery:battery||100, status, updated_at:new Date() },{ onConflict:'user_id' });
        if(status==='danger') {
          const msg=`🚨 ${socket.userName} خرج عن نطاق الأمان`;
          await supabase.from('alerts').insert({ group_id:socket.groupId, user_id:socket.userId, type:'danger', message:msg });
          io.to(`group:${socket.groupId}`).emit('safety_alert',{ type:'danger', userId:socket.userId, name:socket.userName, message:msg });
        }
      } catch(e) { console.error('[loc_save]',e.message); }
    }
  });

  socket.on('sos_send', async ({ latitude, longitude }) => {
    if (!socket.groupId) return;
    const msg=`🆘 ${socket.userName} أرسل نداء استغاثة!`;
    const { data:sos } = await supabase.from('sos_events').insert({ sender_id:socket.userId, group_id:socket.groupId, latitude, longitude, status:'active' }).select().single();
    await supabase.from('alerts').insert({ group_id:socket.groupId, user_id:socket.userId, type:'sos', message:msg });
    io.to(`group:${socket.groupId}`).emit('sos_received',{ sosId:sos?.id, senderId:socket.userId, name:socket.userName, avatar:socket.userAvatar, latitude, longitude, message:msg });
  });

  socket.on('sos_respond', async ({ sosId }) => {
    if (!socket.groupId) return;
    await supabase.from('sos_responders').upsert({ sos_id:sosId, user_id:socket.userId }).catch(()=>{});
    await supabase.from('sos_events').update({ status:'responded' }).eq('id',sosId).catch(()=>{});
    io.to(`group:${socket.groupId}`).emit('sos_response',{ sosId, responderId:socket.userId, name:socket.userName, avatar:socket.userAvatar });
  });

  socket.on('sos_cancel', async ({ sosId }) => {
    if (!socket.groupId) return;
    if(sosId) await supabase.from('sos_events').update({ status:'cancelled', resolved_at:new Date() }).eq('id',sosId).eq('sender_id',socket.userId).catch(()=>{});
    io.to(`group:${socket.groupId}`).emit('sos_cancelled',{ userId:socket.userId, name:socket.userName });
  });

  socket.on('update_radius', async ({ radius }) => {
    if (!socket.groupId||socket.userRole!=='leader'||radius<50||radius>5000) return;
    await supabase.from('groups').update({ safe_radius:radius }).eq('id',socket.groupId).catch(()=>{});
    io.to(`group:${socket.groupId}`).emit('radius_updated',{ radius });
  });

  socket.on('disconnect', async () => {
    live.delete(socket.userId);
    if(socket.groupId) socket.to(`group:${socket.groupId}`).emit('member_left',{ userId:socket.userId, name:socket.userName });
    await supabase.from('member_locations').update({ status:'offline' }).eq('user_id',socket.userId).catch(()=>{});
    await supabase.from('users').update({ last_seen:new Date() }).eq('id',socket.userId).catch(()=>{});
    console.log(`👋 ${socket.userName} disconnected`);
  });
});

const PORT = process.env.PORT||3001;
server.listen(PORT, () => {
  console.log(`🚀 EventPilot API v2.0 — port ${PORT}`);
  console.log(`   Supabase: ${process.env.SUPABASE_URL?'✅':'❌'}`);
  console.log(`   Moyasar:  ${process.env.MOYASAR_API_KEY?'✅':'⚠️ manual'}`);
});
