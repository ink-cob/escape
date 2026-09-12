const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost')
    ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-please-very-long-string-min-40-chars';
const TOKEN_MINUTES = 10;
const PREMIUM_DAYS_PER_30_TOKENS = 30;

function todayLocal() {
  const d = new Date();
  return d.getFullYear() + '-' +
    String(d.getMonth() + 1).padStart(2, '0') + '-' +
    String(d.getDate()).padStart(2, '0');
}

function auth(req, res, next) {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  if (!t) return res.status(401).json({ error: 'Нет токена' });
  try {
    req.userId = jwt.verify(t, JWT_SECRET).userId;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Неверный токен' });
  }
}

async function isAdminUser(userId) {
  const r = await pool.query('SELECT is_admin FROM users WHERE id=$1', [userId]);
  return !!(r.rows[0] && r.rows[0].is_admin);
}

/* ═══════════════════════════════════════════════
   AUTH
   ═══════════════════════════════════════════════ */

app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || username.length < 3)
    return res.status(400).json({ error: 'Логин минимум 3 символа' });
  if (!password || password.length < 6)
    return res.status(400).json({ error: 'Пароль минимум 6 символов' });

  try {
    const ex = await pool.query(
      'SELECT id FROM users WHERE LOWER(username)=LOWER($1)', [username]);
    if (ex.rows.length) return res.status(400).json({ error: 'Логин занят' });

    const hash = await bcrypt.hash(password, 10);
    const c = await pool.query('SELECT COUNT(*) as c FROM users');
    const isAdmin = parseInt(c.rows[0].c, 10) === 0;

    const r = await pool.query(
      'INSERT INTO users (username, password_hash, is_admin) VALUES ($1,$2,$3) RETURNING id',
      [username, hash, isAdmin]
    );
    const token = jwt.sign({ userId: r.rows[0].id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, userId: r.rows[0].id, isAdmin });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const r = await pool.query(
      'SELECT * FROM users WHERE LOWER(username)=LOWER($1)', [username]);
    if (!r.rows.length) return res.status(400).json({ error: 'Неверный логин или пароль' });
    const u = r.rows[0];
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(400).json({ error: 'Неверный логин или пароль' });
    if (u.blocked_until && new Date(u.blocked_until) > new Date())
      return res.status(403).json({ error: 'Забанен: ' + (u.block_reason || '') });

    const token = jwt.sign({ userId: u.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, userId: u.id, isAdmin: !!u.is_admin });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════════════════════════════════════════
   USERS
   ═══════════════════════════════════════════════ */

app.get('/api/users', auth, async (req, res) => {
  const r = await pool.query(`
    SELECT id, username, avatar_url, description, phone, last_seen,
           is_admin, is_flagged, hidden, premium, premium_until,
           custom_status, blocked_until, block_reason, tokens,
           gallery_urls, is_donor, show_donor_badge, donated_total
    FROM users
  `);
  res.json(r.rows);
});

app.get('/api/users/me', auth, async (req, res) => {
  const r = await pool.query(`
    SELECT id, username, avatar_url, description, phone, last_seen,
           is_admin, is_flagged, hidden, premium, premium_until,
           custom_status, tokens, minutes_today, last_activity_date,
           token_given_date, gallery_urls, is_donor, show_donor_badge, donated_total
    FROM users WHERE id=$1`, [req.userId]);
  if (!r.rows.length) return res.status(404).json({ error: 'Нет пользователя' });
  res.json(r.rows[0]);
});

app.put('/api/users/me', auth, async (req, res) => {
  const { username, description, phone, avatar_url, custom_status, gallery_urls } = req.body;
  try {
    if (username) {
      const ex = await pool.query(
        'SELECT id FROM users WHERE LOWER(username)=LOWER($1) AND id<>$2',
        [username, req.userId]);
      if (ex.rows.length) return res.status(400).json({ error: 'Логин занят' });
    }
    await pool.query(`
      UPDATE users SET
        username=COALESCE($1,username),
        description=COALESCE($2,description),
        phone=COALESCE($3,phone),
        avatar_url=COALESCE($4,avatar_url),
        custom_status=COALESCE($5,custom_status),
        gallery_urls=COALESCE($6,gallery_urls)
      WHERE id=$7`,
      [username || null, description, phone, avatar_url, custom_status,
       gallery_urls ? JSON.stringify(gallery_urls) : null, req.userId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/users/me/donor-badge', auth, async (req, res) => {
  const { show } = req.body;
  try {
    await pool.query(
      'UPDATE users SET show_donor_badge = $1 WHERE id = $2',
      [!!show, req.userId]);
    res.json({ ok: true, show: !!show });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════════════════════════════════════════
   PRESENCE + TOKENS
   ═══════════════════════════════════════════════ */

app.post('/api/presence', auth, async (req, res) => {
  try {
    const today = todayLocal();
    const u = await pool.query(
      'SELECT minutes_today, last_activity_date, token_given_date, tokens FROM users WHERE id=$1',
      [req.userId]);
    if (!u.rows.length) return res.status(404).json({ error: 'Нет пользователя' });

    const row = u.rows[0];
    const lastDate = row.last_activity_date
      ? row.last_activity_date.toISOString().slice(0, 10) : null;
    const tokenDate = row.token_given_date
      ? row.token_given_date.toISOString().slice(0, 10) : null;

    let minutes = (lastDate === today) ? (row.minutes_today || 0) : 0;
    minutes += 1;

    let tokens = row.tokens || 0;
    let earnedNow = false;
    let newTokenDate = tokenDate;

    if (minutes >= TOKEN_MINUTES && tokenDate !== today) {
      tokens += 1;
      newTokenDate = today;
      earnedNow = true;
      await pool.query(
        'INSERT INTO token_transactions (user_id, amount, reason) VALUES ($1,$2,$3)',
        [req.userId, 1, 'Ежедневный бонус за 10 минут']);
    }

    await pool.query(`
      UPDATE users SET
        last_seen = NOW(),
        minutes_today = $1,
        last_activity_date = $2,
        tokens = $3,
        token_given_date = $4
      WHERE id = $5`,
      [minutes, today, tokens, newTokenDate, req.userId]);

    res.json({
      tokens, minutes,
      minutesLeft: Math.max(0, TOKEN_MINUTES - minutes),
      earnedNow,
      tokenGivenToday: newTokenDate === today
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/tokens/balance', auth, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT tokens, minutes_today, last_activity_date, token_given_date FROM users WHERE id=$1',
      [req.userId]);
    const row = r.rows[0] || {};
    const today = todayLocal();
    const lastDate = row.last_activity_date
      ? row.last_activity_date.toISOString().slice(0, 10) : null;
    const minutes = (lastDate === today) ? (row.minutes_today || 0) : 0;
    const tokenDate = row.token_given_date
      ? row.token_given_date.toISOString().slice(0, 10) : null;

    res.json({
      tokens: row.tokens || 0,
      minutes,
      minutesLeft: Math.max(0, TOKEN_MINUTES - minutes),
      tokenGivenToday: tokenDate === today
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════════════════════════════════════════
   PREMIUM за токены
   ═══════════════════════════════════════════════ */

app.post('/api/premium/purchase', auth, async (req, res) => {
  const { target_user_id, days } = req.body;
  const d = parseInt(days, 10);
  if (!d || d < 1 || d > 3650)
    return res.status(400).json({ error: 'Дней от 1 до 3650' });

  const cost = Math.ceil(d / PREMIUM_DAYS_PER_30_TOKENS * 30);
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const me = await client.query(
      'SELECT tokens FROM users WHERE id=$1 FOR UPDATE', [req.userId]);
    if (!me.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Покупатель не найден' });
    }
    const balance = me.rows[0].tokens || 0;
    if (balance < cost) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: `Не хватает токенов. Нужно ${cost}, у тебя ${balance}`
      });
    }

    const targetId = target_user_id || req.userId;
    const t = await client.query(
      'SELECT id, username, premium_until FROM users WHERE id=$1 FOR UPDATE',
      [targetId]);
    if (!t.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Получатель не найден' });
    }

    const curUntil = t.rows[0].premium_until;
    const now = new Date();
    const base = (curUntil && new Date(curUntil) > now) ? new Date(curUntil) : now;
    const newUntil = new Date(base.getTime() + d * 86400000);

    await client.query(
      'UPDATE users SET premium=TRUE, premium_until=$1 WHERE id=$2',
      [newUntil.toISOString(), targetId]);
    await client.query(
      'UPDATE users SET tokens = tokens - $1 WHERE id=$2',
      [cost, req.userId]);
    await client.query(
      'INSERT INTO token_transactions (user_id, amount, reason) VALUES ($1,$2,$3)',
      [req.userId, -cost, `Premium ${d} дн. для ${t.rows[0].username}`]);

    await client.query('COMMIT');
    res.json({
      ok: true, cost,
      newUntil: newUntil.toISOString(),
      targetUsername: t.rows[0].username
    });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

/* ═══════════════════════════════════════════════
   DONATIONS — становятся донатерами
   ═══════════════════════════════════════════════ */

app.post('/api/donations', auth, async (req, res) => {
  const { amount, contact, message } = req.body;
  const a = parseInt(amount, 10);
  if (!a || a < 10) return res.status(400).json({ error: 'Минимум 10 ₽' });
  if (!contact) return res.status(400).json({ error: 'Укажи контакт для связи' });

  try {
    await pool.query(
      'INSERT INTO donations (user_id, amount, contact, message) VALUES ($1,$2,$3,$4)',
      [req.userId, a, contact, message || '']);
    await pool.query(
      'UPDATE users SET is_donor = TRUE, show_donor_badge = TRUE, donated_total = donated_total + $1 WHERE id = $2',
      [a, req.userId]);
    res.json({
      ok: true,
      message: 'Спасибо! Тебе открыт значок ❤️ донатера.'
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════════════════════════════════════════
   CHATS
   ═══════════════════════════════════════════════ */

app.get('/api/chats', auth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT c.*, array_agg(cm.user_id) as member_ids
      FROM chats c
      JOIN chat_members cm ON cm.chat_id = c.id
      WHERE c.id IN (SELECT chat_id FROM chat_members WHERE user_id=$1)
      GROUP BY c.id`, [req.userId]);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/chats', auth, async (req, res) => {
  const { name, type, members } = req.body;
  try {
    const r = await pool.query(
      'INSERT INTO chats (name, type, owner_id) VALUES ($1,$2,$3) RETURNING id',
      [name, type || 'private', req.userId]);
    const id = r.rows[0].id;
    const all = [...new Set([req.userId, ...(members || [])])];
    for (const uid of all) {
      await pool.query(
        'INSERT INTO chat_members (chat_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [id, uid]);
    }
    res.json({ id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════════════════════════════════════════
   MESSAGES
   ═══════════════════════════════════════════════ */

app.get('/api/messages/:chatId', auth, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT * FROM messages WHERE chat_id=$1 ORDER BY created_at ASC',
      [req.params.chatId]);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/messages', auth, async (req, res) => {
  const { chat_id, text, reply_to } = req.body;
  try {
    const r = await pool.query(
      'INSERT INTO messages (chat_id, sender_id, text, reply_to) VALUES ($1,$2,$3,$4) RETURNING id',
      [chat_id, req.userId, text, reply_to || null]);
    res.json({ id: r.rows[0].id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/messages/:id', auth, async (req, res) => {
  const { text, reactions, deleted_for_all } = req.body;
  try {
    if (reactions !== undefined) {
      await pool.query('UPDATE messages SET reactions=$1 WHERE id=$2',
        [JSON.stringify(reactions), req.params.id]);
    } else if (deleted_for_all) {
      await pool.query('UPDATE messages SET deleted_for_all=TRUE WHERE id=$1',
        [req.params.id]);
    } else {
      await pool.query('UPDATE messages SET text=$1, edited=TRUE WHERE id=$2',
        [text, req.params.id]);
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════════════════════════════════════════
   FRIENDSHIPS
   ═══════════════════════════════════════════════ */

app.get('/api/friendships', auth, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT * FROM friendships WHERE user_a=$1 OR user_b=$1', [req.userId]);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/friendships', auth, async (req, res) => {
  const { user_id } = req.body;
  const a = Math.min(req.userId, user_id);
  const b = Math.max(req.userId, user_id);
  try {
    await pool.query(
      'INSERT INTO friendships (user_a, user_b, status, requested_by) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING',
      [a, b, 'pending', req.userId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/friendships/:id', auth, async (req, res) => {
  try {
    await pool.query('UPDATE friendships SET status=$1 WHERE id=$2',
      [req.body.status, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/friendships/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM friendships WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════════════════════════════════════════
   ADMIN
   ═══════════════════════════════════════════════ */

app.get('/api/admin/purchases', auth, async (req, res) => {
  if (!(await isAdminUser(req.userId)))
    return res.status(403).json({ error: 'Только админ' });
  const r = await pool.query(`
    SELECT pr.*, u.username FROM purchase_requests pr
    JOIN users u ON u.id=pr.user_id
    WHERE pr.status='pending'
    ORDER BY pr.created_at DESC`);
  res.json(r.rows);
});

app.post('/api/admin/credit-tokens', auth, async (req, res) => {
  if (!(await isAdminUser(req.userId)))
    return res.status(403).json({ error: 'Только админ' });
  const { user_id, amount, request_id } = req.body;
  const a = parseInt(amount, 10);
  if (!a) return res.status(400).json({ error: 'Неверное количество' });
  try {
    await pool.query('UPDATE users SET tokens = tokens + $1 WHERE id=$2', [a, user_id]);
    await pool.query(
      'INSERT INTO token_transactions (user_id, amount, reason) VALUES ($1,$2,$3)',
      [user_id, a, 'Начислено админом']);
    if (request_id) {
      await pool.query('UPDATE purchase_requests SET status=$1 WHERE id=$2',
        ['done', request_id]);
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/donations', auth, async (req, res) => {
  if (!(await isAdminUser(req.userId)))
    return res.status(403).json({ error: 'Только админ' });
  const r = await pool.query(`
    SELECT d.*, u.username FROM donations d
    LEFT JOIN users u ON u.id=d.user_id
    ORDER BY d.created_at DESC`);
  res.json(r.rows);
});

app.put('/api/admin/users/:id', auth, async (req, res) => {
  if (!(await isAdminUser(req.userId)))
    return res.status(403).json({ error: 'Только админ' });
  const allowed = ['is_admin','is_flagged','hidden','premium','premium_until',
                   'blocked_until','block_reason','admin_notes','tokens',
                   'is_donor','show_donor_badge','donated_total'];
  const updates = []; const vals = []; let i = 1;
  for (const k of allowed) {
    if (req.body[k] !== undefined) {
      updates.push(`${k}=$${i++}`);
      vals.push(req.body[k]);
    }
  }
  if (!updates.length) return res.json({ ok: true });
  vals.push(req.params.id);
  try {
    await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id=$${i}`, vals);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/users/:id', auth, async (req, res) => {
  if (!(await isAdminUser(req.userId)))
    return res.status(403).json({ error: 'Только админ' });
  try {
    await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════════════════════════════════════════
   ROOT
   ═══════════════════════════════════════════════ */

app.get('/', (req, res) => res.json({
  ok: true, service: 'Ink API',
  time: new Date().toISOString()
}));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Ink API on :' + PORT));