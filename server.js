const express = require('express');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// Ensure data directory exists before connecting to DB
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const DATA_FILE = path.join(dataDir, 'content.json');
const DB_FILE = path.join(dataDir, 'users.db');
const db = new sqlite3.Database(DB_FILE);

function isRemoteImageUrl(url) {
  return typeof url === 'string' && /^https?:\/\//i.test(url);
}

function proxiedImageUrl(url) {
  if (!url) return '';
  if (!isRemoteImageUrl(url)) return url;
  return `/image-proxy?url=${encodeURIComponent(url)}`;
}

function normalizeListingForClient(listing) {
  const image = listing.image ? proxiedImageUrl(listing.image) : listing.image;
  const images = Array.isArray(listing.images)
    ? listing.images.map(proxiedImageUrl)
    : [];
  return { ...listing, image, images };
}

// INCREASED LIMIT TO 50MB FOR DIRECT BASE64 IMAGE STORAGE
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'rentwise-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// ── MIDDLEWARE ─────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.user) {
    if (req.originalUrl.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
    return res.redirect('/?login=1');
  }
  next();
}

function requireRole(allowedRoles) {
  return (req, res, next) => {
    if (!req.session.user) {
      if (req.originalUrl.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
      return res.redirect('/?login=1');
    }
    if (!allowedRoles.includes(req.session.user.role)) {
      if (req.originalUrl.startsWith('/api/')) return res.status(403).json({ error: 'Access denied' });
      return res.status(403).send('Access denied');
    }
    next();
  };
}

app.use((req, res, next) => {
  const protectedFiles = {
    '/dashboard.html': ['renter', 'provider'],
    '/provider-dashboard.html': ['provider'],
    '/booking.html': ['renter', 'provider'],
  };
  if (protectedFiles[req.path]) {
    if (!req.session.user) return res.redirect('/?login=1');
    if (!protectedFiles[req.path].includes(req.session.user.role)) return res.redirect('/?login=1');
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ── INIT DATABASE ──────────────────────────────────────────────────────────────
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'renter',
    display_name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS listings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    price INTEGER DEFAULT 0,
    location TEXT,
    size TEXT DEFAULT 'Medium',
    description TEXT,
    image TEXT, /* Stores raw Base64 string */
    images TEXT DEFAULT '[]',
    badge TEXT DEFAULT 'New',
    badgeType TEXT DEFAULT 'default',
    tags TEXT DEFAULT '[]',
    features TEXT DEFAULT '[]',
    available INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Smart Fallback: Inject columns if the database is older and missing them.
  const columnsToAdd = [
    "image TEXT",
    "images TEXT DEFAULT '[]'",
    "badge TEXT DEFAULT 'New'",
    "badgeType TEXT DEFAULT 'default'",
    "tags TEXT DEFAULT '[]'",
    "features TEXT DEFAULT '[]'",
    "available INTEGER DEFAULT 1",
    "verified INTEGER DEFAULT 0"
  ];
  columnsToAdd.forEach(col => {
    db.run(`ALTER TABLE listings ADD COLUMN ${col}`, () => {});
  });

  db.run(`CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    listing_id TEXT NOT NULL,
    listing_name TEXT,
    renter_id INTEGER NOT NULL,
    start_date TEXT,
    end_date TEXT,
    total_amount INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// ── AUTH ENDPOINTS ─────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { email, password, displayName, role } = req.body || {};
  if (!email || !password || !displayName) return res.status(400).json({ error: 'All fields are required' });
  const allowed = ['renter', 'provider'];
  const userRole = allowed.includes(role) ? role : 'renter';
  const hash = bcrypt.hashSync(String(password), 10);
  db.run('INSERT INTO users (email, password_hash, role, display_name) VALUES (?,?,?,?)',
    [String(email).trim().toLowerCase(), hash, userRole, displayName],
    function (err) {
      if (err) {
        if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Email already registered' });
        return res.status(500).json({ error: 'Registration failed' });
      }
      req.session.user = { id: this.lastID, email: String(email).trim().toLowerCase(), role: userRole, displayName };
      res.json({ success: true, user: req.session.user });
    });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  db.get('SELECT * FROM users WHERE lower(email) = lower(?)', [String(email).trim()], (err, user) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (!user || !bcrypt.compareSync(String(password), user.password_hash)) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    req.session.user = { id: user.id, email: user.email, role: user.role, displayName: user.display_name };
    res.json({ success: true, user: req.session.user });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/session', (req, res) => {
  res.json({ user: req.session.user || null });
});

// ── CONTENT (CMS) ──────────────────────────────────────────────────────────────
app.get('/api/content', (req, res) => {
  try {
    const content = JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
    if (content.listings) {
      content.listings.items = [];
    }
    res.json(content);
  } catch (e) {
    res.status(500).json({ error: 'Failed to read content' });
  }
});

// ── LISTINGS (PUBLIC) ──────────────────────────────────────────────────────────
app.get('/api/listings', (req, res) => {
  db.all(`SELECT l.*, u.display_name as provider_name FROM listings l
    LEFT JOIN users u ON l.provider_id = u.id
    WHERE l.available = 1 ORDER BY l.created_at DESC`, [], (err, rows) => {
    const dbItems = (err ? [] : rows).map(r => ({
      ...normalizeListingForClient(r),
      tags: JSON.parse(r.tags || '[]'),
      features: JSON.parse(r.features || '[]'),
      images: JSON.parse(r.images || '[]').map(proxiedImageUrl),
      source: 'db'
    }));
    res.json({ listings: dbItems });
  });
});

// Single listing
app.get('/api/listings/:id', (req, res) => {
  const id = req.params.id;
  if (String(id).startsWith('cms-')) {
    try {
      const raw = fs.readFileSync(DATA_FILE, 'utf-8');
      const item = (JSON.parse(raw).listings?.items || []).find(i => String(i.id) === id);
      if (!item) return res.status(404).json({ error: 'Not found' });
      res.json({ listing: normalizeListingForClient({ ...item, source: 'cms' }) });
    } catch (_) { res.status(500).json({ error: 'Failed' }); }
  } else {
    db.get(`SELECT l.*, u.display_name as provider_name FROM listings l
      LEFT JOIN users u ON l.provider_id = u.id WHERE l.id = ?`, [id], (err, row) => {
      if (err || !row) return res.status(404).json({ error: 'Not found' });
      row.tags = JSON.parse(row.tags || '[]');
      row.features = JSON.parse(row.features || '[]');
      row.images = JSON.parse(row.images || '[]');
      res.json({ listing: { ...normalizeListingForClient(row), source: 'db' } });
    });
  }
});

// ── PROVIDER: LISTINGS ─────────────────────────────────────────────────────────
app.post('/api/listings', requireAuth, (req, res) => {
  const user = req.session.user;
  if (user.role !== 'provider') return res.status(403).json({ error: 'Providers only' });
  const { name, price, location, size, description, image, badge, badgeType, tags, features } = req.body || {};
  if (!name || !location) return res.status(400).json({ error: 'Name and location required' });
  
  db.run(`INSERT INTO listings (provider_id, name, price, location, size, description, image, images, badge, badgeType, tags, features, available)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [user.id, name, Number(price) || 0, location, size || 'Medium', description || '',
     image || '', JSON.stringify([]), badge || 'New', badgeType || 'default',
     JSON.stringify(tags || []), JSON.stringify(features || []), 1],
    function (err) {
      if (err) return res.status(500).json({ error: 'Failed to create listing' });
      db.get('SELECT * FROM listings WHERE id = ?', [this.lastID], (e, row) => {
        if (e || !row) return res.status(500).json({ error: 'Failed to fetch' });
        row.tags = JSON.parse(row.tags || '[]');
        row.features = JSON.parse(row.features || '[]');
        row.images = JSON.parse(row.images || '[]');
        res.json({ listing: row });
      });
    });
});

app.get('/api/my/listings', requireAuth, (req, res) => {
  const user = req.session.user;
  if (user.role !== 'provider') return res.json({ listings: [] });
  db.all('SELECT * FROM listings WHERE provider_id = ? ORDER BY created_at DESC', [user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed' });
    rows = rows.map(r => ({ ...r,
      tags: JSON.parse(r.tags || '[]'),
      features: JSON.parse(r.features || '[]'),
      images: JSON.parse(r.images || '[]')
    }));
    res.json({ listings: rows });
  });
});

app.put('/api/listings/:id', requireAuth, (req, res) => {
  const user = req.session.user;
  const { name, price, location, size, description, image, images, badge, badgeType, tags, features, available } = req.body || {};
  const where = 'WHERE id = ? AND provider_id = ?';
  const params = [req.params.id, user.id];
  
  db.run(`UPDATE listings SET name=?, price=?, location=?, size=?, description=?, image=?,
    images=?, badge=?, badgeType=?, tags=?, features=?, available=? ${where}`,
    [name, Number(price) || 0, location, size || 'Medium', description || '', image || '',
     JSON.stringify(images || []), badge || 'New', badgeType || 'default', JSON.stringify(tags || []),
     JSON.stringify(features || []), available !== false ? 1 : 0, ...params],
    function (err) {
      if (err) return res.status(500).json({ error: 'Failed' });
      res.json({ success: true, changes: this.changes });
    });
});

app.delete('/api/listings/:id', requireAuth, (req, res) => {
  const user = req.session.user;
  const id = req.params.id;
  if (String(id).startsWith('cms-')) {
    return res.status(403).json({ error: 'Cannot delete CMS item' });
  } else {
    const where = 'WHERE id = ? AND provider_id = ?';
    const params = [id, user.id];
    db.run(`DELETE FROM listings ${where}`, params, function (err) {
      if (err) return res.status(500).json({ error: 'Failed' });
      if (this.changes === 0) return res.status(403).json({ error: 'Not found or not authorized' });
      res.json({ success: true });
    });
  }
});

// ── BOOKINGS ───────────────────────────────────────────────────────────────────
app.post('/api/bookings', requireAuth, (req, res) => {
  const user = req.session.user;
  const { listing_id, listing_name, start_date, end_date, total_amount } = req.body || {};
  if (!listing_id) return res.status(400).json({ error: 'listing_id required' });
  db.get('SELECT id, name, provider_id, available, price FROM listings WHERE id = ?', [listing_id], (lookupErr, listing) => {
    if (lookupErr) return res.status(500).json({ error: 'Failed to validate listing' });
    if (!listing || !listing.provider_id) return res.status(404).json({ error: 'Listing not found' });
    if (listing.available !== 1) return res.status(400).json({ error: 'Listing is not available' });

    db.run('INSERT INTO bookings (listing_id, listing_name, renter_id, start_date, end_date, total_amount) VALUES (?,?,?,?,?,?)',
      [String(listing_id), listing.name || listing_name || '', user.id, start_date || '', end_date || '', Number(total_amount) || Number(listing.price) || 0],
      function (err) {
        if (err) return res.status(500).json({ error: 'Failed to create booking' });
        db.get('SELECT * FROM bookings WHERE id = ?', [this.lastID], (e, row) => {
          if (e || !row) return res.status(500).json({ error: 'Failed' });
          res.json({ booking: row });
        });
      });
  });
});

app.get('/api/my/bookings', requireAuth, (req, res) => {
  const user = req.session.user;
  if (user.role === 'provider') {
    const sql = `SELECT b.*, u.display_name as renter_name FROM bookings b LEFT JOIN users u ON b.renter_id = u.id
         WHERE b.listing_id IN (SELECT CAST(id AS TEXT) FROM listings WHERE provider_id = ?) ORDER BY b.created_at DESC`;
    db.all(sql, [user.id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Failed' });
      res.json({ bookings: rows });
    });
  } else {
    db.all('SELECT * FROM bookings WHERE renter_id = ? ORDER BY created_at DESC', [user.id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Failed' });
      res.json({ bookings: rows });
    });
  }
});

app.put('/api/bookings/:id/status', requireAuth, (req, res) => {
  const { status } = req.body || {};
  const allowed = ['pending', 'confirmed', 'cancelled', 'completed'];
  if (!allowed.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  const user = req.session.user;
  
  if (user.role === 'provider') {
    db.run(`UPDATE bookings SET status = ? WHERE id = ? AND listing_id IN
      (SELECT CAST(id AS TEXT) FROM listings WHERE provider_id = ?)`,
      [status, req.params.id, user.id], function (err) {
        if (err) return res.status(500).json({ error: 'Failed' });
        res.json({ success: true });
      });
  } else {
    if (status !== 'cancelled') return res.status(403).json({ error: 'Renters can only cancel' });
    db.run('UPDATE bookings SET status = ? WHERE id = ? AND renter_id = ?',
      [status, req.params.id, user.id], function (err) {
        if (err) return res.status(500).json({ error: 'Failed' });
        res.json({ success: true });
      });
  }
});

// Image upload
app.post('/api/upload', requireAuth, (req, res) => {
  const { filename, data } = req.body || {};
  if (!filename || !data) return res.status(400).json({ error: 'filename and data required' });
  const matches = data.match(/^data:(.+);base64,(.+)$/);
  if (!matches) return res.status(400).json({ error: 'Invalid data URL' });
  const safeName = `${Date.now()}-${path.basename(filename).replace(/[^a-zA-Z0-9.\-]/g, '_')}`;
  const outDir = path.join(__dirname, 'public', 'uploads');
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  try {
    fs.writeFileSync(path.join(outDir, safeName), Buffer.from(matches[2], 'base64'));
    res.json({ url: `/uploads/${safeName}` });
  } catch (_) { res.status(500).json({ error: 'Upload failed' }); }
});

// Upload an image directly to a listing (provider-only)
app.post('/api/listings/:id/images', requireAuth, (req, res) => {
  const user = req.session.user;
  if (user.role !== 'provider') return res.status(403).json({ error: 'Providers only' });
  const listingId = req.params.id;
  const { filename, data } = req.body || {};
  if (!filename || !data) return res.status(400).json({ error: 'filename and data required' });
  // verify ownership
  db.get('SELECT provider_id, images FROM listings WHERE id = ?', [listingId], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Listing not found' });
    if (row.provider_id !== user.id) return res.status(403).json({ error: 'Not authorized' });
    const matches = data.match(/^data:(.+);base64,(.+)$/);
    if (!matches) return res.status(400).json({ error: 'Invalid data URL' });
    const safeName = `${Date.now()}-${path.basename(filename).replace(/[^a-zA-Z0-9.\-]/g, '_')}`;
    const outDir = path.join(__dirname, 'public', 'uploads');
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
    try {
      fs.writeFileSync(path.join(outDir, safeName), Buffer.from(matches[2], 'base64'));
      const url = `/uploads/${safeName}`;
      let images = [];
      try { images = JSON.parse(row.images || '[]'); } catch (e) { images = []; }
      images.push(url);
      db.run('UPDATE listings SET images = ? WHERE id = ?', [JSON.stringify(images), listingId], function (uerr) {
        if (uerr) return res.status(500).json({ error: 'Failed to update listing' });
        res.json({ url, images });
      });
    } catch (e) { res.status(500).json({ error: 'Upload failed' }); }
  });
});

// Delete an image from a listing (provider-only)
app.delete('/api/listings/:id/images', requireAuth, (req, res) => {
  const user = req.session.user;
  if (user.role !== 'provider') return res.status(403).json({ error: 'Providers only' });
  const listingId = req.params.id;
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url required' });
  if (!String(url).startsWith('/uploads/')) return res.status(400).json({ error: 'Invalid upload path' });
  db.get('SELECT provider_id, images FROM listings WHERE id = ?', [listingId], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Listing not found' });
    if (row.provider_id !== user.id) return res.status(403).json({ error: 'Not authorized' });
    let images = [];
    try { images = JSON.parse(row.images || '[]'); } catch (e) { images = []; }
    const idx = images.indexOf(url);
    if (idx === -1) return res.status(404).json({ error: 'Image not found on listing' });
    const filename = path.basename(url);
    const outDir = path.join(__dirname, 'public', 'uploads');
    const filePath = path.join(outDir, filename);
    try {
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    } catch (e) {}
    images.splice(idx, 1);
    db.run('UPDATE listings SET images = ? WHERE id = ?', [JSON.stringify(images), listingId], function (uerr) {
      if (uerr) return res.status(500).json({ error: 'Failed to update listing' });
      res.json({ success: true, images });
    });
  });
});

// ── VERIFICATION (Admin) ───────────────────────────────────────────────────────
// Get unverified listings
app.get('/api/verify/listings', (req, res) => {
  const token = req.query.token || req.headers['x-verify-token'];
  if (token !== process.env.VERIFY_TOKEN && token !== 'verify2024') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  db.all(`SELECT l.*, u.display_name as provider_name FROM listings l
    LEFT JOIN users u ON l.provider_id = u.id
    ORDER BY l.verified ASC, l.created_at DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed' });
    rows = rows.map(r => ({ ...r,
      tags: JSON.parse(r.tags || '[]'),
      features: JSON.parse(r.features || '[]'),
      images: JSON.parse(r.images || '[]')
    }));
    res.json({ listings: rows });
  });
});

// Mark listing as verified
app.post('/api/verify/listings/:id/approve', (req, res) => {
  const token = req.query.token || req.headers['x-verify-token'] || req.body.token;
  if (token !== process.env.VERIFY_TOKEN && token !== 'verify2024') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  db.run('UPDATE listings SET verified = 1 WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Failed' });
    res.json({ success: true });
  });
});

// Mark listing as rejected/unverified
app.post('/api/verify/listings/:id/reject', (req, res) => {
  const token = req.query.token || req.headers['x-verify-token'] || req.body.token;
  if (token !== process.env.VERIFY_TOKEN && token !== 'verify2024') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  db.run('UPDATE listings SET verified = 0 WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Failed' });
    res.json({ success: true });
  });
});

// ── ROUTES ─────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/search', (req, res) => res.sendFile(path.join(__dirname, 'public', 'search.html')));
app.get('/storage', (req, res) => res.sendFile(path.join(__dirname, 'public', 'storage.html')));
app.get('/booking', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'booking.html')));
app.get('/dashboard', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/provider-dashboard', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'provider-dashboard.html')));
app.get('/verify-spaces', (req, res) => res.sendFile(path.join(__dirname, 'public', 'verify-spaces.html')));

app.get('/image-proxy', async (req, res) => {
  const remoteUrl = req.query.url;
  if (!remoteUrl || typeof remoteUrl !== 'string') {
    return res.status(400).send('Missing url');
  }

  let parsed;
  try {
    parsed = new URL(remoteUrl);
  } catch (_) {
    return res.status(400).send('Invalid url');
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return res.status(400).send('Unsupported protocol');
  }

  try {
    const upstream = await fetch(remoteUrl, {
      headers: {
        'user-agent': 'RentWise Image Proxy',
        'accept': 'image/*,*/*;q=0.8'
      }
    });

    if (!upstream.ok || !upstream.body) {
      return res.status(502).send('Failed to load image');
    }

    const contentType = upstream.headers.get('content-type') || 'image/jpeg';
    const buffer = Buffer.from(await upstream.arrayBuffer());
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.end(buffer);
  } catch (err) {
    res.status(502).send('Failed to load image');
  }
});

app.listen(PORT, () => console.log(`RentWise running at http://localhost:${PORT}`));