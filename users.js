// Fungsi server Vercel: kelola pengguna (hanya Admin). Memakai service_role key yang
// disimpan sebagai Environment Variable di Vercel, tidak pernah dikirim ke browser.
const { createClient } = require('@supabase/supabase-js');
const ROLES = ['admin', 'kontributor', 'pembaca'];
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const send = (code, o) => res.status(code).json(o);
  const fail = (m, code = 400) => send(code, { ok: false, err: m });
  try {
    if (req.method !== 'POST') return fail('Metode tidak didukung.', 405);
    const url = process.env.SUPABASE_URL, key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!url || !key) return fail('SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY belum diisi di Environment Variables Vercel.', 500);
    const sb = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });

    const token = (req.headers.authorization || '').replace(/^Bearer /, '');
    const { data: ud, error: ue } = await sb.auth.getUser(token);
    if (ue || !ud || !ud.user) return fail('Sesi berakhir, silakan login lagi.', 401);
    const me = ud.user;
    const { data: mp } = await sb.from('profiles').select('role,aktif').eq('id', me.id).maybeSingle();
    if (!mp || !mp.aktif || mp.role !== 'admin') return fail('Hanya Admin yang dapat mengelola pengguna.', 403);

    const b = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const adminLain = async (id) => {
      const { count } = await sb.from('profiles').select('id', { count: 'exact', head: true })
        .eq('role', 'admin').eq('aktif', true).neq('id', id);
      return count || 0;
    };

    switch (b.a) {
      case 'users': {
        const { data: au, error } = await sb.auth.admin.listUsers({ perPage: 1000 });
        if (error) return fail(error.message, 500);
        const { data: ps } = await sb.from('profiles').select('*');
        const pm = new Map((ps || []).map(p => [p.id, p]));
        const users = au.users.map(u => {
          const p = pm.get(u.id);
          return { id: u.id, username: u.email, nama: p ? p.nama : '(belum terdaftar)', role: p ? p.role : 'pembaca',
                   aktif: p && p.aktif ? 1 : 0, last_login: u.last_sign_in_at || null };
        });
        return send(200, { ok: true, users });
      }
      case 'user_add': {
        const email = String(b.username || '').trim().toLowerCase(), nama = String(b.nama || '').trim().slice(0, 100);
        const pw = String(b.password || '');
        if (!EMAIL.test(email)) return fail('Email tidak valid.');
        if (!nama) return fail('Nama lengkap wajib diisi.');
        if (pw.length < 8) return fail('Password minimal 8 karakter.');
        if (!ROLES.includes(b.role)) return fail('Peran tidak valid.');
        const { data, error } = await sb.auth.admin.createUser({ email, password: pw, email_confirm: true });
        if (error) return fail(/already|registered/i.test(error.message) ? 'Email sudah terdaftar.' : error.message);
        const { error: pe } = await sb.from('profiles').insert({ id: data.user.id, nama, role: b.role });
        if (pe) { await sb.auth.admin.deleteUser(data.user.id); return fail('Gagal membuat profil: ' + pe.message, 500); }
        return send(200, { ok: true });
      }
      case 'user_set': {
        const id = String(b.id || '');
        const { data: t } = await sb.from('profiles').select('*').eq('id', id).maybeSingle();
        if (!t) return fail('Pengguna belum punya profil atau tidak ditemukan.', 404);
        let role = t.role, aktif = t.aktif, nama = t.nama;
        if (b.role !== undefined) { if (!ROLES.includes(b.role)) return fail('Peran tidak valid.'); role = b.role; }
        if (b.aktif !== undefined) aktif = !!b.aktif;
        if (b.nama !== undefined) { nama = String(b.nama).trim().slice(0, 100); if (!nama) return fail('Nama tidak boleh kosong.'); }
        if (id === me.id && (role !== 'admin' || !aktif)) return fail('Anda tidak bisa menurunkan atau menonaktifkan akun sendiri.');
        if (t.role === 'admin' && (role !== 'admin' || !aktif) && (await adminLain(id)) < 1) return fail('Harus tersisa minimal satu Admin aktif.');
        if (b.password !== undefined && String(b.password).length < 8) return fail('Password minimal 8 karakter.');
        const { error } = await sb.from('profiles').update({ role, aktif, nama }).eq('id', id);
        if (error) return fail(error.message, 500);
        if (b.password !== undefined) {
          const { error: e2 } = await sb.auth.admin.updateUserById(id, { password: String(b.password) });
          if (e2) return fail(e2.message, 500);
        }
        return send(200, { ok: true });
      }
      case 'user_del': {
        const id = String(b.id || '');
        if (id === me.id) return fail('Anda tidak bisa menghapus akun sendiri.');
        const { data: t } = await sb.from('profiles').select('role').eq('id', id).maybeSingle();
        if (t && t.role === 'admin' && (await adminLain(id)) < 1) return fail('Harus tersisa minimal satu Admin aktif.');
        const { error } = await sb.auth.admin.deleteUser(id);
        if (error) return fail(error.message, 500);
        return send(200, { ok: true });
      }
      default: return fail('Aksi tidak dikenal.', 404);
    }
  } catch (e) {
    console.error(e);
    return fail('Terjadi kesalahan di server.', 500);
  }
};
