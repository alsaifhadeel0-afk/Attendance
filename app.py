import os, csv, io, hmac, hashlib, time, sqlite3, uuid
from datetime import datetime
from zoneinfo import ZoneInfo
from functools import wraps
from flask import (Flask, request, session, redirect, render_template_string,
                   Response, jsonify, abort)
from werkzeug.middleware.proxy_fix import ProxyFix
import segno

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
SECRET = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.secret_key = SECRET
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "attendance.db"))
TZ = ZoneInfo("Asia/Amman")
STEP = 20      # QR changes every 20 seconds
GRACE = 3      # token accepted for ~60-80 seconds in total


# ---------- data ----------
def load_students():
    out = {}
    with open(os.path.join(BASE, "students.csv"), encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            out[r["id"].strip()] = r["name"].strip()
    return out


STUDENTS = load_students()


def db():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS sessions(
            id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT,
            started_at TEXT, active INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS attendance(
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER,
            student_id TEXT, name TEXT, ts TEXT, ip TEXT, device TEXT,
            ldid TEXT, ua TEXT, method TEXT DEFAULT 'qr',
            UNIQUE(session_id, student_id));
        CREATE TABLE IF NOT EXISTS flags(
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER,
            ts TEXT, attempted_id TEXT, existing_id TEXT, ip TEXT, reason TEXT);
        """)


init_db()


def now_str():
    return datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S")


def norm_id(s):
    s = (s or "").strip()
    s = s.translate(str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789"))
    return "".join(ch for ch in s if ch.isdigit())


def active_session():
    with db() as c:
        return c.execute("SELECT * FROM sessions WHERE active=1 ORDER BY id DESC LIMIT 1").fetchone()


# ---------- rotating token ----------
def make_token(sid, w):
    return hmac.new(SECRET.encode(), f"{sid}:{w}".encode(), hashlib.sha256).hexdigest()[:16]


def current_token(sid):
    return make_token(sid, int(time.time() // STEP))


def token_ok(sid, tok):
    now = int(time.time() // STEP)
    return any(hmac.compare_digest(make_token(sid, now - i), tok or "") for i in range(GRACE + 1))


# ---------- UI ----------
SHELL = """<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>تسجيل الحضور</title>
<style>
*{box-sizing:border-box}body{font-family:system-ui,Tahoma,Arial,sans-serif;background:#f3f5f9;margin:0;padding:16px;color:#1c2333}
.card{max-width:900px;margin:0 auto;background:#fff;border-radius:14px;padding:22px;box-shadow:0 2px 12px #0001}
.narrow{max-width:420px}
input,button{font:inherit;padding:12px;border-radius:10px;border:1px solid #c6ccd8;width:100%;margin:6px 0}
button{background:#2457d6;color:#fff;border:0;cursor:pointer;font-weight:600}
button.danger{background:#c0392b}button.small{width:auto;padding:4px 10px;font-size:.8rem;margin:0}
.ok{background:#e6f6ec;color:#16653a;padding:14px;border-radius:10px}
.err{background:#fdecea;color:#8a1f17;padding:14px;border-radius:10px}
table{width:100%;border-collapse:collapse;margin-top:10px;font-size:.9rem}
td,th{padding:6px 8px;border-bottom:1px solid #e5e8ef;text-align:right}
.qrbox{text-align:center}.qrbox img{width:min(380px,90%);border:8px solid #fff;outline:1px solid #ddd}
.big{font-size:1.6rem;font-weight:700;text-align:center}.muted{color:#667}
.row{display:flex;gap:8px}.row>*{flex:1}
</style></head><body>{{ body|safe }}</body></html>"""


def page(tpl, **ctx):
    body = render_template_string(tpl, **ctx)
    return render_template_string(SHELL, body=body)


def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("admin"):
            return redirect("/admin/login")
        return f(*a, **k)
    return w


@app.route("/")
def home():
    return redirect("/admin")


LOGIN = """<div class="card narrow"><h2>دخول الدكتورة</h2>
{% if err %}<div class="err">{{err}}</div>{% endif %}
<form method="post"><input type="password" name="pw" placeholder="كلمة المرور" autofocus>
<button>دخول</button></form></div>"""


@app.route("/admin/login", methods=["GET", "POST"])
def login():
    err = None
    if request.method == "POST":
        if hmac.compare_digest(request.form.get("pw", ""), ADMIN_PASSWORD):
            session["admin"] = True
            return redirect("/admin")
        err = "كلمة المرور غير صحيحة"
    return page(LOGIN, err=err)


DASH = """<div class="card">
{% if sess %}
  <h2>{{ sess['title'] }}</h2>
  <div class="qrbox"><img id="qr" src="/admin/qr.svg" alt="QR"></div>
  <p class="muted" style="text-align:center">الرمز يتغيّر كل {{step}} ثانية، اعرضيه على الشاشة. صورته لا تنفع بعد دقيقة.</p>
  <p class="big"><span id="cnt">0</span> / {{total}} حاضر</p>
  <div class="row">
    <form method="post" action="/admin/manual" class="row">
      <input name="student_id" placeholder="تسجيل يدوي: الرقم الجامعي" inputmode="numeric"><button>تسجيل يدوي</button></form>
    <form method="post" action="/admin/end" onsubmit="return confirm('إنهاء المحاضرة؟')"><button class="danger">إنهاء المحاضرة</button></form>
  </div>
  <p><a href="/admin/export/{{sess['id']}}.csv">تحميل الكشف (Excel/CSV)</a></p>
  <div id="flags"></div>
  <table><thead><tr><th>#</th><th>الاسم</th><th>الوقت</th><th>IP</th><th>الطريقة</th><th></th></tr></thead><tbody id="tb"></tbody></table>
<script>
const sid={{sess['id']}};
function td(t){const e=document.createElement('td');e.textContent=t;return e}
async function live(){
  const r=await fetch('/admin/live.json');if(!r.ok)return;const d=await r.json();
  document.getElementById('cnt').textContent=d.count;
  const tb=document.getElementById('tb');tb.innerHTML='';
  d.rows.forEach((x,i)=>{const tr=document.createElement('tr');
    [i+1,x.name,x.time.slice(11),x.ip,x.method].forEach(v=>tr.appendChild(td(v)));
    const b=document.createElement('td');const bt=document.createElement('button');bt.className='small danger';bt.textContent='حذف';
    bt.onclick=async()=>{if(confirm('حذف '+x.name+'؟')){await fetch('/admin/remove',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'student_id='+x.sid});live()}};
    b.appendChild(bt);tr.appendChild(b);tb.appendChild(tr)});
  const f=document.getElementById('flags');f.innerHTML='';
  if(d.flags.length){const h=document.createElement('div');h.className='err';
    h.innerHTML='<b>محاولات مشبوهة (جهاز سجّل لأكثر من طالب):</b><br>';
    d.flags.forEach(x=>{h.appendChild(document.createTextNode(x.time.slice(11)+' — محاولة تسجيل '+x.attempted+' من جهاز سجّل قبلها '+x.existing+' (IP '+x.ip+')'));h.appendChild(document.createElement('br'))});
    f.appendChild(h)}
}
setInterval(()=>{document.getElementById('qr').src='/admin/qr.svg?'+Date.now()},{{step*1000-2000}});
setInterval(live,4000);live();
</script>
{% else %}
  <h2>تسجيل الحضور</h2>
  <form method="post" action="/admin/start">
    <input name="title" placeholder="اسم المحاضرة (اختياري)" value="{{default_title}}">
    <button>ابدأ محاضرة جديدة وأظهر الـ QR</button></form>
{% endif %}
{% if past %}<h3>محاضرات سابقة</h3><ul>
{% for p in past %}<li>{{p['title']}} ({{p['started_at']}}) — <a href="/admin/export/{{p['id']}}.csv">تحميل الكشف</a></li>{% endfor %}</ul>{% endif %}
</div>"""


@app.route("/admin")
@admin_required
def admin():
    sess = active_session()
    with db() as c:
        past = c.execute("SELECT * FROM sessions WHERE active=0 ORDER BY id DESC LIMIT 15").fetchall()
    return page(DASH, sess=sess, total=len(STUDENTS), step=STEP, past=past,
                default_title="محاضرة " + datetime.now(TZ).strftime("%Y-%m-%d"))


@app.route("/admin/start", methods=["POST"])
@admin_required
def start():
    with db() as c:
        c.execute("UPDATE sessions SET active=0 WHERE active=1")
        c.execute("INSERT INTO sessions(title,started_at,active) VALUES(?,?,1)",
                  (request.form.get("title") or "محاضرة", now_str()))
    return redirect("/admin")


@app.route("/admin/end", methods=["POST"])
@admin_required
def end():
    with db() as c:
        c.execute("UPDATE sessions SET active=0 WHERE active=1")
    return redirect("/admin")


@app.route("/admin/qr.svg")
@admin_required
def qr():
    s = active_session()
    if not s:
        abort(404)
    url = request.url_root.rstrip("/") + f"/a/{s['id']}/{current_token(s['id'])}"
    buf = io.BytesIO()
    segno.make(url, error="m").save(buf, kind="svg", scale=12, border=2)
    r = Response(buf.getvalue(), mimetype="image/svg+xml")
    r.headers["Cache-Control"] = "no-store"
    return r


@app.route("/admin/live.json")
@admin_required
def live():
    s = active_session()
    if not s:
        return jsonify(count=0, rows=[], flags=[])
    with db() as c:
        rows = c.execute("SELECT * FROM attendance WHERE session_id=? ORDER BY ts DESC", (s["id"],)).fetchall()
        fl = c.execute("SELECT * FROM flags WHERE session_id=? ORDER BY ts DESC", (s["id"],)).fetchall()
    return jsonify(
        count=len(rows),
        rows=[dict(sid=r["student_id"], name=r["name"], time=r["ts"], ip=r["ip"], method=r["method"]) for r in rows],
        flags=[dict(time=f["ts"], attempted=STUDENTS.get(f["attempted_id"], f["attempted_id"]),
                    existing=STUDENTS.get(f["existing_id"], f["existing_id"]), ip=f["ip"]) for f in fl])


@app.route("/admin/manual", methods=["POST"])
@admin_required
def manual():
    s = active_session()
    sid = norm_id(request.form.get("student_id"))
    if s and sid in STUDENTS:
        with db() as c:
            c.execute("INSERT OR IGNORE INTO attendance(session_id,student_id,name,ts,ip,method) VALUES(?,?,?,?,?,'manual')",
                      (s["id"], sid, STUDENTS[sid], now_str(), "-"))
    return redirect("/admin")


@app.route("/admin/remove", methods=["POST"])
@admin_required
def remove():
    s = active_session()
    if s:
        with db() as c:
            c.execute("DELETE FROM attendance WHERE session_id=? AND student_id=?",
                      (s["id"], norm_id(request.form.get("student_id"))))
    return ("", 204)


@app.route("/admin/export/<int:sid>.csv")
@admin_required
def export(sid):
    with db() as c:
        sess = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        rows = {r["student_id"]: r for r in c.execute("SELECT * FROM attendance WHERE session_id=?", (sid,))}
    if not sess:
        abort(404)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["الرقم", "اسم الطالب", "الرقم الجامعي", "الحالة", "وقت التسجيل", "IP", "الطريقة"])
    for i, (stid, name) in enumerate(STUDENTS.items(), 1):
        r = rows.get(stid)
        w.writerow([i, name, "'" + stid if False else stid, "حاضر" if r else "غائب",
                    r["ts"] if r else "", r["ip"] if r else "", r["method"] if r else ""])
    data = "\ufeff" + out.getvalue()
    return Response(data, mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=attendance_{sid}.csv"})


# ---------- student side ----------
FORM = """<div class="card narrow"><h2>تسجيل الحضور</h2>
{% if err %}<div class="err">{{err}}</div>{% endif %}
<form method="post"><p>اكتب رقمك الجامعي:</p>
<input name="student_id" inputmode="numeric" autocomplete="off" placeholder="مثال: 0229938" autofocus required>
<input type="hidden" name="ldid" id="ldid"><button>تسجيل</button></form>
<script>let d=localStorage.getItem('did');if(!d){d=(crypto.randomUUID?crypto.randomUUID():String(Math.random()).slice(2)+Date.now());localStorage.setItem('did',d)}document.getElementById('ldid').value=d;</script>
</div>"""

DONE = """<div class="card narrow"><div class="ok"><h2>تم تسجيل حضورك ✅</h2>
<p><b>{{name}}</b></p><p>الوقت: {{ts}}</p></div></div>"""

MSG = """<div class="card narrow"><div class="err">{{msg}}</div></div>"""


@app.route("/a/<int:sid>/<tok>", methods=["GET", "POST"])
def student(sid, tok):
    s = active_session()
    if not s or s["id"] != sid:
        return page(MSG, msg="لا توجد محاضرة مفتوحة للتسجيل حالياً.")
    if not token_ok(sid, tok):
        return page(MSG, msg="انتهت صلاحية الرمز. امسحي/امسح الـ QR من الشاشة مرة ثانية.")
    did = request.cookies.get("did") or uuid.uuid4().hex
    if request.method == "GET":
        r = app.make_response(page(FORM, err=None))
    else:
        r = app.make_response(handle_submit(s, did))
    r.set_cookie("did", did, max_age=365 * 86400, httponly=True, samesite="Lax", secure=request.is_secure)
    return r


def handle_submit(s, did):
    stid = norm_id(request.form.get("student_id"))
    ldid = (request.form.get("ldid") or "")[:80]
    ip = request.remote_addr or "?"
    if stid not in STUDENTS:
        return page(FORM, err="الرقم الجامعي غير موجود في الكشف. تأكد منه وحاول مرة ثانية.")
    with db() as c:
        ex = c.execute("SELECT * FROM attendance WHERE session_id=? AND student_id=?", (s["id"], stid)).fetchone()
        if ex:
            return page(DONE, name=STUDENTS[stid], ts=ex["ts"] + " (مسجل مسبقاً)")
        other = c.execute(
            "SELECT student_id FROM attendance WHERE session_id=? AND student_id!=? AND "
            "(device=? OR (ldid!='' AND ldid=?))", (s["id"], stid, did, ldid)).fetchone()
        if other:
            c.execute("INSERT INTO flags(session_id,ts,attempted_id,existing_id,ip,reason) VALUES(?,?,?,?,?,?)",
                      (s["id"], now_str(), stid, other["student_id"], ip, "same device"))
            return page(MSG, msg="هذا الجهاز سجّل حضور طالب آخر. كل طالب يسجّل من جهازه فقط.")
        ts = now_str()
        c.execute("INSERT INTO attendance(session_id,student_id,name,ts,ip,device,ldid,ua) VALUES(?,?,?,?,?,?,?,?)",
                  (s["id"], stid, STUDENTS[stid], ts, ip, did, ldid, (request.headers.get("User-Agent") or "")[:250]))
    return page(DONE, name=STUDENTS[stid], ts=ts)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
