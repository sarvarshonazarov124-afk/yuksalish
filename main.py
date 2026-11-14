import csv, io, os, sqlite3
from datetime import date, datetime
from functools import wraps

from flask import (Flask, Response, abort, flash, g, redirect,
                   render_template, request, session, url_for)
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "yuksalish-maktabi-almashtiring-123")

# Vercel'da faqat /tmp papkasiga yozish mumkin
if os.environ.get("VERCEL"):
    DB = "/tmp/yuksalish.db"
else:
    DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yuksalish.db")

FANLAR = ["Matematika", "Ona tili", "Ingliz tili", "Fizika", "Kimyo",
          "Biologiya", "Tarix", "Informatika"]
ROLLAR = {"student": "O'quvchi", "teacher": "O'qituvchi", "parent": "Ota-ona", "admin": "Admin"}
KUNLAR = ["Dushanba", "Seshanba", "Chorshanba", "Payshanba", "Juma", "Shanba"]
ST = {"keldi": "Keldi", "kech": "Kech qoldi", "kelmadi": "Kelmadi"}


# ------------------------------------------------------------ Baza
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    c = g.pop("db", None)
    if c: c.close()

def q(sql, *a): return db().execute(sql, a).fetchall()
def q1(sql, *a): return db().execute(sql, a).fetchone()
def run(sql, *a):
    db().execute(sql, a); db().commit()

def nz(v):
    try: return int(v)
    except (TypeError, ValueError): return None

def init_db():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, fio TEXT NOT NULL,
        login TEXT NOT NULL UNIQUE, pw TEXT NOT NULL, role TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS classes(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE);
    CREATE TABLE IF NOT EXISTS grades(id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL,
        fan TEXT NOT NULL, baho INTEGER NOT NULL, hw TEXT, teacher_id INTEGER, created TEXT);
    CREATE TABLE IF NOT EXISTS points(id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL,
        amount INTEGER NOT NULL, reason TEXT, created TEXT);
    CREATE TABLE IF NOT EXISTS attendance(id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL,
        date TEXT NOT NULL, status TEXT NOT NULL, UNIQUE(student_id, date));
    CREATE TABLE IF NOT EXISTS schedule(id INTEGER PRIMARY KEY AUTOINCREMENT, class_id INTEGER NOT NULL,
        day INTEGER NOT NULL, lesson INTEGER NOT NULL, fan TEXT NOT NULL, teacher_id INTEGER, room TEXT,
        UNIQUE(class_id, day, lesson));
    """)
    cols = [r[1] for r in c.execute("PRAGMA table_info(users)")]
    for col, typ in (("class_id", "INTEGER"), ("parent_id", "INTEGER"), ("must_change", "INTEGER DEFAULT 0")):
        if col not in cols: c.execute(f"ALTER TABLE users ADD COLUMN {col} {typ}")
    if not c.execute("SELECT 1 FROM users WHERE login='admin'").fetchone():
        c.execute("INSERT INTO users(fio,login,pw,role,must_change) VALUES(?,?,?,?,1)",
                  ("Bosh Administrator", "admin", generate_password_hash("admin123"), "admin"))
    c.commit(); c.close()

def now(): return datetime.now().strftime("%d.%m.%Y %H:%M")


# ------------------------------------------------------------ Kirish va ruxsatlar
def need(*roles):
    def deco(fn):
        @wraps(fn)
        def w(*a, **kw):
            if "uid" not in session: return redirect(url_for("login"))
            if roles and session["role"] not in roles:
                flash("Bu bo'lim uchun ruxsat yo'q.", "error")
                return redirect(url_for("index"))
            return fn(*a, **kw)
        return w
    return deco

@app.before_request
def force_password_change():
    if session.get("must_change") and request.endpoint not in ("password", "logout", "login", "static"):
        return redirect(url_for("password"))

@app.context_processor
def ctx():
    u = {"id": session["uid"], "fio": session["fio"], "role": session["role"]} if "uid" in session else None
    return {"user": u, "ROLLAR": ROLLAR, "ST": ST, "KUNLAR": KUNLAR}

def can_see(sid):
    r = session["role"]
    if r in ("admin", "teacher"): return True
    if r == "student": return sid == session["uid"]
    return bool(q1("SELECT 1 FROM users WHERE id=? AND parent_id=?", sid, session["uid"]))

def scope():
    """O'qituvchi faqat dars jadvalida o'zi o'qitadigan sinf va fanlar bilan ishlaydi."""
    if session["role"] == "admin":
        st = q("SELECT u.id,u.fio,c.name cname FROM users u LEFT JOIN classes c ON c.id=u.class_id "
               "WHERE u.role='student' ORDER BY u.fio")
        return st, FANLAR
    uid = session["uid"]
    st = q("SELECT u.id,u.fio,c.name cname FROM users u JOIN classes c ON c.id=u.class_id WHERE u.role='student' "
           "AND u.class_id IN (SELECT class_id FROM schedule WHERE teacher_id=?) ORDER BY u.fio", uid)
    return st, [x[0] for x in q("SELECT DISTINCT fan FROM schedule WHERE teacher_id=?", uid)]

def allowed(sid, fan=None):
    st, fans = scope()
    return sid in [s["id"] for s in st] and (fan is None or fan in fans)

def my_classes():
    if session["role"] == "admin": return q("SELECT * FROM classes ORDER BY name")
    return q("SELECT * FROM classes WHERE id IN (SELECT class_id FROM schedule WHERE teacher_id=?) ORDER BY name",
             session["uid"])


# ------------------------------------------------------------ Kirish / parol
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        r = q1("SELECT * FROM users WHERE login=?", request.form.get("login", "").strip())
        if r and check_password_hash(r["pw"], request.form.get("parol", "")):
            session.clear()
            session.update(uid=r["id"], fio=r["fio"], role=r["role"], must_change=bool(r["must_change"]))
            return redirect(url_for("index"))
        flash("Login yoki parol noto'g'ri.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear(); flash("Tizimdan chiqdingiz.", "success")
    return redirect(url_for("login"))

@app.route("/password", methods=["GET", "POST"])
@need()
def password():
    if request.method == "POST":
        old, new = request.form.get("old", ""), request.form.get("new", "")
        row = q1("SELECT pw FROM users WHERE id=?", session["uid"])
        if not check_password_hash(row["pw"], old): flash("Eski parol noto'g'ri.", "error")
        elif len(new) < 6 or new != request.form.get("new2"): flash("Yangi parol kamida 6 ta belgi va ikkala maydonda bir xil bo'lsin.", "error")
        elif new == old: flash("Yangi parol eskisidan farq qilsin.", "error")
        else:
            run("UPDATE users SET pw=?, must_change=0 WHERE id=?", generate_password_hash(new), session["uid"])
            session["must_change"] = False
            flash("Parol almashtirildi.", "success")
            return redirect(url_for("index"))
    return render_template("password.html")


# ------------------------------------------------------------ Bosh sahifa
@app.route("/")
@need()
def index():
    r = session["role"]
    if r == "student": return redirect(url_for("journal", sid=session["uid"]))
    if r == "parent":
        kids = q("SELECT u.*,c.name cname FROM users u LEFT JOIN classes c ON c.id=u.class_id WHERE parent_id=?", session["uid"])
        return render_template("kids.html", kids=kids)
    students, fanlar = scope()
    adm = r == "admin"
    qs, fan = request.args.get("q", "").strip(), request.args.get("fan", "")
    grades = q("SELECT g.*,u.fio,c.name cname FROM grades g JOIN users u ON u.id=g.student_id "
               "LEFT JOIN classes c ON c.id=u.class_id WHERE u.fio LIKE ? AND (?='' OR g.fan=?) "
               "AND (?=1 OR g.teacher_id=?) ORDER BY g.id DESC LIMIT 20",
               f"%{qs}%", fan, fan, 1 if adm else 0, session["uid"])
    pts = q("SELECT p.*,u.fio FROM points p JOIN users u ON u.id=p.student_id ORDER BY p.id DESC LIMIT 10")
    stats = {
        "students": q1("SELECT COUNT(*) FROM users WHERE role='student'")[0],
        "classes": q1("SELECT COUNT(*) FROM classes")[0],
        "today": q1("SELECT COUNT(*) FROM grades WHERE created LIKE ?", date.today().strftime("%d.%m.%Y") + "%")[0],
        "points": q1("SELECT COALESCE(SUM(amount),0) FROM points")[0]}
    return render_template("panel.html", students=students, fanlar=fanlar, grades=grades,
                           pts=pts, stats=stats, qs=qs, fan=fan)

@app.route("/add_grade", methods=["POST"])
@need("admin", "teacher")
def add_grade():
    sid, baho, fan = nz(request.form.get("student")), nz(request.form.get("baho")), request.form.get("fan", "")
    if not sid or baho not in (2, 3, 4, 5) or not allowed(sid, fan):
        flash("Siz faqat o'z sinf va fanlaringiz uchun baho qo'ya olasiz.", "error")
    else:
        run("INSERT INTO grades(student_id,fan,baho,hw,teacher_id,created) VALUES(?,?,?,?,?,?)",
            sid, fan, baho, request.form.get("hw", "").strip(), session["uid"], now())
        flash("Baho saqlandi.", "success")
    return redirect(url_for("index"))

@app.route("/add_points", methods=["POST"])
@need("admin", "teacher")
def add_points():
    sid, ball = nz(request.form.get("student")), nz(request.form.get("ball"))
    if not sid or not ball or not allowed(sid):
        flash("O'quvchi yoki ball noto'g'ri.", "error")
    else:
        ball = -abs(ball) if request.form.get("tur") == "minus" else abs(ball)
        run("INSERT INTO points(student_id,amount,reason,created) VALUES(?,?,?,?)",
            sid, ball, request.form.get("sabab", "").strip(), now())
        flash("Ball yozildi.", "success")
    return redirect(url_for("index"))

@app.route("/export/grades.csv")
@need("admin", "teacher")
def export_grades():
    rows = q("SELECT g.created,u.fio,c.name cname,g.fan,g.baho,g.hw FROM grades g JOIN users u ON u.id=g.student_id "
             "LEFT JOIN classes c ON c.id=u.class_id WHERE (?=1 OR g.teacher_id=?) ORDER BY g.id DESC",
             1 if session["role"] == "admin" else 0, session["uid"])
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["Sana", "O'quvchi", "Sinf", "Fan", "Baho", "Uyga vazifa"])
    for r in rows: w.writerow(list(r))
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=baholar.csv"})


# ------------------------------------------------------------ Baholar jurnali (o'quvchi / ota-ona ko'rinishi)
@app.route("/journal/<int:sid>")
@need()
def journal(sid):
    if not can_see(sid): abort(403)
    s = q1("SELECT u.*,c.name cname FROM users u LEFT JOIN classes c ON c.id=u.class_id WHERE u.id=? AND u.role='student'", sid)
    if not s: abort(404)
    grades = q("SELECT * FROM grades WHERE student_id=? ORDER BY id DESC", sid)
    byfan = q("SELECT fan,ROUND(AVG(baho),2) a,COUNT(*) n FROM grades WHERE student_id=? GROUP BY fan ORDER BY fan", sid)
    att = q("SELECT * FROM attendance WHERE student_id=? ORDER BY date DESC", sid)
    pts = q("SELECT * FROM points WHERE student_id=? ORDER BY id DESC", sid)
    avg = round(sum(x["baho"] for x in grades) / len(grades), 2) if grades else 0
    total = sum(x["amount"] for x in pts)
    rate = round(100 * sum(1 for a in att if a["status"] != "kelmadi") / len(att)) if att else None
    badges = []
    if len(grades) >= 3 and avg >= 4.5: badges.append("A'lochi")
    if total >= 20: badges.append("Faol o'quvchi")
    if len(att) >= 5 and rate >= 95: badges.append("Davomatli")
    return render_template("journal.html", s=s, grades=grades, byfan=byfan, att=att[:15], pts=pts[:15],
                           avg=avg, total=total, rate=rate, badges=badges)


# ------------------------------------------------------------ Foydalanuvchilar
def form_lists():
    return dict(classes=q("SELECT * FROM classes ORDER BY name"),
                parents=q("SELECT id,fio FROM users WHERE role='parent' ORDER BY fio"))

@app.route("/users")
@need("admin")
def users():
    qs, role, cid = request.args.get("q", "").strip(), request.args.get("role", ""), request.args.get("class_id", "")
    rows = q("SELECT u.*,c.name cname,p.fio pfio FROM users u LEFT JOIN classes c ON c.id=u.class_id "
             "LEFT JOIN users p ON p.id=u.parent_id WHERE (u.fio LIKE ? OR u.login LIKE ?) "
             "AND (?='' OR u.role=?) AND (?='' OR u.class_id=?) ORDER BY u.id",
             f"%{qs}%", f"%{qs}%", role, role, cid, cid)
    return render_template("users.html", rows=rows, qs=qs, role=role, cid=cid, **form_lists())

@app.route("/add_user", methods=["POST"])
@need("admin")
def add_user():
    f = request.form
    fio, lg, pw, rol = f.get("fio", "").strip(), f.get("login", "").strip(), f.get("parol", ""), f.get("rol")
    if not fio or not lg or len(pw) < 6 or rol not in ROLLAR:
        flash("Maydonlarni to'ldiring. Parol kamida 6 ta belgi bo'lsin.", "error")
    else:
        try:
            run("INSERT INTO users(fio,login,pw,role,class_id,parent_id,must_change) VALUES(?,?,?,?,?,?,1)",
                fio, lg, generate_password_hash(pw), rol, nz(f.get("class_id")), nz(f.get("parent_id")))
            flash(f"{fio} qo'shildi. Birinchi kirishda parolni almashtiradi.", "success")
        except sqlite3.IntegrityError:
            flash("Bu login band.", "error")
    return redirect(url_for("users"))

@app.route("/users/<int:uid>/edit", methods=["GET", "POST"])
@need("admin")
def edit_user(uid):
    u = q1("SELECT * FROM users WHERE id=?", uid)
    if not u: abort(404)
    if request.method == "POST":
        f = request.form
        rol = u["role"] if uid == 1 else (f.get("rol") if f.get("rol") in ROLLAR else u["role"])
        run("UPDATE users SET fio=?, role=?, class_id=?, parent_id=? WHERE id=?",
            f.get("fio", "").strip() or u["fio"], rol, nz(f.get("class_id")), nz(f.get("parent_id")), uid)
        if len(f.get("parol", "")) >= 6:
            run("UPDATE users SET pw=?, must_change=1 WHERE id=?", generate_password_hash(f["parol"]), uid)
        flash("Saqlandi.", "success")
        return redirect(url_for("users"))
    return render_template("edit.html", u=u, **form_lists())

@app.route("/delete_user/<int:uid>", methods=["POST"])
@need("admin")
def delete_user(uid):
    if uid == 1 or uid == session["uid"]:
        flash("Asosiy adminni o'chirib bo'lmaydi.", "error")
    else:
        for t in ("grades", "points", "attendance"):
            run(f"DELETE FROM {t} WHERE student_id=?", uid)
        run("UPDATE users SET parent_id=NULL WHERE parent_id=?", uid)
        run("DELETE FROM schedule WHERE teacher_id=?", uid)
        run("DELETE FROM users WHERE id=?", uid)
        flash("Foydalanuvchi o'chirildi.", "success")
    return redirect(url_for("users"))


# ------------------------------------------------------------ Sinflar
@app.route("/classes", methods=["GET", "POST"])
@need("admin")
def classes():
    if request.method == "POST":
        name = request.form.get("name", "").strip().upper()
        try:
            if name: run("INSERT INTO classes(name) VALUES(?)", name); flash(f"{name} sinfi yaratildi.", "success")
        except sqlite3.IntegrityError:
            flash("Bunday sinf bor.", "error")
        return redirect(url_for("classes"))
    rows = q("SELECT c.*,(SELECT COUNT(*) FROM users WHERE class_id=c.id AND role='student') n "
             "FROM classes c ORDER BY c.name")
    return render_template("classes.html", rows=rows)

@app.route("/classes/<int:cid>/delete", methods=["POST"])
@need("admin")
def delete_class(cid):
    run("UPDATE users SET class_id=NULL WHERE class_id=?", cid)
    run("DELETE FROM schedule WHERE class_id=?", cid)
    run("DELETE FROM classes WHERE id=?", cid)
    flash("Sinf o'chirildi.", "success")
    return redirect(url_for("classes"))


# ------------------------------------------------------------ Davomat
@app.route("/attendance", methods=["GET", "POST"])
@need("admin", "teacher")
def attendance():
    cls = my_classes()
    cid = request.values.get("class_id") or (str(cls[0]["id"]) if cls else "")
    d = request.values.get("date") or date.today().isoformat()
    students, saved = [], {}
    if cid in [str(c["id"]) for c in cls]:
        students = q("SELECT id,fio FROM users WHERE role='student' AND class_id=? ORDER BY fio", cid)
        if request.method == "POST":
            for s in students:
                st = request.form.get(f"s{s['id']}")
                if st in ST:
                    run("INSERT INTO attendance(student_id,date,status) VALUES(?,?,?) "
                        "ON CONFLICT(student_id,date) DO UPDATE SET status=excluded.status", s["id"], d, st)
            flash("Davomat saqlandi.", "success")
            return redirect(url_for("attendance", class_id=cid, date=d))
        saved = {r["student_id"]: r["status"] for r in q("SELECT student_id,status FROM attendance WHERE date=?", d)}
    return render_template("attendance.html", cls=cls, cid=cid, d=d, students=students, saved=saved)


# ------------------------------------------------------------ Dars jadvali
@app.route("/schedule")
@need()
def schedule():
    r, uid = session["role"], session["uid"]
    if r in ("admin", "teacher"): cls = q("SELECT * FROM classes ORDER BY name")
    elif r == "student": cls = q("SELECT * FROM classes WHERE id=(SELECT class_id FROM users WHERE id=?)", uid)
    else: cls = q("SELECT * FROM classes WHERE id IN (SELECT class_id FROM users WHERE parent_id=?)", uid)
    cid = request.args.get("class_id") or (str(cls[0]["id"]) if cls else "")
    if cid not in [str(c["id"]) for c in cls]: cid = ""
    rows = q("SELECT s.*,u.fio tfio FROM schedule s LEFT JOIN users u ON u.id=s.teacher_id WHERE s.class_id=?", cid) if cid else []
    teachers = q("SELECT id,fio FROM users WHERE role='teacher' ORDER BY fio") if r == "admin" else []
    return render_template("schedule.html", cls=cls, cid=cid, grid={(x["day"], x["lesson"]): x for x in rows},
                           teachers=teachers, fanlar=FANLAR)

@app.route("/schedule/add", methods=["POST"])
@need("admin")
def schedule_add():
    f = request.form
    cid, day, les = nz(f.get("class_id")), nz(f.get("day")), nz(f.get("lesson"))
    if cid is None or day not in range(6) or not les or f.get("fan") not in FANLAR:
        flash("Ma'lumot noto'g'ri.", "error")
    else:
        run("INSERT OR REPLACE INTO schedule(class_id,day,lesson,fan,teacher_id,room) VALUES(?,?,?,?,?,?)",
            cid, day, les, f["fan"], nz(f.get("teacher_id")), f.get("room", "").strip())
        flash("Jadvalga qo'shildi.", "success")
    return redirect(url_for("schedule", class_id=cid))

@app.route("/schedule/<int:sid>/delete", methods=["POST"])
@need("admin")
def schedule_delete(sid):
    r = q1("SELECT class_id FROM schedule WHERE id=?", sid)
    run("DELETE FROM schedule WHERE id=?", sid)
    return redirect(url_for("schedule", class_id=r["class_id"] if r else ""))


# ------------------------------------------------------------ Reyting
@app.route("/rating")
@need()
def rating():
    cid = request.args.get("class_id", "")
    rows = q("SELECT u.id,u.fio,c.name cname,COALESCE(SUM(p.amount),0) total FROM users u "
             "LEFT JOIN classes c ON c.id=u.class_id LEFT JOIN points p ON p.student_id=u.id "
             "WHERE u.role='student' AND (?='' OR u.class_id=?) GROUP BY u.id ORDER BY total DESC,u.fio LIMIT 50", cid, cid)
    return render_template("rating.html", rows=rows, cid=cid, cls=q("SELECT * FROM classes ORDER BY name"))


# ------------------------------------------------------------ Shablonlar
BASE = """<!DOCTYPE html><html lang="uz"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Yuksalish maktabi</title>
<script>document.documentElement.dataset.theme=localStorage.getItem('t')||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light')</script>
<link href="https://fonts.googleapis.com/css2?family=Jost:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>{% raw %}
:root{--orange:#D9701B;--orange-d:#B85A10;--orange-soft:#FBEBDC;--ink:#2A2A2E;--muted:#74747C;--line:#E7E5E1;--bg:#F5F4F1;--card:#FFF;--field:#FAF9F7;--ok:#2E8B57;--bad:#C23B2E}
:root[data-theme=dark]{--orange:#E8812C;--orange-d:#F29442;--orange-soft:#3A2A1B;--ink:#F1EFEA;--muted:#9A9AA2;--line:#34343A;--bg:#18181B;--card:#222226;--field:#1B1B1F}
*{box-sizing:border-box;margin:0}
body{font-family:'Jost',system-ui,sans-serif;background:var(--bg);color:var(--ink);font-size:15px;line-height:1.5;display:flex;min-height:100vh}
a{color:var(--orange)}
.side{width:250px;background:var(--card);border-right:1px solid var(--line);padding:28px 22px;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto}
.brand{text-align:center;padding-bottom:26px;border-bottom:1px solid var(--line)}
.brand svg{width:64px;height:auto;display:block;margin:0 auto 14px}
.w1{font-weight:300;font-size:21px;letter-spacing:.34em;margin-right:-.34em}
.w2{display:flex;align-items:center;gap:8px;justify-content:center;margin-top:6px;font-weight:300;font-size:11px;letter-spacing:.3em}
.w2 i{width:20px;height:1px;background:var(--orange)}
nav{margin-top:22px;display:flex;flex-direction:column;gap:2px}
nav a{display:block;padding:10px 14px;border-radius:8px;color:var(--muted);text-decoration:none;font-weight:500;border-left:3px solid transparent}
nav a:hover{color:var(--ink);background:var(--field)}
nav a.on{color:var(--orange);background:var(--orange-soft);border-left-color:var(--orange)}
.me{margin-top:auto;padding-top:20px;font-size:13px;color:var(--muted)}
.me b{display:block;color:var(--ink);font-weight:500;font-size:14px}
.me a,.me button{color:var(--orange);text-decoration:none;font-weight:500;background:none;border:0;font:inherit;font-weight:500;cursor:pointer;padding:0}
main{flex:1;padding:34px 40px 50px;max-width:1280px;min-width:0}
.top{margin-bottom:22px}h1{font-size:30px;font-weight:300;letter-spacing:.02em}.top p{color:var(--muted)}
.msg{padding:10px 16px;border-radius:8px;font-size:14px;margin-bottom:12px;background:#E6F4EC;color:#1E6B42;border:1px solid #BFE0CD}
.msg.error{background:#FBE9E7;color:#9C2B20;border-color:#F0C4BE}
[data-theme=dark] .msg{background:#1D3327;color:#8FD1AB;border-color:#2C5240}[data-theme=dark] .msg.error{background:#3A1F1C;color:#F2A59D;border-color:#5A2E29}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:22px}.stats.three{grid-template-columns:repeat(3,1fr)}
.stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 20px}
.stat span{color:var(--muted);font-size:13px}.stat b{display:block;font-size:30px;font-weight:300;line-height:1.2}
.stat.hl{border-color:var(--orange)}.stat.hl b{color:var(--orange)}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin-bottom:22px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:24px;border-top:3px solid var(--orange);overflow-x:auto;margin-bottom:22px}
.grid2 .card,.grid3 .card{margin-bottom:0}
.card h2{font-size:18px;font-weight:500;margin-bottom:18px}
label{display:block;font-size:13px;font-weight:500;color:var(--muted);margin:14px 0 6px}label:first-of-type{margin-top:0}
input,select{width:100%;font:inherit;color:var(--ink);background:var(--field);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
input:focus,select:focus,button:focus-visible,a:focus-visible{outline:2px solid var(--orange);outline-offset:1px}
.btn{width:100%;margin-top:20px;font:inherit;font-weight:600;color:#fff;background:var(--orange);border:0;border-radius:8px;padding:11px;cursor:pointer}
.btn:hover{background:var(--orange-d)}.btn.sm{width:auto;margin:0;padding:10px 18px}
.filter{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap}.filter>*{flex:1;min-width:120px}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:13px;font-weight:500;color:var(--muted);padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:11px 10px;border-bottom:1px solid var(--line);vertical-align:top}tr:last-child td{border-bottom:0}
.tag{display:inline-block;padding:2px 12px;border-radius:99px;font-size:13px;font-weight:500;background:var(--orange-soft);color:var(--orange);margin:0 6px 6px 0}
.plus{color:var(--ok);font-weight:600}.minus{color:var(--bad);font-weight:600}
.link{background:none;border:0;font:inherit;font-size:13px;color:var(--muted);cursor:pointer;padding:0}.link:hover{color:var(--bad)}
.empty{text-align:center;color:var(--muted);padding:22px 0}
.cell{font-size:13px;color:var(--muted)}.cell b{display:block;color:var(--ink);font-size:14px}
.radios label{display:inline-flex;gap:6px;align-items:center;margin:0 14px 0 0;color:var(--ink)}.radios input{width:auto}
.loginwrap{margin:auto;width:100%;max-width:400px;padding:24px}.loginwrap .brand{border:0;padding-bottom:22px}
@media (max-width:1100px){.grid3,.grid2{grid-template-columns:1fr}.stats{grid-template-columns:1fr 1fr}}
@media (max-width:780px){body{flex-direction:column}
.side{width:100%;height:auto;position:static;flex-direction:row;align-items:center;gap:16px;padding:14px 18px;border-right:0;border-bottom:1px solid var(--line);overflow-x:auto}
.side .brand{border:0;padding:0;display:flex;align-items:center;gap:12px;text-align:left}.side .brand svg{width:38px;margin:0}.side .w1{font-size:14px}.side .w2{display:none}
nav{flex-direction:row;margin:0}nav a{white-space:nowrap;border-left:0}.me{display:none}main{padding:22px 16px 40px}}
{% endraw %}</style></head><body>
{% macro logo() %}<div class="brand"><svg viewBox="0 0 442 268" role="img" aria-label="Yuksalish maktabi"><path fill="#D9701B" d="M0,0 C120,0 190,55 220,145 C250,55 320,0 442,0 L442,115 C320,125 270,190 288,268 L155,268 C170,190 120,125 0,115 Z"/></svg>
<div><div class="w1">YUKSALISH</div><div class="w2"><i></i>MAKTABI<i></i></div></div></div>{% endmacro %}
{% macro lk(ep, text) %}<a class="{{ 'on' if request.endpoint == ep }}" href="{{ url_for(ep) }}">{{ text }}</a>{% endmacro %}
{% macro flashes() %}{% for cat, t in get_flashed_messages(with_categories=true) %}<div class="msg {{ cat }}">{{ t }}</div>{% endfor %}{% endmacro %}
{% if user %}
<aside class="side">{{ logo() }}<nav>
  {{ lk('index', 'Bosh sahifa') }}
  {% if user.role == 'admin' %}{{ lk('users', 'Foydalanuvchilar') }}{{ lk('classes', 'Sinflar') }}{% endif %}
  {% if user.role in ('admin','teacher') %}{{ lk('attendance', 'Davomat') }}{% endif %}
  {{ lk('schedule', 'Dars jadvali') }}{{ lk('rating', 'Reyting') }}
  {% if user.role in ('admin','teacher') %}<a href="{{ url_for('export_grades') }}">Baholarni yuklab olish</a>{% endif %}
</nav>
<div class="me"><b>{{ user.fio }}</b>{{ ROLLAR[user.role] }}<br>
<a href="{{ url_for('password') }}">Parolni almashtirish</a><br>
<button type="button" onclick="var d=document.documentElement;d.dataset.theme=d.dataset.theme=='dark'?'light':'dark';localStorage.setItem('t',d.dataset.theme)">Yorug' / qorong'i</button><br>
<a href="{{ url_for('logout') }}">Chiqish</a></div></aside>
<main>{{ flashes() }}{% block main %}{% endblock %}</main>
{% else %}<div class="loginwrap">{{ logo() }}{{ flashes() }}{% block login %}{% endblock %}</div>{% endif %}
</body></html>"""

LOGIN = """{% extends 'base.html' %}{% block login %}
<form class="card" method="post"><h2>Tizimga kirish</h2>
<label for="l">Login</label><input id="l" name="login" autocomplete="username" required autofocus>
<label for="p">Parol</label><input id="p" name="parol" type="password" autocomplete="current-password" required>
<button class="btn" type="submit">Kirish</button></form>{% endblock %}"""

PASSWORD = """{% extends 'base.html' %}{% block main %}
<div class="top"><h1>Parolni almashtirish</h1>{% if session.must_change %}<p>Davom etishdan oldin yangi parol o'rnating.</p>{% endif %}</div>
<form class="card" method="post" style="max-width:420px"><label for="o">Eski parol</label><input id="o" name="old" type="password" required>
<label for="n">Yangi parol</label><input id="n" name="new" type="password" minlength="6" required>
<label for="n2">Yangi parolni takrorlang</label><input id="n2" name="new2" type="password" minlength="6" required>
<button class="btn" type="submit">Parolni saqlash</button></form>{% endblock %}"""

PANEL = """{% extends 'base.html' %}{% block main %}
<div class="top"><h1>Boshqaruv paneli</h1><p>Yuksalish maktabi elektron kundaligi</p></div>
<section class="stats">
<div class="stat"><span>O'quvchilar</span><b>{{ stats.students }}</b></div><div class="stat"><span>Sinflar</span><b>{{ stats.classes }}</b></div>
<div class="stat"><span>Bugungi baholar</span><b>{{ stats.today }}</b></div><div class="stat hl"><span>Jami ballar</span><b>{{ stats.points }}</b></div></section>
{% if not students %}<div class="msg error">Sizga biriktirilgan o'quvchi yo'q. Administrator sizni dars jadvaliga qo'shishi kerak.</div>{% endif %}
<section class="grid2" style="margin-bottom:22px">
<form class="card" method="post" action="{{ url_for('add_grade') }}"><h2>Baho va vazifa qo'shish</h2>
<label for="s1">O'quvchi</label><select id="s1" name="student" required><option value="">Tanlang</option>{% for s in students %}<option value="{{ s.id }}">{{ s.fio }} ({{ s.cname or '—' }})</option>{% endfor %}</select>
<label for="fan">Fan</label><select id="fan" name="fan">{% for f in fanlar %}<option>{{ f }}</option>{% endfor %}</select>
<label for="b">Baho</label><select id="b" name="baho"><option value="5">5 (A'lo)</option><option value="4">4 (Yaxshi)</option><option value="3">3 (Qoniqarli)</option><option value="2">2 (Qoniqarsiz)</option></select>
<label for="hw">Uyga vazifa</label><input id="hw" name="hw" placeholder="15-mashqni yechish"><button class="btn" type="submit">Bahoni saqlash</button></form>
<form class="card" method="post" action="{{ url_for('add_points') }}"><h2>Rag'bat va jarima ballari</h2>
<label for="s2">O'quvchi</label><select id="s2" name="student" required><option value="">Tanlang</option>{% for s in students %}<option value="{{ s.id }}">{{ s.fio }} ({{ s.cname or '—' }})</option>{% endfor %}</select>
<label for="t">Ball turi</label><select id="t" name="tur"><option value="plus">Rag'batlantirish (+ ball)</option><option value="minus">Jarima (− ball)</option></select>
<label for="bl">Ball miqdori</label><input id="bl" name="ball" type="number" value="5" min="1" required>
<label for="sb">Sababi</label><input id="sb" name="sabab" placeholder="Darsda faol qatnashdi"><button class="btn" type="submit">Ballni yozish</button></form></section>
<div class="card"><h2>Oxirgi baholar</h2>
<form class="filter" method="get"><input name="q" value="{{ qs }}" placeholder="O'quvchi ismi"><select name="fan"><option value="">Barcha fanlar</option>{% for f in fanlar %}<option {{ 'selected' if f == fan }}>{{ f }}</option>{% endfor %}</select><button class="btn sm" type="submit">Qidirish</button></form>
{% if grades %}<table><thead><tr><th>O'quvchi</th><th>Sinf</th><th>Fan</th><th>Baho</th><th>Vazifa</th><th>Sana</th></tr></thead><tbody>
{% for g in grades %}<tr><td><a href="{{ url_for('journal', sid=g.student_id) }}">{{ g.fio }}</a></td><td>{{ g.cname or '—' }}</td><td>{{ g.fan }}</td><td><b>{{ g.baho }}</b></td><td>{{ g.hw or '—' }}</td><td>{{ g.created }}</td></tr>{% endfor %}</tbody></table>
{% else %}<p class="empty">Baholar topilmadi.</p>{% endif %}</div>
<div class="card"><h2>Oxirgi ballar</h2>{% if pts %}<table><thead><tr><th>O'quvchi</th><th>Ball</th><th>Sababi</th></tr></thead><tbody>
{% for p in pts %}<tr><td><a href="{{ url_for('journal', sid=p.student_id) }}">{{ p.fio }}</a></td><td class="{{ 'plus' if p.amount > 0 else 'minus' }}">{{ '+' if p.amount > 0 }}{{ p.amount }}</td><td>{{ p.reason or '—' }}</td></tr>{% endfor %}</tbody></table>
{% else %}<p class="empty">Ballar yo'q.</p>{% endif %}</div>{% endblock %}"""

KIDS = """{% extends 'base.html' %}{% block main %}
<div class="top"><h1>Farzandlarim</h1><p>Baholar, davomat va ballarni ko'rish</p></div>
<div class="card">{% if kids %}<table><thead><tr><th>Ism-familiya</th><th>Sinf</th><th></th></tr></thead><tbody>
{% for k in kids %}<tr><td><b>{{ k.fio }}</b></td><td>{{ k.cname or '—' }}</td><td><a href="{{ url_for('journal', sid=k.id) }}">Jurnalni ochish</a></td></tr>{% endfor %}</tbody></table>
{% else %}<p class="empty">Sizga farzand biriktirilmagan. Administratorga murojaat qiling.</p>{% endif %}</div>{% endblock %}"""

JOURNAL = """{% extends 'base.html' %}{% block main %}
<div class="top"><h1>{{ s.fio }}</h1><p>Sinf: {{ s.cname or 'biriktirilmagan' }}</p></div>
{% if badges %}<div style="margin-bottom:16px">{% for b in badges %}<span class="tag">★ {{ b }}</span>{% endfor %}</div>{% endif %}
<section class="stats three"><div class="stat"><span>O'rtacha baho</span><b>{{ avg }}</b></div>
<div class="stat"><span>Davomat</span><b>{{ (rate ~ '%') if rate is not none else '—' }}</b></div><div class="stat hl"><span>Jami ballar</span><b>{{ total }}</b></div></section>
<section class="grid2" style="margin-bottom:22px">
<div class="card"><h2>Fanlar bo'yicha o'rtacha</h2>{% if byfan %}<table><thead><tr><th>Fan</th><th>O'rtacha</th><th>Baholar</th></tr></thead><tbody>
{% for f in byfan %}<tr><td>{{ f.fan }}</td><td><b>{{ f.a }}</b></td><td>{{ f.n }}</td></tr>{% endfor %}</tbody></table>{% else %}<p class="empty">Baho yo'q.</p>{% endif %}</div>
<div class="card"><h2>Davomat</h2>{% if att %}<table><thead><tr><th>Sana</th><th>Holat</th></tr></thead><tbody>
{% for a in att %}<tr><td>{{ a.date }}</td><td class="{{ 'minus' if a.status == 'kelmadi' }}">{{ ST[a.status] }}</td></tr>{% endfor %}</tbody></table>{% else %}<p class="empty">Davomat belgilanmagan.</p>{% endif %}</div></section>
<div class="card"><h2>Baholar va uyga vazifa</h2>{% if grades %}<table><thead><tr><th>Fan</th><th>Baho</th><th>Vazifa</th><th>Sana</th></tr></thead><tbody>
{% for g in grades %}<tr><td>{{ g.fan }}</td><td><b>{{ g.baho }}</b></td><td>{{ g.hw or '—' }}</td><td>{{ g.created }}</td></tr>{% endfor %}</tbody></table>{% else %}<p class="empty">Baho yo'q.</p>{% endif %}</div>
<div class="card"><h2>Rag'bat va jarimalar</h2>{% if pts %}<table><thead><tr><th>Ball</th><th>Sababi</th><th>Sana</th></tr></thead><tbody>
{% for p in pts %}<tr><td class="{{ 'plus' if p.amount > 0 else 'minus' }}">{{ '+' if p.amount > 0 }}{{ p.amount }}</td><td>{{ p.reason or '—' }}</td><td>{{ p.created }}</td></tr>{% endfor %}</tbody></table>{% else %}<p class="empty">Ballar yo'q.</p>{% endif %}</div>{% endblock %}"""

USERFORM = """<form class="card" method="post" action="{{ action }}"><h2>{{ title }}</h2>
<label for="fio">To'liq ism-familiya</label><input id="fio" name="fio" value="{{ u.fio if u }}" required>
<label for="lg">Login</label><input id="lg" name="login" value="{{ u.login if u }}" {{ 'disabled' if u else 'required' }}>
<label for="pw">{{ 'Yangi parol (o\\'zgartirmasangiz bo\\'sh qoldiring)' if u else 'Parol' }}</label><input id="pw" name="parol" type="password" minlength="6" placeholder="Kamida 6 ta belgi" {{ '' if u else 'required' }}>
<label for="rol">Roli</label><select id="rol" name="rol">{% for k, v in ROLLAR.items() %}<option value="{{ k }}" {{ 'selected' if u and u.role == k }}>{{ v }}</option>{% endfor %}</select>
<label for="cl">Sinfi (o'quvchi uchun)</label><select id="cl" name="class_id"><option value="">—</option>{% for c in classes %}<option value="{{ c.id }}" {{ 'selected' if u and u.class_id == c.id }}>{{ c.name }}</option>{% endfor %}</select>
<label for="pr">Ota-onasi (o'quvchi uchun)</label><select id="pr" name="parent_id"><option value="">—</option>{% for p in parents %}<option value="{{ p.id }}" {{ 'selected' if u and u.parent_id == p.id }}>{{ p.fio }}</option>{% endfor %}</select>
<button class="btn" type="submit">{{ btn }}</button></form>"""

USERS = """{% extends 'base.html' %}{% block main %}
<div class="top"><h1>Foydalanuvchilar</h1></div>
{% set u = None %}{% set action = url_for('add_user') %}{% set title = "Foydalanuvchi qo'shish" %}{% set btn = "Qo'shish" %}{% include '_userform.html' %}
<div class="card"><h2>Tizim foydalanuvchilari</h2>
<form class="filter" method="get"><input name="q" value="{{ qs }}" placeholder="Ism yoki login"><select name="role"><option value="">Barcha rollar</option>{% for k, v in ROLLAR.items() %}<option value="{{ k }}" {{ 'selected' if role == k }}>{{ v }}</option>{% endfor %}</select>
<select name="class_id"><option value="">Barcha sinflar</option>{% for c in classes %}<option value="{{ c.id }}" {{ 'selected' if cid == c.id|string }}>{{ c.name }}</option>{% endfor %}</select><button class="btn sm" type="submit">Qidirish</button></form>
<table><thead><tr><th>Ism-familiya</th><th>Login</th><th>Rol</th><th>Sinf</th><th>Ota-onasi</th><th>Amal</th></tr></thead><tbody>
{% for r in rows %}<tr><td><b>{{ r.fio }}</b></td><td>@{{ r.login }}</td><td><span class="tag">{{ ROLLAR[r.role] }}</span></td><td>{{ r.cname or '—' }}</td><td>{{ r.pfio or '—' }}</td>
<td style="white-space:nowrap"><a href="{{ url_for('edit_user', uid=r.id) }}">Tahrirlash</a>
{% if r.id != 1 %} · <form method="post" action="{{ url_for('delete_user', uid=r.id) }}" style="display:inline" onsubmit="return confirm('O\\'chirilsinmi?')"><button class="link" type="submit">O'chirish</button></form>{% endif %}</td></tr>{% endfor %}</tbody></table></div>{% endblock %}"""

EDIT = """{% extends 'base.html' %}{% block main %}
<div class="top"><h1>Tahrirlash</h1><p><a href="{{ url_for('users') }}">← Ro'yxatga qaytish</a></p></div>
{% set action = url_for('edit_user', uid=u.id) %}{% set title = u.fio %}{% set btn = "Saqlash" %}{% include '_userform.html' %}{% endblock %}"""

CLASSES = """{% extends 'base.html' %}{% block main %}
<div class="top"><h1>Sinflar</h1><p>O'quvchini sinfga biriktirish: Foydalanuvchilar → Tahrirlash</p></div>
<form class="card" method="post" style="max-width:420px"><h2>Sinf yaratish</h2><label for="n">Sinf nomi</label><input id="n" name="name" placeholder="5-A" required><button class="btn" type="submit">Yaratish</button></form>
<div class="card"><h2>Barcha sinflar</h2>{% if rows %}<table><thead><tr><th>Sinf</th><th>O'quvchilar</th><th>Amal</th></tr></thead><tbody>
{% for c in rows %}<tr><td><b>{{ c.name }}</b></td><td>{{ c.n }}</td><td><a href="{{ url_for('schedule', class_id=c.id) }}">Jadval</a> · <a href="{{ url_for('attendance', class_id=c.id) }}">Davomat</a> ·
<form method="post" action="{{ url_for('delete_class', cid=c.id) }}" style="display:inline" onsubmit="return confirm('Sinf o\\'chirilsinmi?')"><button class="link" type="submit">O'chirish</button></form></td></tr>{% endfor %}</tbody></table>
{% else %}<p class="empty">Hali sinf yo'q. Yuqoridagi formadan birinchi sinfni yarating.</p>{% endif %}</div>{% endblock %}"""

ATT = """{% extends 'base.html' %}{% block main %}
<div class="top"><h1>Davomat</h1></div>
{% if not cls %}<div class="card"><p class="empty">Sinf yo'q yoki sizga sinf biriktirilmagan.</p></div>{% else %}
<div class="card"><form class="filter" method="get"><select name="class_id">{% for c in cls %}<option value="{{ c.id }}" {{ 'selected' if cid == c.id|string }}>{{ c.name }}</option>{% endfor %}</select>
<input type="date" name="date" value="{{ d }}"><button class="btn sm" type="submit">Ko'rsatish</button></form>
{% if students %}<form method="post"><input type="hidden" name="class_id" value="{{ cid }}"><input type="hidden" name="date" value="{{ d }}"><table><tbody>
{% for s in students %}<tr><td><b>{{ s.fio }}</b></td><td class="radios">{% for k, v in ST.items() %}<label><input type="radio" name="s{{ s.id }}" value="{{ k }}" {{ 'checked' if saved.get(s.id, 'keldi') == k }}>{{ v }}</label>{% endfor %}</td></tr>{% endfor %}</tbody></table>
<button class="btn" type="submit">Davomatni saqlash</button></form>{% else %}<p class="empty">Bu sinfda o'quvchi yo'q.</p>{% endif %}</div>{% endif %}{% endblock %}"""

SCHED = """{% extends 'base.html' %}{% block main %}
<div class="top"><h1>Dars jadvali</h1></div>
{% if not cls %}<div class="card"><p class="empty">Sinf topilmadi.</p></div>{% else %}
<div class="card"><form class="filter" method="get" style="max-width:360px"><select name="class_id">{% for c in cls %}<option value="{{ c.id }}" {{ 'selected' if cid == c.id|string }}>{{ c.name }}</option>{% endfor %}</select><button class="btn sm" type="submit">Ko'rsatish</button></form>
<table><thead><tr><th>Dars</th>{% for k in KUNLAR %}<th>{{ k }}</th>{% endfor %}</tr></thead><tbody>
{% for l in range(1, 8) %}<tr><td><b>{{ l }}</b></td>{% for di in range(6) %}{% set x = grid.get((di, l)) %}<td class="cell">{% if x %}<b>{{ x.fan }}</b>{{ x.tfio or '' }}{% if x.room %}<br>{{ x.room }}-xona{% endif %}
{% if user.role == 'admin' %}<form method="post" action="{{ url_for('schedule_delete', sid=x.id) }}"><button class="link" type="submit">o'chirish</button></form>{% endif %}{% endif %}</td>{% endfor %}</tr>{% endfor %}</tbody></table></div>
{% if user.role == 'admin' and cid %}<form class="card" method="post" action="{{ url_for('schedule_add') }}" style="max-width:520px"><h2>Darsni jadvalga qo'shish</h2><input type="hidden" name="class_id" value="{{ cid }}">
<label for="d">Kun</label><select id="d" name="day">{% for k in KUNLAR %}<option value="{{ loop.index0 }}">{{ k }}</option>{% endfor %}</select>
<label for="ls">Dars raqami</label><input id="ls" name="lesson" type="number" min="1" max="7" value="1" required>
<label for="f">Fan</label><select id="f" name="fan">{% for f in fanlar %}<option>{{ f }}</option>{% endfor %}</select>
<label for="t">O'qituvchi</label><select id="t" name="teacher_id"><option value="">—</option>{% for t in teachers %}<option value="{{ t.id }}">{{ t.fio }}</option>{% endfor %}</select>
<label for="r">Xona</label><input id="r" name="room" placeholder="12"><button class="btn" type="submit">Qo'shish</button></form>{% endif %}{% endif %}{% endblock %}"""

RATING = """{% extends 'base.html' %}{% block main %}
<div class="top"><h1>Reyting</h1><p>Eng ko'p ball to'plagan o'quvchilar</p></div>
<div class="card"><form class="filter" method="get" style="max-width:360px"><select name="class_id"><option value="">Butun maktab</option>{% for c in cls %}<option value="{{ c.id }}" {{ 'selected' if cid == c.id|string }}>{{ c.name }}</option>{% endfor %}</select><button class="btn sm" type="submit">Ko'rsatish</button></form>
{% if rows %}<table><thead><tr><th>#</th><th>O'quvchi</th><th>Sinf</th><th>Ball</th></tr></thead><tbody>
{% for r in rows %}<tr><td>{{ loop.index }}</td><td><b>{{ r.fio }}</b></td><td>{{ r.cname or '—' }}</td><td class="{{ 'plus' if r.total > 0 else 'minus' if r.total < 0 }}">{{ r.total }}</td></tr>{% endfor %}</tbody></table>
{% else %}<p class="empty">O'quvchi yo'q.</p>{% endif %}</div>{% endblock %}"""

app.jinja_loader = DictLoader({
    "base.html": BASE, "login.html": LOGIN, "password.html": PASSWORD, "panel.html": PANEL,
    "kids.html": KIDS, "journal.html": JOURNAL, "_userform.html": USERFORM, "users.html": USERS,
    "edit.html": EDIT, "classes.html": CLASSES, "attendance.html": ATT, "schedule.html": SCHED,
    "rating.html": RATING})


# Vercel'da ham, lokal ham: jadvallar va admin foydalanuvchisini yaratadi
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5665, debug=True)