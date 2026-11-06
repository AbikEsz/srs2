
import argparse
import getpass
import hashlib
import hmac
import html
import os
import re
import secrets
import sqlite3
import sys
import time
from contextlib import contextmanager
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# ---------------------------------------------------------------- параметрлер
PBKDF2_ITERATIONS = int(os.environ.get("AUTHLAB_ITERATIONS", "600000"))
IDLE_TIMEOUT = 20 * 60          # 20 минут белсенділік болмаса
ABSOLUTE_TIMEOUT = 4 * 60 * 60  # жалпы ұзақтығы 4 сағат
PRELOGIN_TTL = 10 * 60          # кіру формасының токені 10 минут
MAX_FAILURES = 5                # қате әрекет саны
LOCK_SECONDS = 5 * 60           # шектеу уақыты 5 минут
MAX_BODY = 20000
MAX_PASSWORD_LEN = 128
ROLES = ("student", "teacher")
ROLE_LABEL = {"student": "студент", "teacher": "оқытушы"}
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
GENERIC_LOGIN_ERROR = "Неверный логин или пароль."

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
    ),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


def now():
    """Уақыт көзі (тестте ауыстырылады)."""
    return time.time()


# --------------------------------------------------------------- дерекқор
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    pw_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('student', 'teacher')),
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    created REAL NOT NULL,
    last_seen REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS prelogins (
    token_hash TEXT PRIMARY KEY,
    csrf TEXT NOT NULL,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS login_failures (
    username TEXT NOT NULL,
    ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_failures ON login_failures(username, ts);
"""


@contextmanager
def db(path):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(path):
    with db(path) as conn:
        conn.executescript(SCHEMA)


# ----------------------------------------------------------------- парольдер
def sha256_hex(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_password(password, iterations=None):
    iterations = iterations or PBKDF2_ITERATIONS
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (iterations, salt.hex(), dk.hex())


def verify_password(password, stored):
    try:
        algo, iterations, salt_hex, dk_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk.hex(), dk_hex)


@lru_cache(maxsize=8)
def _dummy_hash(iterations):
    return hash_password("dummy-password", iterations)


def create_user(path, username, password, role):
    username = username.strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]{3,32}", username):
        raise ValueError("Логин: 3-32 символа (a-z, 0-9, _ . -)")
    if role not in ROLES:
        raise ValueError("Роль: student немесе teacher")
    if len(password) < 8 or len(password) > MAX_PASSWORD_LEN:
        raise ValueError("Пароль: 8-%d символов" % MAX_PASSWORD_LEN)
    with db(path) as conn:
        conn.execute(
            "INSERT INTO users (username, pw_hash, role, created) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, now()),
        )


# ------------------------------------------------------------------ HTML
CSS = """
:root { --primary: #28a745; --primary-dark: #1e7e34; --soft: #e9f5e9; --ink: #212529; }
* { box-sizing: border-box; }
body { margin: 0; font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
       color: var(--ink); background: #f8f9fa; line-height: 1.5; }
.topbar { background: var(--primary); color: #fff; padding: 14px 0; }
.navbar { background: #212529; color: #fff; padding: 10px 0; }
.container { width: min(960px, 92%); margin: 0 auto; }
.row { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.brand { font-size: 1.6rem; margin: 0; font-weight: 700; }
.nav a { color: #fff; text-decoration: none; margin-right: 18px; }
.nav a:hover { color: #9be7ae; }
.user-chip { margin-right: 10px; opacity: .9; }
.inline-form { display: inline; margin: 0; }
main { padding: 36px 0 60px; }
.hero { background: var(--soft); padding: 40px 0; text-align: center; }
.hero h2 { margin: 0 0 8px; }
.card { background: #fff; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,.1);
        overflow: hidden; margin-bottom: 24px; }
.card-header { background: var(--primary); color: #fff; padding: 14px 20px; font-weight: 600; }
.card-body { padding: 20px; }
.narrow { max-width: 440px; margin: 0 auto; }
label { display: block; margin: 12px 0 4px; font-weight: 600; }
input[type=text], input[type=password], textarea {
    width: 100%; padding: 10px 12px; border: 1px solid #ced4da; border-radius: 6px; font: inherit; }
input:focus, textarea:focus { outline: 2px solid #9be7ae; border-color: var(--primary); }
.btn { display: inline-block; padding: 9px 18px; border: 0; border-radius: 6px; cursor: pointer;
       font: inherit; text-decoration: none; background: var(--primary); color: #fff; }
.btn:hover { background: var(--primary-dark); }
.btn-light { background: #fff; color: var(--ink); }
.btn-light:hover { background: #e2e6ea; }
.btn-sm { padding: 4px 12px; font-size: .9rem; }
.btn-block { width: 100%; margin-top: 18px; }
.alert { padding: 12px 16px; border-radius: 6px; margin-bottom: 14px; }
.alert-danger { background: #f8d7da; color: #721c24; }
.badge { background: #ffc107; color: #212529; padding: 2px 10px; border-radius: 20px; font-size: .85rem; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #e9ecef; }
th { background: var(--soft); }
.note-list { list-style: none; margin: 0; padding: 0; }
.note-list li { padding: 10px 0; border-bottom: 1px solid #e9ecef; }
.note-list a { color: var(--primary-dark); font-weight: 600; text-decoration: none; }
.note-body { white-space: pre-wrap; word-wrap: break-word; }
.muted { color: #6c757d; font-size: .9rem; }
footer { background: #212529; color: #adb5bd; padding: 20px 0; text-align: center; font-size: .9rem; }
"""


def esc(value):
    return html.escape(str(value), quote=True)


def page(title, body, user=None):
    nav_right = ""
    links = ""
    if user is not None:
        links = '<a href="/dashboard">Личный кабинет</a>'
        if user["role"] == "teacher":
            links += '<a href="/admin/users">Пользователи</a>'
        nav_right = (
            '<span class="user-chip">%s &middot; %s</span>'
            '<form method="post" action="/logout" class="inline-form">'
            '<input type="hidden" name="csrf" value="%s">'
            '<button class="btn btn-light btn-sm" type="submit">Выйти</button></form>'
            % (esc(user["username"]), esc(ROLE_LABEL[user["role"]]), esc(user["csrf"]))
        )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="ru"><head><meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
        "<title>%s - Green Garden AuthLab</title>"
        '<link rel="stylesheet" href="/static/style.css"></head><body>'
        '<header class="topbar"><div class="container row">'
        '<h1 class="brand">Green Garden &middot; AuthLab</h1><div>%s</div></div></header>'
        '<nav class="navbar"><div class="container nav">%s</div></nav>'
        '<main><div class="container">%s</div></main>'
        "<footer>Учебный проект: аутентификация, сессии и контроль доступа</footer>"
        "</body></html>" % (esc(title), nav_right, links, body)
    )


def login_page(csrf, error=""):
    err = '<div class="alert alert-danger">%s</div>' % esc(error) if error else ""
    body = (
        '<div class="card narrow"><div class="card-header">Вход в систему</div>'
        '<div class="card-body">%s'
        '<form method="post" action="/login" autocomplete="off">'
        '<input type="hidden" name="csrf" value="%s">'
        '<label for="username">Логин</label>'
        '<input type="text" id="username" name="username" maxlength="64" required>'
        '<label for="password">Пароль</label>'
        '<input type="password" id="password" name="password" maxlength="256" required>'
        '<button class="btn btn-block" type="submit">Войти</button></form></div></div>'
        % (err, esc(csrf))
    )
    return page("Вход", body)


def message_page(title, text, user=None):
    body = '<div class="card narrow"><div class="card-header">%s</div><div class="card-body">%s</div></div>' % (
        esc(title), esc(text))
    return page(title, body, user)


# ------------------------------------------------------------------- сервер
class Handler(BaseHTTPRequestHandler):
    server_version = "AuthLab"
    sys_version = ""

    def log_message(self, fmt, *args):
        if not getattr(self.server, "quiet", False):
            super().log_message(fmt, *args)

    # ---- көмекші әдістер
    @property
    def sess_name(self):
        return "__Host-session" if self.server.https_mode else "session"

    @property
    def pre_name(self):
        return "__Host-prelogin" if self.server.https_mode else "prelogin"

    def get_cookie(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            key, _, value = part.strip().partition("=")
            if key == name and 0 < len(value) <= 200:
                return value
        return None

    def cookie_header(self, name, value, max_age):
        parts = ["%s=%s" % (name, value), "Path=/", "HttpOnly", "SameSite=Lax",
                 "Max-Age=%d" % max_age]
        if self.server.https_mode:
            parts.append("Secure")
        return "; ".join(parts)

    def send_page(self, code, body="", cookies=(), location=None,
                  ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if location:
            self.send_header("Location", location)
        for cookie in cookies:
            self.send_header("Set-Cookie", cookie)
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location, cookies=()):
        self.send_page(303, "", cookies=cookies, location=location)

    def read_form(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > MAX_BODY:
            return None
        raw = self.rfile.read(length).decode("utf-8", "replace")
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    @staticmethod
    def csrf_ok(expected, form):
        given = (form or {}).get("csrf", "")
        return bool(expected) and hmac.compare_digest(given.encode(), expected.encode())

    # ---- сессия және pre-login
    def current_session(self, conn):
        token = self.get_cookie(self.sess_name)
        if not token:
            return None
        row = conn.execute(
            "SELECT s.token_hash, s.user_id, s.csrf, s.created, s.last_seen, "
            "u.username, u.role FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token_hash = ?", (sha256_hex(token),)).fetchone()
        if row is None:
            return None
        t = now()
        if t - row["last_seen"] > IDLE_TIMEOUT or t - row["created"] > ABSOLUTE_TIMEOUT:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
            return None
        conn.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?",
                     (t, row["token_hash"]))
        return row

    def current_prelogin(self, conn):
        token = self.get_cookie(self.pre_name)
        if not token:
            return None
        row = conn.execute("SELECT token_hash, csrf, created FROM prelogins "
                           "WHERE token_hash = ?", (sha256_hex(token),)).fetchone()
        if row is None or now() - row["created"] > PRELOGIN_TTL:
            return None
        return row

    def new_session(self, conn, user_id):
        token = secrets.token_urlsafe(32)          # 32 байт = 256 бит
        csrf = secrets.token_urlsafe(32)
        t = now()
        conn.execute("INSERT INTO sessions (token_hash, user_id, csrf, created, last_seen) "
                     "VALUES (?, ?, ?, ?, ?)", (sha256_hex(token), user_id, csrf, t, t))
        return token

    # ---- маршруттар
    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def dispatch(self, method):
        path = urlsplit(self.path).path
        try:
            if method == "GET" and path == "/static/style.css":
                return self.send_page(200, CSS, ctype="text/css; charset=utf-8")
            with db(self.server.db_path) as conn:
                self.route(conn, method, path)
        except Exception as exc:  # ішкі қате туралы мәлімет сыртқа шықпайды
            sys.stderr.write("AuthLab error: %r\n" % (exc,))
            self.send_page(500, message_page("Ошибка", "Внутренняя ошибка сервера."))

    def route(self, conn, method, path):
        if method == "GET":
            if path == "/":
                return self.redirect("/dashboard")
            if path == "/login":
                return self.get_login(conn)
            if path == "/dashboard":
                return self.get_dashboard(conn)
            if path == "/admin/users":
                return self.get_admin_users(conn)
            match = re.fullmatch(r"/notes/(\d{1,9})", path)
            if match:
                return self.get_note(conn, int(match.group(1)))
        elif method == "POST":
            if path == "/login":
                return self.post_login(conn)
            if path == "/logout":
                return self.post_logout(conn)
            if path == "/notes":
                return self.post_note(conn)
        self.send_page(404, message_page("404", "Страница не найдена."))

    def get_login(self, conn):
        t = now()
        conn.execute("DELETE FROM prelogins WHERE created < ?", (t - PRELOGIN_TTL,))
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        conn.execute("INSERT INTO prelogins (token_hash, csrf, created) VALUES (?, ?, ?)",
                     (sha256_hex(token), csrf, t))
        self.send_page(200, login_page(csrf),
                       cookies=[self.cookie_header(self.pre_name, token, PRELOGIN_TTL)])

    def post_login(self, conn):
        form = self.read_form()
        pre = self.current_prelogin(conn)
        if form is None or pre is None or not self.csrf_ok(pre["csrf"], form):
            return self.send_page(403, message_page("403", "Недействительный CSRF-токен."))
        username = form.get("username", "").strip().lower()[:64]
        password = form.get("password", "")[:MAX_PASSWORD_LEN + 1]
        t = now()
        conn.execute("DELETE FROM login_failures WHERE ts < ?", (t - LOCK_SECONDS,))
        failures = conn.execute("SELECT COUNT(*) FROM login_failures WHERE username = ? "
                                "AND ts > ?", (username, t - LOCK_SECONDS)).fetchone()[0]
        if failures >= MAX_FAILURES:
            return self.send_page(429, login_page(
                pre["csrf"], "Слишком много попыток. Повторите через 5 минут."))
        user = conn.execute("SELECT id, pw_hash FROM users WHERE username = ?",
                            (username,)).fetchone()
        stored = user["pw_hash"] if user else _dummy_hash(PBKDF2_ITERATIONS)
        ok = verify_password(password, stored) and user is not None \
            and len(password) <= MAX_PASSWORD_LEN
        if not ok:
            conn.execute("INSERT INTO login_failures (username, ts) VALUES (?, ?)",
                         (username, t))
            return self.send_page(401, login_page(pre["csrf"], GENERIC_LOGIN_ERROR))
        conn.execute("DELETE FROM login_failures WHERE username = ?", (username,))
        conn.execute("DELETE FROM prelogins WHERE token_hash = ?", (pre["token_hash"],))
        old = self.get_cookie(self.sess_name)      # session fixation: ескі токен жойылады
        if old:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (sha256_hex(old),))
        token = self.new_session(conn, user["id"])
        self.redirect("/dashboard", cookies=[
            self.cookie_header(self.sess_name, token, ABSOLUTE_TIMEOUT),
            self.cookie_header(self.pre_name, "", 0)])

    def post_logout(self, conn):
        form = self.read_form()
        sess = self.current_session(conn)
        if sess is None:
            return self.redirect("/login")
        if not self.csrf_ok(sess["csrf"], form):
            return self.send_page(403, message_page("403", "Недействительный CSRF-токен.", sess))
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (sess["token_hash"],))
        self.redirect("/login", cookies=[self.cookie_header(self.sess_name, "", 0)])

    def get_dashboard(self, conn):
        sess = self.current_session(conn)
        if sess is None:
            return self.redirect("/login")
        notes = conn.execute("SELECT id, title FROM notes WHERE owner_id = ? "
                             "ORDER BY id DESC", (sess["user_id"],)).fetchall()
        items = "".join('<li><a href="/notes/%d">%s</a></li>' % (n["id"], esc(n["title"]))
                        for n in notes) or '<li class="muted">Записей пока нет.</li>'
        body = (
            '<div class="hero"><h2>Здравствуйте, %s!</h2>'
            '<span class="badge">%s</span></div><br>'
            '<div class="card"><div class="card-header">Новая запись</div><div class="card-body">'
            '<form method="post" action="/notes">'
            '<input type="hidden" name="csrf" value="%s">'
            '<label for="title">Заголовок</label>'
            '<input type="text" id="title" name="title" maxlength="100" required>'
            '<label for="body">Текст</label>'
            '<textarea id="body" name="body" rows="4" maxlength="2000"></textarea>'
            '<button class="btn btn-block" type="submit">Сохранить</button></form></div></div>'
            '<div class="card"><div class="card-header">Мои записи</div><div class="card-body">'
            '<ul class="note-list">%s</ul></div></div>'
            % (esc(sess["username"]), esc(ROLE_LABEL[sess["role"]]), esc(sess["csrf"]), items)
        )
        self.send_page(200, page("Личный кабинет", body, sess))

    def post_note(self, conn):
        form = self.read_form()
        sess = self.current_session(conn)
        if sess is None:
            return self.redirect("/login")
        if not self.csrf_ok(sess["csrf"], form):
            return self.send_page(403, message_page("403", "Недействительный CSRF-токен.", sess))
        title = form.get("title", "").strip()[:100]
        text = form.get("body", "").strip()[:2000]
        if not title:
            return self.send_page(400, message_page("Ошибка", "Заголовок обязателен.", sess))
        conn.execute("INSERT INTO notes (owner_id, title, body, created) VALUES (?, ?, ?, ?)",
                     (sess["user_id"], title, text, now()))
        self.redirect("/dashboard")

    def get_note(self, conn, note_id):
        sess = self.current_session(conn)
        if sess is None:
            return self.redirect("/login")
        # IDOR қорғанысы: id және owner_id бір сұраныста тексеріледі
        note = conn.execute("SELECT * FROM notes WHERE id = ? AND owner_id = ?",
                            (note_id, sess["user_id"])).fetchone()
        if note is None:
            return self.send_page(404, message_page("404", "Запись не найдена.", sess))
        body = ('<div class="card"><div class="card-header">%s</div><div class="card-body">'
                '<p class="note-body">%s</p><a class="btn" href="/dashboard">Назад</a>'
                '</div></div>' % (esc(note["title"]), esc(note["body"])))
        self.send_page(200, page(note["title"], body, sess))

    def get_admin_users(self, conn):
        sess = self.current_session(conn)
        if sess is None:
            return self.redirect("/login")
        if sess["role"] != "teacher":               # серверлік рөл тексеруі
            return self.send_page(403, message_page("403", "Доступ запрещён.", sess))
        users = conn.execute("SELECT id, username, role FROM users ORDER BY id").fetchall()
        rows = "".join("<tr><td>%d</td><td>%s</td><td>%s</td></tr>"
                       % (u["id"], esc(u["username"]), esc(ROLE_LABEL[u["role"]]))
                       for u in users)
        body = ('<div class="card"><div class="card-header">Пользователи</div>'
                '<div class="card-body"><table><tr><th>ID</th><th>Логин</th><th>Роль</th></tr>'
                '%s</table></div></div>' % rows)
        self.send_page(200, page("Пользователи", body, sess))


def make_server(db_path, host="127.0.0.1", port=8000, https_mode=False, quiet=False):
    if host not in LOOPBACK_HOSTS:
        raise ValueError("AuthLab тек loopback мекенжайында (127.0.0.1) іске қосылады")
    init_db(db_path)
    server = ThreadingHTTPServer((host, port), Handler)
    server.db_path = db_path
    server.https_mode = https_mode
    server.quiet = quiet
    return server


# ---------------------------------------------------------------------- CLI
def main(argv=None):
    parser = argparse.ArgumentParser(prog="authlab")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="создать базу данных")
    add = sub.add_parser("add-user", help="добавить пользователя")
    add.add_argument("--username", required=True)
    add.add_argument("--role", required=True, choices=ROLES)
    serve = sub.add_parser("serve", help="запустить сервер")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--https-mode", action="store_true",
                       help="включить Secure и __Host- (за TLS-прокси)")
    args = parser.parse_args(argv)
    db_path = os.environ.get("AUTHLAB_DB", "authlab.db")

    if args.cmd == "init":
        init_db(db_path)
        print("База данных готова:", db_path)
    elif args.cmd == "add-user":
        init_db(db_path)
        password = getpass.getpass("Пароль: ")
        if password != getpass.getpass("Повторите пароль: "):
            sys.exit("Пароли не совпадают")
        try:
            create_user(db_path, args.username, password, args.role)
        except (ValueError, sqlite3.IntegrityError) as exc:
            sys.exit("Ошибка: %s" % exc)
        print("Пользователь создан:", args.username.lower(), "(%s)" % args.role)
    elif args.cmd == "serve":
        server = make_server(db_path, args.host, args.port, args.https_mode)
        print("AuthLab: http://%s:%d/login (Ctrl+C - остановить)" % (args.host, args.port))
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nОстановлено")
        finally:
            server.server_close()


if __name__ == "__main__":
    main()



import http.client
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import authlab  # noqa: E402

authlab.PBKDF2_ITERATIONS = 2000  # тест жылдамдығы үшін; әдепкі режимде 600 000


class Client:
    """Қарапайым HTTP клиент: cookie-ді қолмен сақтайды, redirect-ті ұстамайды."""

    def __init__(self, port):
        self.port = port
        self.cookies = {}
        self.last_set_cookie = []

    def request(self, method, path, data=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {}
        if self.cookies:
            headers["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        body = None
        if data is not None:
            body = "&".join("%s=%s" % (k, self._q(v)) for k, v in data.items())
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        text = resp.read().decode("utf-8", "replace")
        self.last_set_cookie = [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]
        for header in self.last_set_cookie:
            pair = header.split(";")[0]
            name, _, value = pair.partition("=")
            if "Max-Age=0" in header:
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = value
        result = (resp.status, dict((k.lower(), v) for k, v in resp.getheaders()), text)
        conn.close()
        return result

    @staticmethod
    def _q(value):
        from urllib.parse import quote
        return quote(value, safe="")

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, data):
        return self.request("POST", path, data)

    def csrf_from(self, text):
        return re.search(r'name="csrf" value="([^"]+)"', text).group(1)

    def login(self, username, password):
        _, _, text = self.get("/login")
        return self.post("/login", {"csrf": self.csrf_from(text),
                                    "username": username, "password": password})


class AuthLabTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test.db")
        self.offset = 0
        self._orig_now = authlab.now
        authlab.now = lambda: time.time() + self.offset
        self.server = authlab.make_server(self.db_path, port=0, quiet=True)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        authlab.create_user(self.db_path, "alice", "alice-pass-1", "student")
        authlab.create_user(self.db_path, "bob", "bob-pass-12", "student")
        authlab.create_user(self.db_path, "teacher", "teacher-pass-1", "teacher")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        authlab.now = self._orig_now
        self.tmp.cleanup()

    def client(self):
        return Client(self.port)

    def logged_in(self, username, password):
        c = self.client()
        status, _, _ = c.login(username, password)
        self.assertEqual(status, 303)
        return c

    def make_note(self, c, title="Заметка", body="Текст"):
        _, _, dash = c.get("/dashboard")
        status, _, _ = c.post("/notes", {"csrf": c.csrf_from(dash), "title": title, "body": body})
        self.assertEqual(status, 303)
        _, _, dash = c.get("/dashboard")
        return int(re.search(r"/notes/(\d+)", dash).group(1))

    # 01
    def test_01_anonymous_dashboard_redirects(self):
        status, headers, _ = self.client().get("/dashboard")
        self.assertEqual(status, 303)
        self.assertEqual(headers["location"], "/login")

    # 02
    def test_02_password_stored_as_pbkdf2(self):
        conn = sqlite3.connect(self.db_path)
        stored = conn.execute("SELECT pw_hash FROM users WHERE username='alice'").fetchone()[0]
        conn.close()
        self.assertTrue(stored.startswith("pbkdf2_sha256$"))
        self.assertNotIn("alice-pass-1", stored)
        self.assertEqual(len(stored.split("$")), 4)

    # 03
    def test_03_wrong_password_generic_message(self):
        s1, _, t1 = self.client().login("alice", "wrong-password")
        s2, _, t2 = self.client().login("no-such-user", "wrong-password")
        self.assertEqual((s1, s2), (401, 401))
        self.assertIn(authlab.GENERIC_LOGIN_ERROR, t1)
        self.assertIn(authlab.GENERIC_LOGIN_ERROR, t2)

    # 04
    def test_04_login_without_csrf(self):
        c = self.client()
        c.get("/login")
        status, _, _ = c.post("/login", {"username": "alice", "password": "alice-pass-1"})
        self.assertEqual(status, 403)

    # 05
    def test_05_cookie_attributes(self):
        c = self.client()
        c.get("/login")
        self.assertTrue(any("HttpOnly" in h and "SameSite=Lax" in h for h in c.last_set_cookie))
        c.login("alice", "alice-pass-1")
        session_cookie = [h for h in c.last_set_cookie if h.startswith("session=")][0]
        self.assertIn("HttpOnly", session_cookie)
        self.assertIn("SameSite=Lax", session_cookie)

    # 06
    def test_06_session_fixation(self):
        attacker = self.client()
        attacker.cookies["session"] = "attacker-chosen-token"
        status, _, _ = attacker.login("alice", "alice-pass-1")
        self.assertEqual(status, 303)
        self.assertNotEqual(attacker.cookies["session"], "attacker-chosen-token")
        replay = self.client()
        replay.cookies["session"] = "attacker-chosen-token"
        status, headers, _ = replay.get("/dashboard")
        self.assertEqual((status, headers["location"]), (303, "/login"))

    # 07
    def test_07_role_check_admin_users(self):
        student = self.logged_in("alice", "alice-pass-1")
        teacher = self.logged_in("teacher", "teacher-pass-1")
        self.assertEqual(student.get("/admin/users")[0], 403)
        status, _, text = teacher.get("/admin/users")
        self.assertEqual(status, 200)
        self.assertIn("alice", text)

    # 08
    def test_08_idor_foreign_note(self):
        alice = self.logged_in("alice", "alice-pass-1")
        bob = self.logged_in("bob", "bob-pass-12")
        note_id = self.make_note(alice)
        self.assertEqual(bob.get("/notes/%d" % note_id)[0], 404)
        self.assertEqual(alice.get("/notes/%d" % note_id)[0], 200)
        self.assertEqual(alice.get("/notes/999999")[0], 404)

    # 09
    def test_09_create_note_csrf(self):
        alice = self.logged_in("alice", "alice-pass-1")
        _, _, dash = alice.get("/dashboard")
        self.assertEqual(alice.post("/notes", {"title": "x", "body": "y"})[0], 403)
        self.assertEqual(alice.post("/notes", {"csrf": "wrong", "title": "x", "body": "y"})[0], 403)
        ok = alice.post("/notes", {"csrf": alice.csrf_from(dash), "title": "x", "body": "y"})
        self.assertEqual(ok[0], 303)

    # 10
    def test_10_logout_invalidates_cookie(self):
        alice = self.logged_in("alice", "alice-pass-1")
        old_token = alice.cookies["session"]
        _, _, dash = alice.get("/dashboard")
        status, _, _ = alice.post("/logout", {"csrf": alice.csrf_from(dash)})
        self.assertEqual(status, 303)
        replay = self.client()
        replay.cookies["session"] = old_token
        status, headers, _ = replay.get("/dashboard")
        self.assertEqual((status, headers["location"]), (303, "/login"))

    # 11
    def test_11_idle_timeout(self):
        alice = self.logged_in("alice", "alice-pass-1")
        self.offset = 19 * 60
        self.assertEqual(alice.get("/dashboard")[0], 200)
        self.offset += 21 * 60
        status, headers, _ = alice.get("/dashboard")
        self.assertEqual((status, headers["location"]), (303, "/login"))

    # 12
    def test_12_absolute_timeout(self):
        alice = self.logged_in("alice", "alice-pass-1")
        for minutes in range(19, 229, 19):          # әр қадам idle шегінен аз
            self.offset = minutes * 60
            self.assertEqual(alice.get("/dashboard")[0], 200)
        self.offset = 247 * 60                      # 4 сағаттан асты
        self.assertEqual(alice.get("/dashboard")[0], 303)

    # 13
    def test_13_html_escaped(self):
        alice = self.logged_in("alice", "alice-pass-1")
        payload = "<script>alert(1)</script>"
        note_id = self.make_note(alice, title=payload, body=payload)
        for path in ("/dashboard", "/notes/%d" % note_id):
            _, _, text = alice.get(path)
            self.assertNotIn(payload, text)
            self.assertIn("&lt;script&gt;", text)

    # 14
    def test_14_lockout_after_five_failures(self):
        for _ in range(5):
            self.assertEqual(self.client().login("alice", "bad-password")[0], 401)
        self.assertEqual(self.client().login("alice", "alice-pass-1")[0], 429)
        self.offset = 301
        self.assertEqual(self.client().login("alice", "alice-pass-1")[0], 303)

    # 15
    def test_15_sql_injection_login(self):
        status, _, _ = self.client().login("alice' OR '1'='1' --", "x' OR '1'='1")
        self.assertEqual(status, 401)
        status, _, _ = self.client().login("' OR 1=1 --", "anything")
        self.assertEqual(status, 401)

    # 16
    def test_16_security_headers(self):
        _, headers, _ = self.client().get("/login")
        self.assertIn("default-src 'self'", headers["content-security-policy"])
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertEqual(headers["x-content-type-options"], "nosniff")

    # 17
    def test_17_https_mode_cookie(self):
        server = authlab.make_server(self.db_path, port=0, https_mode=True, quiet=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            c = Client(server.server_address[1])
            c.get("/login")
            header = c.last_set_cookie[0]
            self.assertTrue(header.startswith("__Host-prelogin="))
            self.assertIn("Secure", header)
            self.assertIn("Path=/", header)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
