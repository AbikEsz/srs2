"""AuthLab: 17 автоматтандырылған қауіпсіздік сценарийі (unittest)."""
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
