import ipaddress
import logging
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from app import actions, pages, storage

log = logging.getLogger("adapter")
CSS_PATH = Path(__file__).with_name("static") / "style.css"
MAX_BODY = 65536


class App:
    def __init__(self, config, key, hasher, dummy_hash, common, css):
        self.config = config
        self.key = key
        self.hasher = hasher
        self.dummy_hash = dummy_hash
        self.common = common
        self.css = css


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method):
        self._sent = False
        path = urlsplit(self.path).path
        try:
            if path == "/health" and method == "GET":
                self._reply(200, "ok\n", "text/plain; charset=utf-8")
                return
            if path == "/static/style.css" and method == "GET":
                self._reply(200, self.server.app.css, "text/css; charset=utf-8")
                return
            if path == "/" and method == "GET":
                self._home()
                return
            if path == "/setup" and method == "GET":
                self._setup_get()
                return
            if path == "/setup" and method == "POST":
                self._setup_post()
                return
            if path == "/login" and method == "GET":
                self._login_get()
                return
            if path == "/login" and method == "POST":
                self._login_post()
                return
            if path == "/send" and method == "GET":
                self._send_get()
                return
            if path == "/send" and method == "POST":
                self._send_post()
                return
            if path == "/logout" and method == "POST":
                self._logout()
                return
            self._html(404, pages.message_page("Not found.", "/", "Home"))
        except Exception:
            log.exception("request failed")
            if not self._sent:
                self._html(500, pages.message_page("Something went wrong.", "/", "Home"))

    def _home(self):
        if not storage.has_user(self.server.app.config.data_dir):
            self._redirect("/setup")
            return
        if self._auth() is None:
            self._redirect("/login")
            return
        self._redirect("/send")

    def _setup_get(self):
        data_dir = self.server.app.config.data_dir
        if storage.has_user(data_dir):
            self._redirect("/send" if self._auth() else "/login")
            return
        row, raw = self._ensure_csrf()
        self._html(200, pages.setup_page(row["csrf_token"], "", "", ""), self._cookie(raw))

    def _setup_post(self):
        app = self.server.app
        data_dir = app.config.data_dir
        if storage.has_user(data_dir):
            log.info("setup rejected: account already exists")
            self._redirect("/login")
            return
        form = self._form()
        if form is None:
            self._html(400, pages.message_page("Request is too large.", "/setup", "Setup"))
            return
        row = self._session()
        if not storage.csrf_matches(row, form.get("csrf", "")):
            log.info("setup rejected: bad csrf")
            self._html(400, pages.message_page("The form expired. Try again.", "/setup", "Setup"))
            return
        ip = self._client_ip()
        if storage.throttled(data_dir, ip):
            log.info("setup throttled ip=%s", ip)
            self._html(429, pages.setup_page(row["csrf_token"], "Too many attempts. Try again later.", form.get("username", ""), form.get("setup_code", "")))
            return
        try:
            username, _hibp = actions.create_account(
                app,
                form.get("setup_code", ""),
                form.get("username", ""),
                form.get("password", ""),
                form.get("api_key", ""),
            )
        except actions.ActionError as exc:
            if exc.code == "bad_code":
                storage.record_failure(data_dir, ip)
            if exc.code == "account_exists":
                log.info("setup rejected: account already exists")
                self._redirect("/login")
                return
            log.info("setup rejected: %s", exc.code)
            self._html(
                400,
                pages.setup_page(
                    row["csrf_token"],
                    exc.message,
                    form.get("username", ""),
                    form.get("setup_code", ""),
                ),
            )
            return
        storage.clear_failures(data_dir, ip)
        storage.delete_session(data_dir, self._raw_token())
        log.info("account created user=%s", actions.log_value(username))
        self._redirect("/login", self._clear_cookie())

    def _login_get(self):
        data_dir = self.server.app.config.data_dir
        if not storage.has_user(data_dir):
            self._redirect("/setup")
            return
        if self._auth() is not None:
            self._redirect("/send")
            return
        row, raw = self._ensure_csrf()
        self._html(200, pages.login_page(row["csrf_token"], ""), self._cookie(raw))

    def _login_post(self):
        app = self.server.app
        data_dir = app.config.data_dir
        if not storage.has_user(data_dir):
            self._redirect("/setup")
            return
        form = self._form()
        if form is None:
            self._html(400, pages.message_page("Request is too large.", "/login", "Log in"))
            return
        row = self._session()
        if not storage.csrf_matches(row, form.get("csrf", "")):
            log.info("login rejected: bad csrf")
            self._html(400, pages.message_page("The form expired. Try again.", "/login", "Log in"))
            return
        ip = self._client_ip()
        if storage.throttled(data_dir, ip):
            log.info("login throttled ip=%s", ip)
            self._html(429, pages.login_page(row["csrf_token"], "Too many attempts. Try again later."))
            return
        try:
            username = actions.authenticate(app, form.get("username", ""), form.get("password", ""))
        except actions.ActionError:
            storage.record_failure(data_dir, ip)
            log.info("login failed")
            self._html(401, pages.login_page(row["csrf_token"], "Invalid username or password."))
            return
        storage.clear_failures(data_dir, ip)
        storage.delete_session(data_dir, self._raw_token())
        raw, _csrf = storage.create_session(data_dir, 1)
        log.info("login succeeded user=%s", actions.log_value(username))
        self._redirect("/send", self._cookie(raw))

    def _send_get(self):
        row = self._require_auth()
        if row is None:
            return
        self._html(200, pages.send_page(row["csrf_token"], "", "", "", None), self._cookie(self._raw_token()))

    def _send_post(self):
        app = self.server.app
        row = self._require_auth()
        if row is None:
            return
        form = self._form()
        if form is None:
            self._html(400, pages.message_page("Request is too large.", "/send", "Back"))
            return
        if not storage.csrf_matches(row, form.get("csrf", "")):
            log.info("send rejected: bad csrf")
            self._html(400, pages.message_page("The form expired. Try again.", "/send", "Back"))
            return
        alias = form.get("alias", "")
        recipient = form.get("recipient", "")
        try:
            result = actions.build_send(app, alias, recipient)
        except actions.ActionError as exc:
            log.info(
                "send failed alias=%s recipient=%s error=%s",
                actions.log_value(alias),
                actions.log_value(recipient),
                actions.log_value(exc.message),
            )
            self._html(400, pages.send_page(row["csrf_token"], exc.message, alias, recipient, None))
            return
        log.info(
            "send alias=%s recipient=%s alias_created=%s contact_existed=%s disabled=%s",
            actions.log_value(result["alias"]),
            actions.log_value(result["recipient"]),
            result["alias_created"],
            result["contact_existed"],
            result["alias_disabled"],
        )
        self._html(
            200,
            pages.send_page(row["csrf_token"], "", alias, recipient, result),
            self._cookie(self._raw_token()),
        )

    def _logout(self):
        data_dir = self.server.app.config.data_dir
        row = self._auth()
        form = self._form()
        if row is None or form is None or not storage.csrf_matches(row, form.get("csrf", "")):
            log.info("logout rejected")
            if row is None:
                self._redirect("/login")
                return
            self._html(400, pages.message_page("The form expired. Try again.", "/send", "Back"))
            return
        storage.delete_session(data_dir, self._raw_token())
        log.info("logout")
        self._redirect("/login", self._clear_cookie())

    def _require_auth(self):
        data_dir = self.server.app.config.data_dir
        if not storage.has_user(data_dir):
            self._redirect("/setup")
            return None
        row = self._auth()
        if row is None:
            self._redirect("/login")
            return None
        return row

    def _ensure_csrf(self):
        row = self._session()
        if row is not None:
            return row, None
        raw, _csrf = storage.create_session(self.server.app.config.data_dir, None)
        row = storage.get_session(self.server.app.config.data_dir, raw)
        return row, raw

    def _auth(self):
        row = self._session()
        if row is None or row["user_id"] is None:
            return None
        return row

    def _session(self):
        return storage.get_session(self.server.app.config.data_dir, self._raw_token())

    def _raw_token(self):
        return self._cookies().get(self.server.app.config.cookie_name, "")

    def _cookies(self):
        found = {}
        for part in self.headers.get("Cookie", "").split(";"):
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            found[name.strip()] = value.strip()
        return found

    def _form(self):
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            return None
        if length < 0 or length > MAX_BODY:
            return None
        raw = self.rfile.read(length)
        parsed = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
        return {key: values[0] for key, values in parsed.items()}

    def _client_ip(self):
        peer = self.client_address[0]
        try:
            peer_ip = ipaddress.ip_address(peer).compressed
        except ValueError:
            return peer
        trusted = self.server.app.config.trusted_proxies
        if peer_ip not in trusted:
            return peer_ip
        parts = []
        for item in self.headers.get("X-Forwarded-For", "").split(","):
            item = item.strip()
            if not item:
                continue
            try:
                parts.append(ipaddress.ip_address(item).compressed)
            except ValueError:
                continue
        for address in reversed(parts):
            if address not in trusted:
                return address
        return peer_ip

    def _cookie(self, token):
        if not token:
            return None
        name = self.server.app.config.cookie_name
        max_age = 14 * 24 * 3600
        cookie = f"{name}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}"
        if self.server.app.config.cookie_secure:
            cookie += "; Secure"
        return ("Set-Cookie", cookie)

    def _clear_cookie(self):
        name = self.server.app.config.cookie_name
        cookie = f"{name}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
        if self.server.app.config.cookie_secure:
            cookie += "; Secure"
        return ("Set-Cookie", cookie)

    def _redirect(self, location, cookie=None):
        headers = [("Location", location)]
        if cookie:
            headers.append(cookie)
        self._reply(303, "", "text/plain; charset=utf-8", no_store=True, extra_headers=headers)

    def _html(self, status, html, cookie=None):
        headers = [cookie] if cookie else None
        self._reply(status, html, "text/html; charset=utf-8", no_store=True, extra_headers=headers)

    def _reply(self, status, body, content_type, no_store=False, extra_headers=None):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        )
        if no_store:
            self.send_header("Cache-Control", "no-store")
        for header in extra_headers or []:
            self.send_header(header[0], header[1])
        self.end_headers()
        self.wfile.write(data)
        self._sent = True
