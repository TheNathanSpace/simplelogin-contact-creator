import logging
import os
import secrets
import sys
from http.server import ThreadingHTTPServer
from pathlib import Path

from argon2 import PasswordHasher

from app.config import Config
from app.crypto import load_or_create_key
from app.errors import StartupError
from app.logging_setup import configure_logging
from app.passwords import load_common
from app.server import App, Handler
from app.storage import init_db, issue_setup_code

log = logging.getLogger("adapter")


def _inside(path, parent):
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def prepare_storage(config):
    data_dir = config.data_dir
    secret_path = config.secret_path
    if data_dir.resolve() == secret_path.resolve() or _inside(secret_path, data_dir) or _inside(data_dir, secret_path):
        raise StartupError("SECRET_PATH must be outside DATA_DIR.")
    if data_dir.exists() and not data_dir.is_dir():
        raise StartupError(f"DATA_DIR is not a directory: {data_dir}")
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(data_dir, 0o700)
    except OSError as exc:
        raise StartupError(f"Could not create DATA_DIR {data_dir}: {exc.strerror}") from exc
    if not os.access(data_dir, os.W_OK | os.X_OK):
        raise StartupError(f"DATA_DIR is not writable: {data_dir}")


def _stop(message):
    if logging.getLogger().handlers:
        log.error("%s", message)
    else:
        print(f"ERROR {message}", file=sys.stderr)
    sys.exit(1)


def main():
    os.umask(0o077)
    try:
        config = Config.from_env()
    except StartupError as exc:
        _stop(str(exc))
    used_tz = configure_logging(config.tz_name)
    try:
        prepare_storage(config)
        key = load_or_create_key(config.secret_path)
        init_db(config.data_dir)
        common = load_common(Path(__file__).resolve().with_name("common-passwords.txt"))
        hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
        dummy_hash = hasher.hash(secrets.token_urlsafe(32))
        code = issue_setup_code(config.data_dir)
        css_path = Path(__file__).resolve().parent / "static" / "style.css"
        if not css_path.is_file():
            raise StartupError(f"Stylesheet is missing: {css_path}")
        css = css_path.read_bytes()
    except StartupError as exc:
        _stop(str(exc))
    app = App(config, key, hasher, dummy_hash, common, css)
    try:
        server = ThreadingHTTPServer((config.host, config.port), Handler)
    except OSError as exc:
        _stop(f"Could not listen on {config.host}:{config.port}: {exc.strerror or exc}")
    server.app = app
    server.daemon_threads = True
    log.info("listening on %s:%s", config.host, config.port)
    log.info("timezone %s", used_tz)
    if code:
        log.info("setup code: %s", code)
    else:
        log.info("account exists")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
