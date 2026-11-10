import hmac
import logging

from argon2.exceptions import InvalidHashError, VerifyMismatchError

from app.crypto import decrypt, encrypt
from app.logging_setup import one_line
from app.passwords import PasswordError, check_new_password
from app.simplelogin import SLError, clean_email, resolve, verify_api_key
from app.storage import get_user, insert_user, setup_code_matches


class ActionError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def create_account(app, setup_code, username, password, api_key):
    if not setup_code_matches(app.config.data_dir, setup_code):
        raise ActionError("bad_code", "Setup code is not valid.")
    name = _username(username)
    if name is None:
        raise ActionError("bad_username", "Enter a username of up to 64 characters with no spaces.")
    if len(password or "") > 1024:
        raise ActionError("password_length", "Password must be at most 1024 characters.")
    try:
        hibp = check_new_password(password or "", app.common)
    except PasswordError as exc:
        raise ActionError(exc.code, exc.message) from exc
    if hibp == "hibp_skipped":
        logging.getLogger("adapter").warning("HIBP check skipped")
    key = _api_key(api_key)
    if key is None:
        raise ActionError("bad_api_key", "Enter a SimpleLogin API key.")
    try:
        verify_api_key(app.config.base_url, key)
    except SLError as exc:
        raise ActionError("simplelogin", exc.message) from exc
    password_hash = app.hasher.hash(password)
    nonce, ciphertext = encrypt(app.key, key)
    saved = insert_user(app.config.data_dir, name, password_hash, nonce, ciphertext)
    if not saved:
        raise ActionError("account_exists", "An account already exists.")
    return name, hibp


def authenticate(app, username, password):
    user = get_user(app.config.data_dir)
    supplied = username or ""
    password = password or ""
    if len(password) > 1024:
        password = "x" * 16
        user = None
    matched = user is not None and _same(user["username"], supplied)
    if not matched:
        try:
            app.hasher.verify(app.dummy_hash, password)
        except (VerifyMismatchError, InvalidHashError):
            pass
        raise ActionError("login_failed", "Invalid username or password.")
    try:
        app.hasher.verify(user["password_hash"], password)
    except VerifyMismatchError as exc:
        raise ActionError("login_failed", "Invalid username or password.") from exc
    return user["username"]


def build_send(app, alias_raw, recipient_raw):
    alias = clean_email(alias_raw)
    recipient = clean_email(recipient_raw)
    if alias is None or recipient is None:
        raise ActionError("bad_email", "Enter an alias and a recipient.")
    user = get_user(app.config.data_dir)
    if user is None:
        raise ActionError("no_account", "An account is required.")
    try:
        api_key = decrypt(app.key, user["api_nonce"], user["api_ciphertext"])
    except Exception as exc:
        raise ActionError("secret", "Could not read the stored API key.") from exc
    try:
        result = resolve(app.config.base_url, api_key, alias, recipient)
    except SLError as exc:
        raise ActionError("simplelogin", exc.message) from exc
    if result["alias_created"]:
        alias_note = "Alias created."
    else:
        alias_note = "Alias found."
    if result["contact_existed"]:
        contact_note = "Contact already existed."
    else:
        contact_note = "Contact created."
    result["summary"] = f"{alias_note} {contact_note}"
    result["disabled"] = result["alias_disabled"]
    result["alias"] = alias
    result["recipient"] = recipient
    return result


def _same(left, right):
    a = left.encode("utf-8")
    b = right.encode("utf-8")
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)


def _username(value):
    text = (value or "").strip()
    if not text or len(text) > 64 or any(ch.isspace() for ch in text):
        return None
    return text


def _api_key(value):
    text = (value or "").strip()
    if not text or len(text) > 512 or any(ch.isspace() for ch in text):
        return None
    return text


def log_value(value):
    return one_line(value, 254)
