import hashlib
import urllib.error
import urllib.request

from app.errors import StartupError

MIN_LENGTH = 15
HIBP_URL = "https://api.pwnedpasswords.com/range/"


class PasswordError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def load_common(path):
    if not path.is_file():
        raise StartupError(f"Common password list is missing: {path}")
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise StartupError(f"Could not read the common password list {path}: {exc.strerror}") from exc
    words = set()
    for line in text.splitlines():
        item = line.strip()
        if item and not item.startswith("#"):
            words.add(item.casefold())
    if len(words) < 1000:
        raise StartupError(f"Common password list {path} has fewer than 1000 entries.")
    return words


def check_new_password(password, common):
    """Return 'ok' or 'hibp_skipped'. Raise PasswordError when the password is refused."""
    if len(password) < MIN_LENGTH:
        raise PasswordError("password_length", "Password must be at least 15 characters.")
    if password.casefold() in common:
        raise PasswordError("password_common", "Password is too common.")
    try:
        pwned = _hibp_pwned(password)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, RuntimeError):
        return "hibp_skipped"
    if pwned:
        raise PasswordError("password_hibp", "Password has appeared in a data breach.")
    return "ok"


def _hibp_pwned(password):
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    request = urllib.request.Request(
        HIBP_URL + prefix,
        headers={"Add-Padding": "true", "User-Agent": "simplelogin-adapter"},
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            if response.status != 200:
                raise RuntimeError("unexpected status")
            body = response.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("hibp unreachable") from exc
    valid = False
    count = 0
    for line in body.splitlines():
        part, sep, raw_count = line.partition(":")
        if not sep:
            continue
        valid = True
        if part.strip().upper() != suffix:
            continue
        count = max(count, int(raw_count.strip()))
    if not valid:
        raise RuntimeError("hibp response unusable")
    return count > 0
