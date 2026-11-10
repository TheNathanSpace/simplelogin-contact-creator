import json
import re
import urllib.error
import urllib.parse
import urllib.request


class SLError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SLError(f"SimpleLogin returned status {code}.")


_OPENER = urllib.request.build_opener(_NoRedirect)
_PREFIX = re.compile(r"[0-9a-z-_.]{1,40}")
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def clean_email(value):
    text = (value or "").strip().casefold()
    if len(text) > 254 or not _EMAIL.fullmatch(text):
        return None
    return text


def proton_url(address):
    mailto = "mailto:" + address
    return "https://mail.proton.me/inbox/#mailto=" + urllib.parse.quote(mailto, safe="")


def verify_api_key(base_url, api_key):
    _request(base_url, api_key, "GET", "/api/user_info")


def resolve(base_url, api_key, alias, recipient):
    found = _find_alias(base_url, api_key, alias)
    created = False
    if found is None:
        found = _create_alias(base_url, api_key, alias)
        created = True
    alias_id = found.get("id")
    if not isinstance(alias_id, int):
        raise SLError("SimpleLogin returned an unreadable response.")
    contact = _request(
        base_url,
        api_key,
        "POST",
        f"/api/aliases/{alias_id}/contacts",
        body={"contact": recipient},
    )
    address = _reverse_address(contact)
    if not address:
        raise SLError("SimpleLogin did not return a reverse-alias address.")
    return {
        "address": address,
        "alias_created": created,
        "contact_existed": bool(contact.get("existed")),
        "alias_disabled": not bool(found.get("enabled", True)),
    }


def _find_alias(base_url, api_key, alias):
    target = alias.casefold()
    for page in range(20):
        data = _request(
            base_url,
            api_key,
            "POST",
            "/api/v2/aliases",
            query={"page_id": str(page)},
            body={"query": alias},
        )
        aliases = data.get("aliases")
        if not isinstance(aliases, list):
            raise SLError("SimpleLogin returned an unreadable response.")
        for item in aliases:
            email = item.get("email")
            if isinstance(email, str) and email.casefold() == target:
                return item
        if len(aliases) < 20:
            return None
    return None


def _create_alias(base_url, api_key, alias):
    options = _request(base_url, api_key, "GET", "/api/v5/alias/options")
    if options.get("can_create") is False:
        raise SLError("This account cannot create an alias.")
    suffixes = options.get("suffixes")
    if not isinstance(suffixes, list):
        raise SLError("SimpleLogin returned an unreadable response.")
    matched = _match_suffix(alias, suffixes)
    if matched is None:
        raise SLError("That alias cannot be created with the available suffixes.")
    prefix, signed = matched
    mailboxes = _request(base_url, api_key, "GET", "/api/v2/mailboxes")
    mailbox_id = _mailbox_id(mailboxes)
    created = _request(
        base_url,
        api_key,
        "POST",
        "/api/v3/alias/custom/new",
        body={
            "alias_prefix": prefix,
            "signed_suffix": signed,
            "mailbox_ids": [mailbox_id],
        },
    )
    if not isinstance(created.get("id"), int):
        raise SLError("SimpleLogin returned an unreadable response.")
    return created


def _match_suffix(address, suffixes):
    folded_address = address.casefold()
    best = None
    for item in suffixes:
        if not isinstance(item, dict):
            continue
        suffix = item.get("suffix") or ""
        signed = item.get("signed_suffix") or item.get("signed-suffix")
        if not isinstance(suffix, str) or not suffix or not isinstance(signed, str) or not signed:
            continue
        folded = suffix.casefold()
        if not folded_address.endswith(folded):
            continue
        if best is None or len(folded) > best[0]:
            best = (len(folded), folded_address[: -len(folded)], signed)
    if best is None:
        return None
    prefix = best[1]
    if _PREFIX.fullmatch(prefix) is None:
        return None
    return prefix, best[2]


def _mailbox_id(data):
    boxes = data.get("mailboxes")
    if not isinstance(boxes, list):
        raise SLError("SimpleLogin returned an unreadable response.")
    verified = [
        box for box in boxes if isinstance(box, dict) and box.get("verified") and isinstance(box.get("id"), int)
    ]
    for box in verified:
        if box.get("default"):
            return box["id"]
    if verified:
        return verified[0]["id"]
    raise SLError("No verified mailbox is available for a new alias.")


def _reverse_address(contact):
    if not isinstance(contact, dict):
        return None
    direct = contact.get("reverse_alias_address")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    text = contact.get("reverse_alias")
    if isinstance(text, str):
        match = re.search(r"<([^<>\s]+)>", text)
        if match:
            return match.group(1)
    return None


def _request(base_url, api_key, method, path, query=None, body=None):
    url = base_url + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = None
    headers = {
        "Authentication": api_key,
        "Accept": "application/json",
        "User-Agent": "simplelogin-adapter",
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _OPENER.open(request, timeout=20) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    except SLError:
        raise
    except Exception as exc:
        raise SLError("Could not reach SimpleLogin.") from exc
    if status >= 400:
        raise SLError(_error_text(status, raw))
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SLError("SimpleLogin returned an unreadable response.") from exc
    if not isinstance(parsed, dict):
        raise SLError("SimpleLogin returned an unreadable response.")
    return parsed


def _error_text(status, raw):
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return f"SimpleLogin returned status {status}."
    if isinstance(data, dict) and isinstance(data.get("error"), str) and data["error"].strip():
        return data["error"].strip()
    return f"SimpleLogin returned status {status}."
