from html import escape

from app.simplelogin import proton_url


def layout(body):
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        "<title>SimpleLogin Adapter</title>\n"
        '<link rel="stylesheet" href="/static/style.css">\n'
        "</head>\n"
        "<body>\n"
        "<h1>SimpleLogin Adapter</h1>\n"
        f"{body}\n"
        "</body>\n"
        "</html>\n"
    )


def setup_page(csrf, error, username, setup_code):
    parts = ["<p>Create the account. This page is not shown again after it exists.</p>"]
    parts.append("<p>The setup code is printed in the server log at startup.</p>")
    if error:
        parts.append(f"<p>{escape(error)}</p>")
    parts.append('<form method="post" action="/setup">')
    parts.append(_hidden("csrf", csrf))
    parts.append(_field("Setup code", "setup_code", setup_code, "text"))
    parts.append(_field("Username", "username", username, "text", "username"))
    parts.append(_field("Password", "password", "", "password", "new-password"))
    parts.append(_field("SimpleLogin API key", "api_key", "", "password", "off"))
    parts.append('<p><button type="submit">Create account</button></p>')
    parts.append("</form>")
    return layout("".join(parts))


def login_page(csrf, error):
    parts = []
    if error:
        parts.append(f"<p>{escape(error)}</p>")
    parts.append('<form method="post" action="/login">')
    parts.append(_hidden("csrf", csrf))
    parts.append(_field("Username", "username", "", "text", "username"))
    parts.append(_field("Password", "password", "", "password", "current-password"))
    parts.append('<p><button type="submit">Log in</button></p>')
    parts.append("</form>")
    return layout("".join(parts))


def send_page(csrf, error, alias, recipient, result):
    parts = ["<p>Enter the alias to send from and the real recipient.</p>"]
    if error:
        parts.append(f"<p>{escape(error)}</p>")
    parts.append('<form method="post" action="/send">')
    parts.append(_hidden("csrf", csrf))
    parts.append(_field("Alias", "alias", alias, "text"))
    parts.append(_field("Recipient", "recipient", recipient, "text"))
    parts.append('<p><button type="submit">Get address</button></p>')
    parts.append("</form>")
    if result:
        parts.append(f"<p>{escape(result['summary'])}</p>")
        if result.get("disabled"):
            parts.append("<p>This alias is disabled.</p>")
        parts.append(
            "<p><label>Reverse alias<br>"
            f'<input readonly size="72" value="{escape(result["address"], quote=True)}">'
            "</label></p>"
        )
        href = escape(proton_url(result["address"]), quote=True)
        parts.append(
            f'<p><a href="{href}" target="_blank" rel="noopener noreferrer">Open in Proton Mail</a></p>'
        )
    parts.append('<form method="post" action="/logout">')
    parts.append(_hidden("csrf", csrf))
    parts.append('<p><button type="submit">Log out</button></p>')
    parts.append("</form>")
    return layout("".join(parts))


def message_page(text, href, label):
    body = f"<p>{escape(text)}</p><p><a href=\"{escape(href, quote=True)}\">{escape(label)}</a></p>"
    return layout(body)


def _hidden(name, value):
    return f'<input type="hidden" name="{name}" value="{escape(value, quote=True)}">'


def _field(label, name, value, kind, autocomplete=None):
    auto = ""
    if autocomplete:
        auto = f' autocomplete="{escape(autocomplete, quote=True)}"'
    size = ' size="48"' if kind == "text" else ""
    return (
        f"<p><label>{escape(label)}<br>"
        f'<input name="{name}" type="{kind}" value="{escape(value, quote=True)}"{size}{auto}>'
        "</label></p>"
    )
