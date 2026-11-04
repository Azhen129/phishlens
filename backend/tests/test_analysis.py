import hashlib
import socket
from email.message import EmailMessage

import pytest

from backend.analysis import inspect_email, inspect_url, inspect_url_submission


def test_passive_url_never_uses_network(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Network access must never occur")
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket.socket, "connect", fail)
    for url in ("http://127.0.0.1/admin", "https://169.254.169.254/latest/meta-data/", "https://localhost/", "https://user:pass@example.com/path"):
        result = inspect_url_submission(url)
        assert result["kind"] == "url"
        assert result["ml"]["available"] is False


@pytest.mark.parametrize("url", ["javascript:alert(1)", "data:text/html,test", "ftp://example.com", "https:///nohost", "https://bad host.com", "https://example.com:wrong", "https://example.com\nBad", "https://example.com\\@evil.test", "https://<>.test", "https://bad\x7f.test", "https://-bad.test", "https://bad..test"])
def test_invalid_urls(url):
    with pytest.raises(ValueError):
        inspect_url(url)


def test_url_score_is_explainable():
    link, evidence = inspect_url("http://microsoft-account-update-security.test/login")
    assert link["score"] == sum(e["weight"] for e in evidence)
    assert {e["id"] for e in evidence} == {"url-http", "url-hyphens", "url-brand-microsoft"}
    assert link["score"] == 36
    assert link["risk"] == "Medium"


def test_legitimate_unknown_link_never_safe():
    link, findings = inspect_url("example.com")
    assert link["url"] == "https://example.com/"
    assert link["score"] == 0
    assert "not verified safe" in link["reason"]
    assert not findings


def test_lookalike_rule_is_narrow():
    assert any("lookalike" in f["id"] for f in inspect_url("https://micros0ft.com/")[1])
    assert not any("brand" in f["id"] for f in inspect_url("https://support.microsoft.com/")[1])
    assert any("idn" in f["id"] for f in inspect_url("https://xn--pple-43d.com/")[1])


def test_mime_encoded_headers_and_attachments_metadata():
    message = EmailMessage()
    message["From"] = '"Microsoft Support" <support@unrelated.test>'
    message["To"] = "analyst@example.test"
    message["Reply-To"] = "payments@different.test"
    message["Subject"] = "Urgent: Verify your account"
    message["Authentication-Results"] = "untrusted.test; spf=fail; dkim=pass; dmarc=fail"
    message.set_content("Action required. Verify your account within 24 hours or service interruption.")
    message.add_alternative('<script>alert(1)</script><p>Urgent <a href="http://10.0.0.1/login">https://microsoft.com</a></p><img src="https://tracker.test/pixel">', subtype="html")
    message.add_attachment(b"DO NOT EXECUTE", maintype="application", subtype="octet-stream", filename="../../payload.exe")
    result = inspect_email(message.as_bytes())
    assert result["subject"] == "Urgent: Verify your account"
    assert result["attachments"][0]["filename"] == "payload.exe"
    assert result["attachments"][0]["sha256"] == hashlib.sha256(b"DO NOT EXECUTE").hexdigest()
    assert len(result["links"]) == 1
    assert "alert" not in result["email"]["body"]
    assert "unverified" in result["email"]["authentication"]["SPF"]
    assert "Reported pass" in result["email"]["authentication"]["DKIM"]
    assert {"reply-to-mismatch", "display-mismatch-0", "sender-brand-microsoft", "attachment-0"} <= {f["id"] for f in result["evidence"]}
    assert result["score"] <= 100


def test_generic_anchor_label_not_fabricated_mismatch():
    raw = 'Content-Type: text/html\nSubject: Reminder\n\n<a href="https://example.com">Verify your account</a>'
    result = inspect_email(raw)
    assert not any("display-mismatch" in f["id"] for f in result["evidence"])
    assert "Not verified" in result["email"]["authentication"]["SPF"]


def test_html_only_is_inert_and_encoded_header():
    result = inspect_email(b'From: =?utf-8?b?Sm9zw6k=?= <jose@example.test>\nSubject: =?utf-8?b?UsOpc3Vtw6k=?=\nContent-Type: text/html; charset=utf-8\n\n<p>Hello</p><style>secret</style><script>alert(1)</script><img src="https://remote.test/pixel">')
    assert result["subject"] == "Résumé"
    assert "Hello" in result["email"]["body"]
    assert "secret" not in result["email"]["body"]
    assert result["links"] == []


def test_repeated_url_does_not_inflate_score():
    one = inspect_email("Subject: Test\n\nhttp://microsoft-login.test/a")
    many = inspect_email("Subject: Test\n\nhttp://microsoft-login.test/a\nhttp://microsoft-login.test/b")
    assert one["score"] == many["score"]


def test_all_alternatives_are_inspected_for_language():
    message = EmailMessage()
    message["Subject"] = "Update"
    message.set_content("A benign plain-text alternative.")
    message.add_alternative("<p>Urgent: verify your account to avoid account suspension.</p>", subtype="html")
    result = inspect_email(message.as_bytes())
    assert result["score"] == 28
    assert "Urgent" not in result["email"]["body"]


def test_attached_rfc822_message_is_metadata_only():
    inner = EmailMessage()
    inner["Subject"] = "Attached email"
    inner.set_content("Urgent: verify your account")
    outer = EmailMessage()
    outer["Subject"] = "Forwarded material"
    outer.set_content("Please review the attached message separately.")
    outer.add_attachment(inner, filename="forwarded.eml")
    result = inspect_email(outer.as_bytes())
    assert len(result["attachments"]) == 1
    assert result["attachments"][0]["filename"] == "forwarded.eml"
    assert result["attachments"][0]["size"] > 0
    assert result["score"] == 0


def test_non_text_charset_falls_back_instead_of_crashing():
    result = inspect_email(b'From: a@example.test\nSubject: Test\nContent-Type: text/plain; charset=idna\n\nurgent')
    assert result["email"]["body"] == "urgent"
    assert result["score"] == 10


def test_empty_and_mime_depth_rejected():
    with pytest.raises(ValueError):
        inspect_email("  ")
    raw = "Subject: Nesting\nMIME-Version: 1.0\n"
    for index in range(23):
        raw += f'Content-Type: multipart/mixed; boundary="b{index}"\n\n--b{index}\n'
    raw += "Content-Type: text/plain\n\nhello\n"
    for index in reversed(range(23)):
        raw += f"--b{index}--\n"
    with pytest.raises(ValueError, match="nesting"):
        inspect_email(raw)
