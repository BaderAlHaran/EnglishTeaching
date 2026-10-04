import os
import re
import struct


def test_terms_no_longer_claim_a_right_to_distribute_user_work(client):
    body = client.get("/terms").data.decode("utf-8")
    assert "modify, and distribute" not in body
    assert "You keep ownership of everything you submit" in body
    # Section 7 must match what actually happens to the text.
    assert "LanguageTool" in body


def test_contact_page_drops_essay_mill_wording(client):
    body = client.get("/contact").data.decode("utf-8")
    for phrase in ("essay writing service", "your order", "essay writing needs"):
        assert phrase not in body, phrase
    assert "Questions about the checker" in body


def test_footers_describe_checking_not_writing_services(client):
    for path in ("/", "/contact", "/improve", "/ielts-writing-checker"):
        body = client.get(path).data.decode("utf-8")
        assert "professional essay writing services" not in body, path


def test_social_image_is_a_png(client):
    for path in ("/", "/improve", "/ielts-writing-checker", "/contact", "/faq"):
        body = client.get(path).data.decode("utf-8")
        assert 'og:image" content="https://englishessaywriting.net/og-image.png"' in body, path
        assert "logo.svg" not in body.split("og:image")[1][:120], path


def test_share_image_exists_and_is_1200x630():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "og-image.png")
    assert os.path.exists(path), "og-image.png is missing"
    with open(path, "rb") as fh:
        header = fh.read(24)
    assert header[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
    width, height = struct.unpack(">II", header[16:24])
    assert (width, height) == (1200, 630)


def test_share_image_is_served(client):
    response = client.get("/og-image.png")
    assert response.status_code == 200
    assert response.data[:8] == b"\x89PNG\r\n\x1a\n"


def test_sitemap_has_lastmod_for_every_url(client):
    body = client.get("/sitemap.xml").data.decode("utf-8")
    locs = re.findall(r"<loc>", body)
    lastmods = re.findall(r"<lastmod>(\d{4}-\d{2}-\d{2})</lastmod>", body)
    assert len(locs) == len(lastmods) == 11


def test_privacy_policy_drops_accounts_it_does_not_have(client):
    body = client.get("/privacy").data.decode("utf-8")
    assert "your account is active" not in body
    assert "Provide personalized content" not in body
    # The parts that are true stay.
    assert "LanguageTool" in body
    assert "30 days" in body
