import json
import re


def _structured_data(body):
    return [json.loads(block) for block in
            re.findall(r'<script type="application/ld\+json">(.*?)</script>', body, re.S)]


def test_faq_links_to_ielts_checker_and_lists_it_in_structured_data(client):
    body = client.get("/faq").data.decode("utf-8")
    assert '<a href="/ielts-writing-checker">IELTS writing checker</a>' in body
    questions = [q["name"] for data in _structured_data(body) for q in data.get("mainEntity", [])]
    assert "Do you have a checker for IELTS?" in questions


def test_homepage_ielts_card_links_to_the_checker(client):
    body = client.get("/").data.decode("utf-8")
    card = body.split("IELTS &amp; TOEFL Writing Feedback", 1)[1].split('class="service__item"', 1)[0]
    assert 'href="/ielts-writing-checker"' in card
