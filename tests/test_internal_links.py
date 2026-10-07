"""The writing guide had only footer links, which is why Google had never
crawled it. These check the in-content links stay put."""


def _body(client, path):
    response = client.get(path)
    assert response.status_code == 200, path
    # Footer links do not count for this; check the page content above it.
    return response.data.decode("utf-8").split('<footer', 1)[0]


def test_homepage_links_to_the_guide_in_its_content(client):
    body = _body(client, "/")
    assert "New to essay structure?" in body
    assert 'href="/free-essay-writing-help"' in body


def test_essay_checker_links_to_the_guide(client):
    body = _body(client, "/improve")
    assert 'href="/free-essay-writing-help"' in body
    assert "writing guide" in body


def test_ielts_page_links_to_the_guide(client):
    body = _body(client, "/ielts-writing-checker")
    assert 'href="/free-essay-writing-help"' in body
    assert "Not sure how to build the answer?" in body


def test_guide_links_back_to_the_ielts_checker(client):
    body = _body(client, "/free-essay-writing-help")
    assert 'href="/ielts-writing-checker"' in body
    assert "Preparing for IELTS?" in body
