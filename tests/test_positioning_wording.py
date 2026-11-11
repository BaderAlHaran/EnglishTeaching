"""Search results show a page's title and description, so neither should
describe the site as an essay-writing service."""
import glob
import os
import re

PAGES = glob.glob("*.html") + glob.glob(os.path.join("templates", "*.html"))
OLD_POSITIONING = re.compile(r"essay writing services?|expert team|academic essay writing", re.I)


def test_no_title_or_description_uses_the_old_positioning():
    offenders = []
    for path in PAGES:
        html = open(path, encoding="utf-8").read()
        for pattern in (r"<title>(.*?)</title>", r'<meta name="description" content="(.*?)"'):
            match = re.search(pattern, html, re.S)
            if match and OLD_POSITIONING.search(match.group(1)):
                offenders.append("%s: %s" % (path, match.group(1).strip()))
    assert offenders == [], offenders
