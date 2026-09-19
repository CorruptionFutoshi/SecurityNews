"""Fetch public security advisories and write the static site data file."""

from __future__ import annotations

import hashlib
import html
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "feed.json"
JST = timezone(timedelta(hours=9))
WINDOW_DAYS = 30
MAX_ITEMS = 800
USER_AGENT = "SecurityFeed/1.0 (+https://github.com/; public RSS reader)"

SOURCES = (
    {
        "id": "ipa",
        "name": "IPA",
        "category": "alert",
        "url": "https://www.ipa.go.jp/security/alert-rss.rdf",
        "home": "https://www.ipa.go.jp/security/security-alert/index.html",
        "kind": "xml",
    },
    {
        "id": "jpcert",
        "name": "JPCERT/CC",
        "category": "alert",
        "url": "https://www.jpcert.or.jp/rss/jpcert.rdf",
        "home": "https://www.jpcert.or.jp/at/",
        "kind": "xml",
    },
    {
        "id": "jvn",
        "name": "JVN",
        "category": "vulnerability",
        "url": "https://jvn.jp/rss/jvn.rdf",
        "home": "https://jvn.jp/",
        "kind": "xml",
    },
    {
        "id": "jpcert-eyes",
        "name": "JPCERT/CC Eyes",
        "category": "analysis",
        "url": "https://blogs.jpcert.or.jp/ja/atom.xml",
        "home": "https://blogs.jpcert.or.jp/ja/",
        "kind": "xml",
    },
    {
        "id": "cisa-kev",
        "name": "CISA KEV",
        "category": "exploited",
        "url": "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
        "home": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "kind": "kev",
    },
)

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,19}\b", re.IGNORECASE)
IPA_URGENT_PATTERN = re.compile(
    r'<li\s+class="news-list__item"\s+data-search="urgent"[^>]*>\s*'
    r'<a\s+href="([^"]+)"',
    re.IGNORECASE,
)


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def plain_text(value: str | None, limit: int = 240) -> str:
    parser = TextExtractor()
    parser.feed(value or "")
    text = " ".join(html.unescape(" ".join(parser.parts)).split())
    return text[: limit - 1].rstrip() + "…" if len(text) > limit else text


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def child_text(element: ET.Element, *names: str) -> str:
    for name in names:
        for child in element:
            if local_name(child.tag) == name and child.text:
                return child.text.strip()
    return ""


def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    value = value.strip()
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            result = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=JST)
    return result.astimezone(timezone.utc)


def normalized_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    scheme = "https" if parsed.hostname in {"jvn.jp", "www.jpcert.or.jp", "www.ipa.go.jp"} else parsed.scheme
    return urlunparse((scheme, parsed.netloc.lower(), parsed.path or "/", "", parsed.query, ""))


def build_item(source: dict, title: str, url: str, description: str, published: datetime) -> dict | None:
    url = normalized_url(url)
    title = plain_text(title, 180)
    if not title or not url:
        return None
    description = plain_text(description)
    cves = sorted(set(match.upper() for match in CVE_PATTERN.findall(f"{title} {description}")))[:8]
    priority = "normal"
    if source["id"] == "cisa-kev":
        priority = "exploited"
    elif source["id"] == "ipa" and ("緊急" in title or "緊急" in description[:40]):
        priority = "urgent"
    elif source["id"] == "jpcert" and "緊急" in title:
        priority = "urgent"
    return {
        "id": hashlib.sha256(f'{source["id"]}:{url}'.encode("utf-8")).hexdigest()[:20],
        "source": source["id"],
        "category": source["category"],
        "priority": priority,
        "title": title,
        "url": url,
        "description": description,
        "publishedAt": published.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "cves": cves,
    }


def parse_xml_feed(payload: bytes, source: dict) -> list[dict]:
    root = ET.fromstring(payload)
    entries = [node for node in root.iter() if local_name(node.tag) in {"item", "entry"}]
    result = []
    for entry in entries:
        title = child_text(entry, "title")
        url = child_text(entry, "link")
        if not url:
            for node in entry:
                if local_name(node.tag) == "link" and node.attrib.get("href"):
                    if node.attrib.get("rel", "alternate") == "alternate":
                        url = node.attrib["href"]
                        break
        description = child_text(entry, "description", "summary", "content")
        published = parse_date(child_text(entry, "date", "published", "pubDate", "updated"))
        if not published:
            continue
        item = build_item(source, title, url, description, published)
        if item:
            result.append(item)
    return result


def parse_kev(payload: bytes, source: dict) -> list[dict]:
    document = json.loads(payload)
    if not isinstance(document.get("vulnerabilities"), list):
        raise ValueError("KEV vulnerabilities array is missing")
    result = []
    for vulnerability in document["vulnerabilities"]:
        cve = str(vulnerability.get("cveID", ""))
        published = parse_date(vulnerability.get("dateAdded"))
        if not CVE_PATTERN.fullmatch(cve) or not published:
            continue
        title = f'{vulnerability.get("vendorProject", "")} {vulnerability.get("product", "")} — {cve}'
        description = vulnerability.get("shortDescription", "")
        item = build_item(source, title, f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}", description, published)
        if item:
            item["cves"] = [cve]
            result.append(item)
    return result


def parse_ipa_urgent_urls(payload: bytes) -> set[str]:
    """Read IPA's own urgent labels from its current alert index."""
    page = payload.decode("utf-8", errors="replace")
    return {
        normalized_url(urljoin("https://www.ipa.go.jp", html.unescape(match)))
        for match in IPA_URGENT_PATTERN.findall(page)
    }


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/xml, application/json, text/xml, */*"})
    with urllib.request.urlopen(request, timeout=25) as response:
        return response.read(5_000_001)


def load_existing() -> dict:
    if not OUTPUT.exists():
        return {"items": [], "sources": []}
    return json.loads(OUTPUT.read_text(encoding="utf-8"))


def refresh() -> dict:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=WINDOW_DAYS)
    old = load_existing()
    by_id = {}
    for item in old.get("items", []):
        published = parse_date(item.get("publishedAt"))
        if published and published >= cutoff and item.get("id"):
            by_id[item["id"]] = item

    source_status = []
    success_count = 0
    for source in SOURCES:
        try:
            payload = fetch(source["url"])
            items = parse_kev(payload, source) if source["kind"] == "kev" else parse_xml_feed(payload, source)
            if not items:
                raise ValueError("feed contained no dated entries")
            if source["id"] == "ipa":
                try:
                    urgent_urls = parse_ipa_urgent_urls(fetch(source["home"]))
                    for item in items:
                        if item["url"] in urgent_urls:
                            item["priority"] = "urgent"
                except Exception as error:
                    print(f'IPA urgency labels unavailable: {error}', file=sys.stderr)
            for item in items:
                if parse_date(item["publishedAt"]) >= cutoff:
                    by_id[item["id"]] = item
            success_count += 1
            source_status.append({"id": source["id"], "name": source["name"], "home": source["home"], "ok": True, "fetchedAt": now.isoformat(timespec="seconds").replace("+00:00", "Z")})
            print(f'{source["name"]}: {len(items)} entries', file=sys.stderr)
        except Exception as error:
            source_status.append({"id": source["id"], "name": source["name"], "home": source["home"], "ok": False, "fetchedAt": None})
            print(f'{source["name"]}: {type(error).__name__}: {error}', file=sys.stderr)

    if success_count == 0:
        raise RuntimeError("All sources failed; keeping the previous data file")

    items = sorted(by_id.values(), key=lambda item: (item["publishedAt"], item["id"]), reverse=True)[:MAX_ITEMS]
    result = {
        "schemaVersion": 1,
        "checkedAt": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "windowDays": WINDOW_DAYS,
        "sources": source_status,
        "items": items,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Saved {len(items)} items to {OUTPUT}", file=sys.stderr)
    return result


if __name__ == "__main__":
    refresh()
