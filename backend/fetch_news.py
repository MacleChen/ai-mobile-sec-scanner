#!/usr/bin/env python3
"""
fetch_news.py — Fetch tech & software news from RSS feeds, store in SQLite.

Usage:
    python3 fetch_news.py
    DB_PATH=/path/to/scanner.db python3 fetch_news.py

Crontab (runs at 03:00 every night):
    0 3 * * * cd /opt/ai-scanner && DB_PATH=/app/data/scanner.db python3 backend/fetch_news.py >> /var/log/fetch_news.log 2>&1
"""
import os
import re
import sys
import time
import hashlib
import sqlite3
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime

# ── Config ────────────────────────────────────────────────
DB_PATH = os.getenv("DB_PATH", "/app/data/scanner.db")

FEEDS = [
    # Chinese tech & software
    {"url": "https://sspai.com/feed",                         "source": "少数派",   "category": "软件"},
    {"url": "https://www.ifanr.com/feed",                     "source": "爱范儿",   "category": "科技"},
    {"url": "https://www.oschina.net/news/rss",               "source": "开源中国", "category": "Dev"},
    {"url": "https://36kr.com/feed",                          "source": "36氪",     "category": "科技"},
    # International tech
    {"url": "https://techcrunch.com/feed/",                   "source": "TechCrunch",   "category": "Tech"},
    {"url": "https://www.theverge.com/rss/index.xml",         "source": "The Verge",    "category": "Tech"},
    {"url": "https://hnrss.org/frontpage",                    "source": "Hacker News",  "category": "Dev"},
    {"url": "https://feeds.feedburner.com/TheHackersNews",    "source": "Hacker News*", "category": "Security"},
    {"url": "https://www.wired.com/feed/rss",                 "source": "Wired",        "category": "Tech"},
]

_HTML_TAG  = re.compile(r"<[^>]+>")
_WHITESPACE = re.compile(r"\s+")
_CDATA = re.compile(r"<!\[CDATA\[(.*?)\]\]>", re.DOTALL)
ATOM_NS = "http://www.w3.org/2005/Atom"
MEDIA_NS = "http://search.yahoo.com/mrss/"


# ── Helpers ───────────────────────────────────────────────

def strip_html(text: str) -> str:
    text = _CDATA.sub(r"\1", text or "")
    text = _HTML_TAG.sub(" ", text)
    text = _WHITESPACE.sub(" ", text).strip()
    return text


def _init_db(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS news_articles (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            hash         TEXT    UNIQUE NOT NULL,
            title        TEXT    NOT NULL,
            summary      TEXT    DEFAULT '',
            url          TEXT    NOT NULL,
            source       TEXT    DEFAULT '',
            category     TEXT    DEFAULT '',
            image_url    TEXT    DEFAULT '',
            published_at TEXT    DEFAULT '',
            created_at   TEXT    DEFAULT (datetime('now')),
            is_active    INTEGER DEFAULT 1
        )
    """)
    for col, defn in [("image_url", "TEXT DEFAULT ''"), ("is_active", "INTEGER DEFAULT 1")]:
        try:
            conn.execute(f"ALTER TABLE news_articles ADD COLUMN {col} {defn}")
        except sqlite3.OperationalError:
            pass
    conn.commit()


def _fetch(feed: dict) -> list[dict]:
    url, source = feed["url"], feed["source"]
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; AppSecNewsBot/1.0; +https://maclechen.top)",
        "Accept": "application/rss+xml, application/xml, text/xml, */*",
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
    except Exception as exc:
        print(f"  [{source}] fetch error: {exc}", flush=True)
        return []

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        print(f"  [{source}] XML parse error: {exc}", flush=True)
        return []

    items: list[dict] = []

    # ── RSS 2.0 ──────────────────────────────────────────
    for item in root.findall(".//item"):
        title  = strip_html(item.findtext("title", ""))
        link   = (item.findtext("link") or "").strip()
        desc   = strip_html(item.findtext("description", ""))
        pub    = (item.findtext("pubDate") or "").strip()
        img    = ""
        # media:thumbnail
        m = item.find(f"{{{MEDIA_NS}}}thumbnail")
        if m is not None:
            img = m.get("url", "")
        # enclosure image
        enc = item.find("enclosure")
        if not img and enc is not None and "image" in (enc.get("type") or ""):
            img = enc.get("url", "")
        # first <img> tag inside description HTML
        if not img:
            raw_desc = item.findtext("description", "")
            m2 = re.search(r'<img[^>]+src=["\']([^"\']{10,})["\']', raw_desc or "")
            if m2:
                img = m2.group(1)
        if title and link:
            items.append({"title": title, "url": link,
                          "summary": desc[:500], "published_at": pub, "image_url": img})

    # ── Atom ─────────────────────────────────────────────
    for entry in root.findall(f"{{{ATOM_NS}}}entry"):
        title   = strip_html(entry.findtext(f"{{{ATOM_NS}}}title", ""))
        link_el = entry.find(f"{{{ATOM_NS}}}link")
        link    = (link_el.get("href", "") if link_el is not None else "").strip()
        summary = strip_html(
            entry.findtext(f"{{{ATOM_NS}}}summary", "")
            or entry.findtext(f"{{{ATOM_NS}}}content", "")
        )
        pub = (
            entry.findtext(f"{{{ATOM_NS}}}updated")
            or entry.findtext(f"{{{ATOM_NS}}}published")
            or ""
        ).strip()
        if title and link:
            items.append({"title": title, "url": link,
                          "summary": summary[:500], "published_at": pub, "image_url": ""})

    return items[:25]


def _save(conn: sqlite3.Connection, articles: list[dict], source: str, category: str) -> int:
    saved = 0
    for a in articles:
        if not a.get("title") or not a.get("url"):
            continue
        h = hashlib.md5(a["url"].encode()).hexdigest()
        try:
            conn.execute(
                """INSERT OR IGNORE INTO news_articles
                   (hash, title, summary, url, source, category, image_url, published_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    h,
                    a["title"][:200],
                    a.get("summary", "")[:500],
                    a["url"][:600],
                    source,
                    category,
                    a.get("image_url", "")[:300],
                    a.get("published_at", ""),
                ),
            )
            if conn.execute("SELECT changes()").fetchone()[0]:
                saved += 1
        except sqlite3.Error as exc:
            print(f"  DB error: {exc}", flush=True)
    conn.commit()
    return saved


# ── Main ──────────────────────────────────────────────────

def main() -> None:
    print(f"[{datetime.now().isoformat(timespec='seconds')}] fetch_news start  db={DB_PATH}", flush=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _init_db(conn)

    total = 0
    for feed in FEEDS:
        print(f"  Fetching {feed['source']} …", end=" ", flush=True)
        articles = _fetch(feed)
        n = _save(conn, articles, feed["source"], feed["category"])
        print(f"{n} new / {len(articles)} fetched", flush=True)
        total += n
        time.sleep(2)          # be polite to RSS servers

    # Prune articles older than 30 days to keep DB lean
    conn.execute("DELETE FROM news_articles WHERE created_at < datetime('now','-30 days')")
    conn.commit()

    print(f"[{datetime.now().isoformat(timespec='seconds')}] done. total_new={total}", flush=True)
    conn.close()


if __name__ == "__main__":
    main()
