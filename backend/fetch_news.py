#!/usr/bin/env python3
"""
fetch_news.py — Fetch tech & software news from RSS feeds, store in SQLite.

Usage:
    python3 fetch_news.py
    DB_PATH=/path/to/scanner.db python3 fetch_news.py
    python3 fetch_news.py --backfill   # fill og:image for existing rows

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
OG_TIMEOUT   = 7    # seconds per article og:image fetch
OG_MAX_BYTES = 65536  # read at most 64 KB of article HTML
OG_MAX_PER_FEED = 10  # max og:image fetches per feed (keep cron fast)

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

_HTML_TAG   = re.compile(r"<[^>]+>")
_WHITESPACE = re.compile(r"\s+")
_CDATA      = re.compile(r"<!\[CDATA\[(.*?)\]\]>", re.DOTALL)
ATOM_NS  = "http://www.w3.org/2005/Atom"
MEDIA_NS = "http://search.yahoo.com/mrss/"

# Patterns to extract og:image / twitter:image from HTML
_OG_PATTERNS = [
    re.compile(r'<meta[^>]+property=["\']og:image(?::secure_url)?["\'][^>]+content=["\']([^"\']{10,})["\']', re.I),
    re.compile(r'<meta[^>]+content=["\']([^"\']{10,})["\'][^>]+property=["\']og:image["\']', re.I),
    re.compile(r'<meta[^>]+name=["\']twitter:image(?::src)?["\'][^>]+content=["\']([^"\']{10,})["\']', re.I),
    re.compile(r'<meta[^>]+content=["\']([^"\']{10,})["\'][^>]+name=["\']twitter:image["\']', re.I),
]

_OG_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)


# ── Helpers ───────────────────────────────────────────────

def strip_html(text: str) -> str:
    text = _CDATA.sub(r"\1", text or "")
    text = _HTML_TAG.sub(" ", text)
    text = _WHITESPACE.sub(" ", text).strip()
    return text


def _fetch_og_image(url: str) -> str:
    """Scrape og:image / twitter:image meta tag from an article URL."""
    if not url or not url.startswith("http"):
        return ""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": _OG_UA,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })
        with urllib.request.urlopen(req, timeout=OG_TIMEOUT) as resp:
            raw = resp.read(OG_MAX_BYTES)
        text = raw.decode("utf-8", errors="ignore")
        for pat in _OG_PATTERNS:
            m = pat.search(text)
            if m:
                img = m.group(1).strip()
                if img.startswith("http") and len(img) > 10:
                    return img[:500]
    except Exception:
        pass
    return ""


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
        title = strip_html(item.findtext("title", ""))
        link  = (item.findtext("link") or "").strip()
        desc  = strip_html(item.findtext("description", ""))
        pub   = (item.findtext("pubDate") or "").strip()
        img   = ""
        # 1. media:thumbnail
        m = item.find(f"{{{MEDIA_NS}}}thumbnail")
        if m is not None:
            img = m.get("url", "")
        # 2. media:content with image type
        if not img:
            mc = item.find(f"{{{MEDIA_NS}}}content")
            if mc is not None and "image" in (mc.get("type") or ""):
                img = mc.get("url", "")
        # 3. enclosure image
        enc = item.find("enclosure")
        if not img and enc is not None and "image" in (enc.get("type") or ""):
            img = enc.get("url", "")
        # 4. first <img> tag in raw description HTML
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
        img = ""
        # media:thumbnail in Atom entries
        m = entry.find(f"{{{MEDIA_NS}}}thumbnail")
        if m is not None:
            img = m.get("url", "")
        if title and link:
            items.append({"title": title, "url": link,
                          "summary": summary[:500], "published_at": pub, "image_url": img})

    # ── og:image fallback for articles without images ─────
    og_fetched = 0
    for a in items:
        if a["image_url"] or og_fetched >= OG_MAX_PER_FEED:
            continue
        img = _fetch_og_image(a["url"])
        if img:
            a["image_url"] = img
            og_fetched += 1
            time.sleep(0.4)   # be polite

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
                    a.get("image_url", "")[:500],
                    a.get("published_at", ""),
                ),
            )
            if conn.execute("SELECT changes()").fetchone()[0]:
                saved += 1
        except sqlite3.Error as exc:
            print(f"  DB error: {exc}", flush=True)
    conn.commit()
    return saved


def _backfill_images(conn: sqlite3.Connection, limit: int = 50) -> None:
    """Fill og:image for existing articles that have no image_url."""
    rows = conn.execute(
        "SELECT id, url FROM news_articles WHERE (image_url IS NULL OR image_url='') LIMIT ?",
        (limit,)
    ).fetchall()
    print(f"  Backfill: {len(rows)} articles to process", flush=True)
    updated = 0
    for row in rows:
        img = _fetch_og_image(row[0] if isinstance(row, (list, tuple)) else row["url"])
        url_val = row[1] if isinstance(row, (list, tuple)) else row["url"]
        id_val  = row[0] if isinstance(row, (list, tuple)) else row["id"]
        img = _fetch_og_image(url_val)
        if img:
            conn.execute("UPDATE news_articles SET image_url=? WHERE id=?", (img[:500], id_val))
            updated += 1
        time.sleep(0.3)
    conn.commit()
    print(f"  Backfill done: {updated}/{len(rows)} images added", flush=True)


# ── Main ──────────────────────────────────────────────────

def main() -> None:
    backfill_mode = "--backfill" in sys.argv

    print(f"[{datetime.now().isoformat(timespec='seconds')}] fetch_news start  db={DB_PATH}", flush=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _init_db(conn)

    if backfill_mode:
        _backfill_images(conn, limit=100)
        conn.close()
        return

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
