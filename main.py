#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main OSINT Telegram bot
"""

from flask import Flask, request
import types, sys
sys.modules["imghdr"] = types.SimpleNamespace(what=lambda f: None)
import asyncio
import aiohttp
import json
import logging
import os
import socket
import datetime
import re
import hashlib
from typing import Optional, Dict, Any, List
from urllib.parse import quote_plus, quote, unquote_plus, urlparse, parse_qs

# Импорт для python-telegram-bot 20.x
from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters,
    ContextTypes,
)

from lxml import html as lxml_html

# Try to use uvloop for better performance (optional)
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except Exception:
    pass

# ===================== Настройки =====================
BOT_TOKEN = "7125428476:AAE2HdZkvmka_-fC-haCVvgGOeM7oSkQJtQ"
OWNER_ID = 7405715334

AUTH_FILE = "auth.json"
HEADERS = {"User-Agent": "Public-OSINT-Bot/1.0 (+https://example.com)"}
TG_CHUNK = 3900

SEARCH_TIMEOUT = 7
CONNECT_TIMEOUT = aiohttp.ClientTimeout(total=SEARCH_TIMEOUT)
MAX_CONCURRENCY = 6

# ===================== Логирование =====================
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ===================== Файловая auth логика =====================
def load_auth() -> Dict[str, Any]:
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
    else:
        data = {}
    data.setdefault("owner", OWNER_ID)
    data.setdefault("admins", [])
    data.setdefault("allowed_users", [])
    if OWNER_ID is not None and data.get("owner") != OWNER_ID:
        data["owner"] = OWNER_ID
    save_auth(data)
    return data

def save_auth(data: Dict[str, Any]) -> None:
    try:
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.exception("Failed to save auth: %s", e)

def is_owner(user_id: int, auth: Dict[str, Any]) -> bool:
    return auth.get("owner") is not None and user_id == auth.get("owner")

def is_admin(user_id: int, auth: Dict[str, Any]) -> bool:
    return user_id in auth.get("admins", []) or is_owner(user_id, auth)

def is_allowed(user_id: int, auth: Dict[str, Any]) -> bool:
    if is_owner(user_id, auth) or is_admin(user_id, auth):
        return True
    return user_id in auth.get("allowed_users", [])

# ===================== HTTP helpers =====================
async def fetch_head(session: aiohttp.ClientSession, url: str, timeout: int = 4) -> Dict[str, Any]:
    try:
        async with session.head(url, timeout=timeout, headers=HEADERS, allow_redirects=True) as resp:
            return {"status": resp.status, "url": str(resp.url), "ok": resp.status in (200, 301, 302)}
    except Exception:
        pass
    try:
        async with session.get(url, timeout=timeout, headers=HEADERS, allow_redirects=True) as resp:
            await asyncio.sleep(0)
            return {"status": resp.status, "url": str(resp.url), "ok": resp.status in (200, 301, 302)}
    except Exception as e:
        return {"status": None, "url": url, "ok": False, "__error": str(e)}

async def fetch_text(session: aiohttp.ClientSession, url: str, timeout: int = SEARCH_TIMEOUT) -> Dict[str, Any]:
    try:
        async with session.get(url, timeout=timeout, headers=HEADERS, allow_redirects=True) as resp:
            txt = await resp.text(errors="ignore")
            await asyncio.sleep(0)
            return {"status": resp.status, "text": txt, "url": str(resp.url)}
    except Exception as e:
        return {"status": None, "text": None, "__error": str(e), "url": url}

async def fetch_json(session: aiohttp.ClientSession, url: str, params: dict = None, timeout: int = SEARCH_TIMEOUT) -> dict:
    try:
        async with session.get(url, params=params, timeout=timeout, headers=HEADERS, allow_redirects=True) as resp:
            txt = await resp.text(errors="ignore")
            await asyncio.sleep(0)
            try:
                return json.loads(txt)
            except Exception:
                return {"__raw_text": txt[:3000], "__status": resp.status}
    except Exception as e:
        return {"__error": str(e), "url": url}

# ===================== Site templates =====================
SITE_TEMPLATES = [
    ("GitHub", "https://github.com/{}", False),
    ("GitLab", "https://gitlab.com/{}", False),
    ("Reddit", "https://www.reddit.com/user/{}", False),
    ("Steam (community)", "https://steamcommunity.com/id/{}", False),
    ("Steam (profile numeric)", "https://steamcommunity.com/profiles/{}", False),
    ("TikTok", "https://www.tiktok.com/@{}", False),
    ("Instagram", "https://www.instagram.com/{}/", False),
    ("Telegram", "https://t.me/{}", False),
    ("Pinterest", "https://www.pinterest.com/{}/", False),
    ("Medium", "https://medium.com/@{}", False),
    ("DeviantArt", "https://www.deviantart.com/{}", False),
    ("X (Twitter)", "https://x.com/{}", False),
    ("Facebook (profile)", "https://www.facebook.com/{}", False),
    ("YouTube (channel handle)", "https://www.youtube.com/@{}", False),
    ("Twitch", "https://www.twitch.tv/{}", False),
    ("SoundCloud", "https://soundcloud.com/{}", False),
    ("9GAG", "https://9gag.com/u/{}", False),
    ("Badoo", "https://badoo.com/profile/{}", False),
    ("VK", "https://vk.com/{}", False),
    ("OK.ru", "https://ok.ru/{}", False),
    ("Ask.fm", "https://ask.fm/{}", False),
    ("MyAnimeList", "https://myanimelist.net/profile/{}", False),
    ("Fiverr", "https://www.fiverr.com/{}", False),
    ("About.me", "https://about.me/{}", False),
]

# ===================== VK identifier utils =====================
VK_URL_RE = re.compile(r"(?:https?://)?(?:www\.)?vk\.com/(id\d+|[A-Za-z0-9_.]+)(?:[/?#].*)?$", re.IGNORECASE)
def normalize_vk_identifier(s: str) -> Optional[str]:
    s = s.strip()
    m = VK_URL_RE.match(s)
    if m:
        return m.group(1)
    if s.lower().startswith("id") and s[2:].isdigit():
        return s
    if re.match(r"^[A-Za-z0-9_.]{3,}$", s):
        return s
    return None

# ===================== Wayback (CDX) lookup =====================
async def wayback_cdx_lookup(session: aiohttp.ClientSession, target: str, limit: int = 200) -> Dict[str, Any]:
    cdx = f"https://web.archive.org/cdx/search/cdx?url={quote_plus(target)}&output=json&fl=timestamp,original,statuscode&filter=statuscode:200&collapse=digest&limit={limit}"
    return await fetch_json(session, cdx, timeout=SEARCH_TIMEOUT)

# ===================== DuckDuckGo HTML search =====================
DUCK_HTML = "https://html.duckduckgo.com/html/"

def _decode_uddg(href: str) -> str:
    try:
        qs = parse_qs(urlparse(href).query)
        if "uddg" in qs and len(qs["uddg"]) > 0:
            return unquote_plus(qs["uddg"][0])
    except Exception:
        pass
    return href

async def ddg_search(session: aiohttp.ClientSession, query: str, max_results: int = 15) -> List[Dict[str, str]]:
    data = {"q": query}
    out: List[Dict[str, str]] = []
    try:
        async with session.post(DUCK_HTML, data=data, headers=HEADERS, timeout=SEARCH_TIMEOUT) as resp:
            txt = await resp.text(errors="ignore")
            doc = lxml_html.fromstring(txt)
            nodes = doc.xpath('//div[contains(@class,"result")]')
            for n in nodes:
                a = n.xpath('.//a[contains(@class,"result__a")]')
                s = n.xpath('.//a[contains(@class,"result__snippet")] | .//div[contains(@class,"result__snippet")]')
                if not a:
                    continue
                href = a[0].get('href') or ''
                href = _decode_uddg(href)
                title = a[0].text_content().strip()
                snippet = s[0].text_content().strip() if s else ""
                try:
                    dom = urlparse(href).netloc
                except Exception:
                    dom = href
                out.append({"domain": dom, "title": title, "snippet": snippet})
                if len(out) >= max_results:
                    break
    except Exception:
        pass
    return out

# ===================== Email OSINT =====================
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
def looks_like_email(s: str) -> bool:
    return bool(EMAIL_RE.match(s.strip()))

def email_domain(email: str) -> Optional[str]:
    try:
        return email.split("@", 1)[1].lower().strip()
    except Exception:
        return None

async def gravatar_exists(session: aiohttp.ClientSession, email: str) -> Optional[str]:
    md5 = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    url = f"https://www.gravatar.com/avatar/{md5}?d=404"
    try:
        res = await fetch_head(session, url, timeout=6)
        if res.get("status") == 200:
            return url
    except Exception:
        pass
    return None

async def emailrep_lookup(session: aiohttp.ClientSession, email: str) -> Dict[str, Any]:
    try:
        async with session.get(f"https://emailrep.io/{email}", headers=HEADERS, timeout=6) as resp:
            if resp.status == 200:
                return await resp.json()
            return {"__status": resp.status}
    except Exception as e:
        return {"__error": str(e)}

async def dns_mx_lookup(session: aiohttp.ClientSession, domain: str) -> Dict[str, Any]:
    return await fetch_json(session, "https://dns.google/resolve", params={"name": domain, "type": "MX"}, timeout=6)

async def rdap_domain_info(session: aiohttp.ClientSession, domain: str) -> Dict[str, Any]:
    return await fetch_json(session, f"https://rdap.org/domain/{domain}", timeout=6)

async def email_mentions(session: aiohttp.ClientSession, email: str, max_results: int = 15) -> List[Dict[str, str]]:
    return await ddg_search(session, f"\"{email}\"", max_results=max_results)

async def email_pastes(session: aiohttp.ClientSession, email: str, max_results: int = 10) -> List[Dict[str, str]]:
    q = f"\"{email}\" pastebin OR ghostbin OR hastebin OR throwbin OR dpaste OR paste2"
    return await ddg_search(session, q, max_results=max_results)

def compact_details(d: Dict[str, Any], keys: List[str], prefix: str = "") -> List[str]:
    lines = []
    for k in keys:
        v = d.get(k)
        if v is not None and v != "":
            lines.append(f"{prefix}{k}: {v}")
    return lines

async def aggregate_email_search(email: str) -> str:
    lines = [f"Отчёт по email: {email}", ""]
    async with aiohttp.ClientSession(timeout=CONNECT_TIMEOUT, headers=HEADERS) as session:
        tasks = []
        tasks.append(asyncio.create_task(gravatar_exists(session, email)))
        tasks.append(asyncio.create_task(emailrep_lookup(session, email)))
        tasks.append(asyncio.create_task(email_mentions(session, email, max_results=15)))
        tasks.append(asyncio.create_task(email_pastes(session, email, max_results=10)))

        dom = email_domain(email)
        if dom:
            tasks.append(asyncio.create_task(dns_mx_lookup(session, dom)))
            tasks.append(asyncio.create_task(rdap_domain_info(session, dom)))
        else:
            tasks.append(asyncio.create_task(asyncio.sleep(0)))
            tasks.append(asyncio.create_task(asyncio.sleep(0)))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        grav, rep, mentions, pastes, mx, rdapd = results

        lines.append(f"🖼 Gravatar: {'найден' if isinstance(grav, str) and grav else 'не найден'}")
        lines.append("")

        if isinstance(rep, dict) and not rep.get("__error"):
            lines.append("🛡 EmailRep:")
            rep_lines = []
            rep_lines += compact_details(rep, ["reputation", "suspicious", "references"])
            details = rep.get("details") if isinstance(rep.get("details"), dict) else {}
            flags = []
            for k in ["blacklisted", "malicious_activity", "malicious_activity_recent", "credentials_leaked",
                      "domain_exists", "domain_reputation", "new_domain", "spf_strict", "dmarc_enforced",
                      "profiles", "days_since_domain_creation"]:
                v = details.get(k)
                if v is not None and v != "":
                    flags.append(f"{k}={v}")
            if flags:
                rep_lines.append("details: " + ", ".join(flags[:20]))
            if rep_lines:
                lines += ["• " + l for l in rep_lines]
        else:
            lines.append("🛡 EmailRep: недоступно")

        lines.append("")
        lines.append("🔎 Упоминания в сети:")
        if isinstance(mentions, list) and mentions:
            for item in mentions:
                dom = (item.get("domain") or "").strip()
                ttl = (item.get("title") or "").strip()
                sn = (item.get("snippet") or "").strip()
                if not dom and not ttl and not sn:
                    continue
                lines.append(f"• [{dom}] {ttl}")
                if sn:
                    lines.append(f"  {sn[:220]}")
        else:
            lines.append("• Нет результатов")

        lines.append("")
        lines.append("🧾 Пасты/утечки (поиск):")
        if isinstance(pastes, list) and pastes:
            for item in pastes:
                dom = (item.get("domain") or "").strip()
                ttl = (item.get("title") or "").strip()
                sn = (item.get("snippet") or "").strip()
                if not dom and not ttl and not sn:
                    continue
                lines.append(f"• [{dom}] {ttl}")
                if sn:
                    lines.append(f"  {sn[:220]}")
        else:
            lines.append("• Нет результатов")

        lines.append("")
        if dom:
            lines.append(f"🏷 Анализ домена: {dom}")
            if isinstance(mx, dict) and (mx.get("Answer") or mx.get("Authority")):
                mx_hosts = []
                for rec in mx.get("Answer", []):
                    if rec.get("type") == 15 and rec.get("data"):
                        prt = rec["data"].split()
                        host = prt[-1].rstrip(".") if prt else rec["data"]
                        mx_hosts.append(host)
                if mx_hosts:
                    lines.append("• MX: " + ", ".join(sorted(set(mx_hosts))[:10]))
                else:
                    lines.append("• MX: нет ответов")
            else:
                lines.append("• MX: нет данных")

            if isinstance(rdapd, dict) and not rdapd.get("__error"):
                name = rdapd.get("ldhName") or rdapd.get("handle") or dom
                events = rdapd.get("events") or []
                created = None
                changed = None
                for ev in events:
                    if ev.get("eventAction") == "registration":
                        created = ev.get("eventDate")
                    if ev.get("eventAction") in ("last changed", "last changed by registrar", "expiration"):
                        changed = ev.get("eventDate") if not changed else changed
                lines.append(f"• RDAP: name={name}")
                if created:
                    lines.append(f"• Registered: {created}")
                if changed:
                    lines.append(f"• Last changed/exp: {changed}")
            else:
                lines.append("• RDAP: нет данных")

    return "\n".join(lines)

# ===================== VK History aggregator =====================
async def google_cache_link(session: aiohttp.ClientSession, url: str) -> Optional[str]:
    try:
        cache_url = f"https://webcache.googleusercontent.com/search?q=cache:{quote(url, safe='')}"
        res = await fetch_head(session, cache_url, timeout=4)
        if res.get("status") == 200:
            return cache_url
    except Exception:
        pass
    return None

async def bing_cache_link(session: aiohttp.ClientSession, url: str) -> Optional[str]:
    try:
        items = await ddg_search(session, f"site:{url}", max_results=2)
        for it in items:
            if "cc.bingj.com" in (it.get("domain") or "") or "cc.bingj.com" in (it.get("title") or ""):
                return "bing-cache"
    except Exception:
        pass
    return None

async def yandex_cache_link(session: aiohttp.ClientSession, url: str) -> Optional[str]:
    try:
        items = await ddg_search(session, f"site:{url}", max_results=2)
        for it in items:
            if "yandex" in (it.get("domain") or "") and "cache" in (it.get("title") or "").lower():
                return "yandex-cache"
    except Exception:
        pass
    return None

async def vk_history_aggregate(raw_identifier: str) -> str:
    vk_id = normalize_vk_identifier(raw_identifier)
    if not vk_id:
        return "Неверный VK идентификатор. Отправь ник/id или ссылку вида vk.com/username или id12345."

    target = f"vk.com/{vk_id}"
    lines = [f"Отчёт — История VK: {vk_id}", ""]
    async with aiohttp.ClientSession(timeout=CONNECT_TIMEOUT, headers=HEADERS) as session:
        try:
            cdx = await wayback_cdx_lookup(session, target, limit=500)
            if isinstance(cdx, list) and len(cdx) > 1:
                rows = cdx[1:]
                cnt = len(rows)
                first_ts = rows[0][0]
                last_ts = rows[-1][0]
                def ts_to_date(ts: str) -> str:
                    try:
                        dt = datetime.datetime.strptime(ts, "%Y%m%d%H%M%S")
                        return dt.strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        return ts
                lines.append(f"🕰 Wayback: снимков ~{cnt}")
                lines.append(f"• Первый: {ts_to_date(first_ts)}")
                lines.append(f"• Последний: {ts_to_date(last_ts)}")
            else:
                lines.append("🕰 Wayback: снимки не найдены")
        except Exception as e:
            lines.append(f"Wayback: ошибка ({e})")

        lines.append("")

        try:
            ddg = await ddg_search(session, f"vk.com/{vk_id}", max_results=12)
            lines.append("🔎 Следы/упоминания:")
            if ddg:
                for it in ddg[:8]:
                    dom = (it.get("domain") or "").strip()
                    ttl = (it.get("title") or "").strip()
                    sn = (it.get("snippet") or "").strip()
                    lines.append(f"• [{dom}] {ttl}")
                    if sn:
                        lines.append(f"  {sn[:220]}")
            else:
                lines.append("• Нет результатов")
        except Exception as e:
            lines.append(f"DDG: ошибка ({e})")

        lines.append("")

        try:
            g = await google_cache_link(session, f"https://vk.com/{vk_id}")
            b = await bing_cache_link(session, f"https://vk.com/{vk_id}")
            y = await yandex_cache_link(session, f"https://vk.com/{vk_id}")
            lines.append("📦 Кеши:")
            lines.append(f"• Google: {'есть' if g else 'нет'}")
            lines.append(f"• Bing: {'есть' if b else 'нет'}")
            lines.append(f"• Yandex: {'есть' if y else 'нет'}")
        except Exception as e:
            lines.append(f"Кеши: ошибка ({e})")

        lines.append("")

        try:
            profile_url = f"https://vk.com/{vk_id}"
            h = await fetch_text(session, profile_url, timeout=6)
            if h.get("status") == 200 and h.get("text"):
                txt = h.get("text")[:4000]
                title = re.search(r"<title[^>]*>(.*?)</title>", txt, re.I|re.S)
                og = re.search(r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)["\']', txt, re.I|re.S)
                if title:
                    lines.append("🔗 Текущая страница: доступна (200)")
                    lines.append("• Title: " + re.sub(r"\s+", " ", title.group(1)).strip()[:200])
                else:
                    lines.append("🔗 Текущая страница: доступна (200)")
                if og:
                    lines.append("• Описание: " + og.group(1)[:240])
            else:
                lines.append(f"🔗 Текущая страница: недоступна (HTTP {h.get('status')})")
        except Exception as e:
            lines.append(f"Текущая страница: ошибка ({e})")

        lines.append("")

        try:
            subs = ["photo", "album", "wall", "photos"]
            found_subs = []
            for ssub in subs:
                t = f"vk.com/{vk_id}/{ssub}"
                c = await wayback_cdx_lookup(session, t, limit=40)
                if isinstance(c, list) and len(c) > 1:
                    found_subs.append((ssub, len(c)-1))
            if found_subs:
                lines.append("🔎 Архивные разделы:")
                for ssub, cnt in found_subs:
                    lines.append(f"• {ssub}: ~{cnt} снимков")
            else:
                lines.append("🔎 Архивные разделы: не найдены")
        except Exception:
            pass

    return "\n".join(lines)

# ===================== Username search =====================
async def search_username_all(username: str, session: aiohttp.ClientSession, timeout: int = 6) -> List[Dict[str, Any]]:
    tasks = []
    for site, tmpl, quote_flag in SITE_TEMPLATES:
        u = quote_plus(username) if quote_flag else username
        url = tmpl.format(u)
        tasks.append((site, url))

    sem = asyncio.Semaphore(MAX_CONCURRENCY)

    async def _check(site_url_tuple):
        site, url = site_url_tuple
        async with sem:
            res = await fetch_head(session, url, timeout=timeout)
            if res.get("ok"):
                return {"site": site, "url": res.get("url") or url, "status": res.get("status")}
            return {"site": site, "url": res.get("url") or url, "status": res.get("status"), "ok": False}

    results = await asyncio.gather(*[_check(t) for t in tasks], return_exceptions=False)
    await asyncio.sleep(0)
    found = [r for r in results if r.get("status") in (200, 301, 302)]
    return found

async def aggregate_user_search(username: str) -> str:
    header = "Отчёт поиска по нику"
    async with aiohttp.ClientSession(timeout=CONNECT_TIMEOUT, headers=HEADERS) as session:
        found = await search_username_all(username, session)
        lines = [header]
        if not found:
            lines.append(f"Ничего не найдено по нику: {username}")
        else:
            lines.append(f"Найдено ссылок для `{username}`:")
            for r in found:
                lines.append(f"• {r['site']}: {r['url']}")
        vk_id = normalize_vk_identifier(username)
        if vk_id:
            lines.append("")
            lines.append("🕰 (VK) собираю краткую историю...")
            try:
                vk_lines = await vk_history_aggregate(vk_id)
                lines.append(vk_lines)
            except Exception as e:
                lines.append(f"Ошибка при получении истории VK: {e}")
    return "\n".join(lines)

# ===================== IP helpers =====================
async def ip_geolocation(ip: str) -> dict:
    url = f"http://ip-api.com/json/{ip}"
    async with aiohttp.ClientSession(timeout=CONNECT_TIMEOUT, headers=HEADERS) as session:
        return await fetch_json(session, url)

async def ip_rdap_raw(ip: str) -> dict:
    url = f"https://rdap.org/ip/{ip}"
    async with aiohttp.ClientSession(timeout=CONNECT_TIMEOUT, headers=HEADERS) as session:
        return await fetch_json(session, url)

async def reverse_dns(ip: str) -> dict:
    loop = asyncio.get_event_loop()
    def _rdns():
        try:
            host, aliases, _ = socket.gethostbyaddr(ip)
            return {"host": host, "aliases": aliases}
        except Exception as e:
            return {"__error": str(e)}
    return await loop.run_in_executor(None, _rdns)

def _extract_vcard_fields(vcard_array):
    out = {"fn": None, "emails": [], "tels": [], "addrs": [], "org": None, "title": None}
    try:
        items = vcard_array[1]
        for item in items:
            if len(item) >= 4:
                prop = item[0].lower()
                val = item[3]
                if prop == "fn":
                    out["fn"] = val
                elif prop in ("email", "email;internet"):
                    out["emails"].append(val)
                elif prop in ("tel",):
                    out["tels"].append(val)
                elif prop in ("org",):
                    out["org"] = val if not out.get("org") else out["org"]
                elif prop in ("adr",):
                    if isinstance(val, list):
                        out["addrs"].append(", ".join([p for p in val if p]))
                    else:
                        out["addrs"].append(str(val))
                elif prop in ("title",):
                    out["title"] = val
    except Exception:
        pass
    return out

def _format_event_list(events):
    rows = []
    for ev in events or []:
        action = ev.get("eventAction") or ev.get("event")
        date = ev.get("eventDate") or ev.get("date")
        if date:
            try:
                d = datetime.datetime.fromisoformat(date.replace("Z", "+00:00"))
                date = d.strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                pass
        rows.append(f"  • {action or 'event'} — {date or '—'}")
    return "\n".join(rows)

def format_rdap_text(rdap: dict, ip: str) -> str:
    if not rdap:
        return "RDAP: пустой ответ."
    net = rdap.get("network") or rdap
    def safe_get(d, *keys):
        for k in keys:
            v = d.get(k)
            if v:
                return v
        return None
    handle = safe_get(net, "handle", "name") or "—"
    name = safe_get(net, "name") or "—"
    start = net.get("startAddress") or net.get("start") or "—"
    end = net.get("endAddress") or net.get("end") or "—"
    ip_version = net.get("ipVersion") or net.get("type") or "—"
    country = net.get("country") or "—"
    cidr = "—"
    if net.get("cidr"):
        cidr = net.get("cidr")
    else:
        prefixes = net.get("cidr0_cidrs") or net.get("prefixes") or None
        if isinstance(prefixes, list) and len(prefixes) > 0:
            first = prefixes[0]
            if isinstance(first, dict):
                cidr = first.get("v4prefix") or first.get("cidr") or json.dumps(first)
            else:
                cidr = str(first)
    port43 = rdap.get("port43") or net.get("port43") or "—"
    links = rdap.get("links") or net.get("links") or []
    link_urls = [l.get("href") for l in links if l.get("href")]
    events = net.get("events") or rdap.get("events") or []
    events_text = _format_event_list(events)
    entities = rdap.get("entities") or net.get("entities") or []
    ent_lines = []
    ent_details = []
    abuse_contacts = []
    for e in entities:
        name_e = e.get("handle") or e.get("objectClassName") or "entity"
        roles = e.get("roles") or []
        vcard = e.get("vcardArray")
        vinfo = _extract_vcard_fields(vcard) if vcard else {}
        if any("abuse" == r.lower() for r in roles):
            abuse_contacts.append({
                "handle": name_e,
                "emails": vinfo.get("emails", []),
                "tels": vinfo.get("tels", [])
            })
        summary = f"{name_e} ({', '.join(roles) or '—'})"
        details = []
        if vinfo.get("fn"):
            details.append(f"Name: {vinfo.get('fn')}")
        if vinfo.get("org"):
            details.append(f"Org: {vinfo.get('org')}")
        if vinfo.get("title"):
            details.append(f"Title: {vinfo.get('title')}")
        if vinfo.get("emails"):
            details.append("Emails: " + ", ".join(vinfo.get("emails")))
        if vinfo.get("tels"):
            details.append("Phones: " + ", ".join(vinfo.get("tels")))
        if vinfo.get("addrs"):
            details.append("Addresses: " + "; ".join(vinfo.get("addrs")))
        ent_lines.append(f"  • {summary}")
        if details:
            ent_details.append("    - " + "\n    - ".join(details))
    remark_texts = []
    for r in (rdap.get("remarks") or net.get("remarks") or [])[:6]:
        desc = r.get("description") or r.get("title") or None
        if desc:
            if isinstance(desc, list):
                desc = " ".join(desc)
            remark_texts.append(desc)
    out = []
    out.append(f"WHOIS / RDAP для {ip}:")
    out.append(f"• Handle / name: {handle} / {name}")
    out.append(f"• Type / IP version: {ip_version}")
    out.append(f"• Range: {start} — {end}")
    out.append(f"• CIDR / prefixes: {cidr}")
    out.append(f"• Country: {country}")
    out.append(f"• Port43 (WHOIS server): {port43}")
    if link_urls:
        out.append("• Links: " + ", ".join(link_urls[:5]))
    if events_text:
        out.append("")
        out.append("События (registration/last changed):")
        out.append(events_text)
    if entities:
        out.append("")
        out.append("Entities:")
        for i, s in enumerate(ent_lines):
            out.append(s)
            if i < len(ent_details):
                out.append(ent_details[i])
    if remark_texts:
        out.append("")
        out.append("Remarks:")
        for r in remark_texts:
            out.append("  - " + (r if len(r) < 400 else r[:400] + "…"))
    out.append("")
    out.append(f"Полный RDAP JSON: https://rdap.org/ip/{ip}")
    return "\n".join(out)

# ===================== State per chat =====================
pending_actions: Dict[int, str] = {}  # chat_id -> "username" | "ip" | "email" | "vk" | None

# ===================== Handlers =====================
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    auth = load_auth()
    uid = update.effective_user.id
    intro = ("Тишина сети обманчива. Под поверхностью всегда остаются следы — старые профили, "
             "забытые комментарии, обрывки данных. Мы не ломаем двери — мы читаем витражи прошлого "
             "и складываем из них картину.")
    await update.message.reply_text(intro)

    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🔍 Поиск по нику", callback_data="act_name")],
        [InlineKeyboardButton("📧 Поиск по email", callback_data="act_email")],
        [InlineKeyboardButton("🌐 Поиск по IP", callback_data="act_ip")],
        [InlineKeyboardButton("🔎 История VK", callback_data="act_vk")],
    ])
    txt = ("Выбери действие:\n\n"
           "🔍 Поиск по нику — проверка множества публичных сайтов.\n"
           "📧 Поиск по email — Gravatar, EmailRep, упоминания, пасты, MX и RDAP домена.\n"
           "🌐 Поиск по IP — геолокация, RDAP и reverse DNS.\n"
           "🔎 История VK — архивы, кеши и следы.")
    if not is_allowed(uid, auth):
        txt += "\n\n❗ У вас нет доступа. Обратитесь к владельцу бота."
    await update.message.reply_text(txt, reply_markup=kb)

async def btn_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    auth = load_auth()
    query = update.callback_query
    await query.answer()
    uid = query.from_user.id
    cid = query.message.chat_id
    if not is_allowed(uid, auth):
        await query.message.reply_text("У вас нет прав на использование бота. Попросите владельца добавить ваш Telegram ID.")
        return
    data = query.data
    if data == "act_name":
        pending_actions[cid] = "username"
        await query.message.reply_text("Отправь ник/имя пользователя — бот проверит публичные сайты.")
        return
    if data == "act_ip":
        pending_actions[cid] = "ip"
        await query.message.reply_text("Отправь IP-адрес (пример: 8.8.8.8).")
        return
    if data == "act_email":
        pending_actions[cid] = "email"
        await query.message.reply_text("Отправь email (пример: name@example.com).")
        return
    if data == "act_vk":
        pending_actions[cid] = "vk"
        await query.message.reply_text("Отправь VK ник/ID или ссылку (пример: vk.com/username или id12345).")
        return

async def plain_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    auth = load_auth()
    uid = update.effective_user.id
    cid = update.effective_chat.id
    text = (update.message.text or "").strip()
    if not is_allowed(uid, auth):
        await update.message.reply_text("У вас нет прав на использование бота. Попросите владельца добавить ваш Telegram ID.")
        return
    action = pending_actions.get(cid)
    if not action:
        if looks_like_email(text):
            action = "email"
        elif looks_like_ip(text):
            action = "ip"
        elif normalize_vk_identifier(text):
            action = "vk"
        else:
            action = "username"

    if action == "username":
        pending_actions.pop(cid, None)
        if len(text) == 0:
            await update.message.reply_text("Пустой ник — отправь ник/имя.")
            return
        await update.message.chat.send_action("typing")
        res = await aggregate_user_search(text)
        for chunk in [res[i:i+TG_CHUNK] for i in range(0, len(res), TG_CHUNK)]:
            await update.message.reply_text(chunk)
        return

    if action == "email":
        pending_actions.pop(cid, None)
        if not looks_like_email(text):
            await update.message.reply_text("Похоже, это не email. Отправь корректный адрес (пример: name@example.com).")
            return
        await update.message.chat.send_action("typing")
        out = await aggregate_email_search(text)
        for chunk in [out[i:i+TG_CHUNK] for i in range(0, len(out), TG_CHUNK)]:
            await update.message.reply_text(chunk)
        return

    if action == "vk":
        pending_actions.pop(cid, None)
        await update.message.chat.send_action("typing")
        out = await vk_history_aggregate(text)
        for chunk in [out[i:i+TG_CHUNK] for i in range(0, len(out), TG_CHUNK)]:
            await update.message.reply_text(chunk)
        return

    if action == "ip":
        pending_actions.pop(cid, None)
        if not looks_like_ip(text):
            await update.message.reply_text("Похоже, это не IP. Отправь корректный IPv4/IPv6 (пример: 8.8.8.8).")
            return
        ip = text
        await update.message.chat.send_action("typing")
        async with aiohttp.ClientSession(timeout=CONNECT_TIMEOUT, headers=HEADERS) as session:
            geo_task = asyncio.create_task(fetch_json(session, f"http://ip-api.com/json/{ip}"))
            rdap_task = asyncio.create_task(fetch_json(session, f"https://rdap.org/ip/{ip}"))
            loop = asyncio.get_event_loop()
            def _rdns():
                try:
                    host, aliases, _ = socket.gethostbyaddr(ip)
                    return {"host": host, "aliases": aliases}
                except Exception as e:
                    return {"__error": str(e)}
            rdns_task = loop.run_in_executor(None, _rdns)
            geo = await geo_task
            rdap = await rdap_task
            rdns = await rdns_task
        parts = [f"Отчёт по IP: {ip}", ""]
        if isinstance(geo, dict) and geo.get("status") == "success":
            parts += [
                "🌐 Геолокация (ip-api):",
                f"• Country: {geo.get('country')} ({geo.get('countryCode')})",
                f"• Region: {geo.get('regionName')}",
                f"• City: {geo.get('city')}",
                f"• ZIP: {geo.get('zip')}",
                f"• Lat,Lon: {geo.get('lat')}, {geo.get('lon')}",
                f"• Timezone: {geo.get('timezone')}",
                f"• ISP / Org: {geo.get('isp')} / {geo.get('org')}",
                f"• AS: {geo.get('as')}",
                ""
            ]
        else:
            parts.append(f"🌐 Геолокация: ошибка или нет данных ({geo})")
        try:
            rdap_text = format_rdap_text(rdap, ip)
            parts += ["", rdap_text, ""]
        except Exception as e:
            parts += [f"🧾 RDAP: ошибка форматирования ({e})"]
        if isinstance(rdns, dict) and rdns.get("host"):
            parts += ["", "🔁 Reverse DNS:", f"• Host: {rdns.get('host')}", f"• Aliases: {', '.join(rdns.get('aliases') or [])}"]
        else:
            parts += ["", f"🔁 Reverse DNS: ошибка ({rdns})"]
        parts.append("")
        out = "\n".join(parts)
        for chunk in [out[i:i+TG_CHUNK] for i in range(0, len(out), TG_CHUNK)]:
            await update.message.reply_text(chunk)
        return

# ===================== Helper: chunking =====================
def chunk_text(text: str, n: int = TG_CHUNK):
    for i in range(0, len(text), n):
        yield text[i:i+n]

# ===================== Utility: IP/email checks =====================
def looks_like_ip(s: str) -> bool:
    s = s.strip()
    ipv4_re = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    if ipv4_re.match(s):
        parts = s.split(".")
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except Exception:
            return False
    ipv6_re = re.compile(r"^[0-9a-fA-F:]+$")
    if ":" in s and ipv6_re.match(s):
        return True
    return False

# ===================== Management commands =====================
def parse_id_arg(arg: str) -> Optional[int]:
    try:
        return int(arg.strip())
    except Exception:
        return None

async def whoami_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    auth = load_auth()
    uid = update.effective_user.id
    role = "owner" if is_owner(uid, auth) else ("admin" if is_admin(uid, auth) else ("allowed" if uid in auth.get("allowed_users", []) else "none"))
    await update.message.reply_text(f"Ваш Telegram ID: {uid}\nРоль: {role}")

async def list_auth_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    auth = load_auth()
    uid = update.effective_user.id
    if not is_admin(uid, auth):
        await update.message.reply_text("Только owner/admin может просматривать список авторизаций.")
        return
    owner = auth.get("owner")
    admins = auth.get("admins", [])
    allowed = auth.get("allowed_users", [])
    txt = f"Owner: {owner}\nAdmins: {admins}\nAllowed users: {allowed}"
    await update.message.reply_text(txt)

async def allow_add_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    auth = load_auth()
    uid = update.effective_user.id
    if not is_admin(uid, auth):
        await update.message.reply_text("Только owner/admin может добавлять разрешённых пользователей.")
        return
    if not context.args:
        await update.message.reply_text("Использование: /allow_add <telegram_id>")
        return
    target = parse_id_arg(context.args[0])
    if not target:
        await update.message.reply_text("Неверный ID.")
        return
    if target in auth.get("allowed_users", []):
        await update.message.reply_text("Пользователь уже в списке allowed.")
        return
    auth["allowed_users"].append(target)
    save_auth(auth)
    await update.message.reply_text(f"Добавлен allowed user: {target}")

async def allow_remove_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    auth = load_auth()
    uid = update.effective_user.id
    if not is_admin(uid, auth):
        await update.message.reply_text("Только owner/admin может удалять разрешённых пользователей.")
        return
    if not context.args:
        await update.message.reply_text("Использование: /allow_remove <telegram_id>")
        return
    target = parse_id_arg(context.args[0])
    if not target:
        await update.message.reply_text("Неверный ID.")
        return
    if target in auth.get("allowed_users", []):
        auth["allowed_users"].remove(target)
        save_auth(auth)
        await update.message.reply_text(f"Удалён allowed user: {target}")
    else:
        await update.message.reply_text("Этот пользователь не в списке allowed.")

async def admin_add_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    auth = load_auth()
    uid = update.effective_user.id
    if not is_owner(uid, auth):
        await update.message.reply_text("Только owner может добавлять админов.")
        return
    if not context.args:
        await update.message.reply_text("Использование: /admin_add <telegram_id>")
        return
    target = parse_id_arg(context.args[0])
    if not target:
        await update.message.reply_text("Неверный ID.")
        return
    if target in auth.get("admins", []):
        await update.message.reply_text("Пользователь уже админ.")
        return
    auth["admins"].append(target)
    save_auth(auth)
    await update.message.reply_text(f"Добавлен админ: {target}")

async def admin_remove_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    auth = load_auth()
    uid = update.effective_user.id
    if not is_owner(uid, auth):
        await update.message.reply_text("Только owner может удалять админов.")
        return
    if not context.args:
        await update.message.reply_text("Использование: /admin_remove <telegram_id>")
        return
    target = parse_id_arg(context.args[0])
    if not target:
        await update.message.reply_text("Неверный ID.")
        return
    if target in auth.get("admins", []):
        auth["admins"].remove(target)
        save_auth(auth)
        await update.message.reply_text(f"Удалён админ: {target}")
    else:
        await update.message.reply_text("Этот пользователь не является админом.")

# ===================== Main (webhook via Flask) =====================
# === Создаём Telegram Application ===
app = Flask(__name__)
application = Application.builder().token(BOT_TOKEN).build()
application.add_handler(CommandHandler("start", start_cmd))
application.add_handler(CommandHandler("whoami", whoami_cmd))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, plain_message))
application.add_handler(CallbackQueryHandler(btn_callback))

# === Создаём единый event loop ===
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

# === Асинхронный запуск PTB ===
async def init_bot():
    await application.initialize()
    await application.start()
    print("✅ Bot started and ready for webhook updates")

loop.create_task(init_bot())

# === Flask webhook route ===
@app.route("/webhook", methods=["POST"])
def webhook():
    try:
        data = request.get_json(force=True)
        print("🔥 RAW update:", data)
        if not data:
            return "no data", 400

        update = Update.de_json(data, application.bot)
        # Вместо run_coroutine_threadsafe
        asyncio.run_coroutine_threadsafe(application.process_update(update), loop)

        return "ok", 200
    except Exception as e:
        print("❌ Ошибка в webhook:", e)
        import traceback
        traceback.print_exc()
        return str(e), 500


if __name__ == "__main__":
    WEBHOOK_URL = f"https://{os.environ.get('RENDER_EXTERNAL_HOSTNAME', 'https://asdsadfasdfdsfsdfdsc.onrender.com')}/webhook"

    # Устанавливаем вебхук
    try:
        r = requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/setWebhook?url={WEBHOOK_URL}")
        print("Webhook set:", r.json())
    except Exception as e:
        print("Ошибка установки вебхука:", e)

    # Запуск Flask
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))