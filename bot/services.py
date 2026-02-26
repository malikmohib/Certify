from __future__ import annotations

import asyncio
import base64
import binascii
import io
import json
import logging
import os
import random
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape as hesc
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import quote

import requests
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.error import BadRequest

from bot.config import (
    ADMIN_TELEGRAM_ID,
    CERT_API_BASE,
    CERT_API_TOKEN,
    CERT_PASSWORD,
    IPA_MAP,
    BUNDLE_ID_MAP,
    APP_TITLE_MAP,
    PUBLIC_BASE_URL,
    PUBLIC_FILES_DIR,
    PUBLIC_META_DIR,
    SAFE_ID_RE,
    WINDOW_SECONDS,
    MAX_MSGS_PER_WINDOW,
    ZSIGN_BIN,
    SIGNED_TTL_SECONDS,
)

logger = logging.getLogger("coupon-bot")

# =============================================================================
# COUPONS
# =============================================================================
def gen_vinh_coupon() -> str:
    # Your required format: Certify-xxxxxxxx (8 hex)
    return f"Certify-{secrets.token_hex(4)}"


# =============================================================================
# SIMPLE RATE LIMIT (DEV)
# =============================================================================
_rate = {}  # telegram_id -> (window_start, count)


def rate_limit(telegram_id: int) -> bool:
    now = int(time.time())
    start, count = _rate.get(telegram_id, (now, 0))
    if now - start >= WINDOW_SECONDS:
        start, count = now, 0
    count += 1
    _rate[telegram_id] = (start, count)
    return count <= MAX_MSGS_PER_WINDOW


# =============================================================================
# ADMIN CHECKS
# =============================================================================
def is_admin(update) -> bool:
    return bool(update.effective_user and update.effective_user.id == ADMIN_TELEGRAM_ID)


def is_private_chat(update) -> bool:
    return bool(update.effective_chat and update.effective_chat.type == "private")


def admin_guard(update) -> Optional[str]:
    if not is_private_chat(update):
        return "Admin actions are only allowed in private chat."
    if not is_admin(update):
        return "Unauthorized."
    return None


# =============================================================================
# SAFE EDIT
# =============================================================================
async def safe_edit(query, text: str, reply_markup=None, parse_mode: Optional[str] = None):
    try:
        await query.edit_message_text(
            text,
            reply_markup=reply_markup,
            parse_mode=parse_mode,
            disable_web_page_preview=True,
        )
    except BadRequest as e:
        if "Message is not modified" in str(e):
            return
        raise


# =============================================================================
# HELPERS
# =============================================================================
def bytesio_file(content: bytes, filename: str) -> io.BytesIO:
    f = io.BytesIO(content)
    f.name = filename
    f.seek(0)
    return f


def _to_epoch_seconds(ts):
    """
    Normalize provider timestamps to epoch seconds.
    Accepts seconds or milliseconds, int/float/str.
    """
    if ts is None:
        return None
    try:
        if isinstance(ts, str):
            ts = ts.strip()
            if not ts:
                return None
            tsf = float(ts)
        elif isinstance(ts, (int, float)):
            tsf = float(ts)
        else:
            return None

        # If looks like milliseconds, convert to seconds
        if tsf > 1e11:
            tsf /= 1000.0

        return int(tsf)
    except Exception:
        return None


def fmt_dt(ts) -> str:
    s = _to_epoch_seconds(ts)
    if not s:
        return "N/A"
    try:
        dt = datetime.fromtimestamp(s, tz=timezone.utc)
        return dt.strftime("%d %b %Y %I:%M %p UTC")
    except Exception:
        return str(ts)


def fmt_warranty_left(warranty_time) -> str:
    s = _to_epoch_seconds(warranty_time)
    if not s:
        return "N/A"
    try:
        now = int(datetime.now(timezone.utc).timestamp())
        left = s - now
        if left <= 0:
            return "Expired"
        days = left // 86400
        hours = (left % 86400) // 3600
        mins = (left % 3600) // 60
        return f"{days} days, {hours} hours, {mins} minutes"
    except Exception:
        return str(warranty_time)


def _is_within(base_dir: Path, target: Path) -> bool:
    """
    Prevent path traversal. Works on Python 3.12+.
    """
    try:
        base = base_dir.resolve()
        t = target.resolve()
        return t.is_relative_to(base)
    except Exception:
        # safest fallback
        return False


def _atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    """
    Atomic write: write temp then replace.
    Prevents corrupted meta.json if crash mid-write.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding=encoding)
    os.replace(tmp, path)


# =============================================================================
# CERT UI (CARD + KEYBOARD)
# =============================================================================
def build_cert_card(udid: str, r: dict, password: str = CERT_PASSWORD) -> str:
    status = r.get("status", "UNKNOWN")
    state = r.get("state", True)

    if status == "READY" and state:
        status_line = "Status: <b>Active</b> 🟢"
    elif status == "PENDING" and state:
        status_line = "Status: <b>Pending</b> ⏳"
    elif not state or status == "REVOKED":
        status_line = "Status: <b>Revoked</b> 🔴"
    else:
        status_line = f"Status: <b>{hesc(str(status))}</b> ⚠️"

    name = r.get("pname") or "N/A"
    added_on = fmt_dt(r.get("addtime"))
    warranty_left = fmt_warranty_left(r.get("warranty_time"))

    lines = [
        status_line,
        f"Name: <b>{hesc(str(name))}</b>",
        f"UDID: <code>{hesc(udid)}</code>",
        f"Added on: {hesc(str(added_on))}",
        f"Warranty: {hesc(str(warranty_left))}",
    ]

    if status == "READY":
        lines += [
            "",
            "<b>Files</b>",
            f"<code>1) {hesc(udid)}.p12</code>",
            f"<code>2) {hesc(udid)}.mobileprovision</code>",
            f"<code>Password: {hesc(password)}</code>",
            "",
            "Select an app to sign:",
        ]

    return "\n".join(lines)


def cert_action_keyboard(share_text: str) -> InlineKeyboardMarkup:
    share_url = f"https://t.me/share/url?url={quote(share_text)}"
    return InlineKeyboardMarkup(
        [[
            InlineKeyboardButton("Get Certificate", callback_data="cert:get"),
            InlineKeyboardButton("Share", url=share_url),
        ]]
    )


# =============================================================================
# SIGNING UI
# =============================================================================
def signing_app_keyboard() -> InlineKeyboardMarkup:
    # ✅ Fix typo: esign not esgn
    return InlineKeyboardMarkup(
        [[
            InlineKeyboardButton("ESign", callback_data="signapp:esign"),
            InlineKeyboardButton("GBox", callback_data="signapp:gbox"),
            InlineKeyboardButton("Scarlet", callback_data="signapp:scarlet"),
        ]]
    )


def build_signed_app_card(*, udid: str, variant: str, install_url: str, ipa_url: str) -> str:
    title = APP_TITLE_MAP.get(variant, variant)
    return "\n".join([
        "✅ <b>The application has been signed</b> and is ready for installation.",
        f"App: <b>{hesc(str(title))}</b>",
        f"UDID: <code>{hesc(udid)}</code>",
    ])


def signed_app_keyboard(*, install_url: str, ipa_url: str) -> InlineKeyboardMarkup:
    share_text = f"Install: {install_url}\nIPA: {ipa_url}"
    share_url = f"https://t.me/share/url?url={quote(share_text)}"
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("📲 Install", url=install_url),
                InlineKeyboardButton("⬇️ IPA", url=ipa_url),
            ],
            [InlineKeyboardButton("🔗 Share", url=share_url)],
            [InlineKeyboardButton("🔙 Back", callback_data="menu:back")],
        ]
    )


# =============================================================================
# SIGNING (ZSIGN)
# =============================================================================
def write_meta_json(
    *,
    meta_path: Path,
    ipa_filename: str,
    title: str,
    bundle_id: str,
    bundle_version: str,
    variant: str,
) -> None:
    data = {
        "ipa_filename": ipa_filename,
        "title": title,
        "bundle_id": bundle_id,
        "bundle_version": bundle_version,
        "variant": variant,
        "created_at": int(time.time()),
    }
    _atomic_write_text(meta_path, json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


async def sign_with_zsign(
    *,
    ipa_path: Path,
    p12_path: Path,
    prov_path: Path,
    password: str,
    bundleid: str,
    out_ipa: Path,
) -> Path:
    if not ZSIGN_BIN.exists():
        raise RuntimeError(f"zsign not found at: {ZSIGN_BIN}")
    if not ipa_path.exists():
        raise RuntimeError(f"IPA not found: {ipa_path}")
    if not p12_path.exists():
        raise RuntimeError("Missing .p12 file.")
    if not prov_path.exists():
        raise RuntimeError("Missing .mobileprovision file.")
    if not password:
        raise RuntimeError("Password is empty.")

    out_ipa.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(ZSIGN_BIN),
        "-k", str(p12_path),
        "-p", password,
        "-m", str(prov_path),
        "-b", bundleid,
        "-o", str(out_ipa),
        str(ipa_path),
    ]

    def _run():
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )

    try:
        res = await asyncio.to_thread(_run)
    except subprocess.TimeoutExpired:
        raise RuntimeError("zsign timed out. Try again later.")

    if res.returncode != 0 or not out_ipa.exists():
        out = (res.stdout or "")[-4000:]
        raise RuntimeError(f"zsign failed.\n\nOutput:\n{out}")

    return out_ipa


def cleanup_expired_signed_files(*, ttl_seconds: int) -> int:
    now = int(time.time())
    deleted_meta = 0

    PUBLIC_FILES_DIR.mkdir(parents=True, exist_ok=True)
    PUBLIC_META_DIR.mkdir(parents=True, exist_ok=True)

    referenced_ipas = set()

    for meta_path in PUBLIC_META_DIR.glob("*.meta.json"):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            created_at = int(meta.get("created_at") or 0)
            ipa_filename = str(meta.get("ipa_filename") or "").strip()
            if ipa_filename:
                referenced_ipas.add(ipa_filename)

            if not created_at:
                continue

            if now - created_at < ttl_seconds:
                continue

            if ipa_filename:
                ipa_path = (PUBLIC_FILES_DIR / ipa_filename).resolve()
                if _is_within(PUBLIC_FILES_DIR, ipa_path) and ipa_path.exists():
                    try:
                        ipa_path.unlink()
                    except Exception:
                        pass

            try:
                meta_path.unlink()
            except Exception:
                pass

            deleted_meta += 1
        except Exception:
            continue

    # orphan IPA cleanup
    try:
        for ipa_path in PUBLIC_FILES_DIR.glob("*.ipa"):
            try:
                if ipa_path.name in referenced_ipas:
                    continue
                st = ipa_path.stat()
                age = now - int(st.st_mtime)
                if age >= ttl_seconds:
                    if _is_within(PUBLIC_FILES_DIR, ipa_path) and ipa_path.exists():
                        try:
                            ipa_path.unlink()
                        except Exception:
                            pass
            except Exception:
                continue
    except Exception:
        pass

    return deleted_meta


async def sign_and_publish_from_cert_bytes(
    *,
    udid: str,
    variant: str,
    p12_bytes: bytes,
    mp_bytes: bytes,
) -> Tuple[str, str]:
    if variant == "esgn":
        variant = "esign"

    if variant not in IPA_MAP:
        raise RuntimeError("Invalid app selection.")

    ipa_path = IPA_MAP[variant]
    bundleid = BUNDLE_ID_MAP.get(variant, "com.example.app")
    title = APP_TITLE_MAP.get(variant, variant)

    PUBLIC_FILES_DIR.mkdir(parents=True, exist_ok=True)
    PUBLIC_META_DIR.mkdir(parents=True, exist_ok=True)

    job = uuid.uuid4().hex[:10]
    install_id = f"{variant}-{job}"
    if not SAFE_ID_RE.match(install_id):
        raise RuntimeError("Generated install id invalid.")

    with tempfile.TemporaryDirectory(prefix="signjob_") as td:
        workdir = Path(td)
        cert_dir = workdir / "cert"
        cert_dir.mkdir(parents=True, exist_ok=True)

        p12_path = cert_dir / f"{udid}.p12"
        prov_path = cert_dir / f"{udid}.mobileprovision"
        p12_path.write_bytes(p12_bytes)
        prov_path.write_bytes(mp_bytes)

        signed_tmp = workdir / f"{variant}-{job}.signed.ipa"

        signed_path = await sign_with_zsign(
            ipa_path=ipa_path,
            p12_path=p12_path,
            prov_path=prov_path,
            password=CERT_PASSWORD,
            bundleid=bundleid,
            out_ipa=signed_tmp,
        )

        public_ipa_name = signed_path.name
        public_ipa_path = (PUBLIC_FILES_DIR / public_ipa_name).resolve()
        if not _is_within(PUBLIC_FILES_DIR, public_ipa_path):
            raise RuntimeError("Unsafe public path generation.")

        shutil.copy2(signed_path, public_ipa_path)

        meta_path = (PUBLIC_META_DIR / f"{install_id}.meta.json").resolve()
        if not _is_within(PUBLIC_META_DIR, meta_path):
            raise RuntimeError("Unsafe meta path generation.")

        write_meta_json(
            meta_path=meta_path,
            ipa_filename=public_ipa_name,
            title=title,
            bundle_id=bundleid,
            bundle_version="1.0",
            variant=variant,
        )

    cleanup_expired_signed_files(ttl_seconds=SIGNED_TTL_SECONDS)

    install_page_url = f"{PUBLIC_BASE_URL}/install/{install_id}"
    ipa_url = f"{PUBLIC_BASE_URL}/files/{public_ipa_name}"
    return install_page_url, ipa_url


# =============================================================================
# PROVIDER API (PRODUCTION HARDENED + UX MAPPING) ✅ NO SECRET LOGS
# =============================================================================
# Provider retry/timeout tuning
_PROVIDER_MAX_ATTEMPTS = int(os.getenv("PROVIDER_MAX_ATTEMPTS", "3"))
_PROVIDER_CONNECT_TIMEOUT = float(os.getenv("PROVIDER_CONNECT_TIMEOUT", "10"))
_PROVIDER_READ_TIMEOUT = float(os.getenv("PROVIDER_READ_TIMEOUT", "60"))
_PROVIDER_BACKOFF_BASE = float(os.getenv("PROVIDER_BACKOFF_BASE", "1.0"))
_PROVIDER_BACKOFF_CAP = float(os.getenv("PROVIDER_BACKOFF_CAP", "10.0"))

# include 530 (Cloudflare)
_RETRYABLE_HTTP = {429, 500, 502, 503, 504, 530}

# redact patterns
_SENSITIVE_JSON_KEYS = {
    "token",
    "udid",
    "p12",
    "mobileprovision",
    "certificate",
    "cert",
    "profile",
    "provision",
}
_RE_UDIDISH = re.compile(r"\b[0-9a-fA-F]{24,64}\b")
_RE_LONG_BASE64 = re.compile(r"\b[A-Za-z0-9+/]{200,}={0,2}\b")
_RE_TOKENISH = re.compile(r"\b[A-Za-z0-9_\-]{20,}\b")

def _mask_middle(s: str, head: int = 3, tail: int = 3) -> str:
    if not s:
        return "***"
    if len(s) <= head + tail + 2:
        return "***"
    return f"{s[:head]}…{s[-tail:]}"

def _redact_json_for_log(obj):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in _SENSITIVE_JSON_KEYS:
                if lk == "udid" and isinstance(v, str):
                    out[k] = _mask_middle(v, head=6, tail=4)
                elif lk == "token" and isinstance(v, str):
                    out[k] = _mask_middle(v, head=3, tail=3)
                else:
                    out[k] = "***REDACTED***"
            else:
                out[k] = _redact_json_for_log(v)
        return out
    if isinstance(obj, list):
        return [_redact_json_for_log(x) for x in obj]
    return obj

def _redact_text_for_log(text: str) -> str:
    if not text:
        return ""
    t = text
    t = _RE_UDIDISH.sub(lambda m: _mask_middle(m.group(0), head=6, tail=4), t)
    t = _RE_LONG_BASE64.sub("***BASE64_REDACTED***", t)
    t = _RE_TOKENISH.sub(lambda m: _mask_middle(m.group(0), head=3, tail=3), t)
    return t

def _safe_response_snippet_for_log(*, body_text: str, content_type: str) -> str:
    ctype = (content_type or "").lower()
    if "application/json" in ctype:
        try:
            j = json.loads(body_text or "")
            return (json.dumps(_redact_json_for_log(j), ensure_ascii=False)[:600]) or ""
        except Exception:
            pass
    return _redact_text_for_log((body_text or "")[:300])

BUSINESS_MAP = {
    "token不正确": "Invalid token",
    "UDID不存在": "UDID not found",
}

@dataclass
class ProviderError(RuntimeError):
    kind: str  # "business" | "transport" | "unknown"
    public_message: str
    raw_message: str = ""
    http_status: int | None = None
    req_id: str | None = None

def _redact_payload_for_log(payload: dict) -> dict:
    if not payload:
        return {}
    out = dict(payload)

    # secrets
    if out.get("token"):
        out["token"] = _mask_middle(str(out["token"]), head=3, tail=3)
    if out.get("udid"):
        out["udid"] = _mask_middle(str(out["udid"]), head=6, tail=4)

    # IMPORTANT: remark often contains coupon / tg id etc
    if out.get("beizhu"):
        out["beizhu"] = "***REDACTED***"

    return out


def _classify_requests_exc(e: Exception) -> str:
    if isinstance(e, requests.exceptions.ConnectTimeout):
        return "connect_timeout"
    if isinstance(e, requests.exceptions.ReadTimeout):
        return "read_timeout"
    if isinstance(e, requests.exceptions.SSLError):
        return "tls_error"
    if isinstance(e, requests.exceptions.ConnectionError):
        return "connection_error"
    return "request_error"

def _provider_backoff_sleep(attempt: int) -> float:
    sleep_s = min(_PROVIDER_BACKOFF_CAP, _PROVIDER_BACKOFF_BASE * (2 ** (attempt - 1)))
    sleep_s *= (0.7 + random.random() * 0.6)
    time.sleep(sleep_s)
    return sleep_s

def _extract_business_error(text: str) -> ProviderError | None:
    if not text:
        return None
    for cn, en in BUSINESS_MAP.items():
        if cn in text:
            return ProviderError(
                kind="business",
                public_message=f"API Error: {en} ({cn})",
                raw_message=_redact_text_for_log(text)[:300],
            )
    return None

def _provider_error_from_json(j: dict) -> ProviderError | None:
    if j.get("code") == 1:
        return None
    msg = str(j.get("msg") or "").strip()
    be = _extract_business_error(msg)
    if be:
        return be
    safe_msg = _redact_text_for_log(msg)[:200] if msg else "Provider API error"
    return ProviderError(kind="business", public_message=f"API Error: {safe_msg}", raw_message=safe_msg)

def _provider_post(candidates: list[str], payload: dict) -> dict:
    last_err: Optional[Exception] = None
    redacted_payload = _redact_payload_for_log(payload)
    req_id = uuid.uuid4().hex[:10]

    with requests.Session() as s:
        s.headers.update({"User-Agent": "couponbot/1.0 (+requests)"})

        for url in candidates:
            for attempt in range(1, _PROVIDER_MAX_ATTEMPTS + 1):
                t0 = time.monotonic()
                try:
                    logger.info(
                        "provider.request start req_id=%s url=%s attempt=%d/%d payload=%s",
                        req_id, url, attempt, _PROVIDER_MAX_ATTEMPTS, redacted_payload
                    )

                    r = s.post(
                        url,
                        data=payload,
                        timeout=(_PROVIDER_CONNECT_TIMEOUT, _PROVIDER_READ_TIMEOUT),
                    )

                    dt_ms = int((time.monotonic() - t0) * 1000)
                    body_text = (r.text or "")
                    ctype = (r.headers.get("Content-Type") or "")
                    safe_snip = _safe_response_snippet_for_log(body_text=body_text, content_type=ctype)

                    if r.status_code == 404:
                        logger.warning(
                            "provider.request 404 req_id=%s url=%s elapsed_ms=%d (trying next candidate)",
                            req_id, url, dt_ms
                        )
                        break

                    if r.status_code in _RETRYABLE_HTTP:
                        logger.warning(
                            "provider.request http_retryable req_id=%s status=%d url=%s elapsed_ms=%d body=%r",
                            req_id, r.status_code, url, dt_ms, safe_snip
                        )
                        raise ProviderError(
                            kind="transport",
                            public_message="Provider unstable right now. Please retry later.",
                            raw_message=safe_snip,
                            http_status=r.status_code,
                            req_id=req_id,
                        )

                    if not (200 <= r.status_code < 300):
                        be = _extract_business_error(body_text)
                        if be:
                            be.req_id = req_id
                            be.http_status = r.status_code
                            logger.warning(
                                "provider.request business_error_text req_id=%s status=%d url=%s elapsed_ms=%d msg=%r",
                                req_id, r.status_code, url, dt_ms, be.raw_message[:200]
                            )
                            raise be

                        logger.error(
                            "provider.request http_error req_id=%s status=%d url=%s elapsed_ms=%d ctype=%r body=%r",
                            req_id, r.status_code, url, dt_ms, ctype, safe_snip
                        )
                        raise ProviderError(
                            kind="unknown",
                            public_message="Unexpected provider error. Please retry later.",
                            raw_message=safe_snip,
                            http_status=r.status_code,
                            req_id=req_id,
                        )

                    try:
                        j = r.json()
                    except Exception:
                        be = _extract_business_error(body_text)
                        if be:
                            be.req_id = req_id
                            logger.warning(
                                "provider.request business_error_non_json req_id=%s url=%s elapsed_ms=%d msg=%r",
                                req_id, url, dt_ms, be.raw_message[:200]
                            )
                            raise be

                        logger.error(
                            "provider.request non_json req_id=%s url=%s elapsed_ms=%d content_type=%r body=%r",
                            req_id, url, dt_ms, ctype, safe_snip
                        )
                        raise ProviderError(
                            kind="transport",
                            public_message="Provider unstable right now. Please retry later.",
                            raw_message=safe_snip,
                            http_status=r.status_code,
                            req_id=req_id,
                        )

                    pe = _provider_error_from_json(j)
                    if pe:
                        pe.req_id = req_id
                        logger.warning(
                            "provider.request business_error_json req_id=%s url=%s elapsed_ms=%d msg=%r",
                            req_id, url, dt_ms, _redact_text_for_log(pe.raw_message)[:200]
                        )
                        raise pe

                    logger.info(
                        "provider.request success req_id=%s url=%s elapsed_ms=%d",
                        req_id, url, dt_ms
                    )
                    return j

                except ProviderError as e:
                    last_err = e
                    if e.kind == "business":
                        raise e

                    if attempt >= _PROVIDER_MAX_ATTEMPTS:
                        logger.error(
                            "provider.request failed final req_id=%s url=%s attempt=%d/%d kind=%s status=%r",
                            req_id, url, attempt, _PROVIDER_MAX_ATTEMPTS, e.kind, e.http_status
                        )
                        break

                    sleep_s = _provider_backoff_sleep(attempt)
                    logger.warning(
                        "provider.request retrying req_id=%s kind=%s url=%s attempt=%d sleep_s=%.2f status=%r",
                        req_id, e.kind, url, attempt, sleep_s, e.http_status
                    )

                except requests.exceptions.ReadTimeout as e:
                    last_err = e
                    kind = "read_timeout"

                    if attempt >= min(_PROVIDER_MAX_ATTEMPTS, 2):
                        logger.error(
                            "provider.request failed transport_final req_id=%s kind=%s url=%s attempt=%d/%d",
                            req_id, kind, url, attempt, _PROVIDER_MAX_ATTEMPTS
                        )
                        break

                    sleep_s = _provider_backoff_sleep(attempt)
                    logger.warning(
                        "provider.request retrying_transport req_id=%s kind=%s url=%s attempt=%d sleep_s=%.2f",
                        req_id, kind, url, attempt, sleep_s
                    )

                except (
                    requests.exceptions.ConnectTimeout,
                    requests.exceptions.SSLError,
                    requests.exceptions.ConnectionError,
                ) as e:
                    last_err = e
                    kind = _classify_requests_exc(e)

                    if attempt >= _PROVIDER_MAX_ATTEMPTS:
                        logger.error(
                            "provider.request failed transport_final req_id=%s kind=%s url=%s attempt=%d/%d",
                            req_id, kind, url, attempt, _PROVIDER_MAX_ATTEMPTS
                        )
                        break

                    sleep_s = _provider_backoff_sleep(attempt)
                    logger.warning(
                        "provider.request retrying_transport req_id=%s kind=%s url=%s attempt=%d sleep_s=%.2f",
                        req_id, kind, url, attempt, sleep_s
                    )

                except Exception as e:
                    last_err = e
                    logger.error(
                        "provider.request failed non_retryable req_id=%s url=%s attempt=%d/%d err_type=%s",
                        req_id, url, attempt, _PROVIDER_MAX_ATTEMPTS, type(e).__name__
                    )
                    break

    # IMPORTANT: do NOT log repr(last_err) because it may contain raw response
    logger.error(
        "provider.request all_candidates_failed req_id=%s last_err_type=%s",
        req_id, type(last_err).__name__ if last_err else None
    )
    raise ProviderError(
        kind="transport",
        public_message="Provider unstable right now. Please retry later.",
        raw_message="all_candidates_failed",
        req_id=req_id,
    )

def _b64decode_strict(b64s: str) -> bytes:
    if not b64s:
        return b""
    b64s = b64s.strip()
    try:
        return base64.b64decode(b64s, validate=True)
    except (binascii.Error, ValueError) as e:
        raise RuntimeError(f"Invalid base64 data: {e}")

def _provider_getcertificate_by_udid(udid: str) -> dict:
    candidates = [
        f"{CERT_API_BASE}/api/Getcertificate",
        f"{CERT_API_BASE}/api/getcertificate",
        f"{CERT_API_BASE}/api/GetCertificate",
        f"{CERT_API_BASE}/api/getCertificate",
    ]

    j = _provider_post(candidates, {"token": CERT_API_TOKEN, "udid": udid})
    data = j.get("data", {}) or {}

    pname = data.get("pname")
    addtime = data.get("addtime")
    state = data.get("state", True)
    warranty_time = data.get("warranty_time")

    p12_b64 = (data.get("p12") or "").strip()
    mp_b64 = (data.get("mobileprovision") or "").strip()

    has_p12 = bool(p12_b64)
    has_mp = bool(mp_b64)

    if not state:
        status = "REVOKED"
    elif has_p12 and has_mp:
        status = "READY"
    else:
        status = "PENDING"

    result = {
        "status": status,
        "pname": pname,
        "addtime": addtime,
        "state": state,
        "warranty_time": warranty_time,
        "id": data.get("id"),
        "pool": data.get("pool"),
        "type": data.get("type"),
        "warranty": data.get("warranty"),
        "shtype": data.get("shtype"),
        "has_p12": has_p12,
        "has_mobileprovision": has_mp,
    }

    if status == "READY":
        result["p12_bytes"] = _b64decode_strict(p12_b64)
        result["mp_bytes"] = _b64decode_strict(mp_b64)

        if not result["p12_bytes"] or not result["mp_bytes"]:
            raise RuntimeError("Provider returned empty certificate files")

    return result

def _provider_adddevice_standard(udid: str, requestdevice: str, beizhu: str = "") -> dict:
    if requestdevice not in ("iphone", "ipad"):
        raise ValueError("requestdevice must be 'iphone' or 'ipad'")

    candidates = [
        f"{CERT_API_BASE}/api/adddevice",
        f"{CERT_API_BASE}/api/Adddevice",
        f"{CERT_API_BASE}/api/addDevice",
        f"{CERT_API_BASE}/api/AddDevice",
    ]

    payload = {
        "token": CERT_API_TOKEN,
        "udid": udid,
        "warranty": "1",
        "type": "2",
        "devicetype": requestdevice,
    }
    if beizhu:
        payload["beizhu"] = beizhu

    return _provider_post(candidates, payload)


# =============================================================================
# PUBLIC FUNCTIONS YOU CALL FROM handlers.py
# =============================================================================
async def ui_send_cert_files(update, context, udid: str) -> None:
    try:
        cert = await asyncio.to_thread(_provider_getcertificate_by_udid, udid)
        if cert.get("status") != "READY":
            await update.effective_message.reply_text("⏳ Certificate is not ready yet. Try again later.")
            return

        p12_bytes = cert.get("p12_bytes", b"")
        mp_bytes = cert.get("mp_bytes", b"")
        if not p12_bytes or not mp_bytes:
            await update.effective_message.reply_text("❌ Provider returned empty certificate files.")
            return

        await update.effective_message.reply_document(
            document=bytesio_file(p12_bytes, f"{udid}.p12"),
            caption=f"{udid}.p12",
        )
        await update.effective_message.reply_document(
            document=bytesio_file(mp_bytes, f"{udid}.mobileprovision"),
            caption=f"{udid}.mobileprovision\nPassword: {CERT_PASSWORD}",
        )
    except ProviderError as e:
        logger.exception("ui_send_cert_files provider error kind=%s req_id=%s", e.kind, e.req_id)
        await update.effective_message.reply_text(f"❌ {e.public_message}")
    except Exception:
        logger.exception("ui_send_cert_files error")
        await update.effective_message.reply_text("❌ Failed to retrieve files. Try again later.")

async def ui_sign_app_from_udid(update, query, udid: str, variant: str) -> None:
    if variant == "esgn":
        variant = "esign"

    await safe_edit(query, f"⏳ Signing <b>{hesc(variant)}</b> ...", parse_mode="HTML")
    try:
        cert = await asyncio.to_thread(_provider_getcertificate_by_udid, udid)
        if cert.get("status") != "READY":
            await safe_edit(query, "⏳ Certificate is not ready yet. Try again later.", parse_mode="HTML")
            return

        p12_bytes = cert.get("p12_bytes", b"")
        mp_bytes = cert.get("mp_bytes", b"")
        if not p12_bytes or not mp_bytes:
            await safe_edit(query, "❌ Provider returned empty cert files.", parse_mode="HTML")
            return

        install_url, ipa_url = await sign_and_publish_from_cert_bytes(
            udid=udid,
            variant=variant,
            p12_bytes=p12_bytes,
            mp_bytes=mp_bytes,
        )

        text = build_signed_app_card(udid=udid, variant=variant, install_url=install_url, ipa_url=ipa_url)
        kb = signed_app_keyboard(install_url=install_url, ipa_url=ipa_url)
        await safe_edit(query, text, reply_markup=kb, parse_mode="HTML")

    except ProviderError as e:
        logger.exception("ui_sign_app_from_udid provider error kind=%s req_id=%s", e.kind, e.req_id)
        await safe_edit(query, f"❌ {hesc(e.public_message)}", parse_mode="HTML")
    except Exception:
        logger.exception("ui_sign_app_from_udid error")
        await safe_edit(query, "❌ Sign failed. Try again later.", parse_mode="HTML")

def build_cert_status_card(udid: str, r: dict) -> str:
    status = r.get("status", "UNKNOWN")
    state = r.get("state", True)

    if status == "READY" and state:
        status_line = "Status: <b>Active</b> 🟢"
    elif status == "PENDING" and state:
        status_line = "Status: <b>Pending</b> ⏳"
    elif not state or status == "REVOKED":
        status_line = "Status: <b>Revoked</b> 🔴"
    else:
        status_line = f"Status: <b>{hesc(str(status))}</b> ⚠️"

    name = r.get("pname") or "N/A"
    added_on = fmt_dt(r.get("addtime"))
    warranty_left = fmt_warranty_left(r.get("warranty_time"))

    return "\n".join([
        "📄 <b>Certificate Status</b>",
        "",
        status_line,
        f"Name: <b>{hesc(str(name))}</b>",
        f"UDID: <code>{hesc(udid)}</code>",
        f"Added on: {hesc(str(added_on))}",
        f"Warranty: {hesc(str(warranty_left))}",
    ])

async def cleanup_signed_job(context) -> None:
    deleted = cleanup_expired_signed_files(ttl_seconds=SIGNED_TTL_SECONDS)
    if deleted:
        logger.info("cleanup_signed_job: deleted %d expired signed installs", deleted)

async def safe_reply(update, text: str, parse_mode: str = "HTML"):
    msg = update.effective_message
    if msg:
        return await msg.reply_text(text, parse_mode=parse_mode, disable_web_page_preview=True)
    chat = update.effective_chat
    if chat:
        return await update.get_bot().send_message(
            chat_id=chat.id,
            text=text,
            parse_mode=parse_mode,
            disable_web_page_preview=True,
        )
    return None
