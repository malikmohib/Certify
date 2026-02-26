# bot/handlers.py
from __future__ import annotations

import asyncio
import os
import time
from html import escape as hesc
from typing import Dict, Any, Optional
from urllib.parse import quote, urlparse

from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    InputMediaDocument,
    WebAppInfo,
)
from telegram.ext import ContextTypes

from bot.config import COUPON_RE, UDID_RE, logger
from bot.services import fmt_dt, fmt_warranty_left

from bot.services import (
    ProviderError,  # ✅ NEW: proper provider error mapping
    admin_guard,
    build_cert_card,
    cert_action_keyboard,
    gen_vinh_coupon,
    is_admin,
    rate_limit,
    safe_edit,
    signing_app_keyboard,
    sign_and_publish_from_cert_bytes,
    _provider_adddevice_standard,
    _provider_getcertificate_by_udid,
    bytesio_file,
)

# ✅ keep your DB module import exactly as-is
from db.coupons import (
    db_get_coupon,
    db_reserve_coupon,
    db_set_reserved_udid,
    db_log_coupon_failure,
    db_mark_coupon_used,
    db_admin_unreserve_coupon,
    db_create_many_coupons,
)

# =============================================================================
# UI BUTTONS (INLINE KEYBOARD)
# =============================================================================
CB_CREATE_CERT = "menu:create_cert"
CB_RETRIEVE_CERT = "menu:retrieve_cert"
CB_CERT_STATUS = "menu:cert_status"
CB_CREATE_COUPON = "menu:create_coupon"
CB_CHECK_STATUS = "menu:check_status"
CB_UNRESERVE = "menu:unreserve"
CB_BACK = "menu:back"
CB_CANCEL = "menu:cancel"

# =============================================================================
# PRODUCTION HARDENING
# =============================================================================
PROVIDER_TIMEOUT_SECONDS = 60
STATE_TTL_SECONDS = 30 * 60  # 30 minutes
ADMIN_ONLY_MODES = {"await_qty", "await_status_code", "await_unreserve_code"}


async def run_provider(callable_, *args, timeout: int = PROVIDER_TIMEOUT_SECONDS):
    """Run a blocking provider call in a thread with a hard timeout."""
    return await asyncio.wait_for(asyncio.to_thread(callable_, *args), timeout=timeout)


# =============================================================================
# SIGNED UI (CARD + KEYBOARD)
# =============================================================================
def build_signed_card_ui(*, udid: str, variant: str, miniapp_url: str, ipa_url: str) -> str:
    title = variant.upper()
    return "\n".join(
        [
            "✅ <b>The application has been signed</b> and is now ready for installation.",
            f"UDID: <code>{hesc(udid)}</code>",
            f"App: <b>{hesc(title)}</b>",
            "",
            "📲 Tap <b>Install</b> below. iOS will open Safari and start installation.",
            "",
            f"Mini App: <code>{hesc(miniapp_url)}</code>",
        ]
    )


def _extract_install_id_from_install_url(install_url: str) -> Optional[str]:
    """
    install_url is like: https://install.certify.icu/install/<install_id>
    Returns <install_id> or None.
    """
    try:
        p = urlparse(install_url)
        path = (p.path or "").strip("/")
        parts = path.split("/")
        if len(parts) >= 2 and parts[-2] == "install":
            return parts[-1]
        # fallback: find segment after 'install'
        if "install" in parts:
            i = parts.index("install")
            if i + 1 < len(parts):
                return parts[i + 1]
    except Exception:
        return None
    return None


INSTRUCTIONS_URL = "https://t.me/CertifyInstruction"

def signed_buttons(*, variant: str, install_url: str, ipa_url: str, udid: str) -> InlineKeyboardMarkup:
    install_id = _extract_install_id_from_install_url(install_url)

    # Forward-safe Mini App deep link
    if install_id:
        mini_run = f"https://t.me/Certifyicu_bot?startapp={quote(install_id)}&mode=compact"
    else:
        mini_run = "https://t.me/Certifyicu_bot"

    # Nice title
    title_map = {"gbox": "GBox", "esign": "ESign", "scarlet": "Scarlet"}
    app_title = title_map.get(variant, variant)

    share_text = f"UDID: {udid}\nApp: {app_title}\nInstall: {mini_run}\nSafari: {install_url}\nIPA: {ipa_url}"
    share_url = f"https://t.me/share/url?url={quote(share_text)}"

    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(f"📲 Install {app_title}", url=mini_run)],
            [InlineKeyboardButton("🌐 Safari Install", url=install_url)],
            [InlineKeyboardButton("⬇️ IPA", url=ipa_url)],
            [InlineKeyboardButton("Instructions 💡", url=INSTRUCTIONS_URL)],
            [InlineKeyboardButton("🔗 Share", url=share_url)],
        ]
    )




# =============================================================================
# MENUS
# =============================================================================
def main_menu_keyboard(admin: bool) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []

    rows.append(
        [
            InlineKeyboardButton("✅ Create Cert", callback_data=CB_CREATE_CERT),
            InlineKeyboardButton("📥 Retrieve", callback_data=CB_RETRIEVE_CERT),
        ]
    )

    rows.append(
        [
            InlineKeyboardButton("📌 Status", callback_data=CB_CERT_STATUS),
            InlineKeyboardButton("❌ Cancel", callback_data=CB_CANCEL),
        ]
    )

    if admin:
        rows.append(
            [
                InlineKeyboardButton("🎟️ Create", callback_data=CB_CREATE_COUPON),
                InlineKeyboardButton("🔎 Coupon", callback_data=CB_CHECK_STATUS),
            ]
        )
        rows.append(
            [
                InlineKeyboardButton("🔓 Unreserve", callback_data=CB_UNRESERVE),
                InlineKeyboardButton("🔙 Back", callback_data=CB_BACK),
            ]
        )

    return InlineKeyboardMarkup(rows)


def back_cancel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("🔙 Back to Menu", callback_data=CB_BACK)],
            [InlineKeyboardButton("❌ Cancel", callback_data=CB_CANCEL)],
        ]
    )


# =============================================================================
# SIMPLE STATE MACHINE (per user)
# =============================================================================
USER_STATE: Dict[int, Dict[str, Any]] = {}


def _state_cleanup_now() -> None:
    now = time.time()
    dead = []
    for uid, st in USER_STATE.items():
        ts = st.get("ts", now)
        if (now - ts) > STATE_TTL_SECONDS:
            dead.append(uid)
    for uid in dead:
        USER_STATE.pop(uid, None)


def set_state(user_id: int, mode: Optional[str]):
    if mode is None:
        USER_STATE.pop(user_id, None)
    else:
        USER_STATE[user_id] = {"mode": mode, "ts": time.time()}


def get_state(user_id: int) -> Optional[str]:
    d = USER_STATE.get(user_id)
    return d.get("mode") if d else None


def clear_create_flow(context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop("create_coupon", None)
    context.user_data.pop("create_coupon_category", None)
    context.user_data.pop("create_udid", None)


def _pool(context: ContextTypes.DEFAULT_TYPE):
    # pool set in entrypoint => app.bot_data["pool"]
    try:
        return context.application.bot_data["pool"]
    except Exception as e:
        raise RuntimeError("DB pool not initialized") from e


# =============================================================================
# HANDLERS
# =============================================================================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    admin = is_admin(update)

    # Support Telegram deep-links:
    # https://t.me/Certifyicu_bot?start=inst_<install_id>
    arg = ""
    if update.message and update.message.text:
        parts = update.message.text.split(maxsplit=1)
        if len(parts) == 2:
            arg = parts[1].strip()

    if arg.startswith("inst_"):
        install_id = arg[len("inst_"):].strip()

        # Basic validation (avoid garbage)
        if not install_id or len(install_id) < 6 or len(install_id) > 128:
            await update.message.reply_text("❌ Invalid install id.")
            return

        base = (os.environ.get("BASE_URL") or os.environ.get("PUBLIC_BASE_URL") or "https://install-hk.certify.icu").strip().rstrip("/")
        miniapp_url = f"{base}/miniapp/?id={quote(install_id)}&v=2"
        safari_url = f"{base}/install/{quote(install_id)}"

        kb = InlineKeyboardMarkup(
            [
                [InlineKeyboardButton("📲 Install", web_app=WebAppInfo(url=miniapp_url))],
                [InlineKeyboardButton("🌐 Safari Install Page", url=safari_url)],
            ]
        )

        await update.message.reply_text(
            "✅ Ready to install.\nTap the button below:",
            reply_markup=kb,
            disable_web_page_preview=True,
        )
        return

    await update.message.reply_text("Hi 👋\nChoose an option:", reply_markup=main_menu_keyboard(admin))



async def on_menu_click(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    admin = is_admin(update)
    user_id = update.effective_user.id

    if query.data in (CB_BACK, CB_CANCEL):
        set_state(user_id, None)
        clear_create_flow(context)
        text = "Menu:" if query.data == CB_BACK else "Canceled ✅\nMenu:"
        await safe_edit(query, text, reply_markup=main_menu_keyboard(admin), parse_mode=None)
        return

    if query.data == CB_CREATE_CERT:
        set_state(user_id, "await_create_coupon")
        clear_create_flow(context)
        await safe_edit(query, "Send coupon code:", reply_markup=back_cancel_keyboard(), parse_mode=None)
        return

    if query.data == CB_RETRIEVE_CERT:
        set_state(user_id, "await_retrieve_udid")
        await safe_edit(query, "Send UDID:", reply_markup=back_cancel_keyboard(), parse_mode=None)
        return

    if query.data == CB_CERT_STATUS:
        set_state(user_id, "await_cert_status_udid")
        await safe_edit(query, "Send UDID to check status:", reply_markup=back_cancel_keyboard(), parse_mode=None)
        return

    # admin menu entries
    if query.data in (CB_CREATE_COUPON, CB_CHECK_STATUS, CB_UNRESERVE):
        err = admin_guard(update)
        if err:
            await safe_edit(query, err, reply_markup=main_menu_keyboard(admin), parse_mode=None)
            return

    if query.data == CB_CREATE_COUPON:
        set_state(user_id, "await_qty")
        await safe_edit(query, "Send: iphone 10  OR  ipad 10 (qty 1–100)", reply_markup=back_cancel_keyboard(), parse_mode=None)
        return

    if query.data == CB_CHECK_STATUS:
        set_state(user_id, "await_status_code")
        await safe_edit(query, "Send coupon code to CHECK STATUS:", reply_markup=back_cancel_keyboard(), parse_mode=None)
        return

    if query.data == CB_UNRESERVE:
        set_state(user_id, "await_unreserve_code")
        await safe_edit(query, "Send coupon code to UNRESERVE (unlock):", reply_markup=back_cancel_keyboard(), parse_mode=None)
        return


async def on_cert_action(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if query.data != "cert:get":
        return

    udid = context.user_data.get("last_udid")
    if not udid:
        await safe_edit(query, "No UDID found. Please send UDID again.", reply_markup=back_cancel_keyboard(), parse_mode=None)
        return

    await safe_edit(query, "⏳ Getting certificate…", parse_mode=None)

    try:
        result = await run_provider(_provider_getcertificate_by_udid, udid)
    except ProviderError as e:
        await safe_edit(query, f"❌ {e.public_message}", parse_mode=None)
        return
    except TimeoutError:
        await safe_edit(query, "❌ Provider timeout. Try again.", parse_mode=None)
        return
    except Exception as e:
        logger.error("Provider getcertificate error: %s", str(e))
        await safe_edit(query, "❌ Failed to fetch certificate. Try again.", parse_mode=None)
        return

    share_text = f"UDID: {udid}\nStatus: {result.get('status')}"
    await safe_edit(
        query,
        build_cert_card(udid, result),
        reply_markup=cert_action_keyboard(share_text),
        parse_mode="HTML",
    )

    if result.get("status") != "READY":
        return

    # Send cert files
    p12_name = f"{udid}.p12"
    mp_name = f"{udid}.mobileprovision"
    media = [
        InputMediaDocument(media=bytesio_file(result["p12_bytes"], p12_name)),
        InputMediaDocument(media=bytesio_file(result["mp_bytes"], mp_name)),
    ]
    await query.message.reply_media_group(media=media)

    # store for signing flow
    context.user_data["sign_udid"] = udid
    context.user_data["sign_p12_bytes"] = result["p12_bytes"]
    context.user_data["sign_mp_bytes"] = result["mp_bytes"]

    await query.message.reply_text(
        "✅ Certificate retrieved.\n\nNow choose which app you want to sign:",
        reply_markup=signing_app_keyboard(),
    )


async def on_sign_app_click(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    data = query.data or ""

    # Back from signed UI -> show cert card again
    if data == "signed:back":
        udid = context.user_data.get("sign_udid") or context.user_data.get("last_udid")
        if not udid:
            await safe_edit(
                query,
                "No UDID found. Please retrieve certificate again.",
                reply_markup=back_cancel_keyboard(),
            )
            return

        await safe_edit(query, "⏳ Getting certificate…", parse_mode=None)

        try:
            result = await run_provider(_provider_getcertificate_by_udid, udid)
        except ProviderError as e:
            await safe_edit(query, f"❌ {e.public_message}", parse_mode=None)
            return
        except TimeoutError:
            await safe_edit(query, "❌ Provider timeout. Try again.", parse_mode=None)
            return
        except Exception as e:
            logger.error("Provider getcertificate error: %s", str(e))
            await safe_edit(query, "❌ Failed to fetch certificate. Try again.", parse_mode=None)
            return

        share_text = f"UDID: {udid}\nStatus: {result.get('status')}"
        kb = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton("Get Certificate", callback_data="cert:get"),
                    InlineKeyboardButton("Share", url=f"https://t.me/share/url?url={quote(share_text)}"),
                ],
                [
                    InlineKeyboardButton("ESign", callback_data="signapp:esign"),
                    InlineKeyboardButton("GBox", callback_data="signapp:gbox"),
                    InlineKeyboardButton("Scarlet", callback_data="signapp:scarlet"),
                ],
            ]
        )

        await safe_edit(query, build_cert_card(udid, result), reply_markup=kb, parse_mode="HTML")
        return

    # Normal sign click
    if not data.startswith("signapp:"):
        return

    variant = data.split(":", 1)[1].strip()
    if variant == "esgn":
        variant = "esign"

    udid = context.user_data.get("sign_udid")
    p12_bytes = context.user_data.get("sign_p12_bytes")
    mp_bytes = context.user_data.get("sign_mp_bytes")

    if not udid or not p12_bytes or not mp_bytes:
        await safe_edit(
            query,
            "❌ Signing session expired.\nPlease click 'Get Certificate' again.",
            parse_mode=None,
        )
        return

    await safe_edit(query, f"⏳ Signing <b>{hesc(variant)}</b>… please wait.", parse_mode="HTML")

    try:
        install_url, ipa_url = await sign_and_publish_from_cert_bytes(
            udid=udid,
            variant=variant,
            p12_bytes=p12_bytes,
            mp_bytes=mp_bytes,
        )
    except Exception as e:
        logger.error("Signing failed: %s", str(e))
        await safe_edit(query, "❌ Signing failed. Try again.", parse_mode=None)
        return

    install_id = _extract_install_id_from_install_url(install_url)

    base = (
        os.environ.get("BASE_URL")
        or os.environ.get("PUBLIC_BASE_URL")
        or "https://install-hk.certify.icu"
    ).strip().rstrip("/")

    if install_id:
        miniapp_url = f"{base}/miniapp/?id={quote(install_id)}&v=2"
    else:
        miniapp_url = f"{base}/miniapp/?v=2"

    text = build_signed_card_ui(
        udid=udid,
        variant=variant,
        miniapp_url=miniapp_url,
        ipa_url=ipa_url,
    )

    kb = signed_buttons(
        variant=variant,
        install_url=install_url,
        ipa_url=ipa_url,
        udid=udid,
    )

    await safe_edit(query, text, reply_markup=kb, parse_mode="HTML")



async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return

    user_id = update.effective_user.id
    msg = (update.message.text or "").strip()
    if not msg:
        return

    if not rate_limit(user_id):
        await update.message.reply_text("Too many requests. Please slow down.")
        return

    _state_cleanup_now()
    mode = get_state(user_id)

    # Defense-in-depth: admin modes must always be admin
    if mode in ADMIN_ONLY_MODES and not is_admin(update):
        set_state(user_id, None)
        clear_create_flow(context)
        await update.message.reply_text("❌ Admin only.", reply_markup=main_menu_keyboard(False))
        return

    # Get pool once (avoid KeyError crashes)
    try:
        pool = _pool(context)
    except Exception:
        set_state(user_id, None)
        clear_create_flow(context)
        await update.message.reply_text("⚠️ Server misconfigured. Contact admin.")
        return

    # ======================================
    # ADMIN: CREATE COUPONS
    # format: iphone 10  OR  ipad 10
    # ======================================
    if mode == "await_qty":
        parts = msg.lower().split()
        if len(parts) != 2 or parts[0] not in ("iphone", "ipad") or not parts[1].isdigit():
            await update.message.reply_text(
                "❌ Format: iphone 10  OR  ipad 10 (qty 1–100). Try again:",
                reply_markup=back_cancel_keyboard(),
            )
            return

        category = parts[0]
        qty = int(parts[1])
        if qty < 1 or qty > 100:
            await update.message.reply_text(
                "❌ Quantity must be between 1 and 100. Try again:",
                reply_markup=back_cancel_keyboard(),
            )
            return

        await update.message.reply_text("⏳ Creating coupons…")

        try:
            codes = set()
            while len(codes) < qty:
                codes.add(gen_vinh_coupon())
            created = db_create_many_coupons(pool, list(codes), category=category)
        except Exception as e:
            logger.error("Create coupon error: %s", str(e))
            set_state(user_id, None)
            await update.message.reply_text(
                "❌ Failed to create coupons.",
                reply_markup=main_menu_keyboard(is_admin(update)),
            )
            return

        set_state(user_id, None)

        if not created:
            await update.message.reply_text(
                "⚠️ No new coupons were created (duplicates skipped).",
                reply_markup=main_menu_keyboard(is_admin(update)),
            )
            return

        text = (
            f"✅ <b>{len(created)}</b> coupon(s) created for <b>{hesc(category)}</b>:\n\n"
            + "\n".join(f"<code>{c}</code>" for c in created)
        )
        await update.message.reply_text(
            text,
            parse_mode="HTML",
            disable_web_page_preview=True,
        )

        await update.message.reply_text(
            "Menu:",
            reply_markup=main_menu_keyboard(is_admin(update)),
        )
        return

    # ======================================
    # ADMIN: CHECK COUPON STATUS
    # ======================================
    if mode == "await_status_code":
        code = msg.strip()
        if not COUPON_RE.fullmatch(code):
            await update.message.reply_text("Invalid coupon format. Send coupon code again:", reply_markup=back_cancel_keyboard())
            return

        try:
            row = db_get_coupon(pool, code)
        except Exception as e:
            logger.error("DB get coupon error: %s", str(e))
            set_state(user_id, None)
            await update.message.reply_text("Server error.", reply_markup=main_menu_keyboard(is_admin(update)))
            return

        set_state(user_id, None)

        if not row:
            await update.message.reply_text("❌ NOT FOUND", reply_markup=main_menu_keyboard(is_admin(update)))
            return

        lines = [
            f"🎟️ <b>{hesc(row['coupon_code'])}</b>",
            f"Category: <b>{hesc(row['category'])}</b>",
            f"Status: <b>{hesc(row['status'])}</b>",
            "",
            f"Reserved by: <code>{hesc(str(row.get('reserved_by_telegram_id') or 'N/A'))}</code>",
            f"Reserved UDID: <code>{hesc(str(row.get('reserved_udid') or 'N/A'))}</code>",
            f"Reserved at: {hesc(str(row.get('reserved_at') or 'N/A'))}",
            "",
            f"Last failure step: <code>{hesc(str(row.get('last_failure_step') or 'N/A'))}</code>",
            f"Last failure reason: {hesc(str(row.get('last_failure_reason') or 'N/A'))}",
            f"Last failed at: {hesc(str(row.get('last_failed_at') or 'N/A'))}",
            "",
            f"Used by: <code>{hesc(str(row.get('used_by_telegram_id') or 'N/A'))}</code>",
            f"Used UDID: <code>{hesc(str(row.get('used_udid') or 'N/A'))}</code>",
            f"Used at: {hesc(str(row.get('used_at') or 'N/A'))}",
        ]
        await update.message.reply_text("\n".join(lines), parse_mode="HTML", reply_markup=main_menu_keyboard(is_admin(update)))
        return

    # ======================================
    # ADMIN: UNRESERVE
    # ======================================
    if mode == "await_unreserve_code":
        code = msg.strip()
        if not COUPON_RE.fullmatch(code):
            await update.message.reply_text("Invalid coupon format. Send coupon again:", reply_markup=back_cancel_keyboard())
            return

        try:
            res = db_admin_unreserve_coupon(pool, code)
        except Exception as e:
            logger.error("DB unreserve error: %s", str(e))
            set_state(user_id, None)
            await update.message.reply_text("Server error.", reply_markup=main_menu_keyboard(is_admin(update)))
            return

        set_state(user_id, None)

        if res == "UNRESERVED":
            await update.message.reply_text("✅ Coupon UNRESERVED (unlocked).", reply_markup=main_menu_keyboard(is_admin(update)))
        elif res == "NOT_FOUND":
            await update.message.reply_text("❌ Coupon NOT FOUND.", reply_markup=main_menu_keyboard(is_admin(update)))
        else:
            await update.message.reply_text("⚠️ Coupon is not RESERVED.", reply_markup=main_menu_keyboard(is_admin(update)))
        return

    # ======================================
    # CREATE CERT FLOW
    # ======================================
    if mode == "await_create_coupon":
        code = msg.strip()
        if not COUPON_RE.fullmatch(code):
            await update.message.reply_text("Invalid coupon format. Send coupon again:", reply_markup=back_cancel_keyboard())
            return

        try:
            res, category = db_reserve_coupon(pool, code, telegram_id=user_id)
        except Exception as e:
            logger.error("DB reserve coupon error: %s", str(e))
            set_state(user_id, None)
            clear_create_flow(context)
            await update.message.reply_text("Server error. Try again.", reply_markup=main_menu_keyboard(is_admin(update)))
            return

        if res == "NOT_FOUND":
            await update.message.reply_text("❌ Coupon NOT FOUND. Send coupon again:", reply_markup=back_cancel_keyboard())
            return
        if res == "ALREADY_USED":
            await update.message.reply_text("⚠️ Coupon already USED. Send another coupon:", reply_markup=back_cancel_keyboard())
            return
        if res == "ALREADY_RESERVED":
            await update.message.reply_text("⚠️ Coupon is RESERVED (locked). Contact admin if needed.", reply_markup=back_cancel_keyboard())
            return

        context.user_data["create_coupon"] = code
        context.user_data["create_coupon_category"] = category
        set_state(user_id, "await_create_udid")

        await update.message.reply_text("✅ Coupon RESERVED.\nNow send UDID:", reply_markup=back_cancel_keyboard())
        return

    if mode == "await_create_udid":
        udid = msg.strip()
        code = context.user_data.get("create_coupon")

        if not code:
            set_state(user_id, None)
            clear_create_flow(context)
            await update.message.reply_text("No coupon found. Start again from Create Cert.", reply_markup=main_menu_keyboard(is_admin(update)))
            return

        if not UDID_RE.fullmatch(udid):
            await update.message.reply_text(
                "Invalid UDID. Use letters/numbers and: - _ . : (min 5 chars)\nSend UDID again:",
                reply_markup=back_cancel_keyboard(),
            )
            return

        try:
            r = db_set_reserved_udid(pool, code, telegram_id=user_id, udid=udid)
            if r != "OK":
                set_state(user_id, None)
                clear_create_flow(context)
                await update.message.reply_text("⚠️ Reservation not valid anymore. Start again.", reply_markup=main_menu_keyboard(is_admin(update)))
                return
        except Exception as e:
            logger.error("DB set reserved udid error: %s", str(e))
            set_state(user_id, None)
            clear_create_flow(context)
            await update.message.reply_text("Server error. Try again.", reply_markup=main_menu_keyboard(is_admin(update)))
            return

        await update.message.reply_text("⏳ Creating certificate…")

        try:
            remark = f"tg:{user_id} coupon:{code}"
            await run_provider(_provider_adddevice_standard, udid, "iphone", remark)
        except ProviderError as e:
            logger.error("Create cert provider error kind=%s msg=%s", e.kind, e.public_message)
            try:
                db_log_coupon_failure(pool, code, telegram_id=user_id, reason=e.public_message, step="adddevice_standard")
            except Exception as db_e:
                logger.error("Failed to log coupon failure: %s", str(db_e))

            set_state(user_id, None)
            clear_create_flow(context)
            await update.message.reply_text(
                f"❌ {e.public_message}\n\n⚠️ Coupon stays RESERVED (locked). Admin can unreserve if needed.",
                reply_markup=main_menu_keyboard(is_admin(update)),
            )
            return
        except TimeoutError:
            logger.error("Create cert timeout")
            try:
                db_log_coupon_failure(pool, code, telegram_id=user_id, reason="provider timeout", step="adddevice_standard")
            except Exception as db_e:
                logger.error("Failed to log coupon failure: %s", str(db_e))

            set_state(user_id, None)
            clear_create_flow(context)
            await update.message.reply_text(
                "❌ Provider timeout. Try again.\n\n⚠️ Coupon stays RESERVED (locked). Admin can unreserve if needed.",
                reply_markup=main_menu_keyboard(is_admin(update)),
            )
            return
        except Exception as e:
            logger.error("Create cert error: %s", str(e))
            try:
                db_log_coupon_failure(pool, code, telegram_id=user_id, reason=str(e), step="adddevice_standard")
            except Exception as db_e:
                logger.error("Failed to log coupon failure: %s", str(db_e))

            set_state(user_id, None)
            clear_create_flow(context)
            await update.message.reply_text(
                "❌ Create failed.\n\n⚠️ Coupon stays RESERVED (locked). Admin can unreserve if needed.",
                reply_markup=main_menu_keyboard(is_admin(update)),
            )
            return

        # mark used only after provider success
        try:
            used_res = db_mark_coupon_used(pool, code, telegram_id=user_id, udid=udid)
        except Exception as e:
            logger.error("Coupon finalize DB error: %s", str(e))
            set_state(user_id, None)
            clear_create_flow(context)
            await update.message.reply_text(
                "⚠️ Certificate created, but coupon finalize failed. Contact admin.",
                reply_markup=main_menu_keyboard(is_admin(update)),
            )
            return

        if used_res != "USED":
            set_state(user_id, None)
            clear_create_flow(context)
            await update.message.reply_text(
                f"⚠️ Certificate created, but coupon could not be finalized (status={hesc(used_res)}). Contact admin.",
                reply_markup=main_menu_keyboard(is_admin(update)),
                parse_mode="HTML",
            )
            return

        # fetch + show card
        try:
            result = await run_provider(_provider_getcertificate_by_udid, udid)
        except ProviderError as e:
            set_state(user_id, None)
            clear_create_flow(context)
            await update.message.reply_text(
                f"✅ Certificate created and coupon USED.\n⚠️ {e.public_message}\nUse 'Retrieve Certificate' later.",
                reply_markup=main_menu_keyboard(is_admin(update)),
            )
            return
        except TimeoutError:
            logger.error("Getcertificate after create timeout")
            set_state(user_id, None)
            clear_create_flow(context)
            await update.message.reply_text(
                "✅ Certificate created and coupon USED.\n⚠️ Status fetch timed out. Use 'Retrieve Certificate' later.",
                reply_markup=main_menu_keyboard(is_admin(update)),
            )
            return
        except Exception as e:
            logger.error("Getcertificate after create failed: %s", str(e))
            set_state(user_id, None)
            clear_create_flow(context)
            await update.message.reply_text(
                "✅ Certificate created and coupon USED.\n⚠️ Status fetch failed. Use 'Retrieve Certificate' later.",
                reply_markup=main_menu_keyboard(is_admin(update)),
            )
            return

        set_state(user_id, None)
        clear_create_flow(context)
        context.user_data["last_udid"] = udid

        share_text = f"UDID: {udid}\nStatus: {result.get('status')}"
        await update.message.reply_text(
            build_cert_card(udid, result),
            parse_mode="HTML",
            reply_markup=cert_action_keyboard(share_text),
        )
        return

    # ======================================
    # CERT STATUS
    # ======================================
    if mode == "await_cert_status_udid":
        udid = msg.strip()
        if not UDID_RE.fullmatch(udid):
            await update.message.reply_text("Invalid UDID.", reply_markup=back_cancel_keyboard())
            return

        await update.message.reply_text("⏳ Checking status…")
        try:
            result = await run_provider(_provider_getcertificate_by_udid, udid)
        except ProviderError as e:
            set_state(user_id, None)
            await update.message.reply_text(f"❌ {e.public_message}", reply_markup=main_menu_keyboard(is_admin(update)))
            return
        except TimeoutError:
            set_state(user_id, None)
            await update.message.reply_text("❌ Provider timeout. Try again.", reply_markup=main_menu_keyboard(is_admin(update)))
            return
        except Exception as e:
            logger.error("Cert status error: %s", str(e))
            set_state(user_id, None)
            await update.message.reply_text("❌ Failed. Try again later.", reply_markup=main_menu_keyboard(is_admin(update)))
            return

        set_state(user_id, None)
        context.user_data["last_udid"] = udid

        await update.message.reply_text(
            build_status_only_card(udid, result),
            parse_mode="HTML",
            reply_markup=main_menu_keyboard(is_admin(update)),
        )
        return

    # ======================================
    # RETRIEVE CERT
    # ======================================
    if mode == "await_retrieve_udid":
        udid = msg.strip()
        if not UDID_RE.fullmatch(udid):
            await update.message.reply_text("Invalid UDID.", reply_markup=back_cancel_keyboard())
            return

        context.user_data["last_udid"] = udid
        await update.message.reply_text("⏳ Retrieving…")

        try:
            result = await run_provider(_provider_getcertificate_by_udid, udid)
        except ProviderError as e:
            set_state(user_id, None)
            await update.message.reply_text(f"❌ {e.public_message}", reply_markup=main_menu_keyboard(is_admin(update)))
            return
        except TimeoutError:
            set_state(user_id, None)
            await update.message.reply_text("❌ Provider timeout. Try again.", reply_markup=main_menu_keyboard(is_admin(update)))
            return
        except Exception as e:
            logger.error("Retrieve cert error: %s", str(e))
            set_state(user_id, None)
            await update.message.reply_text("❌ Failed. Try again later.", reply_markup=main_menu_keyboard(is_admin(update)))
            return

        set_state(user_id, None)

        share_text = f"UDID: {udid}\nStatus: {result.get('status')}"
        await update.message.reply_text(
            build_cert_card(udid, result),
            parse_mode="HTML",
            reply_markup=cert_action_keyboard(share_text),
        )
        return

    # ======================================
    # DEFAULT: user sends coupon in chat (just show status)
    # ======================================
    code = msg.strip()
    if not COUPON_RE.fullmatch(code):
        await update.message.reply_text("Use menu buttons.\nOr send a coupon code.\nExample: Vinh-1a2b3c4d")
        return

    try:
        row = db_get_coupon(pool, code)
    except Exception as e:
        logger.error("DB get coupon error: %s", str(e))
        await update.message.reply_text("Server error while checking coupon.")
        return

    if not row:
        await update.message.reply_text("❌ Coupon NOT FOUND.")
    elif row["status"] == "used":
        await update.message.reply_text("⚠️ Coupon EXISTS but is USED.")
    elif row["status"] == "reserved":
        await update.message.reply_text("⚠️ Coupon EXISTS but is RESERVED (locked).")
    else:
        await update.message.reply_text(f"✅ Coupon valid (UNUSED). Category: {row['category']}")


async def on_create_device_click(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if not query:
        return
    await query.answer()
    await safe_edit(
        query,
        "⚠️ Device selection is disabled for now.\nPlease use Create Cert flow (no device choice).",
        reply_markup=back_cancel_keyboard(),
        parse_mode=None,
    )


def build_status_only_card(udid: str, r: dict) -> str:
    status = r.get("status", "UNKNOWN")
    state = r.get("state", True)

    if status == "READY" and state:
        status_line = "Status: <b>Active</b> 🟢"
    elif status == "PENDING" and state:
        status_line = "Status: <b>Pending</b> ⏳"
    elif (not state) or status == "REVOKED":
        status_line = "Status: <b>Revoked</b> 🔴"
    else:
        status_line = f"Status: <b>{hesc(str(status))}</b> ⚠️"

    pname = r.get("pname") or "N/A"
    cert_id = r.get("id") or "N/A"

    pool_val = r.get("pool")
    pool_label = (
        "Public (0)" if pool_val == 0 else
        "Private (1)" if pool_val == 1 else
        hesc(str(pool_val)) if pool_val is not None else "N/A"
    )

    type_val = r.get("type")
    type_label = (
        "Real-time (0)" if type_val == 0 else
        "Reservation (1)" if type_val == 1 else
        hesc(str(type_val)) if type_val is not None else "N/A"
    )

    warranty_flag = r.get("warranty")
    warranty_label = "Yes ✅" if warranty_flag is True else "No ❌" if warranty_flag is False else "N/A"

    shtype_val = r.get("shtype")
    shtype_label = hesc(str(shtype_val)) if shtype_val is not None else "N/A"

    added_on = fmt_dt(r.get("addtime"))
    warranty_left = fmt_warranty_left(r.get("warranty_time"))
    warranty_expire_at = fmt_dt(r.get("warranty_time"))

    return "\n".join(
        [
            "📌 <b>Certificate Status</b>",
            "",
            status_line,
            f"Name: <b>{hesc(str(pname))}</b>",
            f"UDID: <code>{hesc(udid)}</code>",
            f"Cert ID: <code>{hesc(str(cert_id))}</code>",
            f"Pool: <b>{pool_label}</b>",
            f"Mode: <b>{type_label}</b>",
            f"Platform (shtype): <code>{shtype_label}</code>",
            f"Added on: <code>{hesc(str(added_on))}</code>",
            f"Warranty cert: <b>{warranty_label}</b>",
            f"Warranty left: <code>{hesc(str(warranty_left))}</code>",
            f"Warranty expires: <code>{hesc(str(warranty_expire_at))}</code>",
        ]
    )


# =============================================================================
# Error handler
# =============================================================================
async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Unhandled error: %s", context.error)

async def cmd_createcert(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    set_state(user_id, "await_create_coupon")
    clear_create_flow(context)
    await update.message.reply_text("Send coupon code:", reply_markup=back_cancel_keyboard())

async def cmd_retrieve(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    set_state(user_id, "await_retrieve_udid")
    await update.message.reply_text("Send UDID:", reply_markup=back_cancel_keyboard())

async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    set_state(user_id, "await_cert_status_udid")
    await update.message.reply_text("Send UDID to check status:", reply_markup=back_cancel_keyboard())

# -------------------------
# Admin commands
# -------------------------
async def cmd_create(update: Update, context: ContextTypes.DEFAULT_TYPE):
    err = admin_guard(update)
    if err:
        await update.message.reply_text(err)
        return
    user_id = update.effective_user.id
    set_state(user_id, "await_qty")
    await update.message.reply_text("Send: iphone 10  OR  ipad 10 (qty 1–100)", reply_markup=back_cancel_keyboard())

async def cmd_coupon(update: Update, context: ContextTypes.DEFAULT_TYPE):
    err = admin_guard(update)
    if err:
        await update.message.reply_text(err)
        return
    user_id = update.effective_user.id
    set_state(user_id, "await_status_code")
    await update.message.reply_text("Send coupon code to CHECK STATUS:", reply_markup=back_cancel_keyboard())

async def cmd_unreserve(update: Update, context: ContextTypes.DEFAULT_TYPE):
    err = admin_guard(update)
    if err:
        await update.message.reply_text(err)
        return
    user_id = update.effective_user.id
    set_state(user_id, "await_unreserve_code")
    await update.message.reply_text("Send coupon code to UNRESERVE (unlock):", reply_markup=back_cancel_keyboard())
