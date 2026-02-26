# test.py (entry point) — production-safe PTB v20+
# - validates env/files
# - creates Application
# - initializes DB pool
# - stores pool in app.bot_data
# - registers handlers
# - schedules signed-file cleanup job
# - starts polling
# NO business logic here.

from __future__ import annotations

from psycopg2.pool import SimpleConnectionPool
from telegram import Update, BotCommand
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    MessageHandler,
    filters,
)
from telegram import BotCommandScopeDefault, BotCommandScopeChat

from bot.config import (
    BOT_TOKEN,
    DATABASE_URL,
    ZSIGN_BIN,
    IPA_MAP,
    PUBLIC_FILES_DIR,
    PUBLIC_META_DIR,
    ADMIN_TELEGRAM_ID,
    logger,
)

from bot.services import cleanup_signed_job
from bot.handlers import (
    start,
    cmd_createcert,
    cmd_retrieve,
    cmd_status,
    cmd_create,
    cmd_coupon,
    cmd_unreserve,
    on_menu_click,
    on_create_device_click,
    on_cert_action,
    on_sign_app_click,
    on_text,
    on_error,
)


# -------------------------------------------------------------------------
# Set command menu (public + admin)
# -------------------------------------------------------------------------
async def post_init(app: Application) -> None:
    public_commands = [
        BotCommand("start", "Start the bot"),
        BotCommand("createcert", "Create certificate"),
        BotCommand("retrieve", "Retrieve certificate"),
        BotCommand("status", "Check certificate status"),
    ]

    admin_only_commands = [
        BotCommand("create", "Create coupons (admin)"),
        BotCommand("coupon", "Check coupon status (admin)"),
        BotCommand("unreserve", "Unreserve coupon (admin)"),
    ]

    # Default commands for everyone
    await app.bot.set_my_commands(public_commands, scope=BotCommandScopeDefault())

    # Admin chat sees public + admin commands
    await app.bot.set_my_commands(
        public_commands + admin_only_commands,
        scope=BotCommandScopeChat(chat_id=ADMIN_TELEGRAM_ID),
    )


def main() -> None:
    # ---------------------------------------------------------------------
    # Validate env
    # ---------------------------------------------------------------------
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN is not set")
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set")

    # ---------------------------------------------------------------------
    # Validate signing dependencies
    # ---------------------------------------------------------------------
    if not ZSIGN_BIN.exists():
        raise RuntimeError(f"zsign not found at {ZSIGN_BIN}")

    missing_ipas = [k for k, p in IPA_MAP.items() if not p.exists()]
    if missing_ipas:
        raise RuntimeError("Missing IPA files: " + ", ".join(missing_ipas))

    PUBLIC_FILES_DIR.mkdir(parents=True, exist_ok=True)
    PUBLIC_META_DIR.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------------
    # DB pool init + test
    # ---------------------------------------------------------------------
    pool = SimpleConnectionPool(minconn=1, maxconn=5, dsn=DATABASE_URL)
    try:
        conn = pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
            conn.commit()
        finally:
            pool.putconn(conn)
    except Exception as e:
        pool.closeall()
        raise RuntimeError(f"Database connection test failed: {e}") from e

    # ---------------------------------------------------------------------
    # Telegram app
    # ---------------------------------------------------------------------
    app = Application.builder().token(BOT_TOKEN).post_init(post_init).build()
    app.bot_data["pool"] = pool

    # ---------------------------------------------------------------------
    # Handlers (ORDER MATTERS)
    # ---------------------------------------------------------------------
    # Commands
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("createcert", cmd_createcert))
    app.add_handler(CommandHandler("retrieve", cmd_retrieve))
    app.add_handler(CommandHandler("status", cmd_status))

    # Admin commands
    app.add_handler(CommandHandler("create", cmd_create))
    app.add_handler(CommandHandler("coupon", cmd_coupon))
    app.add_handler(CommandHandler("unreserve", cmd_unreserve))

    # Callback queries
    app.add_handler(CallbackQueryHandler(on_create_device_click, pattern=r"^create:device:"))
    app.add_handler(CallbackQueryHandler(on_cert_action, pattern=r"^cert:"))
    app.add_handler(CallbackQueryHandler(on_sign_app_click, pattern=r"^signapp:"))
    app.add_handler(CallbackQueryHandler(on_menu_click))

    # Text messages
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    # Errors
    app.add_error_handler(on_error)

    # ---------------------------------------------------------------------
    # Cleanup job
    # ---------------------------------------------------------------------
    if app.job_queue:
        app.job_queue.run_repeating(
            cleanup_signed_job,
            interval=300,  # 5 minutes
            first=60,
        )
    else:
        logger.warning("JobQueue not available; cleanup disabled.")

    # ---------------------------------------------------------------------
    # Run bot
    # ---------------------------------------------------------------------
    logger.info("Bot started.")
    try:
        app.run_polling(
            allowed_updates=[
                Update.MESSAGE,
                Update.EDITED_MESSAGE,
                Update.CALLBACK_QUERY,
            ]
        )
    finally:
        try:
            pool.closeall()
        except Exception:
            pass


if __name__ == "__main__":
    main()
