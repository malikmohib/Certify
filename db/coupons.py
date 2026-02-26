# db/coupons.py
from typing import Optional, Dict, Any, Tuple, Literal
from psycopg2.pool import SimpleConnectionPool
from typing import List

ReserveResult = Literal["RESERVED", "NOT_FOUND", "ALREADY_RESERVED", "ALREADY_USED"]
UseResult = Literal["USED", "NOT_FOUND", "NOT_RESERVED", "NOT_RESERVED_BY_YOU", "ALREADY_USED"]
SetUdidResult = Literal["OK", "NOT_FOUND", "NOT_RESERVED", "NOT_RESERVED_BY_YOU", "ALREADY_USED"]
FailLogResult = Literal["OK", "NOT_FOUND", "NOT_RESERVED", "NOT_RESERVED_BY_YOU"]
UnreserveResult = Literal["UNRESERVED", "NOT_FOUND", "NOT_RESERVED"]

def db_get_coupon(pool: SimpleConnectionPool, code: str) -> Optional[Dict[str, Any]]:
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT coupon_code, category, status,
                       reserved_by_telegram_id, reserved_udid, reserved_at,
                       last_failure_reason, last_failure_step, last_failed_at,
                       used_by_telegram_id, used_udid, used_at,
                       created_at
                FROM coupons
                WHERE coupon_code = %s
                """,
                (code,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "coupon_code": row[0],
                "category": row[1],
                "status": row[2],
                "reserved_by_telegram_id": row[3],
                "reserved_udid": row[4],
                "reserved_at": row[5],
                "last_failure_reason": row[6],
                "last_failure_step": row[7],
                "last_failed_at": row[8],
                "used_by_telegram_id": row[9],
                "used_udid": row[10],
                "used_at": row[11],
                "created_at": row[12],
            }
    finally:
        pool.putconn(conn)


def db_reserve_coupon(pool: SimpleConnectionPool, code: str, telegram_id: int) -> Tuple[ReserveResult, Optional[str]]:
    """
    Lock coupon immediately when user submits it.
    Returns: (result, category_if_reserved)
    """
    conn = pool.getconn()
    try:
        conn.autocommit = False
        with conn.cursor() as cur:
            # Try to reserve if unused
            cur.execute(
                """
                UPDATE coupons
                SET status='reserved',
                    reserved_by_telegram_id=%s,
                    reserved_at=NOW(),
                    -- clear old failure info on new reservation attempt
                    last_failure_reason=NULL,
                    last_failure_step=NULL,
                    last_failed_at=NULL
                WHERE coupon_code=%s AND status='unused'
                RETURNING category
                """,
                (telegram_id, code),
            )
            row = cur.fetchone()
            if row:
                conn.commit()
                return "RESERVED", row[0]

            # Not reserved: figure out why
            cur.execute("SELECT status FROM coupons WHERE coupon_code=%s", (code,))
            r2 = cur.fetchone()
            conn.commit()
            if not r2:
                return "NOT_FOUND", None
            if r2[0] == "used":
                return "ALREADY_USED", None
            return "ALREADY_RESERVED", None
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


def db_set_reserved_udid(pool: SimpleConnectionPool, code: str, telegram_id: int, udid: str) -> SetUdidResult:
    """
    Store UDID against the reservation (so admin can see it).
    Only allowed if reserved by same user.
    """
    conn = pool.getconn()
    try:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE coupons
                SET reserved_udid=%s
                WHERE coupon_code=%s
                  AND status='reserved'
                  AND reserved_by_telegram_id=%s
                RETURNING coupon_code
                """,
                (udid, code, telegram_id),
            )
            row = cur.fetchone()
            if row:
                conn.commit()
                return "OK"

            cur.execute("SELECT status, reserved_by_telegram_id FROM coupons WHERE coupon_code=%s", (code,))
            row2 = cur.fetchone()
            conn.commit()
            if not row2:
                return "NOT_FOUND"
            status, rby = row2
            if status == "used":
                return "ALREADY_USED"
            if status != "reserved":
                return "NOT_RESERVED"
            if rby != telegram_id:
                return "NOT_RESERVED_BY_YOU"
            return "NOT_RESERVED"
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


def db_log_coupon_failure(
    pool: SimpleConnectionPool,
    code: str,
    telegram_id: int,
    reason: str,
    step: str,
) -> FailLogResult:
    """
    If provider fails, keep coupon reserved, but store failure reason/step/time.
    Only allowed if reserved by same user.
    """
    conn = pool.getconn()
    try:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE coupons
                SET last_failure_reason=%s,
                    last_failure_step=%s,
                    last_failed_at=NOW()
                WHERE coupon_code=%s
                  AND status='reserved'
                  AND reserved_by_telegram_id=%s
                RETURNING coupon_code
                """,
                (reason[:2000], step[:200], code, telegram_id),  # small safety truncation
            )
            row = cur.fetchone()
            if row:
                conn.commit()
                return "OK"

            cur.execute("SELECT status, reserved_by_telegram_id FROM coupons WHERE coupon_code=%s", (code,))
            row2 = cur.fetchone()
            conn.commit()
            if not row2:
                return "NOT_FOUND"
            status, rby = row2
            if status != "reserved":
                return "NOT_RESERVED"
            if rby != telegram_id:
                return "NOT_RESERVED_BY_YOU"
            return "NOT_RESERVED"
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


def db_mark_coupon_used(pool: SimpleConnectionPool, code: str, telegram_id: int, udid: str) -> UseResult:
    """
    Finalize usage after certificate creation succeeds.
    Only allowed if reserved by same user.
    """
    conn = pool.getconn()
    try:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE coupons
                SET status='used',
                    used_by_telegram_id=%s,
                    used_udid=%s,
                    used_at=NOW()
                WHERE coupon_code=%s
                  AND status='reserved'
                  AND reserved_by_telegram_id=%s
                RETURNING coupon_code
                """,
                (telegram_id, udid, code, telegram_id),
            )
            row = cur.fetchone()
            if row:
                conn.commit()
                return "USED"

            cur.execute("SELECT status, reserved_by_telegram_id FROM coupons WHERE coupon_code=%s", (code,))
            row2 = cur.fetchone()
            conn.commit()
            if not row2:
                return "NOT_FOUND"
            status, rby = row2
            if status == "used":
                return "ALREADY_USED"
            if status != "reserved":
                return "NOT_RESERVED"
            if rby != telegram_id:
                return "NOT_RESERVED_BY_YOU"
            return "NOT_RESERVED"
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


def db_admin_unreserve_coupon(pool: SimpleConnectionPool, code: str) -> UnreserveResult:
    """
    Admin-only: release a reserved coupon back to unused.
    Keeps failure info by default (so you can still see why it failed).
    """
    conn = pool.getconn()
    try:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE coupons
                SET status='unused',
                    reserved_by_telegram_id=NULL,
                    reserved_udid=NULL,
                    reserved_at=NULL
                WHERE coupon_code=%s AND status='reserved'
                RETURNING coupon_code
                """,
                (code,),
            )
            row = cur.fetchone()
            if row:
                conn.commit()
                return "UNRESERVED"

            cur.execute("SELECT status FROM coupons WHERE coupon_code=%s", (code,))
            row2 = cur.fetchone()
            conn.commit()
            if not row2:
                return "NOT_FOUND"
            return "NOT_RESERVED"
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)

def db_create_many_coupons(pool: SimpleConnectionPool, codes: List[str], category: str) -> List[str]:
    """
    Insert many coupons. Returns list of inserted coupon codes (duplicates skipped).
    Assumes coupons table has coupon_code (unique), category, status, created_at.
    """
    if category not in ("iphone", "ipad"):
        raise ValueError("category must be 'iphone' or 'ipad'")

    if not codes:
        return []

    conn = pool.getconn()
    try:
        conn.autocommit = False
        with conn.cursor() as cur:
            inserted = []
            for code in codes:
                cur.execute(
                    """
                    INSERT INTO coupons (coupon_code, category, status, created_at)
                    VALUES (%s, %s, 'unused', NOW())
                    ON CONFLICT (coupon_code) DO NOTHING
                    RETURNING coupon_code
                    """,
                    (code, category),
                )
                row = cur.fetchone()
                if row:
                    inserted.append(row[0])
            conn.commit()
            return inserted
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)