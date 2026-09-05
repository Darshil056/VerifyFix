"""
VerifyFix MongoDB Service
==========================

Provides a MongoDB client wrapper for persisting scan states, events,
and results.  Falls back gracefully to in-memory storage if MongoDB
is unavailable (for local development without a running MongoDB instance).
"""

import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

logger = logging.getLogger("verifyfix.db")

# MongoDB client (lazy-initialized)
_client = None
_db = None
_fallback_mode = False


def init_mongo(uri: str, db_name: str):
    """
    Initialize the MongoDB connection.

    Falls back to in-memory mode if pymongo is not installed or
    the MongoDB server is unreachable.
    """
    global _client, _db, _fallback_mode

    try:
        from pymongo import MongoClient
        from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

        _client = MongoClient(uri, serverSelectionTimeoutMS=3000)
        # Force a connection check
        _client.admin.command("ping")
        _db = _client[db_name]

        # Ensure indexes
        _db.scans.create_index("scan_id", unique=True)
        _db.scan_events.create_index("scan_id")
        _db.scan_events.create_index([("scan_id", 1), ("index", 1)])

        _fallback_mode = False
        logger.info(f"MongoDB connected: {uri} / {db_name}")

    except ImportError:
        logger.warning("pymongo not installed — running in in-memory fallback mode")
        _fallback_mode = True
    except Exception as e:
        logger.warning(f"MongoDB connection failed ({e}) — running in in-memory fallback mode")
        _fallback_mode = True


def is_fallback() -> bool:
    """Returns True if using in-memory fallback instead of MongoDB."""
    return _fallback_mode


# ---------------------------------------------------------------------------
# Scan CRUD Operations
# ---------------------------------------------------------------------------

def save_scan(scan_id: str, state: dict):
    """Insert or update a scan state document."""
    if _fallback_mode:
        return
    try:
        doc = {**state, "scan_id": scan_id, "updated_at": datetime.now(timezone.utc).isoformat()}
        _db.scans.update_one(
            {"scan_id": scan_id},
            {"$set": doc},
            upsert=True,
        )
    except Exception as e:
        logger.error(f"MongoDB save_scan failed: {e}")


def get_scan(scan_id: str) -> Optional[dict]:
    """Retrieve a scan state document by scan_id."""
    if _fallback_mode:
        return None
    try:
        doc = _db.scans.find_one({"scan_id": scan_id}, {"_id": 0})
        return doc
    except Exception as e:
        logger.error(f"MongoDB get_scan failed: {e}")
        return None


def list_all_scans() -> List[dict]:
    """Retrieve summaries of all scans."""
    if _fallback_mode:
        return []
    try:
        cursor = _db.scans.find(
            {},
            {
                "_id": 0,
                "scan_id": 1,
                "repo_owner": 1,
                "repo_name": 1,
                "execution_step": 1,
                "started_at": 1,
                "completed_at": 1,
            },
        ).sort("started_at", -1).limit(50)
        return list(cursor)
    except Exception as e:
        logger.error(f"MongoDB list_all_scans failed: {e}")
        return []


def mark_scan_completed(scan_id: str, state: dict):
    """Mark a scan as completed and persist the final state."""
    if _fallback_mode:
        return
    try:
        doc = {
            **state,
            "scan_id": scan_id,
            "completed": True,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        _db.scans.update_one(
            {"scan_id": scan_id},
            {"$set": doc},
            upsert=True,
        )
    except Exception as e:
        logger.error(f"MongoDB mark_scan_completed failed: {e}")


# ---------------------------------------------------------------------------
# Scan Events (for SSE replay)
# ---------------------------------------------------------------------------

def push_scan_event(scan_id: str, event: dict, index: int):
    """Store an SSE event for a scan."""
    if _fallback_mode:
        return
    try:
        _db.scan_events.insert_one({
            "scan_id": scan_id,
            "index": index,
            "event": event,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as e:
        logger.error(f"MongoDB push_scan_event failed: {e}")


def get_scan_events(scan_id: str, from_index: int = 0) -> List[dict]:
    """Retrieve SSE events for a scan starting from a given index."""
    if _fallback_mode:
        return []
    try:
        cursor = _db.scan_events.find(
            {"scan_id": scan_id, "index": {"$gte": from_index}},
            {"_id": 0, "event": 1, "index": 1},
        ).sort("index", 1)
        return [doc["event"] for doc in cursor]
    except Exception as e:
        logger.error(f"MongoDB get_scan_events failed: {e}")
        return []
