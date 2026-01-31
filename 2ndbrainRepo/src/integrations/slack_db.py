"""
Slack Installation Database
Multi-tenant token storage for Slack workspaces
"""

import os
import json
import sqlite3
from datetime import datetime
from typing import Optional, Dict, List
from pathlib import Path


# Database path - use environment variable or default
DATABASE_DIR = Path(os.getenv("DATA_DIR", Path(__file__).parent.parent.parent / "data"))
DATABASE_PATH = DATABASE_DIR / "slack_installations.db"


def get_db_connection():
    """Get database connection"""
    DATABASE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DATABASE_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database tables"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS slack_installations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id TEXT UNIQUE NOT NULL,
            team_name TEXT,
            bot_token TEXT NOT NULL,
            bot_user_id TEXT,
            app_id TEXT,
            authed_user_id TEXT,
            scope TEXT,
            tenant_id TEXT,
            installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            last_event_at TIMESTAMP,
            settings TEXT DEFAULT '{}'
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_slack_team_id ON slack_installations(team_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_slack_active ON slack_installations(is_active)
    """)

    conn.commit()
    conn.close()
    print(f"[Slack DB] Initialized at {DATABASE_PATH}")


def save_installation(data: Dict) -> bool:
    """Save or update a Slack installation"""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO slack_installations
            (team_id, team_name, bot_token, bot_user_id, app_id, authed_user_id, scope, tenant_id, settings)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(team_id) DO UPDATE SET
                team_name = excluded.team_name,
                bot_token = excluded.bot_token,
                bot_user_id = excluded.bot_user_id,
                app_id = excluded.app_id,
                authed_user_id = excluded.authed_user_id,
                scope = excluded.scope,
                updated_at = CURRENT_TIMESTAMP,
                is_active = 1
        """, (
            data['team_id'],
            data.get('team_name'),
            data['bot_token'],
            data.get('bot_user_id'),
            data.get('app_id'),
            data.get('authed_user_id'),
            data.get('scope'),
            data.get('tenant_id'),
            json.dumps(data.get('settings', {}))
        ))
        conn.commit()
        print(f"[Slack DB] Saved installation for team {data.get('team_name', data['team_id'])}")
        return True
    except Exception as e:
        print(f"[Slack DB] Error saving installation: {e}")
        return False
    finally:
        conn.close()


def get_installation(team_id: str) -> Optional[Dict]:
    """Get installation by team_id"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM slack_installations WHERE team_id = ? AND is_active = 1",
        (team_id,)
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        return dict(row)
    return None


def get_bot_token(team_id: str) -> Optional[str]:
    """Quick lookup for bot token by team_id"""
    installation = get_installation(team_id)
    return installation['bot_token'] if installation else None


def get_all_installations() -> List[Dict]:
    """Get all active installations"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM slack_installations WHERE is_active = 1 ORDER BY installed_at DESC")
    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def delete_installation(team_id: str) -> bool:
    """Soft delete an installation (mark as inactive)"""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "UPDATE slack_installations SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE team_id = ?",
            (team_id,)
        )
        conn.commit()
        print(f"[Slack DB] Deleted installation for team {team_id}")
        return True
    except Exception as e:
        print(f"[Slack DB] Error deleting installation: {e}")
        return False
    finally:
        conn.close()


def update_last_event(team_id: str):
    """Update last event timestamp for a team"""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "UPDATE slack_installations SET last_event_at = CURRENT_TIMESTAMP WHERE team_id = ?",
            (team_id,)
        )
        conn.commit()
    except Exception as e:
        print(f"[Slack DB] Error updating last event: {e}")
    finally:
        conn.close()


def get_installation_count() -> int:
    """Get count of active installations"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM slack_installations WHERE is_active = 1")
    count = cursor.fetchone()[0]
    conn.close()

    return count


# Initialize database on import
init_db()
