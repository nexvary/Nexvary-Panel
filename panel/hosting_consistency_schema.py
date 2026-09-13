from __future__ import annotations

from .db_layer import db


def ensure_hosting_consistency_schema() -> None:
    with db() as conn:
        conn.executescript("""
          CREATE TRIGGER IF NOT EXISTS trg_hosting_package_assignment_insert
          AFTER INSERT ON user_hosting_package
          BEGIN
            UPDATE hosting_accounts
               SET package_id=NEW.package_id, updated_at=NEW.assigned_at
             WHERE username=NEW.username;
          END;

          CREATE TRIGGER IF NOT EXISTS trg_hosting_package_assignment_update
          AFTER UPDATE OF package_id,assigned_at ON user_hosting_package
          BEGIN
            UPDATE hosting_accounts
               SET package_id=NEW.package_id, updated_at=NEW.assigned_at
             WHERE username=NEW.username;
          END;
        """)
        conn.execute(
            """UPDATE hosting_accounts
                  SET package_id=(SELECT u.package_id FROM user_hosting_package u WHERE u.username=hosting_accounts.username),
                      updated_at=MAX(updated_at,COALESCE((SELECT u.assigned_at FROM user_hosting_package u WHERE u.username=hosting_accounts.username),updated_at))
                WHERE EXISTS(SELECT 1 FROM user_hosting_package u WHERE u.username=hosting_accounts.username)
                  AND package_id<>(SELECT u.package_id FROM user_hosting_package u WHERE u.username=hosting_accounts.username)"""
        )
