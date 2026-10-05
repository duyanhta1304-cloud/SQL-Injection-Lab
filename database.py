"""SQLite database engine and repeatable demo data for Apex Gear Store."""

from pathlib import Path
import sqlite3


DB_PATH = Path(__file__).with_name("apex_store.db")


def get_db_connection() -> sqlite3.Connection:
    """Return a configured connection to the local Apex Gear Store database."""
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db() -> None:
    """Rebuild the demonstration schema and seed it with predictable records."""
    with get_db_connection() as connection:
        cursor = connection.cursor()
        cursor.executescript(
            """
            DROP TABLE IF EXISTS sys_canary_credentials;
            DROP TABLE IF EXISTS products;
            DROP TABLE IF EXISTS users;

            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL CHECK (role IN ('admin', 'customer')),
                credit_card TEXT NOT NULL
            );

            CREATE TABLE products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                price REAL NOT NULL CHECK (price >= 0),
                description TEXT NOT NULL,
                stock INTEGER NOT NULL CHECK (stock >= 0)
            );

            CREATE TABLE sys_canary_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                decoy_user TEXT NOT NULL,
                decoy_token TEXT NOT NULL,
                trap_flag TEXT NOT NULL
            );
            """
        )

        cursor.executemany(
            """
            INSERT INTO users (username, password, email, role, credit_card)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                ("admin", "AdminPass2026!", "admin@apexgear.local", "admin", "4532-XXXX-XXXX-8921"),
                ("maya.chen", "NovaMouse#41", "maya.chen@example.test", "customer", "5424-XXXX-XXXX-1184"),
                ("liam.nguyen", "Switches!88", "liam.nguyen@example.test", "customer", "4716-XXXX-XXXX-6042"),
            ],
        )

        cursor.executemany(
            """
            INSERT INTO products (name, category, price, description, stock)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                ("SteelSeries Apex Pro TKL Gen 3", "Keyboards", 249.95, "TKL magnetic gaming keyboard with adjustable actuation and per-key RGB.", 18),
                ("Keychron Q1 Max", "Keyboards", 179.00, "75% wireless aluminium keyboard with a double-gasket mount and PBT keycaps.", 31),
                ("LG UltraGear 27GR83Q-B", "Monitors", 429.00, "27-inch QHD 240 Hz IPS gaming monitor with adaptive sync.", 12),
                ("Dell UltraSharp U3223QE", "Monitors", 699.95, "32-inch 4K IPS Black USB-C hub monitor with power delivery.", 7),
                ("Samsung 990 PRO 2TB", "Storage", 229.00, "PCIe 4.0 NVMe SSD rated for sequential reads up to 7,450 MB/s.", 44),
                ("WD_BLACK SN850X 1TB", "Storage", 119.00, "High-performance PCIe 4.0 NVMe gaming SSD.", 56),
                ("Logitech G PRO X SUPERLIGHT 2", "Mice", 139.95, "Ultra-light LIGHTSPEED wireless gaming mouse with a HERO 2 sensor.", 26),
                ("Logitech MX Master 3S", "Mice", 99.00, "Ergonomic wireless productivity mouse with quiet clicks.", 39),
            ],
        )

        cursor.executemany(
            """
            INSERT INTO sys_canary_credentials (decoy_user, decoy_token, trap_flag)
            VALUES (?, ?, ?)
            """,
            [
                ("svc_backup_admin", "APX-DECOY-91F4C2", "CANARY_DO_NOT_USE"),
                ("legacy_root", "APX-DECOY-77A0BD", "CANARY_DO_NOT_USE"),
            ],
        )
        connection.commit()


if __name__ == "__main__":
    init_db()
    print(f"Apex Gear Store database rebuilt at {DB_PATH}")
