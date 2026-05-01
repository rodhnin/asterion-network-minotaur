#!/usr/bin/env python3
"""
Database Migration/Setup Script for Argos Suite
Supports: Argus, Hephaestus, Pythia, Asterion

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import sqlite3
import os
import sys
from pathlib import Path


def get_db_path():
    """Get database path (same location for all Argos Suite tools)"""
    home = Path.home()
    return home / ".argos" / "argos.db"


def find_schema_file():
    """Find migrate.sql in multiple locations"""
    script_dir = Path(__file__).parent.parent
    
    locations = [
        "db/migrate.sql",
        script_dir / "db" / "migrate.sql",
        Path.cwd() / "db" / "migrate.sql",
        Path.cwd() / ".." / "db" / "migrate.sql"
    ]
    
    for location in locations:
        path = Path(location).resolve()
        if path.exists():
            print(f"✓ Found schema: {path}", file=sys.stderr)
            return path
    
    return None


def ensure_database():
    """Ensure database exists with correct schema"""
    
    db_path = get_db_path()
    db_dir = db_path.parent
    
    # Create directory if doesn't exist
    if not db_dir.exists():
        db_dir.mkdir(parents=True, exist_ok=True)
        print(f"✓ Created directory: {db_dir}", file=sys.stderr)
    
    # Check if database exists
    db_exists = db_path.exists()
    
    if not db_exists:
        print(f"✓ Creating new database: {db_path}", file=sys.stderr)
    else:
        print(f"✓ Database exists: {db_path}", file=sys.stderr)
    
    # Connect (creates if doesn't exist)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Find schema file
    schema_path = find_schema_file()
    
    if not schema_path:
        print(f"ERROR: Schema file (migrate.sql) not found", file=sys.stderr)
        print(f"Searched in:", file=sys.stderr)
        print(f"  - db/migrate.sql", file=sys.stderr)
        print(f"  - ../db/migrate.sql", file=sys.stderr)
        conn.close()
        return False
    
    # Read schema
    with open(schema_path, 'r', encoding='utf-8') as f:
        schema_sql = f.read()
    
    # Execute schema (idempotent - uses IF NOT EXISTS)
    try:
        cursor.executescript(schema_sql)
        conn.commit()
        print("✓ Database schema up to date", file=sys.stderr)
        
        # Verify tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row[0] for row in cursor.fetchall()]
        
        print(f"\n✓ Found {len(tables)} tables:", file=sys.stderr)
        for table in tables:
            # Count rows
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            print(f"  - {table}: {count} rows", file=sys.stderr)
        
        # Verify views exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='view' ORDER BY name")
        views = [row[0] for row in cursor.fetchall()]
        
        if views:
            print(f"\n✓ Found {len(views)} views:", file=sys.stderr)
            for view in views:
                print(f"  - {view}", file=sys.stderr)
        
        # Check for Asterion support
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
        if cursor.fetchone():
            # Check if tool column accepts 'asterion'
            cursor.execute("SELECT sql FROM sqlite_master WHERE name='scans'")
            schema = cursor.fetchone()[0]
            
            if 'asterion' in schema.lower():
                print(f"\n✓ Asterion support enabled in schema", file=sys.stderr)
            else:
                print(f"\n⚠ WARNING: 'asterion' may not be in tool CHECK constraint", file=sys.stderr)
                print(f"  Update migrate.sql to include: CHECK(tool IN ('argus', 'hephaestus', 'pythia', 'asterion'))", file=sys.stderr)
        
        return True
        
    except sqlite3.Error as e:
        print(f"ERROR: Database migration failed: {e}", file=sys.stderr)
        return False
    
    finally:
        conn.close()


def get_stats():
    """Get statistics about the database"""
    db_path = get_db_path()
    
    if not db_path.exists():
        print("Database does not exist yet", file=sys.stderr)
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Total scans by tool
        cursor.execute("""
            SELECT tool, COUNT(*) as count 
            FROM scans 
            GROUP BY tool 
            ORDER BY count DESC
        """)
        
        print("\n📊 Scan Statistics:", file=sys.stderr)
        print("="*50, file=sys.stderr)
        
        for row in cursor.fetchall():
            tool, count = row
            print(f"  {tool}: {count} scans", file=sys.stderr)
        
        # Total findings by severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM findings 
            GROUP BY severity 
            ORDER BY 
                CASE severity 
                    WHEN 'critical' THEN 1 
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3 
                    WHEN 'low' THEN 4 
                    WHEN 'info' THEN 5 
                END
        """)
        
        print("\n🔍 Finding Statistics:", file=sys.stderr)
        print("="*50, file=sys.stderr)
        
        for row in cursor.fetchall():
            severity, count = row
            emoji = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵',
                'info': '⚪'
            }.get(severity, '⚫')
            print(f"  {emoji} {severity}: {count} findings", file=sys.stderr)
        
        # Recent scans
        cursor.execute("""
            SELECT tool, target_url, started_at 
            FROM scans 
            ORDER BY started_at DESC 
            LIMIT 5
        """)
        
        print("\n🕒 Recent Scans:", file=sys.stderr)
        print("="*50, file=sys.stderr)
        
        for row in cursor.fetchall():
            tool, target, date = row
            print(f"  [{tool}] {target} - {date}", file=sys.stderr)
        
    except sqlite3.Error as e:
        print(f"ERROR: Failed to get stats: {e}", file=sys.stderr)
    
    finally:
        conn.close()


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Argos Suite Database Setup & Migration",
        epilog="Example: python db_migrate.py --stats"
    )
    
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show database statistics"
    )
    
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force recreate database (DANGEROUS - deletes existing data)"
    )
    
    args = parser.parse_args()
    
    if args.force:
        db_path = get_db_path()
        if db_path.exists():
            response = input(f"⚠️  DELETE {db_path}? This cannot be undone! (yes/no): ")
            if response.lower() == "yes":
                db_path.unlink()
                print(f"✓ Deleted: {db_path}", file=sys.stderr)
            else:
                print("Cancelled", file=sys.stderr)
                return 0
    
    print("Argos Suite - Database Setup", file=sys.stderr)
    print("="*50, file=sys.stderr)
    
    success = ensure_database()
    
    if success:
        if args.stats:
            get_stats()
        
        print("\n" + "="*50, file=sys.stderr)
        print("✓ Database setup complete!", file=sys.stderr)
        print("="*50, file=sys.stderr)
        return 0
    else:
        print("\n" + "="*50, file=sys.stderr)
        print("✗ Database setup failed", file=sys.stderr)
        print("="*50, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())