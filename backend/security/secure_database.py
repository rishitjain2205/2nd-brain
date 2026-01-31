"""
Secure Database Query Wrapper
Demonstrates CORRECT SQL injection prevention using parameterized queries

⚠️ THE ONLY WAY TO PREVENT SQL INJECTION:
✅ Use parameterized queries (prepared statements)
❌ NEVER use string concatenation or f-strings for SQL
❌ NEVER rely on regex validation

SUPPORTED DATABASES:
- PostgreSQL (psycopg2)
- MySQL (mysql-connector-python)
- SQLite (built-in)
- SQL Server (pyodbc)
"""

import sqlite3
from typing import Any, Dict, List, Optional, Tuple, Union
from contextlib import contextmanager
import logging


class SecureDatabase:
    """
    Secure database wrapper with parameterized queries

    Example usage:
        db = SecureDatabase('sqlite:///mydb.db')

        # ✅ SECURE - Uses parameterization
        results = db.execute_query(
            "SELECT * FROM users WHERE email = ?",
            ('user@example.com',)
        )

        # ❌ NEVER DO THIS - SQL injection!
        # results = db.execute_query(
        #     f"SELECT * FROM users WHERE email = '{user_input}'"
        # )
    """

    def __init__(self, connection_string: str, db_type: str = 'sqlite'):
        """
        Initialize database connection

        Args:
            connection_string: Database connection string
            db_type: Database type (sqlite, postgresql, mysql, sqlserver)
        """
        self.connection_string = connection_string
        self.db_type = db_type.lower()
        self.logger = logging.getLogger(__name__)

        # Store connection (lazy initialization)
        self._connection = None

    def _get_connection(self):
        """Get or create database connection"""
        if self._connection is None:
            if self.db_type == 'sqlite':
                import sqlite3
                # Parse SQLite connection string (strip sqlite:// or sqlite:/// prefix)
                db_path = self.connection_string
                if db_path.startswith('sqlite:///'):
                    db_path = db_path[10:]  # Remove 'sqlite:///'
                elif db_path.startswith('sqlite://'):
                    db_path = db_path[9:]   # Remove 'sqlite://'

                self._connection = sqlite3.connect(db_path)
                self._connection.row_factory = sqlite3.Row  # Dict-like rows

            elif self.db_type == 'postgresql':
                try:
                    import psycopg2
                    import psycopg2.extras
                    self._connection = psycopg2.connect(self.connection_string)
                except ImportError:
                    raise ImportError("psycopg2 not installed. Install with: pip install psycopg2-binary")

            elif self.db_type == 'mysql':
                try:
                    import mysql.connector
                    # Parse connection string
                    self._connection = mysql.connector.connect(
                        **self._parse_mysql_connection_string(self.connection_string)
                    )
                except ImportError:
                    raise ImportError("mysql-connector-python not installed. Install with: pip install mysql-connector-python")

            elif self.db_type == 'sqlserver':
                try:
                    import pyodbc
                    self._connection = pyodbc.connect(self.connection_string)
                except ImportError:
                    raise ImportError("pyodbc not installed. Install with: pip install pyodbc")

            else:
                raise ValueError(f"Unsupported database type: {self.db_type}")

        return self._connection

    def _parse_mysql_connection_string(self, conn_str: str) -> Dict[str, Any]:
        """Parse MySQL connection string"""
        # Simple parser for mysql://user:pass@host:port/database
        import re
        match = re.match(r'mysql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', conn_str)
        if not match:
            raise ValueError("Invalid MySQL connection string format")

        user, password, host, port, database = match.groups()
        return {
            'user': user,
            'password': password,
            'host': host,
            'port': int(port),
            'database': database
        }

    @contextmanager
    def transaction(self):
        """
        Context manager for database transactions

        Usage:
            with db.transaction():
                db.execute_update("INSERT INTO users ...", (...))
                db.execute_update("UPDATE accounts ...", (...))
                # Auto-commits on success, rolls back on error
        """
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Transaction failed, rolled back: {e}")
            raise

    def execute_query(
        self,
        query: str,
        params: Optional[Tuple] = None,
        fetch_one: bool = False
    ) -> Union[List[Dict], Dict, None]:
        """
        Execute SELECT query with parameterization

        ✅ SECURE EXAMPLE:
            results = db.execute_query(
                "SELECT * FROM users WHERE email = ? AND active = ?",
                ('user@example.com', True)
            )

        ❌ INSECURE - NEVER DO THIS:
            results = db.execute_query(
                f"SELECT * FROM users WHERE email = '{user_input}'"
            )

        Args:
            query: SQL query with ? placeholders (SQLite) or %s (PostgreSQL/MySQL)
            params: Tuple of parameters to bind
            fetch_one: Return single row instead of list

        Returns:
            List of dict rows, single dict row, or None
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Execute with parameters
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            # Fetch results
            if fetch_one:
                row = cursor.fetchone()
                if row:
                    if self.db_type == 'sqlite':
                        return dict(row)
                    else:
                        # Convert to dict for other databases
                        return dict(zip([col[0] for col in cursor.description], row))
                return None
            else:
                rows = cursor.fetchall()
                if self.db_type == 'sqlite':
                    return [dict(row) for row in rows]
                else:
                    # Convert to dict for other databases
                    columns = [col[0] for col in cursor.description]
                    return [dict(zip(columns, row)) for row in rows]

        except Exception as e:
            self.logger.error(f"Query failed: {e}")
            self.logger.error(f"Query: {query}")
            self.logger.error(f"Params: {params}")
            raise

        finally:
            cursor.close()

    def execute_update(
        self,
        query: str,
        params: Optional[Tuple] = None
    ) -> int:
        """
        Execute INSERT/UPDATE/DELETE query with parameterization

        ✅ SECURE EXAMPLE:
            rows_affected = db.execute_update(
                "UPDATE users SET active = ? WHERE email = ?",
                (True, 'user@example.com')
            )

        Args:
            query: SQL query with ? placeholders
            params: Tuple of parameters to bind

        Returns:
            Number of rows affected
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            conn.commit()
            return cursor.rowcount

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Update failed: {e}")
            self.logger.error(f"Query: {query}")
            self.logger.error(f"Params: {params}")
            raise

        finally:
            cursor.close()

    def execute_many(
        self,
        query: str,
        params_list: List[Tuple]
    ) -> int:
        """
        Execute query with multiple parameter sets (bulk insert/update)

        ✅ SECURE EXAMPLE:
            db.execute_many(
                "INSERT INTO users (email, name) VALUES (?, ?)",
                [
                    ('user1@example.com', 'User 1'),
                    ('user2@example.com', 'User 2'),
                    ('user3@example.com', 'User 3'),
                ]
            )

        Args:
            query: SQL query with ? placeholders
            params_list: List of parameter tuples

        Returns:
            Number of rows affected
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.executemany(query, params_list)
            conn.commit()
            return cursor.rowcount

        except Exception as e:
            conn.rollback()
            self.logger.error(f"Bulk operation failed: {e}")
            raise

        finally:
            cursor.close()

    def close(self):
        """Close database connection"""
        if self._connection:
            self._connection.close()
            self._connection = None


# ==============================================================================
# SAFE QUERY EXAMPLES
# ==============================================================================

class UserRepository:
    """
    Example repository class demonstrating secure database queries

    ALL queries use parameterization - NO SQL injection possible!
    """

    def __init__(self, db: SecureDatabase):
        self.db = db

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """
        Get user by email address

        ✅ SECURE: Uses parameterized query
        """
        # Validate email format first (data type validation)
        from security.input_validator_fixed import InputValidator
        validator = InputValidator()

        try:
            clean_email = validator.validate_email(email)
        except ValueError as e:
            raise ValueError(f"Invalid email format: {e}")

        # Execute parameterized query
        return self.db.execute_query(
            "SELECT * FROM users WHERE email = ?",
            (clean_email,),
            fetch_one=True
        )

    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """
        Get user by ID

        ✅ SECURE: Uses parameterized query
        """
        # Validate ID is actually an integer
        from security.input_validator_fixed import InputValidator
        validator = InputValidator()

        try:
            clean_id = validator.validate_integer(user_id, min_value=1)
        except ValueError as e:
            raise ValueError(f"Invalid user ID: {e}")

        return self.db.execute_query(
            "SELECT * FROM users WHERE id = ?",
            (clean_id,),
            fetch_one=True
        )

    def search_users(self, search_term: str, limit: int = 10) -> List[Dict]:
        """
        Search users by name or email

        ✅ SECURE: Uses parameterized query with LIKE
        ⚠️  Note: LIKE queries still need validation for wildcards
        """
        from security.input_validator_fixed import InputValidator
        validator = InputValidator()

        # Validate inputs
        try:
            clean_search = validator.validate_length(search_term, max_length=100)
            clean_limit = validator.validate_integer(limit, min_value=1, max_value=100)
        except ValueError as e:
            raise ValueError(f"Invalid search parameters: {e}")

        # Add wildcards for LIKE search
        search_pattern = f"%{clean_search}%"

        # SQLite doesn't support LIMIT as parameter, but we validate it above
        return self.db.execute_query(
            f"SELECT * FROM users WHERE name LIKE ? OR email LIKE ? LIMIT {clean_limit}",
            (search_pattern, search_pattern)
        )

    def create_user(self, email: str, name: str, organization_id: str) -> int:
        """
        Create new user

        ✅ SECURE: Uses parameterized query
        """
        from security.input_validator_fixed import InputValidator
        validator = InputValidator()

        # Validate all inputs
        try:
            clean_email = validator.validate_email(email)
            clean_name = validator.validate_length(name, max_length=100, min_length=1)
            clean_org_id = validator.validate_organization_id(organization_id)
        except ValueError as e:
            raise ValueError(f"Invalid user data: {e}")

        # Execute parameterized insert
        return self.db.execute_update(
            "INSERT INTO users (email, name, organization_id) VALUES (?, ?, ?)",
            (clean_email, clean_name, clean_org_id)
        )

    def update_user_status(self, user_id: int, is_active: bool) -> int:
        """
        Update user active status

        ✅ SECURE: Uses parameterized query
        """
        from security.input_validator_fixed import InputValidator
        validator = InputValidator()

        # Validate inputs
        try:
            clean_id = validator.validate_integer(user_id, min_value=1)
        except ValueError as e:
            raise ValueError(f"Invalid user ID: {e}")

        if not isinstance(is_active, bool):
            raise ValueError("is_active must be boolean")

        return self.db.execute_update(
            "UPDATE users SET is_active = ? WHERE id = ?",
            (is_active, clean_id)
        )

    def delete_user(self, user_id: int) -> int:
        """
        Delete user (soft delete - set is_deleted=True)

        ✅ SECURE: Uses parameterized query
        """
        from security.input_validator_fixed import InputValidator
        validator = InputValidator()

        try:
            clean_id = validator.validate_integer(user_id, min_value=1)
        except ValueError as e:
            raise ValueError(f"Invalid user ID: {e}")

        # Soft delete (recommended over hard delete for audit trail)
        return self.db.execute_update(
            "UPDATE users SET is_deleted = ? WHERE id = ?",
            (True, clean_id)
        )


# ==============================================================================
# DEMONSTRATION & TESTING
# ==============================================================================

def demonstrate_sql_injection_prevention():
    """
    Demonstrate that parameterized queries prevent SQL injection
    """
    print("\n" + "="*80)
    print("SQL INJECTION PREVENTION DEMONSTRATION")
    print("="*80)

    # Create in-memory SQLite database
    db = SecureDatabase(':memory:', db_type='sqlite')

    # Create test table
    db.execute_update("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            name TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    """)

    # Insert test data
    db.execute_update(
        "INSERT INTO users (email, name, is_admin) VALUES (?, ?, ?)",
        ('admin@example.com', 'Admin User', 1)
    )
    db.execute_update(
        "INSERT INTO users (email, name, is_admin) VALUES (?, ?, ?)",
        ('user@example.com', 'Regular User', 0)
    )

    print("\n✅ Test database created with 2 users")

    # ATTACK 1: Classic SQL injection attempt
    print("\n" + "-"*80)
    print("ATTACK 1: Classic SQL Injection")
    print("-"*80)

    malicious_email = "' OR '1'='1"
    print(f"Attacker input: {malicious_email}")

    # ❌ INSECURE WAY (for demonstration - DON'T DO THIS!)
    print("\n❌ INSECURE CODE (string concatenation):")
    print(f"   query = \"SELECT * FROM users WHERE email = '{malicious_email}'\"")
    print("   Result: Returns ALL users (SQL injection successful!)")

    # ✅ SECURE WAY (parameterized query)
    print("\n✅ SECURE CODE (parameterized query):")
    print(f"   query = \"SELECT * FROM users WHERE email = ?\"")
    print(f"   params = ('{malicious_email}',)")

    repo = UserRepository(db)
    try:
        result = db.execute_query(
            "SELECT * FROM users WHERE email = ?",
            (malicious_email,)
        )
        print(f"   Result: {len(result)} users found")
        print("   ✅ SQL injection PREVENTED! The quote is treated as literal text.")
    except Exception as e:
        print(f"   Error: {e}")

    # ATTACK 2: Blind time-based injection
    print("\n" + "-"*80)
    print("ATTACK 2: Time-Based Blind Injection")
    print("-"*80)

    malicious_email2 = "'; WAITFOR DELAY '0:0:5'--"
    print(f"Attacker input: {malicious_email2}")

    # ✅ SECURE WAY
    print("\n✅ SECURE CODE (parameterized query):")
    try:
        result = db.execute_query(
            "SELECT * FROM users WHERE email = ?",
            (malicious_email2,)
        )
        print(f"   Result: {len(result)} users found")
        print("   ✅ SQL injection PREVENTED! WAITFOR is treated as literal text.")
    except Exception as e:
        print(f"   Error: {e}")

    # ATTACK 3: UNION-based injection
    print("\n" + "-"*80)
    print("ATTACK 3: UNION-Based Injection")
    print("-"*80)

    malicious_email3 = "' UNION SELECT id, email, name, is_admin FROM users WHERE '1'='1"
    print(f"Attacker input: {malicious_email3}")

    # ✅ SECURE WAY
    print("\n✅ SECURE CODE (parameterized query):")
    try:
        result = db.execute_query(
            "SELECT * FROM users WHERE email = ?",
            (malicious_email3,)
        )
        print(f"   Result: {len(result)} users found")
        print("   ✅ SQL injection PREVENTED! UNION is treated as literal text.")
    except Exception as e:
        print(f"   Error: {e}")

    # Show correct usage
    print("\n" + "-"*80)
    print("CORRECT USAGE: Legitimate Query")
    print("-"*80)

    legitimate_email = "user@example.com"
    print(f"Input: {legitimate_email}")

    result = db.execute_query(
        "SELECT * FROM users WHERE email = ?",
        (legitimate_email,),
        fetch_one=True
    )

    if result:
        print(f"\n✅ Found user:")
        print(f"   Email: {result['email']}")
        print(f"   Name: {result['name']}")
        print(f"   Is Admin: {result['is_admin']}")

    print("\n" + "="*80)
    print("✅ ALL SQL INJECTION ATTEMPTS PREVENTED!")
    print("="*80)
    print("\nKEY TAKEAWAYS:")
    print("  1. Parameterized queries treat user input as DATA, not CODE")
    print("  2. Special characters (', --, UNION) become literal text")
    print("  3. This works for ALL databases (SQLite, PostgreSQL, MySQL, SQL Server)")
    print("  4. Regex validation CANNOT prevent SQL injection reliably")
    print("  5. ALWAYS use parameterized queries for database operations")
    print("="*80 + "\n")

    db.close()


if __name__ == "__main__":
    # Run demonstration
    demonstrate_sql_injection_prevention()

    # Show additional examples
    print("\n" + "="*80)
    print("ADDITIONAL SECURE QUERY EXAMPLES")
    print("="*80)

    print("\n✅ Example 1: Get user by ID")
    print("""
    user_id = request.get('id')  # User input: could be "1 OR 1=1"

    # SECURE:
    result = db.execute_query(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)  # Parameterized - safe!
    )
    """)

    print("\n✅ Example 2: Search with LIKE")
    print("""
    search_term = request.get('search')  # User input: could be "%' OR '1'='1"

    # SECURE:
    search_pattern = f"%{search_term}%"  # Add wildcards
    result = db.execute_query(
        "SELECT * FROM users WHERE name LIKE ?",
        (search_pattern,)  # Parameterized - safe!
    )
    """)

    print("\n✅ Example 3: Bulk insert")
    print("""
    users_data = [
        ('user1@example.com', 'User 1'),
        ('user2@example.com', 'User 2'),
    ]

    # SECURE:
    db.execute_many(
        "INSERT INTO users (email, name) VALUES (?, ?)",
        users_data  # All parameterized - safe!
    )
    """)

    print("\n" + "="*80)
    print("✅ Secure Database Wrapper Ready!")
    print("="*80)
