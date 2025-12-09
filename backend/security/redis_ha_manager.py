"""
Redis High Availability Manager with Fail-Closed Behavior

CRITICAL SECURITY FIX:
- Before: Redis failure might cause fail-open behavior (accepting revoked tokens)
- After: Redis failures cause fail-closed (reject ALL requests for safety)

Features:
- Redis Sentinel support (automatic failover)
- Fail-closed behavior (refuse operation on Redis failure)
- Connection pooling and retry logic
- Health monitoring and alerting
- Authentication and TLS support
"""

import os
import time
from typing import Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum


class RedisFailureMode(Enum):
    """How to handle Redis failures"""
    FAIL_CLOSED = "fail_closed"  # Reject all requests (SECURE - recommended for production)
    FAIL_OPEN = "fail_open"      # Allow all requests (INSECURE - only for dev/testing)
    CIRCUIT_BREAKER = "circuit_breaker"  # Temporary fail-open with automatic recovery


@dataclass
class RedisHAConfig:
    """Redis HA configuration"""
    # Sentinel configuration
    sentinel_hosts: list = None  # [(host1, port1), (host2, port2), (host3, port3)]
    sentinel_master_name: str = "mymaster"
    sentinel_password: Optional[str] = None

    # Single instance fallback (dev only)
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None

    # Security settings
    use_tls: bool = False
    tls_cert_file: Optional[str] = None
    tls_key_file: Optional[str] = None
    tls_ca_cert: Optional[str] = None

    # Failure handling
    failure_mode: RedisFailureMode = RedisFailureMode.FAIL_CLOSED

    # Connection settings
    socket_timeout: float = 1.0  # Short timeout for fail-fast
    socket_connect_timeout: float = 2.0
    socket_keepalive: bool = True
    max_connections: int = 50

    # Retry settings
    retry_on_timeout: bool = True
    max_retries: int = 3
    retry_delay: float = 0.1

    # Circuit breaker settings (only if failure_mode == CIRCUIT_BREAKER)
    circuit_breaker_threshold: int = 5  # Failures before opening circuit
    circuit_breaker_timeout: int = 60  # Seconds before retry


class RedisHAManager:
    """
    Redis High Availability Manager with fail-closed security

    Usage:
        # Production with Sentinel
        config = RedisHAConfig(
            sentinel_hosts=[
                ('sentinel1', 26379),
                ('sentinel2', 26379),
                ('sentinel3', 26379)
            ],
            failure_mode=RedisFailureMode.FAIL_CLOSED
        )
        redis_ha = RedisHAManager(config)

        # Dev with single instance
        redis_ha = RedisHAManager()  # Uses defaults

        # Use for JWT blacklist
        redis_ha.set('token:abc123', '{"user": "john"}', ex=3600)
        if redis_ha.exists('token:abc123'):
            # Token is blacklisted
            raise Unauthorized("Token revoked")
    """

    def __init__(
        self,
        config: Optional[RedisHAConfig] = None,
        audit_logger=None
    ):
        """
        Initialize Redis HA Manager

        Args:
            config: Redis HA configuration
            audit_logger: Audit logger for Redis failures
        """
        if config is None:
            config = RedisHAConfig(
                redis_host=os.getenv("REDIS_HOST", "localhost"),
                redis_port=int(os.getenv("REDIS_PORT", "6379")),
                redis_password=os.getenv("REDIS_PASSWORD"),
                failure_mode=RedisFailureMode.FAIL_CLOSED if os.getenv("ENVIRONMENT") == "production" else RedisFailureMode.FAIL_OPEN
            )

        self.config = config
        self.audit_logger = audit_logger
        self._client = None
        self._circuit_breaker_failures = 0
        self._circuit_breaker_opened_at = None

        # Initialize Redis connection
        self._initialize_redis()

    def _initialize_redis(self):
        """Initialize Redis connection with HA support"""
        try:
            import redis
            from redis.sentinel import Sentinel

            # Check if Sentinel is configured
            if self.config.sentinel_hosts:
                print(f"✓ Initializing Redis Sentinel HA...")

                # Create Sentinel connection
                sentinel = Sentinel(
                    self.config.sentinel_hosts,
                    sentinel_kwargs={
                        'password': self.config.sentinel_password,
                        'socket_timeout': self.config.socket_timeout,
                        'socket_connect_timeout': self.config.socket_connect_timeout
                    }
                )

                # Get master connection
                self._client = sentinel.master_for(
                    self.config.sentinel_master_name,
                    socket_timeout=self.config.socket_timeout,
                    socket_connect_timeout=self.config.socket_connect_timeout,
                    password=self.config.redis_password,
                    db=self.config.redis_db,
                    decode_responses=True,
                    max_connections=self.config.max_connections,
                    socket_keepalive=self.config.socket_keepalive,
                    retry_on_timeout=self.config.retry_on_timeout,
                    ssl=self.config.use_tls,
                    ssl_cert_reqs='required' if self.config.use_tls else None,
                    ssl_ca_certs=self.config.tls_ca_cert if self.config.use_tls else None
                )

                # Test connection
                self._client.ping()

                print(f"✅ Redis Sentinel HA: Connected")
                print(f"   Master: {self.config.sentinel_master_name}")
                print(f"   Sentinels: {len(self.config.sentinel_hosts)}")
                print(f"   Failure mode: {self.config.failure_mode.value}")

            else:
                # Single instance (dev only)
                print(f"✓ Initializing Redis single instance (DEV ONLY)...")

                self._client = redis.Redis(
                    host=self.config.redis_host,
                    port=self.config.redis_port,
                    db=self.config.redis_db,
                    password=self.config.redis_password,
                    decode_responses=True,
                    socket_timeout=self.config.socket_timeout,
                    socket_connect_timeout=self.config.socket_connect_timeout,
                    socket_keepalive=self.config.socket_keepalive,
                    max_connections=self.config.max_connections,
                    retry_on_timeout=self.config.retry_on_timeout,
                    ssl=self.config.use_tls,
                    ssl_cert_reqs='required' if self.config.use_tls else None,
                    ssl_ca_certs=self.config.tls_ca_cert if self.config.use_tls else None
                )

                # Test connection
                self._client.ping()

                print(f"✅ Redis connected: {self.config.redis_host}:{self.config.redis_port}")
                print(f"   ⚠️  WARNING: Single instance - no automatic failover")
                print(f"   Failure mode: {self.config.failure_mode.value}")

        except ImportError:
            self._handle_initialization_failure("Redis library not installed. Run: pip install redis")
        except Exception as e:
            self._handle_initialization_failure(f"Redis connection failed: {e}")

    def _handle_initialization_failure(self, error: str):
        """Handle Redis initialization failure"""
        if self.config.failure_mode == RedisFailureMode.FAIL_CLOSED:
            # FAIL-CLOSED: Refuse to start without Redis
            print(f"❌ CRITICAL: {error}")
            print("   Application CANNOT START without Redis in fail-closed mode")
            raise RuntimeError(f"Redis initialization failed (fail-closed): {error}")

        elif self.config.failure_mode == RedisFailureMode.FAIL_OPEN:
            # FAIL-OPEN: Start without Redis (INSECURE - dev only)
            print(f"⚠️  WARNING: {error}")
            print("   ⚠️  RUNNING IN FAIL-OPEN MODE - INSECURE!")
            print("   DO NOT USE IN PRODUCTION")
            self._client = None

        elif self.config.failure_mode == RedisFailureMode.CIRCUIT_BREAKER:
            # Circuit breaker: Start but monitor failures
            print(f"⚠️  WARNING: {error}")
            print("   Circuit breaker mode enabled")
            self._client = None

    def _execute_with_retry(self, operation, *args, **kwargs):
        """Execute Redis operation with retry logic"""
        last_error = None

        for attempt in range(self.config.max_retries + 1):
            try:
                # Check circuit breaker state
                if self.config.failure_mode == RedisFailureMode.CIRCUIT_BREAKER:
                    if self._is_circuit_breaker_open():
                        raise RuntimeError("Circuit breaker is OPEN - Redis unavailable")

                # Execute operation
                result = operation(*args, **kwargs)

                # Success - reset circuit breaker
                self._circuit_breaker_failures = 0
                self._circuit_breaker_opened_at = None

                return result

            except Exception as e:
                last_error = e

                # Log failure
                if self.audit_logger:
                    try:
                        self.audit_logger.log_event(
                            "redis_operation_failure",
                            {
                                "operation": operation.__name__,
                                "attempt": attempt + 1,
                                "error": str(e)
                            },
                            level="WARNING"
                        )
                    except Exception:
                        pass  # Don't crash on audit logging failure

                # Check if we should retry
                if attempt < self.config.max_retries:
                    time.sleep(self.config.retry_delay * (attempt + 1))  # Exponential backoff
                    continue
                else:
                    # All retries exhausted
                    break

        # Operation failed after all retries
        self._handle_operation_failure(operation.__name__, last_error)

    def _handle_operation_failure(self, operation_name: str, error: Exception):
        """Handle Redis operation failure according to failure mode"""
        # Increment circuit breaker counter
        if self.config.failure_mode == RedisFailureMode.CIRCUIT_BREAKER:
            self._circuit_breaker_failures += 1

            if self._circuit_breaker_failures >= self.config.circuit_breaker_threshold:
                # Open circuit breaker
                self._circuit_breaker_opened_at = time.time()
                print(f"🔴 Circuit breaker OPENED after {self._circuit_breaker_failures} failures")

                if self.audit_logger:
                    try:
                        self.audit_logger.log_event(
                            "redis_circuit_breaker_opened",
                            {
                                "failures": self._circuit_breaker_failures,
                                "threshold": self.config.circuit_breaker_threshold
                            },
                            level="CRITICAL"
                        )
                    except Exception as e:
                        # Don't crash on audit logging failure
                        print(f"⚠️  Audit logging failed: {e}")

        # Handle according to failure mode
        if self.config.failure_mode == RedisFailureMode.FAIL_CLOSED:
            # FAIL-CLOSED: Reject request for safety
            if self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        "redis_fail_closed",
                        {
                            "operation": operation_name,
                            "error": str(error)
                        },
                        level="CRITICAL"
                    )
                except Exception:
                    pass  # Don't crash on audit logging failure

            raise RuntimeError(
                f"SECURITY: Redis operation failed - rejecting request for safety. "
                f"Operation: {operation_name}, Error: {error}"
            )

        elif self.config.failure_mode == RedisFailureMode.FAIL_OPEN:
            # FAIL-OPEN: Allow request (INSECURE)
            print(f"⚠️  WARNING: Redis operation failed, allowing request (FAIL-OPEN - INSECURE)")
            print(f"   Operation: {operation_name}, Error: {error}")

            if self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        "redis_fail_open",
                        {
                            "operation": operation_name,
                            "error": str(error),
                            "warning": "INSECURE_FAIL_OPEN_MODE"
                        },
                        level="HIGH"
                    )
                except Exception:
                    pass  # Don't crash on audit logging failure

            # Return None (caller must handle)
            return None

        elif self.config.failure_mode == RedisFailureMode.CIRCUIT_BREAKER:
            # Circuit breaker: Return None if circuit open
            if self._is_circuit_breaker_open():
                print(f"🔴 Circuit breaker OPEN - rejecting request")
                raise RuntimeError("Redis circuit breaker is OPEN")
            else:
                # Circuit closed but operation failed
                return None

    def _is_circuit_breaker_open(self) -> bool:
        """Check if circuit breaker is open"""
        if self._circuit_breaker_opened_at is None:
            return False

        # Check if timeout has elapsed
        elapsed = time.time() - self._circuit_breaker_opened_at

        if elapsed >= self.config.circuit_breaker_timeout:
            # Timeout elapsed - attempt to close circuit
            print(f"🟡 Circuit breaker timeout elapsed - attempting to close")
            self._circuit_breaker_opened_at = None
            self._circuit_breaker_failures = 0
            return False

        return True

    # Redis operations with fail-safe wrappers

    def get(self, key: str) -> Optional[str]:
        """Get value from Redis (fail-safe)"""
        if self._client is None:
            return self._handle_operation_failure("get", Exception("Redis client not initialized"))

        return self._execute_with_retry(self._client.get, key)

    def set(self, key: str, value: str, ex: Optional[int] = None) -> bool:
        """Set value in Redis (fail-safe)"""
        if self._client is None:
            return self._handle_operation_failure("set", Exception("Redis client not initialized"))

        result = self._execute_with_retry(self._client.set, key, value, ex=ex)
        return result is not None

    def exists(self, key: str) -> bool:
        """Check if key exists in Redis (fail-safe)"""
        if self._client is None:
            self._handle_operation_failure("exists", Exception("Redis client not initialized"))
            return False  # Only reached in fail-open mode

        result = self._execute_with_retry(self._client.exists, key)
        return bool(result) if result is not None else False

    def delete(self, key: str) -> bool:
        """Delete key from Redis (fail-safe)"""
        if self._client is None:
            self._handle_operation_failure("delete", Exception("Redis client not initialized"))
            return False

        result = self._execute_with_retry(self._client.delete, key)
        return bool(result) if result is not None else False

    def setex(self, key: str, seconds: int, value: str) -> bool:
        """Set with expiration (fail-safe)"""
        if self._client is None:
            self._handle_operation_failure("setex", Exception("Redis client not initialized"))
            return False

        result = self._execute_with_retry(self._client.setex, key, seconds, value)
        return result is not None

    def sismember(self, set_name: str, member: str) -> bool:
        """Check set membership (fail-safe)"""
        if self._client is None:
            self._handle_operation_failure("sismember", Exception("Redis client not initialized"))
            return False

        result = self._execute_with_retry(self._client.sismember, set_name, member)
        return bool(result) if result is not None else False

    def sadd(self, set_name: str, *members) -> int:
        """Add to set (fail-safe)"""
        if self._client is None:
            self._handle_operation_failure("sadd", Exception("Redis client not initialized"))
            return 0

        result = self._execute_with_retry(self._client.sadd, set_name, *members)
        return int(result) if result is not None else 0

    def incr(self, key: str) -> int:
        """Increment counter (fail-safe)"""
        if self._client is None:
            self._handle_operation_failure("incr", Exception("Redis client not initialized"))
            return 0

        result = self._execute_with_retry(self._client.incr, key)
        return int(result) if result is not None else 0

    def expire(self, key: str, seconds: int) -> bool:
        """Set expiration (fail-safe)"""
        if self._client is None:
            self._handle_operation_failure("expire", Exception("Redis client not initialized"))
            return False

        result = self._execute_with_retry(self._client.expire, key, seconds)
        return bool(result) if result is not None else False

    def ping(self) -> bool:
        """Health check"""
        if self._client is None:
            return False

        try:
            return self._client.ping()
        except Exception:
            return False

    def get_health_status(self) -> Dict[str, Any]:
        """Get detailed health status"""
        status = {
            "connected": False,
            "mode": self.config.failure_mode.value,
            "sentinel_enabled": self.config.sentinel_hosts is not None,
            "circuit_breaker_open": False,
            "circuit_breaker_failures": 0
        }

        if self._client:
            try:
                self._client.ping()
                status["connected"] = True
            except Exception as e:
                status["error"] = str(e)

        if self.config.failure_mode == RedisFailureMode.CIRCUIT_BREAKER:
            status["circuit_breaker_open"] = self._is_circuit_breaker_open()
            status["circuit_breaker_failures"] = self._circuit_breaker_failures

        return status


if __name__ == "__main__":
    """Test Redis HA setup"""
    print("=" * 70)
    print("REDIS HA MANAGER - SETUP GUIDE")
    print("=" * 70)
    print()

    print("1. SINGLE INSTANCE (Development Only):")
    print("   docker run -d -p 6379:6379 redis:7-alpine")
    print()

    print("2. REDIS WITH AUTHENTICATION:")
    print("   docker run -d -p 6379:6379 redis:7-alpine redis-server --requirepass mypassword")
    print("   Set: REDIS_PASSWORD=mypassword")
    print()

    print("3. REDIS SENTINEL HA (Production):")
    print("   See: docker-compose-redis-ha.yml")
    print("   docker-compose -f docker-compose-redis-ha.yml up -d")
    print()

    print("4. TEST CONNECTION:")
    try:
        redis_ha = RedisHAManager()
        health = redis_ha.get_health_status()
        print(f"   Status: {health}")
    except Exception as e:
        print(f"   Error: {e}")
