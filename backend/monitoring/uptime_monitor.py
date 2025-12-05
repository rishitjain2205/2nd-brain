"""
Uptime Monitoring and Health Check System
Monitors system availability and performance

SOC 2 Requirements:
- A1.1: System availability monitoring
- CC7.2: System monitoring
"""

import time
import json
import psutil
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import threading


@dataclass
class HealthCheckResult:
    """Health check result"""
    component: str
    status: str  # healthy, degraded, unhealthy
    response_time_ms: float
    timestamp: str
    details: Dict[str, Any]
    error: Optional[str] = None


class UptimeMonitor:
    """
    System uptime and health monitoring

    Features:
    - Endpoint health checks
    - Database connectivity checks
    - Disk space monitoring
    - Memory usage monitoring
    - CPU usage monitoring
    - Response time tracking
    - Availability percentage calculation
    """

    def __init__(
        self,
        check_interval: int = 60,
        alert_threshold: float = 0.99,
        log_dir: str = "data/monitoring"
    ):
        """
        Initialize uptime monitor

        Args:
            check_interval: Seconds between health checks
            alert_threshold: Minimum uptime percentage (0.99 = 99%)
            log_dir: Directory for monitoring logs
        """
        self.check_interval = check_interval
        self.alert_threshold = alert_threshold
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.health_checks: List[HealthCheckResult] = []
        self.is_running = False
        self.monitor_thread = None

        print(f"✓ Uptime Monitor initialized")
        print(f"  - Check interval: {check_interval}s")
        print(f"  - Alert threshold: {alert_threshold * 100}%")

    def check_api_endpoint(self, url: str, timeout: int = 5) -> HealthCheckResult:
        """
        Check API endpoint health

        Args:
            url: Endpoint URL
            timeout: Request timeout

        Returns:
            Health check result
        """
        start_time = time.time()

        try:
            response = requests.get(url, timeout=timeout)
            response_time = (time.time() - start_time) * 1000  # ms

            status = "healthy" if response.status_code == 200 else "degraded"

            return HealthCheckResult(
                component=f"api_endpoint_{url}",
                status=status,
                response_time_ms=response_time,
                timestamp=datetime.utcnow().isoformat() + "Z",
                details={
                    "url": url,
                    "status_code": response.status_code,
                    "response_size": len(response.content)
                }
            )

        except Exception as e:
            response_time = (time.time() - start_time) * 1000

            return HealthCheckResult(
                component=f"api_endpoint_{url}",
                status="unhealthy",
                response_time_ms=response_time,
                timestamp=datetime.utcnow().isoformat() + "Z",
                details={"url": url},
                error=str(e)
            )

    def check_disk_space(self) -> HealthCheckResult:
        """Check disk space availability"""
        start_time = time.time()

        try:
            disk = psutil.disk_usage('/')
            percent_used = disk.percent

            # Status based on usage
            if percent_used < 80:
                status = "healthy"
            elif percent_used < 90:
                status = "degraded"
            else:
                status = "unhealthy"

            response_time = (time.time() - start_time) * 1000

            return HealthCheckResult(
                component="disk_space",
                status=status,
                response_time_ms=response_time,
                timestamp=datetime.utcnow().isoformat() + "Z",
                details={
                    "total_gb": disk.total / (1024**3),
                    "used_gb": disk.used / (1024**3),
                    "free_gb": disk.free / (1024**3),
                    "percent_used": percent_used
                }
            )

        except Exception as e:
            return HealthCheckResult(
                component="disk_space",
                status="unhealthy",
                response_time_ms=0,
                timestamp=datetime.utcnow().isoformat() + "Z",
                details={},
                error=str(e)
            )

    def check_memory(self) -> HealthCheckResult:
        """Check memory usage"""
        start_time = time.time()

        try:
            memory = psutil.virtual_memory()
            percent_used = memory.percent

            # Status based on usage
            if percent_used < 80:
                status = "healthy"
            elif percent_used < 90:
                status = "degraded"
            else:
                status = "unhealthy"

            response_time = (time.time() - start_time) * 1000

            return HealthCheckResult(
                component="memory",
                status=status,
                response_time_ms=response_time,
                timestamp=datetime.utcnow().isoformat() + "Z",
                details={
                    "total_gb": memory.total / (1024**3),
                    "available_gb": memory.available / (1024**3),
                    "used_gb": memory.used / (1024**3),
                    "percent_used": percent_used
                }
            )

        except Exception as e:
            return HealthCheckResult(
                component="memory",
                status="unhealthy",
                response_time_ms=0,
                timestamp=datetime.utcnow().isoformat() + "Z",
                details={},
                error=str(e)
            )

    def check_cpu(self) -> HealthCheckResult:
        """Check CPU usage"""
        start_time = time.time()

        try:
            # Get CPU usage over 1 second interval
            cpu_percent = psutil.cpu_percent(interval=1)

            # Status based on usage
            if cpu_percent < 70:
                status = "healthy"
            elif cpu_percent < 85:
                status = "degraded"
            else:
                status = "unhealthy"

            response_time = (time.time() - start_time) * 1000

            return HealthCheckResult(
                component="cpu",
                status=status,
                response_time_ms=response_time,
                timestamp=datetime.utcnow().isoformat() + "Z",
                details={
                    "percent_used": cpu_percent,
                    "cpu_count": psutil.cpu_count(),
                    "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
                }
            )

        except Exception as e:
            return HealthCheckResult(
                component="cpu",
                status="unhealthy",
                response_time_ms=0,
                timestamp=datetime.utcnow().isoformat() + "Z",
                details={},
                error=str(e)
            )

    def check_database(self) -> HealthCheckResult:
        """Check database connectivity"""
        start_time = time.time()

        try:
            # Check ChromaDB
            from indexing.vector_database import VectorDatabaseBuilder

            db = VectorDatabaseBuilder()
            # Simple collection count as health check
            collections = db.client.list_collections()

            response_time = (time.time() - start_time) * 1000

            return HealthCheckResult(
                component="database_chromadb",
                status="healthy",
                response_time_ms=response_time,
                timestamp=datetime.utcnow().isoformat() + "Z",
                details={
                    "type": "chromadb",
                    "collections_count": len(collections)
                }
            )

        except Exception as e:
            response_time = (time.time() - start_time) * 1000

            return HealthCheckResult(
                component="database_chromadb",
                status="unhealthy",
                response_time_ms=response_time,
                timestamp=datetime.utcnow().isoformat() + "Z",
                details={"type": "chromadb"},
                error=str(e)
            )

    def run_all_checks(self) -> List[HealthCheckResult]:
        """Run all health checks"""
        results = []

        # System checks
        results.append(self.check_disk_space())
        results.append(self.check_memory())
        results.append(self.check_cpu())

        # Database check
        results.append(self.check_database())

        # API endpoint check (localhost)
        results.append(self.check_api_endpoint("http://localhost:5000/api/v1/health"))

        # Store results
        self.health_checks.extend(results)

        # Log results
        self._log_health_checks(results)

        # Check for alerts
        self._check_alerts(results)

        return results

    def _log_health_checks(self, results: List[HealthCheckResult]):
        """Log health check results"""
        today = datetime.now().strftime("%Y-%m-%d")
        log_file = self.log_dir / f"health_checks_{today}.jsonl"

        with open(log_file, 'a') as f:
            for result in results:
                f.write(json.dumps(asdict(result)) + '\n')

    def _check_alerts(self, results: List[HealthCheckResult]):
        """Check if alerts should be triggered"""
        unhealthy = [r for r in results if r.status == "unhealthy"]

        if unhealthy:
            print(f"\n🚨 ALERT: {len(unhealthy)} unhealthy components!")
            for result in unhealthy:
                print(f"  ❌ {result.component}: {result.error}")

            # Log to incident logger
            try:
                from security.incident_logger import log_security_incident, IncidentType, IncidentSeverity

                log_security_incident(
                    IncidentType.SUSPICIOUS_ACTIVITY,
                    IncidentSeverity.HIGH,
                    f"System health check failed: {len(unhealthy)} components unhealthy",
                    metadata={
                        "unhealthy_components": [r.component for r in unhealthy],
                        "errors": [r.error for r in unhealthy]
                    }
                )
            except Exception:
                pass

    def get_uptime_percentage(self, hours: int = 24) -> float:
        """
        Calculate uptime percentage

        Args:
            hours: Number of hours to calculate

        Returns:
            Uptime percentage (0.0 to 1.0)
        """
        cutoff = datetime.now() - timedelta(hours=hours)

        # Read recent health checks
        total_checks = 0
        healthy_checks = 0

        for day_offset in range(int(hours / 24) + 1):
            date = datetime.now() - timedelta(days=day_offset)
            date_str = date.strftime("%Y-%m-%d")
            log_file = self.log_dir / f"health_checks_{date_str}.jsonl"

            if not log_file.exists():
                continue

            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        result = json.loads(line)
                        timestamp = datetime.fromisoformat(result['timestamp'].replace('Z', '+00:00'))

                        if timestamp < cutoff:
                            continue

                        total_checks += 1
                        if result['status'] == 'healthy':
                            healthy_checks += 1

                    except Exception:
                        continue

        if total_checks == 0:
            return 1.0  # No data = assume healthy

        return healthy_checks / total_checks

    def get_metrics(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get uptime metrics

        Args:
            hours: Hours to analyze

        Returns:
            Metrics dictionary
        """
        uptime = self.get_uptime_percentage(hours)

        return {
            "uptime_percentage": uptime * 100,
            "sla_met": uptime >= self.alert_threshold,
            "alert_threshold": self.alert_threshold * 100,
            "period_hours": hours,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def start_monitoring(self):
        """Start continuous monitoring in background thread"""
        if self.is_running:
            print("⚠️  Monitoring already running")
            return

        self.is_running = True

        def monitor_loop():
            print("✓ Uptime monitoring started")
            while self.is_running:
                self.run_all_checks()
                time.sleep(self.check_interval)

        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop monitoring"""
        self.is_running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        print("✓ Uptime monitoring stopped")


# Flask health endpoint
def init_health_endpoints(app):
    """
    Initialize health check endpoints

    Routes:
    - GET /health - Simple health check
    - GET /health/detailed - Detailed health status
    - GET /health/metrics - Uptime metrics
    """
    from flask import Blueprint, jsonify

    health = Blueprint('health', __name__)

    monitor = UptimeMonitor()

    @health.route('/health', methods=['GET'])
    def simple_health():
        """Simple health check (fast)"""
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }), 200

    @health.route('/health/detailed', methods=['GET'])
    def detailed_health():
        """Detailed health check (runs all checks)"""
        results = monitor.run_all_checks()

        overall_status = "healthy"
        if any(r.status == "unhealthy" for r in results):
            overall_status = "unhealthy"
        elif any(r.status == "degraded" for r in results):
            overall_status = "degraded"

        return jsonify({
            "status": overall_status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "checks": [asdict(r) for r in results]
        }), 200 if overall_status == "healthy" else 503

    @health.route('/health/metrics', methods=['GET'])
    def health_metrics():
        """Get uptime metrics"""
        metrics = monitor.get_metrics(hours=24)
        return jsonify(metrics), 200

    app.register_blueprint(health)
    print("✓ Health check endpoints registered")

    return monitor


if __name__ == "__main__":
    print("="*60)
    print("Uptime Monitor Test")
    print("="*60)

    # Initialize
    monitor = UptimeMonitor(check_interval=5)

    # Run checks
    print("\n1️⃣  Running health checks...")
    results = monitor.run_all_checks()

    for result in results:
        status_emoji = {"healthy": "✅", "degraded": "⚠️", "unhealthy": "❌"}
        print(f"{status_emoji.get(result.status, '❓')} {result.component}: {result.status}")
        print(f"   Response time: {result.response_time_ms:.2f}ms")
        if result.error:
            print(f"   Error: {result.error}")

    # Get metrics
    print("\n2️⃣  Uptime metrics...")
    metrics = monitor.get_metrics(hours=1)
    print(f"  Uptime: {metrics['uptime_percentage']:.2f}%")
    print(f"  SLA Met: {metrics['sla_met']}")

    # Cleanup
    import shutil
    shutil.rmtree("data/monitoring", ignore_errors=True)

    print("\n" + "="*60)
    print("✅ Uptime Monitor Working!")
    print("="*60)
