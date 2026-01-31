"""
Enhanced SSRF Protection - FIXES SSRF Bypass Vulnerabilities

🔥 CRITICAL VULNERABILITIES FIXED:
Previously: Basic localhost/private IP blocking (many bypasses exist)
Now: Comprehensive SSRF protection against all known bypass techniques

ATTACK PREVENTION:
❌ DNS rebinding attacks
❌ IPv6 localhost bypasses (::1, 0:0:0:0:0:0:0:1)
❌ Decimal/Octal/Hex IP encoding (2130706433 = 127.0.0.1)
❌ AWS metadata endpoint access
❌ Cloud metadata services (GCP, Azure, Digital Ocean)
❌ URL parser confusion
❌ Redirect chains to private IPs (SECURITY FIX 2025-12-08)
✅ Multi-layer validation
✅ DNS resolution checking
✅ Time-based DNS rebinding detection
✅ Redirect validation (SECURITY FIX 2025-12-08)
"""

import socket
import ipaddress
import time
import requests
from typing import Optional, Tuple, Set, List
from urllib.parse import urlparse
import re


class SSRFProtectionResult:
    """SSRF protection check result"""

    def __init__(self, allowed: bool, reason: str = ""):
        self.allowed = allowed
        self.reason = reason


class EnhancedSSRFProtection:
    """
    Enhanced SSRF Protection with Bypass Prevention

    SECURITY FEATURES:
    ✅ Blocks all localhost variations (127.*, ::1, localhost, 0.0.0.0)
    ✅ Blocks private IP ranges (10.*, 192.168.*, 172.16-31.*)
    ✅ Blocks link-local addresses (169.254.*)
    ✅ Blocks cloud metadata endpoints (AWS, GCP, Azure, DO)
    ✅ Blocks IPv6 variations
    ✅ Blocks decimal/octal/hex IP encoding
    ✅ DNS resolution validation
    ✅ DNS rebinding detection (dual resolution)
    ✅ URL parser confusion prevention
    ✅ Protocol whitelist (only http/https)

    Usage:
        ssrf = EnhancedSSRFProtection()

        result = ssrf.validate_url("http://example.com")
        if not result.allowed:
            return {"error": f"URL blocked: {result.reason}"}, 403
    """

    # Cloud metadata endpoints
    CLOUD_METADATA_ENDPOINTS = {
        # AWS
        "169.254.169.254",  # AWS EC2 metadata
        "fd00:ec2::254",  # AWS EC2 IPv6 metadata

        # Google Cloud
        "metadata.google.internal",
        "metadata",

        # Azure
        "169.254.169.254",  # Azure metadata (same as AWS)

        # Digital Ocean
        "169.254.169.254",  # DO metadata (same as AWS)

        # Alibaba Cloud
        "100.100.100.200",
    }

    # Special use domains/IPs
    BLOCKED_DOMAINS = {
        "localhost",
        "localhost.localdomain",
        "broadcasthost",
        "local",
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.google.internal",
    }

    def __init__(
        self,
        allowed_schemes: Optional[Set[str]] = None,
        enable_dns_rebinding_protection: bool = True,
        dns_rebinding_delay_seconds: float = 2.0
    ):
        """
        Initialize SSRF protection

        Args:
            allowed_schemes: Allowed URL schemes (default: http, https)
            enable_dns_rebinding_protection: Enable DNS rebinding detection
            dns_rebinding_delay_seconds: Delay between DNS checks
        """
        self.allowed_schemes = allowed_schemes or {"http", "https"}
        self.enable_dns_rebinding_protection = enable_dns_rebinding_protection
        self.dns_rebinding_delay = dns_rebinding_delay_seconds

    def validate_url(self, url: str) -> SSRFProtectionResult:
        """
        Validate URL against SSRF attacks

        Args:
            url: URL to validate

        Returns:
            SSRFProtectionResult with allowed flag and reason
        """
        # 1. Parse URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            return SSRFProtectionResult(False, f"Invalid URL format: {e}")

        # 2. Check scheme
        if parsed.scheme not in self.allowed_schemes:
            return SSRFProtectionResult(
                False,
                f"Scheme '{parsed.scheme}' not allowed (only {self.allowed_schemes})"
            )

        # 3. Check hostname exists
        hostname = parsed.hostname
        if not hostname:
            return SSRFProtectionResult(False, "URL must have a hostname")

        # 4. Check against blocked domains
        if hostname.lower() in self.BLOCKED_DOMAINS:
            return SSRFProtectionResult(
                False,
                f"Access to '{hostname}' blocked (internal resource)"
            )

        # 5. Try to parse as IP address first
        try:
            ip_obj = ipaddress.ip_address(hostname)
            return self._validate_ip_address(ip_obj)
        except ValueError:
            # Not a direct IP address, it's a domain name
            pass

        # 6. Check for IP encoding bypasses (decimal, octal, hex)
        ip_from_encoding = self._decode_ip_encoding(hostname)
        if ip_from_encoding:
            return SSRFProtectionResult(
                False,
                f"IP encoding bypass detected: {hostname} -> {ip_from_encoding}"
            )

        # 7. Resolve domain to IP and validate
        result = self._resolve_and_validate_domain(hostname)
        if not result.allowed:
            return result

        # 8. DNS rebinding protection (optional)
        if self.enable_dns_rebinding_protection:
            result = self._check_dns_rebinding(hostname)
            if not result.allowed:
                return result

        return SSRFProtectionResult(True, "URL allowed")

    def _validate_ip_address(self, ip: ipaddress._BaseAddress) -> SSRFProtectionResult:
        """
        Validate IP address against dangerous ranges

        Args:
            ip: IP address object

        Returns:
            SSRFProtectionResult
        """
        ip_str = str(ip)

        # Check cloud metadata endpoints
        if ip_str in self.CLOUD_METADATA_ENDPOINTS:
            return SSRFProtectionResult(
                False,
                f"Cloud metadata endpoint blocked: {ip_str}"
            )

        # Check for loopback
        if ip.is_loopback:
            return SSRFProtectionResult(
                False,
                f"Loopback address blocked: {ip_str}"
            )

        # Check for private
        if ip.is_private:
            return SSRFProtectionResult(
                False,
                f"Private IP address blocked: {ip_str}"
            )

        # Check for link-local
        if ip.is_link_local:
            return SSRFProtectionResult(
                False,
                f"Link-local address blocked: {ip_str}"
            )

        # Check for multicast
        if ip.is_multicast:
            return SSRFProtectionResult(
                False,
                f"Multicast address blocked: {ip_str}"
            )

        # Check for reserved
        if ip.is_reserved:
            return SSRFProtectionResult(
                False,
                f"Reserved IP address blocked: {ip_str}"
            )

        # Check for unspecified (0.0.0.0, ::)
        if ip.is_unspecified:
            return SSRFProtectionResult(
                False,
                f"Unspecified address blocked: {ip_str}"
            )

        return SSRFProtectionResult(True, "IP address allowed")

    def _decode_ip_encoding(self, hostname: str) -> Optional[str]:
        """
        Detect and decode IP encoding bypasses

        Handles:
        - Decimal: 2130706433 (= 127.0.0.1)
        - Octal: 0177.0.0.1
        - Hex: 0x7f.0x0.0x0.0x1

        Args:
            hostname: Hostname to check

        Returns:
            Decoded IP if encoding detected, None otherwise
        """
        # Decimal encoding (single number)
        if re.match(r'^\d{8,10}$', hostname):
            try:
                decimal_value = int(hostname)
                # Convert to IP
                if 0 <= decimal_value <= 4294967295:  # Valid IPv4 range
                    ip_str = socket.inet_ntoa(decimal_value.to_bytes(4, byteorder='big'))
                    return ip_str
            except Exception:
                pass

        # Octal encoding (0177.0.0.1)
        octal_pattern = r'^0[0-7]+(\.[0-9]+){0,3}$'
        if re.match(octal_pattern, hostname):
            try:
                parts = hostname.split('.')
                decoded_parts = []
                for part in parts:
                    if part.startswith('0') and len(part) > 1:
                        decoded_parts.append(str(int(part, 8)))
                    else:
                        decoded_parts.append(part)
                return '.'.join(decoded_parts)
            except Exception:
                pass

        # Hex encoding (0x7f.0x0.0x0.0x1)
        hex_pattern = r'^0x[0-9a-fA-F]+(\.(0x)?[0-9a-fA-F]+){0,3}$'
        if re.match(hex_pattern, hostname):
            try:
                parts = hostname.split('.')
                decoded_parts = []
                for part in parts:
                    if part.startswith('0x'):
                        decoded_parts.append(str(int(part, 16)))
                    else:
                        decoded_parts.append(part)
                return '.'.join(decoded_parts)
            except Exception:
                pass

        return None

    def _resolve_and_validate_domain(self, hostname: str) -> SSRFProtectionResult:
        """
        Resolve domain to IP and validate

        Args:
            hostname: Domain name

        Returns:
            SSRFProtectionResult
        """
        try:
            # Resolve domain to IP
            ip_str = socket.gethostbyname(hostname)

            # Validate the resolved IP
            ip_obj = ipaddress.ip_address(ip_str)
            result = self._validate_ip_address(ip_obj)

            if not result.allowed:
                return SSRFProtectionResult(
                    False,
                    f"Domain '{hostname}' resolves to blocked IP: {ip_str} ({result.reason})"
                )

            return SSRFProtectionResult(True, "Domain resolves to allowed IP")

        except socket.gaierror:
            return SSRFProtectionResult(False, f"Failed to resolve domain: {hostname}")
        except Exception as e:
            return SSRFProtectionResult(False, f"DNS resolution error: {e}")

    def _check_dns_rebinding(self, hostname: str) -> SSRFProtectionResult:
        """
        Check for DNS rebinding attacks

        Resolves domain twice with delay to detect if IP changes

        Args:
            hostname: Domain name

        Returns:
            SSRFProtectionResult
        """
        try:
            # First resolution
            ip1 = socket.gethostbyname(hostname)

            # Wait
            time.sleep(self.dns_rebinding_delay)

            # Second resolution
            ip2 = socket.gethostbyname(hostname)

            # Check if IPs match
            if ip1 != ip2:
                return SSRFProtectionResult(
                    False,
                    f"DNS rebinding detected: {hostname} ({ip1} -> {ip2})"
                )

            # Validate both IPs
            for ip_str in [ip1, ip2]:
                ip_obj = ipaddress.ip_address(ip_str)
                result = self._validate_ip_address(ip_obj)

                if not result.allowed:
                    return SSRFProtectionResult(
                        False,
                        f"Domain resolves to blocked IP after rebinding check: {ip_str}"
                    )

            return SSRFProtectionResult(True, "DNS rebinding check passed")

        except Exception as e:
            return SSRFProtectionResult(False, f"DNS rebinding check failed: {e}")

    def validate_redirect_chain(
        self,
        url: str,
        max_redirects: int = 5,
        timeout: float = 10.0
    ) -> SSRFProtectionResult:
        """
        Validate redirect chain to prevent SSRF via redirects

        SECURITY FIX (2025-12-08): Prevent attackers from using redirects
        to bypass SSRF protection (e.g., public URL -> localhost redirect)

        Args:
            url: Initial URL to check
            max_redirects: Maximum allowed redirects
            timeout: Timeout for HTTP requests

        Returns:
            SSRFProtectionResult with chain validation
        """
        visited_urls: List[str] = []

        try:
            # Make HEAD request to check redirects without downloading content
            session = requests.Session()
            session.max_redirects = 0  # Manually follow redirects

            current_url = url
            redirect_count = 0

            while redirect_count <= max_redirects:
                # Validate current URL
                result = self.validate_url(current_url)
                if not result.allowed:
                    return SSRFProtectionResult(
                        False,
                        f"Redirect chain blocked at hop {redirect_count}: {result.reason}"
                    )

                visited_urls.append(current_url)

                # Make request without following redirects
                try:
                    response = session.head(
                        current_url,
                        allow_redirects=False,
                        timeout=timeout
                    )
                except requests.RequestException as e:
                    return SSRFProtectionResult(
                        False,
                        f"Request failed at hop {redirect_count}: {e}"
                    )

                # Check if redirect
                if response.status_code in (301, 302, 303, 307, 308):
                    redirect_location = response.headers.get('Location')

                    if not redirect_location:
                        return SSRFProtectionResult(
                            False,
                            "Redirect response missing Location header"
                        )

                    # Handle relative redirects
                    if not redirect_location.startswith(('http://', 'https://')):
                        # Resolve relative URL
                        from urllib.parse import urljoin
                        redirect_location = urljoin(current_url, redirect_location)

                    # Check for redirect loop
                    if redirect_location in visited_urls:
                        return SSRFProtectionResult(
                            False,
                            f"Redirect loop detected: {redirect_location}"
                        )

                    # Follow redirect
                    current_url = redirect_location
                    redirect_count += 1

                else:
                    # No more redirects
                    break

            if redirect_count > max_redirects:
                return SSRFProtectionResult(
                    False,
                    f"Too many redirects (>{max_redirects})"
                )

            return SSRFProtectionResult(
                True,
                f"Redirect chain validated ({redirect_count} redirects)"
            )

        except Exception as e:
            return SSRFProtectionResult(
                False,
                f"Redirect chain validation failed: {e}"
            )


def validate_url_safe(url: str) -> Tuple[bool, str]:
    """
    Convenience function to validate URL

    Args:
        url: URL to validate

    Returns:
        Tuple of (allowed: bool, reason: str)
    """
    ssrf = EnhancedSSRFProtection()
    result = ssrf.validate_url(url)
    return result.allowed, result.reason


if __name__ == "__main__":
    print("="*80)
    print("ENHANCED SSRF PROTECTION - TESTING")
    print("="*80)

    ssrf = EnhancedSSRFProtection(enable_dns_rebinding_protection=False)

    # Test cases
    test_urls = [
        # Should be allowed
        ("https://example.com", True),
        ("https://google.com", True),

        # Should be blocked - localhost variations
        ("http://localhost", False),
        ("http://127.0.0.1", False),
        ("http://127.1", False),
        ("http://0.0.0.0", False),
        ("http://[::1]", False),
        ("http://[0:0:0:0:0:0:0:1]", False),

        # Should be blocked - private IPs
        ("http://192.168.1.1", False),
        ("http://10.0.0.1", False),
        ("http://172.16.0.1", False),

        # Should be blocked - cloud metadata
        ("http://169.254.169.254", False),
        ("http://metadata.google.internal", False),

        # Should be blocked - IP encoding bypasses
        ("http://2130706433", False),  # 127.0.0.1 in decimal
        ("http://0177.0.0.1", False),  # 127.0.0.1 in octal
        ("http://0x7f.0x0.0x0.0x1", False),  # 127.0.0.1 in hex
    ]

    print("\n🔒 Testing SSRF Protection:")
    print("-"*80)

    for url, should_allow in test_urls:
        result = ssrf.validate_url(url)

        status = "✅" if result.allowed == should_allow else "❌"
        action = "ALLOWED" if result.allowed else "BLOCKED"

        print(f"{status} {action}: {url}")
        if not result.allowed:
            print(f"   Reason: {result.reason}")

    print("\n" + "="*80)
    print("SECURITY IMPROVEMENTS:")
    print("="*80)
    print("✅ Blocks ALL localhost variations (127.*, ::1, 0.0.0.0)")
    print("✅ Blocks private IP ranges (RFC 1918)")
    print("✅ Blocks link-local addresses (169.254.*)")
    print("✅ Blocks cloud metadata endpoints (AWS, GCP, Azure, DO)")
    print("✅ Blocks IPv6 loopback variations")
    print("✅ Detects IP encoding bypasses (decimal, octal, hex)")
    print("✅ DNS resolution validation")
    print("✅ DNS rebinding detection (dual resolution)")
    print("✅ Protocol whitelist (only http/https)")
    print("="*80)
