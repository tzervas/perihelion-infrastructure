"""
Security utilities for GitLab Runner Controller.

This module provides comprehensive security validation, rate limiting,
input sanitization, and threat detection capabilities designed to
protect against various attack vectors.
"""

import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

import structlog
from cryptography.fernet import Fernet

from ..models.runner import RunnerProfile, SecurityContext


class SecurityError(Exception):
    """Raised when security validation fails."""
    pass


class RateLimiter:
    """
    Rate limiter with sliding window algorithm and attack detection.
    
    Provides protection against:
    - Brute force attacks
    - API abuse
    - Resource exhaustion
    - Distributed attacks
    """
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60) -> None:
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed in time window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.blocked_ips: Dict[str, datetime] = {}
        self.attack_patterns: Set[str] = set()
        
        self.logger = structlog.get_logger().bind(component="rate_limiter")
        
    def allow_request(self, identifier: str, weight: int = 1) -> bool:
        """
        Check if request is allowed based on rate limits.
        
        Args:
            identifier: Unique identifier for rate limiting (IP, user, etc.)
            weight: Request weight (default 1)
            
        Returns:
            True if request is allowed, False if rate limited
        """
        current_time = time.time()
        
        # Check if identifier is temporarily blocked
        if identifier in self.blocked_ips:
            if datetime.utcnow() < self.blocked_ips[identifier]:
                return False
            else:
                # Unblock expired entries
                del self.blocked_ips[identifier]
        
        # Clean old requests outside the window
        window_start = current_time - self.window_seconds
        request_times = self.requests[identifier]
        
        while request_times and request_times[0] < window_start:
            request_times.popleft()
        
        # Check rate limit
        current_requests = sum(1 for _ in request_times)  # Count weighted requests
        
        if current_requests + weight > self.max_requests:
            # Rate limit exceeded
            self._handle_rate_limit_violation(identifier)
            return False
        
        # Add current request(s) to the window
        for _ in range(weight):
            request_times.append(current_time)
            
        return True
    
    def _handle_rate_limit_violation(self, identifier: str) -> None:
        """Handle rate limit violations with progressive penalties."""
        self.logger.warning(
            "Rate limit violation detected",
            identifier=identifier,
            max_requests=self.max_requests,
            window_seconds=self.window_seconds
        )
        
        # Track attack patterns
        self.attack_patterns.add(identifier)
        
        # Progressive blocking: longer blocks for repeat offenders
        violation_count = len([ts for ts in self.requests[identifier] 
                             if ts > time.time() - 3600])  # Last hour
        
        if violation_count > self.max_requests * 3:
            # Severe violation - block for 1 hour
            block_duration = timedelta(hours=1)
        elif violation_count > self.max_requests * 2:
            # Moderate violation - block for 15 minutes
            block_duration = timedelta(minutes=15)
        else:
            # Minor violation - block for 5 minutes
            block_duration = timedelta(minutes=5)
            
        self.blocked_ips[identifier] = datetime.utcnow() + block_duration
        
        self.logger.warning(
            "Identifier temporarily blocked",
            identifier=identifier,
            duration=block_duration.total_seconds(),
            violation_count=violation_count
        )
    
    def is_blocked(self, identifier: str) -> bool:
        """Check if identifier is currently blocked."""
        if identifier not in self.blocked_ips:
            return False
            
        if datetime.utcnow() >= self.blocked_ips[identifier]:
            del self.blocked_ips[identifier]
            return False
            
        return True
    
    def get_remaining_requests(self, identifier: str) -> int:
        """Get remaining requests for identifier in current window."""
        current_time = time.time()
        window_start = current_time - self.window_seconds
        
        request_times = self.requests[identifier]
        current_requests = sum(1 for ts in request_times if ts >= window_start)
        
        return max(0, self.max_requests - current_requests)
    
    def reset_identifier(self, identifier: str) -> None:
        """Reset rate limits for a specific identifier (admin function)."""
        if identifier in self.requests:
            del self.requests[identifier]
        if identifier in self.blocked_ips:
            del self.blocked_ips[identifier]
        self.attack_patterns.discard(identifier)
        
        self.logger.info("Rate limit reset for identifier", identifier=identifier)


class SecurityValidator:
    """
    Comprehensive security validator for GitLab runner configurations.
    
    Validates configurations against security best practices and
    detects potential security vulnerabilities or misconfigurations.
    """
    
    def __init__(self) -> None:
        """Initialize security validator."""
        self.logger = structlog.get_logger().bind(component="security_validator")
        
        # Known vulnerable patterns
        self.dangerous_capabilities = {
            "SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE",
            "DAC_OVERRIDE", "DAC_READ_SEARCH", "SETUID", "SETGID",
            "SYS_CHROOT", "SYS_TIME", "MKNOD", "AUDIT_WRITE"
        }
        
        self.suspicious_image_patterns = [
            "latest", "alpine", "busybox", "scratch", "ubuntu"
        ]
        
        self.insecure_env_patterns = [
            "password", "token", "key", "secret", "credential",
            "auth", "api_key", "private_key", "cert"
        ]
    
    def validate_runner_profile(self, profile: RunnerProfile) -> List[str]:
        """
        Validate runner profile for security issues.
        
        Args:
            profile: Runner profile to validate
            
        Returns:
            List of security issues found
        """
        issues = []
        
        # Validate security context
        issues.extend(self._validate_security_context(profile.security_context))
        
        # Validate container image
        issues.extend(self._validate_container_image(profile.image))
        
        # Validate resource limits
        issues.extend(self._validate_resource_limits(profile.resources))
        
        # Validate environment variables
        if profile.environment_variables:
            issues.extend(self._validate_environment_variables(profile.environment_variables))
        
        # Validate concurrent jobs
        if profile.concurrent_jobs > 5:
            issues.append(f"High concurrent job count ({profile.concurrent_jobs}) may impact security")
        
        # Validate job timeout
        if profile.job_timeout > 14400:  # 4 hours
            issues.append(f"Excessive job timeout ({profile.job_timeout}s) may allow resource abuse")
        
        return issues
    
    def _validate_security_context(self, security_context: SecurityContext) -> List[str]:
        """Validate container security context."""
        issues = []
        
        # Check for root execution
        if not security_context.run_as_non_root:
            issues.append("Container configured to run as root user")
        
        # Check for privilege escalation
        if security_context.allow_privilege_escalation:
            issues.append("Privilege escalation is allowed")
        
        # Check for writable root filesystem
        if not security_context.read_only_root_filesystem:
            issues.append("Root filesystem is writable")
        
        # Check for dangerous capabilities
        for cap in security_context.capabilities_add:
            if cap in self.dangerous_capabilities:
                issues.append(f"Dangerous capability added: {cap}")
        
        # Verify ALL capabilities are dropped
        if "ALL" not in security_context.capabilities_drop:
            issues.append("Not all capabilities are dropped by default")
        
        # Check seccomp profile
        if security_context.seccomp_profile_type != "RuntimeDefault":
            issues.append(f"Non-default seccomp profile: {security_context.seccomp_profile_type}")
        
        return issues
    
    def _validate_container_image(self, image: str) -> List[str]:
        """Validate container image for security concerns."""
        issues = []
        
        # Check for latest tag
        if image.endswith(":latest") or ":" not in image:
            issues.append("Image uses 'latest' tag or no tag specified")
        
        # Check for suspicious base images
        image_name = image.split("/")[-1].split(":")[0].lower()
        if any(pattern in image_name for pattern in self.suspicious_image_patterns):
            issues.append(f"Potentially insecure base image: {image_name}")
        
        # Check for missing registry
        if "/" not in image:
            issues.append("Image does not specify registry")
        
        # Check for insecure registries
        if image.startswith("http://"):
            issues.append("Image uses insecure HTTP registry")
        
        return issues
    
    def _validate_resource_limits(self, resources: Any) -> List[str]:
        """Validate resource limits and requests."""
        issues = []
        
        # Check for missing CPU limits
        if not hasattr(resources, 'cpu_limit') or not resources.cpu_limit:
            issues.append("CPU limit not specified")
        
        # Check for missing memory limits
        if not hasattr(resources, 'memory_limit') or not resources.memory_limit:
            issues.append("Memory limit not specified")
        
        # Check for excessive resource requests
        if hasattr(resources, 'cpu_limit'):
            cpu_limit = resources.cpu_limit
            if cpu_limit.endswith('m'):
                cpu_value = int(cpu_limit[:-1])
                if cpu_value > 8000:  # 8 CPU cores
                    issues.append(f"Excessive CPU limit: {cpu_limit}")
            elif cpu_limit.isdigit():
                if int(cpu_limit) > 8:
                    issues.append(f"Excessive CPU limit: {cpu_limit}")
        
        if hasattr(resources, 'memory_limit'):
            memory_limit = resources.memory_limit
            if memory_limit.endswith('Gi'):
                memory_value = int(memory_limit[:-2])
                if memory_value > 32:  # 32 GB
                    issues.append(f"Excessive memory limit: {memory_limit}")
        
        return issues
    
    def _validate_environment_variables(self, env_vars: Dict[str, str]) -> List[str]:
        """Validate environment variables for security issues."""
        issues = []
        
        for key, value in env_vars.items():
            key_lower = key.lower()
            
            # Check for sensitive information in plain text
            if any(pattern in key_lower for pattern in self.insecure_env_patterns):
                if not (key.startswith("VAULT_") or key.endswith("_FROM_VAULT")):
                    issues.append(f"Potentially sensitive environment variable: {key}")
            
            # Check for suspicious values
            if len(value) > 1000:
                issues.append(f"Unusually long environment variable value: {key}")
            
            # Check for embedded credentials
            if any(pattern in value.lower() for pattern in ["password=", "token=", "key="]):
                issues.append(f"Potential embedded credential in: {key}")
        
        return issues
    
    def validate_pod_spec(self, pod_spec: Dict[str, Any]) -> List[str]:
        """Validate Kubernetes pod specification for security."""
        issues = []
        
        # Check pod-level security settings
        if 'spec' in pod_spec:
            spec = pod_spec['spec']
            
            # Check for host network
            if spec.get('hostNetwork', False):
                issues.append("Pod uses host network")
            
            # Check for host PID
            if spec.get('hostPID', False):
                issues.append("Pod uses host PID namespace")
            
            # Check for host IPC
            if spec.get('hostIPC', False):
                issues.append("Pod uses host IPC namespace")
            
            # Check for privileged containers
            containers = spec.get('containers', [])
            for container in containers:
                security_context = container.get('securityContext', {})
                if security_context.get('privileged', False):
                    issues.append(f"Privileged container: {container.get('name', 'unknown')}")
                
                # Check for volume mounts
                volume_mounts = container.get('volumeMounts', [])
                for mount in volume_mounts:
                    mount_path = mount.get('mountPath', '')
                    if mount_path in ['/var/run/docker.sock', '/dev', '/proc', '/sys']:
                        issues.append(f"Dangerous volume mount: {mount_path}")
        
        return issues
    
    def sanitize_input(self, input_str: str, max_length: int = 1000) -> str:
        """Sanitize user input to prevent injection attacks."""
        if not isinstance(input_str, str):
            raise SecurityError("Input must be a string")
        
        # Truncate to maximum length
        if len(input_str) > max_length:
            self.logger.warning(
                "Input truncated due to excessive length",
                original_length=len(input_str),
                max_length=max_length
            )
            input_str = input_str[:max_length]
        
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '&', '"', "'", '`', '$', '\x00']
        for char in dangerous_chars:
            input_str = input_str.replace(char, '')
        
        # Remove control characters
        input_str = ''.join(char for char in input_str if ord(char) >= 32 or char in '\t\n\r')
        
        return input_str.strip()
    
    def validate_kubernetes_name(self, name: str) -> bool:
        """Validate Kubernetes resource name format."""
        if not name:
            return False
        
        # Kubernetes naming rules
        if len(name) > 253:
            return False
        
        # Must start and end with alphanumeric
        if not (name[0].isalnum() and name[-1].isalnum()):
            return False
        
        # Only lowercase letters, numbers, and hyphens
        for char in name:
            if not (char.islower() or char.isdigit() or char == '-'):
                return False
        
        return True
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure random token."""
        return secrets.token_hex(length)
    
    def hash_sensitive_data(self, data: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hash sensitive data with salt for secure storage."""
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Use PBKDF2 for key derivation
        hash_value = hashlib.pbkdf2_hmac(
            'sha256',
            data.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # 100k iterations
        )
        
        return hash_value.hex(), salt
    
    def verify_signature(self, data: str, signature: str, secret: str) -> bool:
        """Verify HMAC signature for data integrity."""
        try:
            expected_signature = hmac.new(
                secret.encode('utf-8'),
                data.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
        except Exception:
            return False
    
    def detect_anomalous_behavior(self, 
                                  metrics: Dict[str, float],
                                  baseline: Dict[str, float],
                                  threshold: float = 2.0) -> List[str]:
        """Detect anomalous behavior based on metrics."""
        anomalies = []
        
        for metric, value in metrics.items():
            if metric in baseline:
                baseline_value = baseline[metric]
                if baseline_value > 0:  # Avoid division by zero
                    ratio = value / baseline_value
                    if ratio > threshold or ratio < (1.0 / threshold):
                        anomalies.append(
                            f"Anomalous {metric}: {value} (baseline: {baseline_value})"
                        )
        
        return anomalies
    
    def create_security_context(self, profile_name: str) -> SecurityContext:
        """Create hardened security context for runner profile."""
        return SecurityContext(
            run_as_non_root=True,
            run_as_user=1000,
            run_as_group=1000,
            fs_group=1000,
            allow_privilege_escalation=False,
            read_only_root_filesystem=True,
            capabilities_drop=["ALL"],
            capabilities_add=[],  # No additional capabilities by default
            seccomp_profile_type="RuntimeDefault"
        )
