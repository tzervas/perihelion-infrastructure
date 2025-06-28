"""
Security validator tests.

Comprehensive tests for security validation, attack detection,
and defensive mechanisms implemented in the GitLab runner controller.
"""

import pytest
from datetime import datetime, timedelta

from gitlab_runner_controller.models.runner import (
    RunnerProfile,
    SecurityContext,
    ResourceRequirements,
)
from gitlab_runner_controller.utils.security import (
    SecurityValidator,
    RateLimiter,
    SecurityError,
)


class TestSecurityValidator:
    """Test security validation functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = SecurityValidator()
    
    def test_secure_profile_validation(self):
        """Test validation of secure runner profile."""
        # Create secure profile
        secure_profile = RunnerProfile(
            name="secure-test",
            description="Secure test profile",
            image="gitlab/gitlab-runner:v16.9.0",
            concurrent_jobs=1,
            job_timeout=3600,
        )
        
        # Should pass validation
        issues = self.validator.validate_runner_profile(secure_profile)
        assert len(issues) == 0
    
    def test_insecure_profile_detection(self):
        """Test detection of insecure profile configurations."""
        # Create insecure profile
        insecure_context = SecurityContext(
            run_as_non_root=False,  # Running as root
            allow_privilege_escalation=True,  # Privilege escalation allowed
            read_only_root_filesystem=False,  # Writable root filesystem
            capabilities_drop=[],  # No capabilities dropped
            capabilities_add=["SYS_ADMIN"],  # Dangerous capability
        )
        
        insecure_profile = RunnerProfile(
            name="insecure-test",
            description="Insecure test profile",
            image="ubuntu:latest",  # Latest tag
            concurrent_jobs=10,  # High concurrency
            job_timeout=86400,  # 24 hour timeout
            security_context=insecure_context,
        )
        
        # Should detect multiple security issues
        issues = self.validator.validate_runner_profile(insecure_profile)
        assert len(issues) > 0
        
        # Check for specific issues
        issue_text = " ".join(issues)
        assert "root user" in issue_text
        assert "privilege escalation" in issue_text
        assert "writable" in issue_text
        assert "latest" in issue_text
        assert "SYS_ADMIN" in issue_text
    
    def test_dangerous_capabilities_detection(self):
        """Test detection of dangerous Linux capabilities."""
        dangerous_caps = [
            "SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE",
            "DAC_OVERRIDE", "SETUID", "SETGID"
        ]
        
        for cap in dangerous_caps:
            context = SecurityContext(capabilities_add=[cap])
            issues = self.validator._validate_security_context(context)
            
            assert any(cap in issue for issue in issues), f"Failed to detect {cap}"
    
    def test_image_security_validation(self):
        """Test container image security validation."""
        # Test various insecure image patterns
        insecure_images = [
            "ubuntu:latest",
            "alpine",
            "busybox:latest",
            "scratch",
            "ubuntu",  # No tag
            "malicious-registry.com/evil:v1.0",
        ]
        
        for image in insecure_images:
            issues = self.validator._validate_container_image(image)
            assert len(issues) > 0, f"Failed to detect issues with {image}"
    
    def test_environment_variable_security(self):
        """Test environment variable security validation."""
        # Test sensitive environment variables
        sensitive_env_vars = {
            "DATABASE_PASSWORD": "secret123",
            "API_TOKEN": "token_value",
            "PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----",
            "SECRET_KEY": "supersecret",
            "AUTH_CREDENTIAL": "credential",
        }
        
        issues = self.validator._validate_environment_variables(sensitive_env_vars)
        assert len(issues) > 0
        
        # Test secure environment variables (using Vault)
        secure_env_vars = {
            "VAULT_DATABASE_PASSWORD": "vault:secret/db#password",
            "CONFIG_FROM_VAULT": "vault:secret/config#key",
            "NORMAL_CONFIG": "normal_value",
        }
        
        issues = self.validator._validate_environment_variables(secure_env_vars)
        # Should only flag the normal config if it's suspicious
        assert len(issues) == 0 or all("NORMAL_CONFIG" not in issue for issue in issues)
    
    def test_input_sanitization(self):
        """Test input sanitization functionality."""
        # Test malicious inputs
        malicious_inputs = [
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "../../etc/passwd",
            "$(rm -rf /)",
            "\x00\x01\x02",  # Control characters
        ]
        
        for malicious_input in malicious_inputs:
            sanitized = self.validator.sanitize_input(malicious_input)
            
            # Should remove dangerous characters
            assert "<" not in sanitized
            assert ">" not in sanitized
            assert "'" not in sanitized
            assert "$" not in sanitized
            assert "\x00" not in sanitized
    
    def test_kubernetes_name_validation(self):
        """Test Kubernetes resource name validation."""
        # Valid names
        valid_names = [
            "valid-name",
            "valid123",
            "a-b-c-1-2-3",
            "test",
        ]
        
        for name in valid_names:
            assert self.validator.validate_kubernetes_name(name)
        
        # Invalid names
        invalid_names = [
            "Invalid-Name",  # Uppercase
            "-invalid",  # Start with hyphen
            "invalid-",  # End with hyphen
            "in_valid",  # Underscore
            "too-long-" + "a" * 250,  # Too long
            "",  # Empty
            "invalid space",  # Space
        ]
        
        for name in invalid_names:
            assert not self.validator.validate_kubernetes_name(name)
    
    def test_pod_spec_security_validation(self):
        """Test Kubernetes pod specification security validation."""
        # Insecure pod spec
        insecure_pod_spec = {
            "spec": {
                "hostNetwork": True,
                "hostPID": True,
                "hostIPC": True,
                "containers": [
                    {
                        "name": "test-container",
                        "securityContext": {
                            "privileged": True
                        },
                        "volumeMounts": [
                            {
                                "mountPath": "/var/run/docker.sock"
                            },
                            {
                                "mountPath": "/dev"
                            }
                        ]
                    }
                ]
            }
        }
        
        issues = self.validator.validate_pod_spec(insecure_pod_spec)
        assert len(issues) > 0
        
        # Check for specific security issues
        issue_text = " ".join(issues)
        assert "host network" in issue_text.lower()
        assert "host pid" in issue_text.lower()
        assert "privileged" in issue_text.lower()
        assert "docker.sock" in issue_text.lower()
    
    def test_anomaly_detection(self):
        """Test anomalous behavior detection."""
        # Normal baseline metrics
        baseline = {
            "cpu_usage": 50.0,
            "memory_usage": 60.0,
            "request_rate": 100.0,
        }
        
        # Normal metrics (should not trigger anomalies)
        normal_metrics = {
            "cpu_usage": 55.0,
            "memory_usage": 58.0,
            "request_rate": 95.0,
        }
        
        anomalies = self.validator.detect_anomalous_behavior(normal_metrics, baseline)
        assert len(anomalies) == 0
        
        # Anomalous metrics (should trigger detection)
        anomalous_metrics = {
            "cpu_usage": 200.0,  # 4x baseline
            "memory_usage": 15.0,  # Much lower than baseline
            "request_rate": 1000.0,  # 10x baseline
        }
        
        anomalies = self.validator.detect_anomalous_behavior(anomalous_metrics, baseline)
        assert len(anomalies) > 0
    
    def test_secure_token_generation(self):
        """Test secure token generation."""
        token1 = self.validator.generate_secure_token()
        token2 = self.validator.generate_secure_token()
        
        # Tokens should be different
        assert token1 != token2
        
        # Should be hex format
        assert all(c in "0123456789abcdef" for c in token1)
        assert all(c in "0123456789abcdef" for c in token2)
        
        # Should be proper length (32 bytes = 64 hex chars by default)
        assert len(token1) == 64
        assert len(token2) == 64
    
    def test_sensitive_data_hashing(self):
        """Test sensitive data hashing with salt."""
        sensitive_data = "super_secret_password"
        
        hash1, salt1 = self.validator.hash_sensitive_data(sensitive_data)
        hash2, salt2 = self.validator.hash_sensitive_data(sensitive_data)
        
        # Different salts should produce different hashes
        assert hash1 != hash2
        assert salt1 != salt2
        
        # Same data with same salt should produce same hash
        hash3, _ = self.validator.hash_sensitive_data(sensitive_data, salt1)
        assert hash1 == hash3
    
    def test_signature_verification(self):
        """Test HMAC signature verification."""
        data = "important_data_to_sign"
        secret = "shared_secret_key"
        
        # Generate valid signature
        import hmac
        import hashlib
        valid_signature = hmac.new(
            secret.encode('utf-8'),
            data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # Valid signature should verify
        assert self.validator.verify_signature(data, valid_signature, secret)
        
        # Invalid signature should not verify
        invalid_signature = "invalid_signature"
        assert not self.validator.verify_signature(data, invalid_signature, secret)
        
        # Modified data should not verify
        modified_data = "modified_data"
        assert not self.validator.verify_signature(modified_data, valid_signature, secret)


class TestRateLimiter:
    """Test rate limiting functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.rate_limiter = RateLimiter(max_requests=5, window_seconds=60)
    
    def test_normal_rate_limiting(self):
        """Test normal rate limiting behavior."""
        identifier = "test_user"
        
        # Should allow requests within limit
        for i in range(5):
            assert self.rate_limiter.allow_request(identifier)
        
        # Should block request that exceeds limit
        assert not self.rate_limiter.allow_request(identifier)
    
    def test_rate_limit_recovery(self):
        """Test rate limit recovery over time."""
        identifier = "test_user"
        
        # Exhaust rate limit
        for i in range(5):
            self.rate_limiter.allow_request(identifier)
        
        # Should be blocked
        assert not self.rate_limiter.allow_request(identifier)
        
        # Simulate time passage (in real implementation, would wait)
        # For testing, we'll manipulate the internal state
        import time
        old_time = time.time() - 70  # 70 seconds ago
        self.rate_limiter.requests[identifier].clear()
        
        # Should allow requests after window expiry
        assert self.rate_limiter.allow_request(identifier)
    
    def test_weighted_requests(self):
        """Test weighted request rate limiting."""
        identifier = "test_user"
        
        # Make weighted request
        assert self.rate_limiter.allow_request(identifier, weight=3)
        
        # Should only allow 2 more normal requests
        assert self.rate_limiter.allow_request(identifier)
        assert self.rate_limiter.allow_request(identifier)
        
        # Should block the next request
        assert not self.rate_limiter.allow_request(identifier)
    
    def test_progressive_blocking(self):
        """Test progressive blocking for repeat offenders."""
        identifier = "repeat_offender"
        
        # Simulate multiple violations
        for _ in range(3):
            # Exhaust limit
            for i in range(6):  # Exceed by 1
                self.rate_limiter.allow_request(identifier)
        
        # Should be blocked for longer periods
        assert self.rate_limiter.is_blocked(identifier)
    
    def test_remaining_requests(self):
        """Test remaining request calculation."""
        identifier = "test_user"
        
        # Initially should have full quota
        remaining = self.rate_limiter.get_remaining_requests(identifier)
        assert remaining == 5
        
        # After 2 requests, should have 3 remaining
        self.rate_limiter.allow_request(identifier)
        self.rate_limiter.allow_request(identifier)
        
        remaining = self.rate_limiter.get_remaining_requests(identifier)
        assert remaining == 3
    
    def test_identifier_reset(self):
        """Test rate limit reset functionality."""
        identifier = "test_user"
        
        # Exhaust rate limit
        for i in range(5):
            self.rate_limiter.allow_request(identifier)
        
        # Should be blocked
        assert not self.rate_limiter.allow_request(identifier)
        
        # Reset the identifier
        self.rate_limiter.reset_identifier(identifier)
        
        # Should allow requests again
        assert self.rate_limiter.allow_request(identifier)
    
    def test_multiple_identifiers(self):
        """Test rate limiting with multiple identifiers."""
        user1 = "user1"
        user2 = "user2"
        
        # Each user should have independent limits
        for i in range(5):
            assert self.rate_limiter.allow_request(user1)
            assert self.rate_limiter.allow_request(user2)
        
        # Both should be blocked after exceeding limits
        assert not self.rate_limiter.allow_request(user1)
        assert not self.rate_limiter.allow_request(user2)


class TestSecurityIntegration:
    """Integration tests for security components."""
    
    def test_comprehensive_security_validation(self):
        """Test comprehensive security validation pipeline."""
        validator = SecurityValidator()
        
        # Create a profile that should pass all security checks
        secure_profile = RunnerProfile(
            name="secure-profile",
            description="Fully secure test profile",
            image="gitlab/gitlab-runner:v16.9.0",
            concurrent_jobs=1,
            job_timeout=3600,
            environment_variables={
                "VAULT_DB_PASSWORD": "vault:secret/db#password",
                "NORMAL_CONFIG": "safe_value",
            },
        )
        
        # Should pass all validations
        issues = validator.validate_runner_profile(secure_profile)
        assert len(issues) == 0
        
        # Test that the profile generates secure pod specs
        # (This would require mocking Kubernetes client in full integration test)
    
    def test_attack_scenario_simulation(self):
        """Simulate various attack scenarios and verify defenses."""
        validator = SecurityValidator()
        rate_limiter = RateLimiter(max_requests=3, window_seconds=60)
        
        # Simulate brute force attack
        attacker = "attacker_ip"
        
        # Should initially allow requests
        for i in range(3):
            assert rate_limiter.allow_request(attacker)
        
        # Should block further requests
        for i in range(10):
            assert not rate_limiter.allow_request(attacker)
        
        # Should track the attacker
        assert attacker in rate_limiter.attack_patterns
        
        # Simulate injection attack
        malicious_input = "<script>evil()</script>'; DROP TABLE users; --"
        sanitized = validator.sanitize_input(malicious_input)
        
        # Should neutralize the attack
        assert "script" not in sanitized
        assert "DROP" not in sanitized
        assert "'" not in sanitized
    
    def test_security_monitoring_integration(self):
        """Test security monitoring and alerting integration."""
        validator = SecurityValidator()
        
        # Test anomaly detection with realistic scenarios
        baseline_metrics = {
            "request_rate": 100.0,
            "error_rate": 1.0,
            "response_time": 200.0,
        }
        
        # Simulate DDoS attack (high request rate)
        ddos_metrics = {
            "request_rate": 10000.0,  # 100x normal
            "error_rate": 50.0,       # High errors
            "response_time": 5000.0,  # Slow responses
        }
        
        anomalies = validator.detect_anomalous_behavior(ddos_metrics, baseline_metrics)
        assert len(anomalies) >= 2  # Should detect multiple anomalies
        
        # Should detect request rate and response time anomalies
        anomaly_text = " ".join(anomalies)
        assert "request_rate" in anomaly_text
        assert "response_time" in anomaly_text
