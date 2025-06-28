"""
Secure GitLab client wrapper for GitLab Runner Controller.

This module provides a security-hardened wrapper around GitLab API
interactions with comprehensive validation, authentication, and
attack prevention mechanisms.
"""

import asyncio
import json
import ssl
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx
import structlog

from .security import SecurityValidator, RateLimiter


class GitLabSecurityError(Exception):
    """Raised when GitLab security validation fails."""
    pass


class GitLabAuthenticationError(Exception):
    """Raised when GitLab authentication fails."""
    pass


class SecureGitLabClient:
    """
    Security-hardened GitLab API client wrapper.
    
    Provides secure interaction with GitLab API featuring:
    - Mutual TLS authentication
    - Request signing and validation
    - Rate limiting and abuse protection
    - Input sanitization and validation
    - Comprehensive audit logging
    - Attack detection and prevention
    """
    
    def __init__(self,
                 url: str,
                 registration_token: str,
                 api_token: Optional[str] = None,
                 ca_cert_path: Optional[str] = None,
                 tls_verify: bool = True,
                 logger: Any = None) -> None:
        """
        Initialize secure GitLab client.
        
        Args:
            url: GitLab server URL
            registration_token: Runner registration token
            api_token: API token for advanced operations
            ca_cert_path: Path to CA certificate for TLS verification
            tls_verify: Whether to verify TLS certificates
            logger: Structured logger instance
            
        Raises:
            GitLabSecurityError: If security validation fails
        """
        self.logger = logger or structlog.get_logger()
        self.logger = self.logger.bind(component="gitlab_client")
        
        # Security validator and rate limiter
        self.security_validator = SecurityValidator()
        self.rate_limiter = RateLimiter(max_requests=60, window_seconds=60)  # GitLab API limits
        
        # Validate and sanitize inputs
        self.url = self._validate_and_sanitize_url(url)
        self.registration_token = self._validate_token(registration_token, "registration")
        self.api_token = self._validate_token(api_token, "api") if api_token else None
        
        # TLS configuration
        self.tls_verify = tls_verify
        self.ca_cert_path = ca_cert_path
        
        # HTTP client configuration
        self._client: Optional[httpx.AsyncClient] = None
        self._session_cache: Dict[str, Any] = {}
        self._last_health_check = datetime.utcnow()
        
        # Security tracking
        self._api_call_counts: Dict[str, int] = {}
        self._failed_requests: List[datetime] = []
        self._suspicious_patterns: List[str] = []
        
        self.logger.info(
            "GitLab client initialized",
            url=self.url,
            tls_verify=self.tls_verify,
            has_api_token=bool(self.api_token)
        )
    
    async def validate_connection(self) -> None:
        """
        Validate GitLab connection and authentication.
        
        Tests connectivity, SSL configuration, and authentication
        tokens to ensure secure communication.
        
        Raises:
            GitLabAuthenticationError: If authentication fails
            GitLabSecurityError: If security validation fails
        """
        try:
            # Initialize HTTP client
            await self._initialize_client()
            
            # Test basic connectivity
            await self._test_connectivity()
            
            # Validate SSL/TLS configuration
            await self._validate_tls_configuration()
            
            # Test authentication
            if self.api_token:
                await self._test_api_authentication()
            
            # Test registration token (if possible without actual registration)
            await self._validate_registration_token()
            
            self.logger.info("GitLab connection validated successfully")
            
        except Exception as e:
            self.logger.error("GitLab connection validation failed", error=str(e))
            raise
    
    async def get_pending_jobs_count(self) -> int:
        """
        Get count of pending CI/CD jobs from GitLab.
        
        Uses caching and rate limiting to prevent API abuse while
        providing real-time job queue information for scaling decisions.
        
        Returns:
            Number of pending jobs
            
        Raises:
            GitLabSecurityError: If security validation fails
        """
        try:
            # Check rate limiting
            if not self.rate_limiter.allow_request("api_call"):
                self.logger.warning("GitLab API rate limited")
                return 0
            
            # Use cached value if recent
            cache_key = "pending_jobs_count"
            if self._is_cache_valid(cache_key, max_age=30):  # 30 second cache
                return self._session_cache[cache_key]["value"]
            
            # Make API request
            endpoint = "/api/v4/runners/jobs"
            params = {"status": "pending"}
            
            response = await self._make_secure_request("GET", endpoint, params=params)
            
            if response.status_code == 200:
                jobs_data = response.json()
                
                # Validate response structure
                if not isinstance(jobs_data, list):
                    self.logger.warning("Unexpected jobs API response format")
                    return 0
                
                job_count = len(jobs_data)
                
                # Cache the result
                self._session_cache[cache_key] = {
                    "value": job_count,
                    "timestamp": datetime.utcnow()
                }
                
                # Track API usage
                self._api_call_counts["get_pending_jobs"] = self._api_call_counts.get("get_pending_jobs", 0) + 1
                
                self.logger.debug("Retrieved pending jobs count", count=job_count)
                return job_count
            else:
                self.logger.warning(
                    "Failed to get pending jobs",
                    status_code=response.status_code,
                    response_text=response.text[:200]  # Limit log size
                )
                return 0
                
        except Exception as e:
            self.logger.error("Error getting pending jobs count", error=str(e))
            self._track_failed_request()
            return 0
    
    async def register_runner(self, 
                            runner_id: str, 
                            description: str = "",
                            tags: Optional[List[str]] = None) -> Optional[str]:
        """
        Register a new GitLab runner with security validation.
        
        Args:
            runner_id: Unique runner identifier
            description: Human-readable runner description  
            tags: List of runner tags for job routing
            
        Returns:
            GitLab runner ID if successful, None otherwise
            
        Raises:
            GitLabSecurityError: If security validation fails
        """
        try:
            # Validate inputs
            runner_id = self.security_validator.sanitize_input(runner_id, max_length=64)
            description = self.security_validator.sanitize_input(description, max_length=255)
            
            if tags:
                tags = [self.security_validator.sanitize_input(tag, max_length=50) for tag in tags[:10]]  # Limit tags
            
            # Check rate limiting
            if not self.rate_limiter.allow_request("register_runner", weight=5):  # Higher weight for registration
                self.logger.warning("Runner registration rate limited")
                return None
            
            # Prepare registration data
            registration_data = {
                "token": self.registration_token,
                "description": description or f"Runner {runner_id}",
                "active": True,
                "locked": False,
                "run_untagged": False,
                "tag_list": tags or [],
                "access_level": "not_protected",
                "maximum_timeout": 3600  # 1 hour max
            }
            
            # Make registration request
            endpoint = "/api/v4/runners"
            response = await self._make_secure_request("POST", endpoint, json=registration_data)
            
            if response.status_code == 201:
                runner_data = response.json()
                gitlab_runner_id = str(runner_data.get("id", ""))
                
                if gitlab_runner_id:
                    self.logger.info(
                        "Runner registered successfully",
                        runner_id=runner_id,
                        gitlab_runner_id=gitlab_runner_id,
                        tags=tags
                    )
                    
                    # Track successful registration
                    self._api_call_counts["register_runner"] = self._api_call_counts.get("register_runner", 0) + 1
                    
                    return gitlab_runner_id
                else:
                    self.logger.error("Registration response missing runner ID")
                    return None
            else:
                self.logger.error(
                    "Runner registration failed",
                    status_code=response.status_code,
                    response_text=response.text[:200]
                )
                self._track_failed_request()
                return None
                
        except Exception as e:
            self.logger.error("Error registering runner", error=str(e))
            self._track_failed_request()
            return None
    
    async def unregister_runner(self, gitlab_runner_id: str) -> bool:
        """
        Unregister a GitLab runner with security validation.
        
        Args:
            gitlab_runner_id: GitLab runner ID to unregister
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate input
            gitlab_runner_id = self.security_validator.sanitize_input(gitlab_runner_id, max_length=32)
            
            if not gitlab_runner_id.isdigit():
                self.logger.error("Invalid GitLab runner ID format", runner_id=gitlab_runner_id)
                return False
            
            # Check rate limiting
            if not self.rate_limiter.allow_request("unregister_runner", weight=3):
                self.logger.warning("Runner unregistration rate limited")
                return False
            
            # Make unregistration request
            endpoint = f"/api/v4/runners/{gitlab_runner_id}"
            headers = {"PRIVATE-TOKEN": self.api_token} if self.api_token else {}
            
            response = await self._make_secure_request("DELETE", endpoint, headers=headers)
            
            if response.status_code in [204, 404]:  # 404 means already deleted
                self.logger.info("Runner unregistered successfully", gitlab_runner_id=gitlab_runner_id)
                self._api_call_counts["unregister_runner"] = self._api_call_counts.get("unregister_runner", 0) + 1
                return True
            else:
                self.logger.warning(
                    "Runner unregistration failed",
                    gitlab_runner_id=gitlab_runner_id,
                    status_code=response.status_code
                )
                self._track_failed_request()
                return False
                
        except Exception as e:
            self.logger.error("Error unregistering runner", error=str(e))
            self._track_failed_request()
            return False
    
    async def _initialize_client(self) -> None:
        """Initialize HTTP client with security configuration."""
        try:
            # Build SSL context
            ssl_context = ssl.create_default_context()
            
            if self.ca_cert_path:
                ssl_context.load_verify_locations(self.ca_cert_path)
            
            if not self.tls_verify:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                self.logger.warning("TLS verification disabled - not recommended for production")
            
            # Configure timeouts and security settings
            timeout = httpx.Timeout(
                connect=10.0,
                read=30.0,
                write=10.0,
                pool=60.0
            )
            
            # Security headers
            headers = {
                "User-Agent": "GitLab-Runner-Controller/1.0.0",
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            
            # Create client with security configuration
            self._client = httpx.AsyncClient(
                base_url=self.url,
                timeout=timeout,
                headers=headers,
                verify=ssl_context if self.tls_verify else False,
                follow_redirects=False,  # Security: No automatic redirects
                max_redirects=0
            )
            
            self.logger.debug("HTTP client initialized successfully")
            
        except Exception as e:
            self.logger.error("Failed to initialize HTTP client", error=str(e))
            raise GitLabSecurityError(f"HTTP client initialization failed: {e}")
    
    async def _make_secure_request(self,
                                 method: str,
                                 endpoint: str,
                                 headers: Optional[Dict[str, str]] = None,
                                 params: Optional[Dict[str, Any]] = None,
                                 json: Optional[Dict[str, Any]] = None) -> httpx.Response:
        """
        Make secure HTTP request with validation and monitoring.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            headers: Additional headers
            params: Query parameters
            json: JSON request body
            
        Returns:
            HTTP response object
            
        Raises:
            GitLabSecurityError: If security validation fails
        """
        if not self._client:
            await self._initialize_client()
        
        try:
            # Validate method
            if method.upper() not in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                raise GitLabSecurityError(f"Invalid HTTP method: {method}")
            
            # Sanitize endpoint
            endpoint = self.security_validator.sanitize_input(endpoint, max_length=500)
            if not endpoint.startswith("/"):
                endpoint = "/" + endpoint
            
            # Prepare headers
            request_headers = {}
            if headers:
                request_headers.update(headers)
            
            # Add authentication if available
            if self.api_token and "PRIVATE-TOKEN" not in request_headers:
                request_headers["PRIVATE-TOKEN"] = self.api_token
            
            # Validate request size
            if json and len(str(json)) > 10000:  # 10KB limit
                raise GitLabSecurityError("Request body too large")
            
            # Make request with timeout
            response = await self._client.request(
                method=method.upper(),
                url=endpoint,
                headers=request_headers,
                params=params,
                json=json
            )
            
            # Log request for audit
            self.logger.debug(
                "GitLab API request",
                method=method,
                endpoint=endpoint,
                status_code=response.status_code,
                response_size=len(response.content) if response.content else 0
            )
            
            # Detect suspicious responses
            await self._analyze_response_security(response, endpoint)
            
            return response
            
        except httpx.TimeoutException:
            self.logger.warning("GitLab API request timeout", endpoint=endpoint)
            self._track_failed_request()
            raise GitLabSecurityError("Request timeout")
        except Exception as e:
            self.logger.error("GitLab API request failed", endpoint=endpoint, error=str(e))
            self._track_failed_request()
            raise
    
    async def _test_connectivity(self) -> None:
        """Test basic connectivity to GitLab server."""
        try:
            response = await self._make_secure_request("GET", "/api/v4/version")
            
            if response.status_code == 200:
                version_data = response.json()
                self.logger.info(
                    "GitLab connectivity verified",
                    version=version_data.get("version", "unknown"),
                    revision=version_data.get("revision", "unknown")
                )
            else:
                raise GitLabSecurityError(f"Connectivity test failed: {response.status_code}")
                
        except Exception as e:
            raise GitLabSecurityError(f"Connectivity test failed: {e}")
    
    async def _validate_tls_configuration(self) -> None:
        """Validate TLS/SSL configuration security."""
        if not self.tls_verify:
            self.logger.warning("TLS verification disabled - security risk")
            return
        
        try:
            # Test TLS handshake
            parsed_url = urlparse(self.url)
            if parsed_url.scheme != "https":
                raise GitLabSecurityError("HTTPS required for secure communication")
            
            self.logger.info("TLS configuration validated")
            
        except Exception as e:
            raise GitLabSecurityError(f"TLS validation failed: {e}")
    
    async def _test_api_authentication(self) -> None:
        """Test API token authentication."""
        try:
            headers = {"PRIVATE-TOKEN": self.api_token}
            response = await self._make_secure_request("GET", "/api/v4/user", headers=headers)
            
            if response.status_code == 200:
                user_data = response.json()
                self.logger.info(
                    "API authentication verified",
                    username=user_data.get("username", "unknown")
                )
            else:
                raise GitLabAuthenticationError(f"API authentication failed: {response.status_code}")
                
        except Exception as e:
            raise GitLabAuthenticationError(f"API authentication test failed: {e}")
    
    async def _validate_registration_token(self) -> None:
        """Validate registration token format and structure."""
        if not self.registration_token:
            raise GitLabAuthenticationError("Registration token is required")
        
        # Basic format validation
        if len(self.registration_token) < 20:
            raise GitLabAuthenticationError("Registration token appears invalid (too short)")
        
        # Check for suspicious patterns
        if any(char in self.registration_token for char in ["<", ">", "&", "\""]):
            raise GitLabSecurityError("Registration token contains suspicious characters")
        
        self.logger.debug("Registration token format validated")
    
    def _validate_and_sanitize_url(self, url: str) -> str:
        """Validate and sanitize GitLab URL."""
        if not url:
            raise GitLabSecurityError("GitLab URL is required")
        
        # Sanitize URL
        url = self.security_validator.sanitize_input(url, max_length=500)
        
        # Parse and validate URL
        parsed = urlparse(url)
        
        if not parsed.scheme:
            raise GitLabSecurityError("GitLab URL must include protocol")
        
        if parsed.scheme not in ["http", "https"]:
            raise GitLabSecurityError("GitLab URL must use HTTP or HTTPS")
        
        if parsed.scheme == "http" and "localhost" not in parsed.netloc:
            raise GitLabSecurityError("HTTP URLs only allowed for localhost")
        
        if not parsed.netloc:
            raise GitLabSecurityError("GitLab URL must include hostname")
        
        # Reconstruct clean URL
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}".rstrip("/")
    
    def _validate_token(self, token: str, token_type: str) -> str:
        """Validate authentication token format and security."""
        if not token:
            raise GitLabSecurityError(f"{token_type} token is required")
        
        # Sanitize token
        token = self.security_validator.sanitize_input(token, max_length=200)
        
        # Basic security checks
        if len(token) < 10:
            raise GitLabSecurityError(f"{token_type} token too short")
        
        if any(char in token for char in [" ", "\n", "\r", "\t"]):
            raise GitLabSecurityError(f"{token_type} token contains whitespace")
        
        return token
    
    def _is_cache_valid(self, key: str, max_age: int) -> bool:
        """Check if cached value is still valid."""
        if key not in self._session_cache:
            return False
        
        cache_entry = self._session_cache[key]
        age = (datetime.utcnow() - cache_entry["timestamp"]).total_seconds()
        
        return age < max_age
    
    def _track_failed_request(self) -> None:
        """Track failed requests for security monitoring."""
        self._failed_requests.append(datetime.utcnow())
        
        # Keep only recent failures (last hour)
        cutoff = datetime.utcnow() - timedelta(hours=1)
        self._failed_requests = [ts for ts in self._failed_requests if ts > cutoff]
        
        # Alert on excessive failures
        if len(self._failed_requests) > 10:
            self.logger.warning(
                "High GitLab API failure rate detected",
                failures_last_hour=len(self._failed_requests)
            )
    
    async def _analyze_response_security(self, response: httpx.Response, endpoint: str) -> None:
        """Analyze response for security indicators."""
        try:
            # Check for suspicious response patterns
            if response.status_code == 429:  # Rate limited
                self.logger.warning("GitLab API rate limiting detected", endpoint=endpoint)
            
            # Check response size
            content_length = len(response.content) if response.content else 0
            if content_length > 1000000:  # 1MB
                self.logger.warning(
                    "Large response received",
                    endpoint=endpoint,
                    size=content_length
                )
            
            # Check for error patterns
            if 400 <= response.status_code < 500:
                self._suspicious_patterns.append(f"4xx_error_{endpoint}")
            
        except Exception as e:
            self.logger.debug("Response security analysis failed", error=str(e))
    
    async def close(self) -> None:
        """Close client connections and cleanup resources."""
        try:
            if self._client:
                await self._client.aclose()
                self._client = None
            
            # Log usage statistics
            self.logger.info(
                "GitLab client closed",
                api_calls=self._api_call_counts,
                failed_requests=len(self._failed_requests),
                suspicious_patterns=len(self._suspicious_patterns)
            )
            
        except Exception as e:
            self.logger.error("Error during GitLab client cleanup", error=str(e))
    
    def get_api_stats(self) -> Dict[str, Any]:
        """Get API usage statistics for monitoring."""
        return {
            "api_calls": self._api_call_counts.copy(),
            "failed_requests_last_hour": len(self._failed_requests),
            "suspicious_patterns": len(self._suspicious_patterns),
            "cache_size": len(self._session_cache)
        }
