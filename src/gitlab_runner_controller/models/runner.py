"""
GitLab Runner models with comprehensive type safety and security features.

This module defines the core data models for GitLab runners, including
runner profiles, scaling policies, and status tracking with proper
validation and security constraints.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, validator, root_validator
from pydantic.types import PositiveInt, SecretStr


class ScalingPolicy(str, Enum):
    """
    Scaling policy options for runner pools.
    
    Defines how the controller should scale runners based on demand
    and resource utilization patterns.
    """
    
    STATIC = "static"           # Fixed number of runners
    ADAPTIVE = "adaptive"       # Scale based on job queue and utilization
    AGGRESSIVE = "aggressive"   # Fast scaling for burst workloads
    CONSERVATIVE = "conservative" # Slow scaling for steady workloads


class RunnerStatus(str, Enum):
    """
    Runner lifecycle status enumeration.
    
    Tracks the current state of individual runners for proper
    lifecycle management and monitoring.
    """
    
    PENDING = "pending"         # Runner creation requested
    STARTING = "starting"       # Runner pod is starting
    READY = "ready"            # Runner is ready to accept jobs
    RUNNING = "running"        # Runner is executing a job
    STOPPING = "stopping"      # Runner is gracefully stopping
    FAILED = "failed"          # Runner encountered an error
    TERMINATED = "terminated"  # Runner has been terminated


class SecurityContext(BaseModel):
    """
    Container security context configuration.
    
    Defines security constraints and capabilities for runner containers
    following Pod Security Standards and principle of least privilege.
    """
    
    run_as_non_root: bool = Field(
        default=True,
        description="Require container to run as non-root user"
    )
    run_as_user: PositiveInt = Field(
        default=1000,
        description="UID to run container processes"
    )
    run_as_group: PositiveInt = Field(
        default=1000,
        description="GID to run container processes"
    )
    fs_group: PositiveInt = Field(
        default=1000,
        description="Group ID for volume ownership"
    )
    allow_privilege_escalation: bool = Field(
        default=False,
        description="Allow privilege escalation"
    )
    read_only_root_filesystem: bool = Field(
        default=True,
        description="Mount root filesystem as read-only"
    )
    capabilities_drop: List[str] = Field(
        default_factory=lambda: ["ALL"],
        description="Capabilities to drop from container"
    )
    capabilities_add: List[str] = Field(
        default_factory=list,
        description="Capabilities to add to container (use sparingly)"
    )
    seccomp_profile_type: str = Field(
        default="RuntimeDefault",
        description="Seccomp profile type for syscall filtering"
    )
    
    @validator("capabilities_add")
    def validate_capabilities(cls, v: List[str]) -> List[str]:
        """Validate that only safe capabilities are added."""
        dangerous_caps = {
            "SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE",
            "DAC_OVERRIDE", "DAC_READ_SEARCH", "SETUID", "SETGID"
        }
        
        for cap in v:
            if cap in dangerous_caps:
                raise ValueError(f"Dangerous capability {cap} not allowed")
        return v


class ResourceRequirements(BaseModel):
    """
    Container resource requirements and limits.
    
    Defines CPU, memory, and storage requirements with proper
    validation to prevent resource exhaustion attacks.
    """
    
    cpu_request: str = Field(
        default="100m",
        description="CPU request (minimum required)"
    )
    cpu_limit: str = Field(
        default="2000m", 
        description="CPU limit (maximum allowed)"
    )
    memory_request: str = Field(
        default="256Mi",
        description="Memory request (minimum required)"
    )
    memory_limit: str = Field(
        default="4Gi",
        description="Memory limit (maximum allowed)"
    )
    ephemeral_storage_request: str = Field(
        default="1Gi",
        description="Ephemeral storage request"
    )
    ephemeral_storage_limit: str = Field(
        default="10Gi",
        description="Ephemeral storage limit"
    )
    
    @validator("cpu_request", "cpu_limit")
    def validate_cpu_format(cls, v: str) -> str:
        """Validate CPU resource format."""
        if not (v.endswith("m") or v.isdigit()):
            raise ValueError("CPU must be in millicores (e.g., '100m') or cores (e.g., '1')")
        return v
    
    @validator("memory_request", "memory_limit", "ephemeral_storage_request", "ephemeral_storage_limit")
    def validate_memory_format(cls, v: str) -> str:
        """Validate memory/storage resource format."""
        valid_suffixes = ["Mi", "Gi", "Ki", "M", "G", "K"]
        if not any(v.endswith(suffix) for suffix in valid_suffixes):
            raise ValueError("Memory/Storage must have valid suffix (Mi, Gi, Ki, M, G, K)")
        return v


class RunnerProfile(BaseModel):
    """
    GitLab runner profile configuration.
    
    Defines the specifications for a runner profile including
    resource allocations, security settings, and runtime configuration.
    """
    
    name: str = Field(
        ...,
        description="Profile name (must be DNS-compatible)",
        regex=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
    )
    description: str = Field(
        default="",
        description="Human-readable profile description"
    )
    resources: ResourceRequirements = Field(
        default_factory=ResourceRequirements,
        description="Resource requirements and limits"
    )
    security_context: SecurityContext = Field(
        default_factory=SecurityContext,
        description="Container security context"
    )
    concurrent_jobs: PositiveInt = Field(
        default=1,
        le=10,
        description="Maximum concurrent jobs per runner"
    )
    job_timeout: PositiveInt = Field(
        default=3600,
        le=14400,  # 4 hours max
        description="Job timeout in seconds"
    )
    image: str = Field(
        default="gitlab/gitlab-runner:latest",
        description="Container image for runner"
    )
    node_selector: Optional[Dict[str, str]] = Field(
        default=None,
        description="Node selector for runner placement"
    )
    tolerations: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Pod tolerations for node taints"
    )
    affinity: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Pod affinity/anti-affinity rules"
    )
    environment_variables: Optional[Dict[str, str]] = Field(
        default=None,
        description="Environment variables for runner container"
    )
    tags: List[str] = Field(
        default_factory=list,
        description="GitLab runner tags for job routing"
    )
    
    @validator("image")
    def validate_image_security(cls, v: str) -> str:
        """Validate container image for security concerns."""
        # Prevent latest tag in production
        if v.endswith(":latest"):
            raise ValueError("Using 'latest' tag is not allowed for security reasons")
            
        # Ensure image has a registry
        if "/" not in v:
            raise ValueError("Image must include registry for security")
            
        return v
    
    @validator("environment_variables")
    def validate_environment_variables(cls, v: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        """Validate environment variables for security."""
        if v is None:
            return v
            
        sensitive_patterns = ["password", "token", "key", "secret", "credential"]
        for key, value in v.items():
            # Check for sensitive information in plain text
            key_lower = key.lower()
            if any(pattern in key_lower for pattern in sensitive_patterns):
                if not key.startswith("VAULT_") and not key.endswith("_FROM_VAULT"):
                    raise ValueError(f"Sensitive variable {key} should use Vault integration")
                    
        return v


class RunnerInstance(BaseModel):
    """
    Individual runner instance state and metadata.
    
    Tracks the runtime state of a specific runner instance including
    current status, job information, and lifecycle timestamps.
    """
    
    id: str = Field(
        default_factory=lambda: f"runner-{secrets.token_hex(8)}",
        description="Unique runner instance identifier"
    )
    profile_name: str = Field(
        ...,
        description="Profile this runner was created from"
    )
    status: RunnerStatus = Field(
        default=RunnerStatus.PENDING,
        description="Current runner status"
    )
    gitlab_runner_id: Optional[str] = Field(
        default=None,
        description="GitLab runner ID after registration"
    )
    pod_name: Optional[str] = Field(
        default=None,
        description="Kubernetes pod name"
    )
    node_name: Optional[str] = Field(
        default=None,
        description="Kubernetes node where runner is scheduled"
    )
    current_job_id: Optional[str] = Field(
        default=None,
        description="Currently executing job ID"
    )
    current_job_url: Optional[str] = Field(
        default=None,
        description="URL of currently executing job"
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Runner creation timestamp"
    )
    started_at: Optional[datetime] = Field(
        default=None,
        description="Runner start timestamp"
    )
    last_activity: Optional[datetime] = Field(
        default=None,
        description="Last activity timestamp"
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Error message if runner failed"
    )
    metrics: Dict[str, Union[int, float]] = Field(
        default_factory=dict,
        description="Runtime metrics and statistics"
    )
    
    @validator("gitlab_runner_id")
    def validate_gitlab_runner_id(cls, v: Optional[str]) -> Optional[str]:
        """Validate GitLab runner ID format."""
        if v is not None and not v.isdigit():
            raise ValueError("GitLab runner ID must be numeric")
        return v
    
    def is_idle(self, idle_threshold: timedelta = timedelta(minutes=30)) -> bool:
        """
        Check if runner has been idle for longer than threshold.
        
        Args:
            idle_threshold: Time threshold for considering runner idle
            
        Returns:
            True if runner has been idle longer than threshold
        """
        if self.status != RunnerStatus.READY:
            return False
            
        if self.last_activity is None:
            # If no activity recorded, use creation time
            return datetime.utcnow() - self.created_at > idle_threshold
            
        return datetime.utcnow() - self.last_activity > idle_threshold
    
    def update_activity(self) -> None:
        """Update last activity timestamp to current time."""
        self.last_activity = datetime.utcnow()
    
    class Config:
        """Pydantic configuration."""
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


class ScalingConfiguration(BaseModel):
    """
    Auto-scaling configuration for runner pools.
    
    Defines parameters for automatic scaling decisions including
    thresholds, timing, and scaling behavior.
    """
    
    policy: ScalingPolicy = Field(
        default=ScalingPolicy.ADAPTIVE,
        description="Scaling policy to use"
    )
    min_replicas: PositiveInt = Field(
        default=0,
        description="Minimum number of runners"
    )
    max_replicas: PositiveInt = Field(
        default=50,
        le=100,  # Hard limit for safety
        description="Maximum number of runners"
    )
    target_utilization: float = Field(
        default=0.8,
        ge=0.1,
        le=1.0,
        description="Target utilization percentage"
    )
    scale_up_threshold: PositiveInt = Field(
        default=5,
        description="Queue depth to trigger scale up"
    )
    scale_down_delay: PositiveInt = Field(
        default=300,
        description="Delay before scaling down (seconds)"
    )
    scale_up_delay: PositiveInt = Field(
        default=30,
        description="Delay between scale up operations (seconds)"
    )
    max_idle_time: PositiveInt = Field(
        default=1800,
        description="Maximum idle time before termination (seconds)"
    )
    cooldown_period: PositiveInt = Field(
        default=300,
        description="Cooldown period between scaling operations (seconds)"
    )
    
    @root_validator
    def validate_scaling_configuration(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """Validate scaling configuration for consistency."""
        min_replicas = values.get("min_replicas", 0)
        max_replicas = values.get("max_replicas", 50)
        
        if min_replicas >= max_replicas:
            raise ValueError("min_replicas must be less than max_replicas")
            
        return values


class GitLabConfiguration(BaseModel):
    """
    GitLab server configuration and authentication.
    
    Contains connection details and authentication information
    for communicating with GitLab API.
    """
    
    url: str = Field(
        ...,
        description="GitLab server URL"
    )
    registration_token: SecretStr = Field(
        ...,
        description="GitLab runner registration token"
    )
    api_token: Optional[SecretStr] = Field(
        default=None,
        description="GitLab API token for advanced operations"
    )
    ca_cert_path: Optional[str] = Field(
        default=None,
        description="Path to CA certificate for TLS verification"
    )
    tls_verify: bool = Field(
        default=True,
        description="Verify TLS certificates"
    )
    
    @validator("url")
    def validate_gitlab_url(cls, v: str) -> str:
        """Validate GitLab URL format."""
        if not (v.startswith("https://") or v.startswith("http://")):
            raise ValueError("GitLab URL must include protocol (https:// or http://)")
            
        # Warn about HTTP in production
        if v.startswith("http://") and "localhost" not in v:
            raise ValueError("HTTP connections not allowed for non-localhost GitLab instances")
            
        return v.rstrip("/")  # Remove trailing slash
    
    class Config:
        """Pydantic configuration."""
        # Don't include secrets in string representation
        repr_exclude = {"registration_token", "api_token"}


class ControllerConfiguration(BaseModel):
    """
    Main controller configuration.
    
    Aggregates all configuration components required for
    the GitLab runner controller operation.
    """
    
    namespace: str = Field(
        default="gitlab-runners",
        description="Kubernetes namespace for runners"
    )
    gitlab: GitLabConfiguration = Field(
        ...,
        description="GitLab server configuration"
    )
    default_profile: str = Field(
        default="default",
        description="Default runner profile to use"
    )
    profiles: Dict[str, RunnerProfile] = Field(
        default_factory=dict,
        description="Available runner profiles"
    )
    scaling: ScalingConfiguration = Field(
        default_factory=ScalingConfiguration,
        description="Auto-scaling configuration"
    )
    monitoring_port: PositiveInt = Field(
        default=8080,
        description="Port for metrics and health endpoints"
    )
    log_level: str = Field(
        default="INFO",
        regex=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$",
        description="Logging level"
    )
    enable_metrics: bool = Field(
        default=True,
        description="Enable Prometheus metrics"
    )
    enable_debug: bool = Field(
        default=False,
        description="Enable debug mode (not for production)"
    )
    
    @validator("profiles")
    def validate_profiles(cls, v: Dict[str, RunnerProfile], values: Dict[str, Any]) -> Dict[str, RunnerProfile]:
        """Validate runner profiles configuration."""
        if not v:
            # Create a default profile if none provided
            v["default"] = RunnerProfile(name="default", description="Default runner profile")
            
        # Ensure default profile exists
        default_profile = values.get("default_profile", "default")
        if default_profile not in v:
            raise ValueError(f"Default profile '{default_profile}' not found in profiles")
            
        return v
    
    class Config:
        """Pydantic configuration."""
        validate_assignment = True
        extra = "forbid"  # Prevent extra fields for security
