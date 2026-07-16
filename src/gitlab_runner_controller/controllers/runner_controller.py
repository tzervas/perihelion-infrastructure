"""
Secure GitLab Runner Controller for Kubernetes.

This module implements a production-grade GitLab runner controller with
comprehensive security measures, intelligent scaling, and attack resistance.
Designed with security-first principles and defense-in-depth strategies.
"""

import asyncio
import json
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any

import structlog
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException
from prometheus_client import Counter, Gauge, Histogram, start_http_server
import httpx
from cryptography.fernet import Fernet

from ..models.runner import (
    ControllerConfiguration,
    RunnerInstance,
    RunnerProfile,
    RunnerStatus,
    ScalingPolicy,
)
from ..utils.security import SecurityValidator, RateLimiter
from ..utils.kubernetes_client import SecureKubernetesClient
from ..utils.gitlab_client import SecureGitLabClient


# Prometheus metrics for monitoring and alerting
RUNNER_COUNT = Gauge(
    "gitlab_runner_count_total",
    "Total number of GitLab runners",
    ["status", "profile"]
)
RUNNER_OPERATIONS = Counter(
    "gitlab_runner_operations_total",
    "Total runner operations",
    ["operation", "result", "profile"]
)
SCALING_DECISIONS = Counter(
    "gitlab_runner_scaling_decisions_total",
    "Total scaling decisions made",
    ["direction", "reason", "profile"]
)
JOB_QUEUE_DEPTH = Gauge(
    "gitlab_job_queue_depth",
    "Current job queue depth"
)
RUNNER_LIFECYCLE_DURATION = Histogram(
    "gitlab_runner_lifecycle_duration_seconds",
    "Runner lifecycle duration in seconds",
    ["phase", "profile"]
)
SECURITY_EVENTS = Counter(
    "gitlab_runner_security_events_total",
    "Security events detected",
    ["event_type", "severity"]
)


class GitLabRunnerController:
    """
    Secure GitLab Runner Controller with intelligent scaling and security monitoring.
    
    This controller provides:
    - Dynamic runner pool management with security constraints
    - Intelligent auto-scaling based on workload patterns
    - Comprehensive security monitoring and threat detection
    - Attack-resistant design with input validation and rate limiting
    - Zero-trust security model with minimal privileges
    """
    
    def __init__(self, config: ControllerConfiguration) -> None:
        """
        Initialize the GitLab runner controller.
        
        Args:
            config: Controller configuration with validation
            
        Raises:
            ValueError: If configuration is invalid
            SecurityError: If security validation fails
        """
        self.config = config
        self.logger = structlog.get_logger().bind(
            component="runner_controller",
            namespace=config.namespace
        )
        
        # Security components
        self.security_validator = SecurityValidator()
        self.rate_limiter = RateLimiter(max_requests=100, window_seconds=60)
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
        
        # State management
        self.runners: Dict[str, RunnerInstance] = {}
        self.last_scaling_decision = datetime.utcnow()
        self.scaling_cooldown = timedelta(seconds=config.scaling.cooldown_period)
        self.security_events: List[Dict[str, Any]] = []
        
        # Client connections
        self.k8s_client: Optional[SecureKubernetesClient] = None
        self.gitlab_client: Optional[SecureGitLabClient] = None
        
        # Control flags
        self._running = False
        self._shutdown_event = asyncio.Event()
        
        # Track suspicious activities for security monitoring
        self._failed_operations: Dict[str, int] = {}
        self._rate_limit_violations: Set[str] = set()
        
        self.logger.info(
            "GitLab runner controller initialized",
            profiles=list(config.profiles.keys()),
            scaling_policy=config.scaling.policy,
            max_runners=config.scaling.max_replicas
        )
        
    async def start(self) -> None:
        """
        Start the GitLab runner controller.
        
        Initializes clients, starts monitoring, and begins the control loop
        with comprehensive error handling and security monitoring.
        
        Raises:
            RuntimeError: If controller is already running
            ConnectionError: If unable to connect to required services
        """
        if self._running:
            raise RuntimeError("Controller is already running")
            
        self.logger.info("Starting GitLab runner controller")
        
        try:
            # Initialize Kubernetes client with security validation
            await self._initialize_kubernetes_client()
            
            # Initialize GitLab client with authentication
            await self._initialize_gitlab_client()
            
            # Start metrics server if enabled
            if self.config.enable_metrics:
                start_http_server(self.config.monitoring_port)
                self.logger.info(
                    "Metrics server started",
                    port=self.config.monitoring_port
                )
            
            # Validate security configuration
            await self._validate_security_configuration()
            
            # Start background tasks
            tasks = [
                asyncio.create_task(self._control_loop()),
                asyncio.create_task(self._monitor_security_events()),
                asyncio.create_task(self._cleanup_failed_runners()),
                asyncio.create_task(self._update_metrics()),
            ]
            
            self._running = True
            self.logger.info("GitLab runner controller started successfully")
            
            # Wait for shutdown signal
            await self._shutdown_event.wait()
            
        except Exception as e:
            self.logger.error("Failed to start controller", error=str(e))
            SECURITY_EVENTS.labels(event_type="startup_failure", severity="high").inc()
            raise
        finally:
            # Cancel all tasks
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self._running = False
            
    async def stop(self) -> None:
        """
        Gracefully stop the GitLab runner controller.
        
        Terminates all runners, cleans up resources, and shuts down
        monitoring with proper security audit logging.
        """
        self.logger.info("Stopping GitLab runner controller")
        
        try:
            # Gracefully terminate all runners
            await self._terminate_all_runners()
            
            # Close client connections
            if self.gitlab_client:
                await self.gitlab_client.close()
            if self.k8s_client:
                await self.k8s_client.close()
                
            # Signal shutdown
            self._shutdown_event.set()
            
            self.logger.info("GitLab runner controller stopped successfully")
            
        except Exception as e:
            self.logger.error("Error during controller shutdown", error=str(e))
            SECURITY_EVENTS.labels(event_type="shutdown_error", severity="medium").inc()
            
    async def _initialize_kubernetes_client(self) -> None:
        """Initialize secure Kubernetes client with proper authentication."""
        try:
            # Load Kubernetes configuration
            try:
                config.load_incluster_config()
                self.logger.info("Loaded in-cluster Kubernetes configuration")
            except config.ConfigException:
                config.load_kube_config()
                self.logger.info("Loaded local Kubernetes configuration")
                
            # Create secure client wrapper
            self.k8s_client = SecureKubernetesClient(
                namespace=self.config.namespace,
                logger=self.logger
            )
            
            # Validate cluster access and permissions
            await self.k8s_client.validate_permissions()
            
        except Exception as e:
            self.logger.error("Failed to initialize Kubernetes client", error=str(e))
            SECURITY_EVENTS.labels(event_type="k8s_init_failure", severity="critical").inc()
            raise ConnectionError(f"Kubernetes initialization failed: {e}")
            
    async def _initialize_gitlab_client(self) -> None:
        """Initialize secure GitLab client with authentication validation."""
        try:
            self.gitlab_client = SecureGitLabClient(
                url=self.config.gitlab.url,
                registration_token=self.config.gitlab.registration_token.get_secret_value(),
                api_token=self.config.gitlab.api_token.get_secret_value() if self.config.gitlab.api_token else None,
                ca_cert_path=self.config.gitlab.ca_cert_path,
                tls_verify=self.config.gitlab.tls_verify,
                logger=self.logger
            )
            
            # Validate GitLab connectivity and authentication
            await self.gitlab_client.validate_connection()
            
        except Exception as e:
            self.logger.error("Failed to initialize GitLab client", error=str(e))
            SECURITY_EVENTS.labels(event_type="gitlab_init_failure", severity="critical").inc()
            raise ConnectionError(f"GitLab initialization failed: {e}")
            
    async def _validate_security_configuration(self) -> None:
        """Validate security configuration and detect potential vulnerabilities."""
        try:
            # Validate runner profiles for security compliance
            for profile_name, profile in self.config.profiles.items():
                issues = self.security_validator.validate_runner_profile(profile)
                if issues:
                    self.logger.warning(
                        "Security issues found in runner profile",
                        profile=profile_name,
                        issues=issues
                    )
                    SECURITY_EVENTS.labels(event_type="profile_security_warning", severity="medium").inc()
                    
            # Validate namespace security policies
            await self.k8s_client.validate_namespace_security()
            
            # Check for suspicious configuration patterns
            if self.config.enable_debug:
                self.logger.warning(
                    "Debug mode enabled - not recommended for production",
                    environment="production"
                )
                SECURITY_EVENTS.labels(event_type="debug_mode_warning", severity="low").inc()
                
        except Exception as e:
            self.logger.error("Security validation failed", error=str(e))
            SECURITY_EVENTS.labels(event_type="security_validation_failure", severity="high").inc()
            raise
            
    async def _control_loop(self) -> None:
        """Main control loop with security monitoring and intelligent scaling."""
        self.logger.info("Starting main control loop")
        
        while self._running:
            try:
                # Check rate limiting to prevent abuse
                if not self.rate_limiter.allow_request("control_loop"):
                    self.logger.warning("Control loop rate limited")
                    SECURITY_EVENTS.labels(event_type="rate_limit_violation", severity="medium").inc()
                    await asyncio.sleep(5)
                    continue
                    
                # Update runner states from Kubernetes
                await self._sync_runner_states()
                
                # Get current job queue information
                queue_depth = await self._get_job_queue_depth()
                JOB_QUEUE_DEPTH.set(queue_depth)
                
                # Make scaling decisions
                await self._make_scaling_decision(queue_depth)
                
                # Clean up failed/idle runners
                await self._cleanup_idle_runners()
                
                # Update metrics
                self._update_runner_metrics()
                
                # Check for security anomalies
                await self._detect_security_anomalies()
                
                await asyncio.sleep(10)  # Control loop interval
                
            except Exception as e:
                self.logger.error("Error in control loop", error=str(e))
                SECURITY_EVENTS.labels(event_type="control_loop_error", severity="high").inc()
                await asyncio.sleep(30)  # Back off on errors
                
    async def _sync_runner_states(self) -> None:
        """Synchronize runner states with Kubernetes cluster."""
        try:
            # Get all runner pods from Kubernetes
            pods = await self.k8s_client.list_runner_pods()
            
            # Update existing runner states
            for runner_id, runner in list(self.runners.items()):
                pod = next((p for p in pods if p.metadata.name == runner.pod_name), None)
                
                if pod is None:
                    # Pod no longer exists
                    if runner.status not in [RunnerStatus.TERMINATED, RunnerStatus.FAILED]:
                        self.logger.warning(
                            "Runner pod disappeared unexpectedly",
                            runner_id=runner_id,
                            pod_name=runner.pod_name
                        )
                        runner.status = RunnerStatus.FAILED
                        runner.error_message = "Pod disappeared unexpectedly"
                        SECURITY_EVENTS.labels(event_type="pod_disappeared", severity="medium").inc()
                else:
                    # Update runner status based on pod state
                    await self._update_runner_from_pod(runner, pod)
                    
            # Detect orphaned pods (pods without corresponding runner objects)
            runner_pod_names = {r.pod_name for r in self.runners.values() if r.pod_name}
            for pod in pods:
                if pod.metadata.name not in runner_pod_names:
                    self.logger.warning(
                        "Found orphaned runner pod",
                        pod_name=pod.metadata.name,
                        pod_namespace=pod.metadata.namespace
                    )
                    SECURITY_EVENTS.labels(event_type="orphaned_pod", severity="medium").inc()
                    # Optionally clean up orphaned pods
                    await self.k8s_client.delete_pod(pod.metadata.name)
                    
        except Exception as e:
            self.logger.error("Failed to sync runner states", error=str(e))
            RUNNER_OPERATIONS.labels(operation="sync_states", result="failure", profile="all").inc()
            
    async def _update_runner_from_pod(self, runner: RunnerInstance, pod: Any) -> None:
        """Update runner instance from Kubernetes pod state."""
        pod_phase = pod.status.phase
        
        # Update basic information
        runner.node_name = pod.spec.node_name
        
        # Map Kubernetes pod phase to runner status
        if pod_phase == "Pending":
            if runner.status == RunnerStatus.PENDING:
                runner.status = RunnerStatus.STARTING
        elif pod_phase == "Running":
            if runner.status in [RunnerStatus.PENDING, RunnerStatus.STARTING]:
                runner.status = RunnerStatus.READY
                runner.started_at = datetime.utcnow()
                RUNNER_LIFECYCLE_DURATION.labels(
                    phase="startup", 
                    profile=runner.profile_name
                ).observe(
                    (runner.started_at - runner.created_at).total_seconds()
                )
        elif pod_phase in ["Failed", "Succeeded"]:
            if runner.status != RunnerStatus.TERMINATED:
                runner.status = RunnerStatus.FAILED if pod_phase == "Failed" else RunnerStatus.TERMINATED
                if pod.status.container_statuses:
                    for container_status in pod.status.container_statuses:
                        if container_status.state.terminated:
                            runner.error_message = container_status.state.terminated.reason
                            
        # Check for security events in pod events
        await self._check_pod_security_events(runner, pod)
        
    async def _check_pod_security_events(self, runner: RunnerInstance, pod: Any) -> None:
        """Check for security-related events in pod lifecycle."""
        try:
            # Get pod events
            events = await self.k8s_client.get_pod_events(pod.metadata.name)
            
            for event in events:
                event_reason = event.reason.lower()
                event_message = event.message.lower()
                
                # Detect suspicious events
                suspicious_patterns = [
                    "failed to pull image",
                    "image pull backoff",
                    "crashloopbackoff",
                    "oomkilled",
                    "security context",
                    "privilege escalation",
                ]
                
                if any(pattern in event_reason or pattern in event_message 
                       for pattern in suspicious_patterns):
                    self.logger.warning(
                        "Suspicious pod event detected",
                        runner_id=runner.id,
                        pod_name=pod.metadata.name,
                        event_reason=event.reason,
                        event_message=event.message
                    )
                    SECURITY_EVENTS.labels(event_type="suspicious_pod_event", severity="medium").inc()
                    
        except Exception as e:
            self.logger.debug("Failed to check pod events", error=str(e))
            
    async def _get_job_queue_depth(self) -> int:
        """Get current GitLab job queue depth with caching and validation."""
        try:
            # Rate limit GitLab API calls
            if not self.rate_limiter.allow_request("gitlab_api"):
                self.logger.debug("GitLab API rate limited")
                return 0
                
            # Get pending jobs from GitLab
            queue_depth = await self.gitlab_client.get_pending_jobs_count()
            
            # Validate reasonable queue depth (detect potential API manipulation)
            if queue_depth > 10000:  # Sanity check
                self.logger.warning(
                    "Extremely high queue depth detected",
                    queue_depth=queue_depth
                )
                SECURITY_EVENTS.labels(event_type="suspicious_queue_depth", severity="medium").inc()
                return min(queue_depth, 1000)  # Cap at reasonable value
                
            return queue_depth
            
        except Exception as e:
            self.logger.error("Failed to get job queue depth", error=str(e))
            return 0
            
    async def _make_scaling_decision(self, queue_depth: int) -> None:
        """Make intelligent scaling decisions based on current state and policy."""
        # Check if we're in cooldown period
        if datetime.utcnow() - self.last_scaling_decision < self.scaling_cooldown:
            return
            
        try:
            current_runners = len([r for r in self.runners.values() 
                                  if r.status in [RunnerStatus.READY, RunnerStatus.RUNNING]])
            
            scaling_config = self.config.scaling
            
            # Determine scaling action based on policy
            if scaling_config.policy == ScalingPolicy.STATIC:
                target_runners = scaling_config.min_replicas
            else:
                target_runners = self._calculate_target_runners(queue_depth, current_runners)
                
            # Apply scaling constraints
            target_runners = max(scaling_config.min_replicas, 
                               min(target_runners, scaling_config.max_replicas))
            
            # Execute scaling action
            if target_runners > current_runners:
                await self._scale_up(target_runners - current_runners)
            elif target_runners < current_runners:
                await self._scale_down(current_runners - target_runners)
                
        except Exception as e:
            self.logger.error("Failed to make scaling decision", error=str(e))
            SECURITY_EVENTS.labels(event_type="scaling_decision_error", severity="medium").inc()
            
    def _calculate_target_runners(self, queue_depth: int, current_runners: int) -> int:
        """Calculate target number of runners based on intelligent algorithms."""
        scaling_config = self.config.scaling
        
        if scaling_config.policy == ScalingPolicy.AGGRESSIVE:
            # Scale quickly for burst workloads
            if queue_depth > scaling_config.scale_up_threshold:
                return current_runners + max(1, queue_depth // 2)
            elif queue_depth == 0:
                return max(scaling_config.min_replicas, current_runners - 2)
        elif scaling_config.policy == ScalingPolicy.CONSERVATIVE:
            # Scale slowly for steady workloads
            if queue_depth > scaling_config.scale_up_threshold * 2:
                return current_runners + 1
            elif queue_depth == 0:
                return max(scaling_config.min_replicas, current_runners - 1)
        else:  # ADAPTIVE
            # Balance between responsiveness and stability
            utilization = queue_depth / max(current_runners, 1)
            
            if utilization > scaling_config.target_utilization * 1.5:
                return current_runners + max(1, queue_depth // 3)
            elif utilization < scaling_config.target_utilization * 0.3 and queue_depth == 0:
                return max(scaling_config.min_replicas, current_runners - 1)
                
        return current_runners
        
    async def _scale_up(self, count: int) -> None:
        """Scale up runner pool with security validation."""
        self.logger.info("Scaling up runners", count=count)
        
        try:
            for _ in range(count):
                # Select profile (could be enhanced with intelligent selection)
                profile = self.config.profiles[self.config.default_profile]
                
                # Create new runner instance
                runner = RunnerInstance(profile_name=profile.name)
                
                # Deploy runner pod with security constraints
                success = await self._deploy_runner_pod(runner, profile)
                
                if success:
                    self.runners[runner.id] = runner
                    RUNNER_OPERATIONS.labels(
                        operation="scale_up", 
                        result="success", 
                        profile=profile.name
                    ).inc()
                    SCALING_DECISIONS.labels(
                        direction="up", 
                        reason="queue_depth", 
                        profile=profile.name
                    ).inc()
                else:
                    RUNNER_OPERATIONS.labels(
                        operation="scale_up", 
                        result="failure", 
                        profile=profile.name
                    ).inc()
                    
            self.last_scaling_decision = datetime.utcnow()
            
        except Exception as e:
            self.logger.error("Failed to scale up", error=str(e))
            SECURITY_EVENTS.labels(event_type="scale_up_error", severity="medium").inc()
            
    async def _scale_down(self, count: int) -> None:
        """Scale down runner pool gracefully."""
        self.logger.info("Scaling down runners", count=count)
        
        try:
            # Select idle runners for termination
            idle_runners = [
                r for r in self.runners.values()
                if r.status == RunnerStatus.READY and r.is_idle()
            ]
            
            # Sort by idle time (longest idle first)
            idle_runners.sort(
                key=lambda r: r.last_activity or r.created_at
            )
            
            # Terminate selected runners
            terminated_count = 0
            for runner in idle_runners[:count]:
                success = await self._terminate_runner(runner)
                if success:
                    terminated_count += 1
                    RUNNER_OPERATIONS.labels(
                        operation="scale_down", 
                        result="success", 
                        profile=runner.profile_name
                    ).inc()
                    SCALING_DECISIONS.labels(
                        direction="down", 
                        reason="idle_timeout", 
                        profile=runner.profile_name
                    ).inc()
                    
            self.logger.info("Scaled down runners", terminated=terminated_count)
            self.last_scaling_decision = datetime.utcnow()
            
        except Exception as e:
            self.logger.error("Failed to scale down", error=str(e))
            SECURITY_EVENTS.labels(event_type="scale_down_error", severity="medium").inc()
            
    async def _deploy_runner_pod(self, runner: RunnerInstance, profile: RunnerProfile) -> bool:
        """Deploy runner pod with comprehensive security hardening."""
        try:
            # Generate unique pod name
            pod_name = f"gitlab-runner-{runner.id}"
            runner.pod_name = pod_name
            
            # Create pod specification with security context
            pod_spec = await self.k8s_client.create_runner_pod_spec(
                name=pod_name,
                profile=profile,
                runner_id=runner.id
            )
            
            # Deploy pod
            success = await self.k8s_client.create_pod(pod_spec)
            
            if success:
                self.logger.info(
                    "Runner pod deployed successfully",
                    runner_id=runner.id,
                    pod_name=pod_name,
                    profile=profile.name
                )
                return True
            else:
                self.logger.error(
                    "Failed to deploy runner pod",
                    runner_id=runner.id,
                    pod_name=pod_name
                )
                return False
                
        except Exception as e:
            self.logger.error(
                "Exception during pod deployment",
                runner_id=runner.id,
                error=str(e)
            )
            SECURITY_EVENTS.labels(event_type="pod_deployment_error", severity="medium").inc()
            return False
            
    async def _terminate_runner(self, runner: RunnerInstance) -> bool:
        """Gracefully terminate a runner with proper cleanup."""
        try:
            self.logger.info(
                "Terminating runner",
                runner_id=runner.id,
                pod_name=runner.pod_name
            )
            
            # Unregister from GitLab if registered
            if runner.gitlab_runner_id and self.gitlab_client:
                await self.gitlab_client.unregister_runner(runner.gitlab_runner_id)
                
            # Delete Kubernetes pod
            if runner.pod_name and self.k8s_client:
                success = await self.k8s_client.delete_pod(runner.pod_name)
                if not success:
                    self.logger.warning(
                        "Failed to delete runner pod",
                        runner_id=runner.id,
                        pod_name=runner.pod_name
                    )
                    
            # Update runner status
            runner.status = RunnerStatus.TERMINATED
            
            # Record lifecycle duration
            if runner.started_at:
                duration = (datetime.utcnow() - runner.started_at).total_seconds()
                RUNNER_LIFECYCLE_DURATION.labels(
                    phase="total", 
                    profile=runner.profile_name
                ).observe(duration)
                
            return True
            
        except Exception as e:
            self.logger.error(
                "Failed to terminate runner",
                runner_id=runner.id,
                error=str(e)
            )
            return False
            
    async def _cleanup_idle_runners(self) -> None:
        """Clean up idle and failed runners."""
        try:
            max_idle_time = timedelta(seconds=self.config.scaling.max_idle_time)
            current_time = datetime.utcnow()
            
            runners_to_remove = []
            
            for runner_id, runner in self.runners.items():
                should_remove = False
                
                # Remove terminated runners
                if runner.status == RunnerStatus.TERMINATED:
                    should_remove = True
                    
                # Remove failed runners after delay
                elif runner.status == RunnerStatus.FAILED:
                    if current_time - runner.created_at > timedelta(minutes=5):
                        should_remove = True
                        
                # Remove long-idle runners
                elif runner.is_idle(max_idle_time):
                    await self._terminate_runner(runner)
                    should_remove = True
                    
                if should_remove:
                    runners_to_remove.append(runner_id)
                    
            # Clean up runner objects
            for runner_id in runners_to_remove:
                del self.runners[runner_id]
                
        except Exception as e:
            self.logger.error("Failed to cleanup idle runners", error=str(e))
            
    async def _terminate_all_runners(self) -> None:
        """Terminate all runners during shutdown."""
        self.logger.info("Terminating all runners", count=len(self.runners))
        
        for runner in list(self.runners.values()):
            await self._terminate_runner(runner)
            
        self.runners.clear()
        
    def _update_runner_metrics(self) -> None:
        """Update Prometheus metrics for monitoring."""
        # Clear existing metrics
        RUNNER_COUNT._metrics.clear()
        
        # Count runners by status and profile
        status_counts: Dict[Tuple[str, str], int] = {}
        
        for runner in self.runners.values():
            key = (runner.status.value, runner.profile_name)
            status_counts[key] = status_counts.get(key, 0) + 1
            
        # Update metrics
        for (status, profile), count in status_counts.items():
            RUNNER_COUNT.labels(status=status, profile=profile).set(count)
            
    async def _monitor_security_events(self) -> None:
        """Monitor for security events and anomalies."""
        while self._running:
            try:
                # Check for repeated failures
                for operation, count in self._failed_operations.items():
                    if count > 10:  # Threshold for suspicious activity
                        self.logger.warning(
                            "High failure rate detected",
                            operation=operation,
                            failures=count
                        )
                        SECURITY_EVENTS.labels(
                            event_type="high_failure_rate", 
                            severity="medium"
                        ).inc()
                        
                # Reset failure counters periodically
                self._failed_operations.clear()
                self._rate_limit_violations.clear()
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error("Error in security monitoring", error=str(e))
                await asyncio.sleep(60)
                
    async def _detect_security_anomalies(self) -> None:
        """Detect security anomalies in runner behavior."""
        try:
            # Check for runners with suspicious behavior
            for runner in self.runners.values():
                # Detect long-running startup
                if (runner.status == RunnerStatus.STARTING and 
                    datetime.utcnow() - runner.created_at > timedelta(minutes=10)):
                    
                    self.logger.warning(
                        "Runner taking too long to start",
                        runner_id=runner.id,
                        duration=(datetime.utcnow() - runner.created_at).total_seconds()
                    )
                    SECURITY_EVENTS.labels(
                        event_type="slow_startup", 
                        severity="low"
                    ).inc()
                    
                # Detect frequent failures for same runner
                if runner.status == RunnerStatus.FAILED:
                    failure_key = f"runner_failure_{runner.profile_name}"
                    self._failed_operations[failure_key] = self._failed_operations.get(failure_key, 0) + 1
                    
        except Exception as e:
            self.logger.debug("Error detecting security anomalies", error=str(e))
            
    async def _cleanup_failed_runners(self) -> None:
        """Background task to clean up consistently failing runners."""
        while self._running:
            try:
                await self._cleanup_idle_runners()
                await asyncio.sleep(60)  # Run every minute
            except Exception as e:
                self.logger.error("Error in cleanup task", error=str(e))
                await asyncio.sleep(60)
                
    async def _update_metrics(self) -> None:
        """Background task to update metrics."""
        while self._running:
            try:
                self._update_runner_metrics()
                await asyncio.sleep(30)  # Update every 30 seconds
            except Exception as e:
                self.logger.error("Error updating metrics", error=str(e))
                await asyncio.sleep(30)
                
    # Public API methods for external management
    
    async def get_runner_status(self) -> Dict[str, Any]:
        """Get current status of all runners."""
        return {
            "total_runners": len(self.runners),
            "runners_by_status": {
                status.value: len([r for r in self.runners.values() if r.status == status])
                for status in RunnerStatus
            },
            "runners_by_profile": {
                profile: len([r for r in self.runners.values() if r.profile_name == profile])
                for profile in self.config.profiles.keys()
            },
            "last_scaling_decision": self.last_scaling_decision.isoformat(),
        }
        
    async def manually_scale(self, target_count: int, profile_name: Optional[str] = None) -> bool:
        """Manually scale to target runner count with security validation."""
        # Validate request
        if not self.rate_limiter.allow_request("manual_scale"):
            self.logger.warning("Manual scaling rate limited")
            return False
            
        if target_count < 0 or target_count > self.config.scaling.max_replicas:
            self.logger.error(
                "Invalid target count for manual scaling",
                target_count=target_count,
                max_allowed=self.config.scaling.max_replicas
            )
            return False
            
        try:
            current_count = len([r for r in self.runners.values() 
                               if r.status in [RunnerStatus.READY, RunnerStatus.RUNNING]])
            
            if target_count > current_count:
                await self._scale_up(target_count - current_count)
            elif target_count < current_count:
                await self._scale_down(current_count - target_count)
                
            self.logger.info(
                "Manual scaling completed",
                target_count=target_count,
                current_count=current_count
            )
            
            return True
            
        except Exception as e:
            self.logger.error("Manual scaling failed", error=str(e))
            return False
            
    async def emergency_shutdown(self) -> None:
        """Emergency shutdown with immediate runner termination."""
        self.logger.warning("Emergency shutdown initiated")
        SECURITY_EVENTS.labels(event_type="emergency_shutdown", severity="high").inc()
        
        # Immediately terminate all runners
        await self._terminate_all_runners()
        
        # Signal shutdown
        await self.stop()
