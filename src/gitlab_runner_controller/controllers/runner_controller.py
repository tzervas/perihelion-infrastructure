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
            )\n            \n            # Validate GitLab connectivity and authentication\n            await self.gitlab_client.validate_connection()\n            \n        except Exception as e:\n            self.logger.error(\"Failed to initialize GitLab client\", error=str(e))\n            SECURITY_EVENTS.labels(event_type=\"gitlab_init_failure\", severity=\"critical\").inc()\n            raise ConnectionError(f\"GitLab initialization failed: {e}\")\n            \n    async def _validate_security_configuration(self) -> None:\n        \"\"\"Validate security configuration and detect potential vulnerabilities.\"\"\"\n        try:\n            # Validate runner profiles for security compliance\n            for profile_name, profile in self.config.profiles.items():\n                issues = self.security_validator.validate_runner_profile(profile)\n                if issues:\n                    self.logger.warning(\n                        \"Security issues found in runner profile\",\n                        profile=profile_name,\n                        issues=issues\n                    )\n                    SECURITY_EVENTS.labels(event_type=\"profile_security_warning\", severity=\"medium\").inc()\n                    \n            # Validate namespace security policies\n            await self.k8s_client.validate_namespace_security()\n            \n            # Check for suspicious configuration patterns\n            if self.config.enable_debug:\n                self.logger.warning(\n                    \"Debug mode enabled - not recommended for production\",\n                    environment=\"production\"\n                )\n                SECURITY_EVENTS.labels(event_type=\"debug_mode_warning\", severity=\"low\").inc()\n                \n        except Exception as e:\n            self.logger.error(\"Security validation failed\", error=str(e))\n            SECURITY_EVENTS.labels(event_type=\"security_validation_failure\", severity=\"high\").inc()\n            raise\n            \n    async def _control_loop(self) -> None:\n        \"\"\"Main control loop with security monitoring and intelligent scaling.\"\"\"\n        self.logger.info(\"Starting main control loop\")\n        \n        while self._running:\n            try:\n                # Check rate limiting to prevent abuse\n                if not self.rate_limiter.allow_request(\"control_loop\"):\n                    self.logger.warning(\"Control loop rate limited\")\n                    SECURITY_EVENTS.labels(event_type=\"rate_limit_violation\", severity=\"medium\").inc()\n                    await asyncio.sleep(5)\n                    continue\n                    \n                # Update runner states from Kubernetes\n                await self._sync_runner_states()\n                \n                # Get current job queue information\n                queue_depth = await self._get_job_queue_depth()\n                JOB_QUEUE_DEPTH.set(queue_depth)\n                \n                # Make scaling decisions\n                await self._make_scaling_decision(queue_depth)\n                \n                # Clean up failed/idle runners\n                await self._cleanup_idle_runners()\n                \n                # Update metrics\n                self._update_runner_metrics()\n                \n                # Check for security anomalies\n                await self._detect_security_anomalies()\n                \n                await asyncio.sleep(10)  # Control loop interval\n                \n            except Exception as e:\n                self.logger.error(\"Error in control loop\", error=str(e))\n                SECURITY_EVENTS.labels(event_type=\"control_loop_error\", severity=\"high\").inc()\n                await asyncio.sleep(30)  # Back off on errors\n                \n    async def _sync_runner_states(self) -> None:\n        \"\"\"Synchronize runner states with Kubernetes cluster.\"\"\"\n        try:\n            # Get all runner pods from Kubernetes\n            pods = await self.k8s_client.list_runner_pods()\n            \n            # Update existing runner states\n            for runner_id, runner in list(self.runners.items()):\n                pod = next((p for p in pods if p.metadata.name == runner.pod_name), None)\n                \n                if pod is None:\n                    # Pod no longer exists\n                    if runner.status not in [RunnerStatus.TERMINATED, RunnerStatus.FAILED]:\n                        self.logger.warning(\n                            \"Runner pod disappeared unexpectedly\",\n                            runner_id=runner_id,\n                            pod_name=runner.pod_name\n                        )\n                        runner.status = RunnerStatus.FAILED\n                        runner.error_message = \"Pod disappeared unexpectedly\"\n                        SECURITY_EVENTS.labels(event_type=\"pod_disappeared\", severity=\"medium\").inc()\n                else:\n                    # Update runner status based on pod state\n                    await self._update_runner_from_pod(runner, pod)\n                    \n            # Detect orphaned pods (pods without corresponding runner objects)\n            runner_pod_names = {r.pod_name for r in self.runners.values() if r.pod_name}\n            for pod in pods:\n                if pod.metadata.name not in runner_pod_names:\n                    self.logger.warning(\n                        \"Found orphaned runner pod\",\n                        pod_name=pod.metadata.name,\n                        pod_namespace=pod.metadata.namespace\n                    )\n                    SECURITY_EVENTS.labels(event_type=\"orphaned_pod\", severity=\"medium\").inc()\n                    # Optionally clean up orphaned pods\n                    await self.k8s_client.delete_pod(pod.metadata.name)\n                    \n        except Exception as e:\n            self.logger.error(\"Failed to sync runner states\", error=str(e))\n            RUNNER_OPERATIONS.labels(operation=\"sync_states\", result=\"failure\", profile=\"all\").inc()\n            \n    async def _update_runner_from_pod(self, runner: RunnerInstance, pod: Any) -> None:\n        \"\"\"Update runner instance from Kubernetes pod state.\"\"\"\n        pod_phase = pod.status.phase\n        \n        # Update basic information\n        runner.node_name = pod.spec.node_name\n        \n        # Map Kubernetes pod phase to runner status\n        if pod_phase == \"Pending\":\n            if runner.status == RunnerStatus.PENDING:\n                runner.status = RunnerStatus.STARTING\n        elif pod_phase == \"Running\":\n            if runner.status in [RunnerStatus.PENDING, RunnerStatus.STARTING]:\n                runner.status = RunnerStatus.READY\n                runner.started_at = datetime.utcnow()\n                RUNNER_LIFECYCLE_DURATION.labels(\n                    phase=\"startup\", \n                    profile=runner.profile_name\n                ).observe(\n                    (runner.started_at - runner.created_at).total_seconds()\n                )\n        elif pod_phase in [\"Failed\", \"Succeeded\"]:\n            if runner.status != RunnerStatus.TERMINATED:\n                runner.status = RunnerStatus.FAILED if pod_phase == \"Failed\" else RunnerStatus.TERMINATED\n                if pod.status.container_statuses:\n                    for container_status in pod.status.container_statuses:\n                        if container_status.state.terminated:\n                            runner.error_message = container_status.state.terminated.reason\n                            \n        # Check for security events in pod events\n        await self._check_pod_security_events(runner, pod)\n        \n    async def _check_pod_security_events(self, runner: RunnerInstance, pod: Any) -> None:\n        \"\"\"Check for security-related events in pod lifecycle.\"\"\"\n        try:\n            # Get pod events\n            events = await self.k8s_client.get_pod_events(pod.metadata.name)\n            \n            for event in events:\n                event_reason = event.reason.lower()\n                event_message = event.message.lower()\n                \n                # Detect suspicious events\n                suspicious_patterns = [\n                    \"failed to pull image\",\n                    \"image pull backoff\",\n                    \"crashloopbackoff\",\n                    \"oomkilled\",\n                    \"security context\",\n                    \"privilege escalation\",\n                ]\n                \n                if any(pattern in event_reason or pattern in event_message \n                       for pattern in suspicious_patterns):\n                    self.logger.warning(\n                        \"Suspicious pod event detected\",\n                        runner_id=runner.id,\n                        pod_name=pod.metadata.name,\n                        event_reason=event.reason,\n                        event_message=event.message\n                    )\n                    SECURITY_EVENTS.labels(event_type=\"suspicious_pod_event\", severity=\"medium\").inc()\n                    \n        except Exception as e:\n            self.logger.debug(\"Failed to check pod events\", error=str(e))\n            \n    async def _get_job_queue_depth(self) -> int:\n        \"\"\"Get current GitLab job queue depth with caching and validation.\"\"\"\n        try:\n            # Rate limit GitLab API calls\n            if not self.rate_limiter.allow_request(\"gitlab_api\"):\n                self.logger.debug(\"GitLab API rate limited\")\n                return 0\n                \n            # Get pending jobs from GitLab\n            queue_depth = await self.gitlab_client.get_pending_jobs_count()\n            \n            # Validate reasonable queue depth (detect potential API manipulation)\n            if queue_depth > 10000:  # Sanity check\n                self.logger.warning(\n                    \"Extremely high queue depth detected\",\n                    queue_depth=queue_depth\n                )\n                SECURITY_EVENTS.labels(event_type=\"suspicious_queue_depth\", severity=\"medium\").inc()\n                return min(queue_depth, 1000)  # Cap at reasonable value\n                \n            return queue_depth\n            \n        except Exception as e:\n            self.logger.error(\"Failed to get job queue depth\", error=str(e))\n            return 0\n            \n    async def _make_scaling_decision(self, queue_depth: int) -> None:\n        \"\"\"Make intelligent scaling decisions based on current state and policy.\"\"\"\n        # Check if we're in cooldown period\n        if datetime.utcnow() - self.last_scaling_decision < self.scaling_cooldown:\n            return\n            \n        try:\n            current_runners = len([r for r in self.runners.values() \n                                  if r.status in [RunnerStatus.READY, RunnerStatus.RUNNING]])\n            \n            scaling_config = self.config.scaling\n            \n            # Determine scaling action based on policy\n            if scaling_config.policy == ScalingPolicy.STATIC:\n                target_runners = scaling_config.min_replicas\n            else:\n                target_runners = self._calculate_target_runners(queue_depth, current_runners)\n                \n            # Apply scaling constraints\n            target_runners = max(scaling_config.min_replicas, \n                               min(target_runners, scaling_config.max_replicas))\n            \n            # Execute scaling action\n            if target_runners > current_runners:\n                await self._scale_up(target_runners - current_runners)\n            elif target_runners < current_runners:\n                await self._scale_down(current_runners - target_runners)\n                \n        except Exception as e:\n            self.logger.error(\"Failed to make scaling decision\", error=str(e))\n            SECURITY_EVENTS.labels(event_type=\"scaling_decision_error\", severity=\"medium\").inc()\n            \n    def _calculate_target_runners(self, queue_depth: int, current_runners: int) -> int:\n        \"\"\"Calculate target number of runners based on intelligent algorithms.\"\"\"\n        scaling_config = self.config.scaling\n        \n        if scaling_config.policy == ScalingPolicy.AGGRESSIVE:\n            # Scale quickly for burst workloads\n            if queue_depth > scaling_config.scale_up_threshold:\n                return current_runners + max(1, queue_depth // 2)\n            elif queue_depth == 0:\n                return max(scaling_config.min_replicas, current_runners - 2)\n        elif scaling_config.policy == ScalingPolicy.CONSERVATIVE:\n            # Scale slowly for steady workloads\n            if queue_depth > scaling_config.scale_up_threshold * 2:\n                return current_runners + 1\n            elif queue_depth == 0:\n                return max(scaling_config.min_replicas, current_runners - 1)\n        else:  # ADAPTIVE\n            # Balance between responsiveness and stability\n            utilization = queue_depth / max(current_runners, 1)\n            \n            if utilization > scaling_config.target_utilization * 1.5:\n                return current_runners + max(1, queue_depth // 3)\n            elif utilization < scaling_config.target_utilization * 0.3 and queue_depth == 0:\n                return max(scaling_config.min_replicas, current_runners - 1)\n                \n        return current_runners\n        \n    async def _scale_up(self, count: int) -> None:\n        \"\"\"Scale up runner pool with security validation.\"\"\"\n        self.logger.info(\"Scaling up runners\", count=count)\n        \n        try:\n            for _ in range(count):\n                # Select profile (could be enhanced with intelligent selection)\n                profile = self.config.profiles[self.config.default_profile]\n                \n                # Create new runner instance\n                runner = RunnerInstance(profile_name=profile.name)\n                \n                # Deploy runner pod with security constraints\n                success = await self._deploy_runner_pod(runner, profile)\n                \n                if success:\n                    self.runners[runner.id] = runner\n                    RUNNER_OPERATIONS.labels(\n                        operation=\"scale_up\", \n                        result=\"success\", \n                        profile=profile.name\n                    ).inc()\n                    SCALING_DECISIONS.labels(\n                        direction=\"up\", \n                        reason=\"queue_depth\", \n                        profile=profile.name\n                    ).inc()\n                else:\n                    RUNNER_OPERATIONS.labels(\n                        operation=\"scale_up\", \n                        result=\"failure\", \n                        profile=profile.name\n                    ).inc()\n                    \n            self.last_scaling_decision = datetime.utcnow()\n            \n        except Exception as e:\n            self.logger.error(\"Failed to scale up\", error=str(e))\n            SECURITY_EVENTS.labels(event_type=\"scale_up_error\", severity=\"medium\").inc()\n            \n    async def _scale_down(self, count: int) -> None:\n        \"\"\"Scale down runner pool gracefully.\"\"\"\n        self.logger.info(\"Scaling down runners\", count=count)\n        \n        try:\n            # Select idle runners for termination\n            idle_runners = [\n                r for r in self.runners.values()\n                if r.status == RunnerStatus.READY and r.is_idle()\n            ]\n            \n            # Sort by idle time (longest idle first)\n            idle_runners.sort(\n                key=lambda r: r.last_activity or r.created_at\n            )\n            \n            # Terminate selected runners\n            terminated_count = 0\n            for runner in idle_runners[:count]:\n                success = await self._terminate_runner(runner)\n                if success:\n                    terminated_count += 1\n                    RUNNER_OPERATIONS.labels(\n                        operation=\"scale_down\", \n                        result=\"success\", \n                        profile=runner.profile_name\n                    ).inc()\n                    SCALING_DECISIONS.labels(\n                        direction=\"down\", \n                        reason=\"idle_timeout\", \n                        profile=runner.profile_name\n                    ).inc()\n                    \n            self.logger.info(\"Scaled down runners\", terminated=terminated_count)\n            self.last_scaling_decision = datetime.utcnow()\n            \n        except Exception as e:\n            self.logger.error(\"Failed to scale down\", error=str(e))\n            SECURITY_EVENTS.labels(event_type=\"scale_down_error\", severity=\"medium\").inc()\n            \n    async def _deploy_runner_pod(self, runner: RunnerInstance, profile: RunnerProfile) -> bool:\n        \"\"\"Deploy runner pod with comprehensive security hardening.\"\"\"\n        try:\n            # Generate unique pod name\n            pod_name = f\"gitlab-runner-{runner.id}\"\n            runner.pod_name = pod_name\n            \n            # Create pod specification with security context\n            pod_spec = await self.k8s_client.create_runner_pod_spec(\n                name=pod_name,\n                profile=profile,\n                runner_id=runner.id\n            )\n            \n            # Deploy pod\n            success = await self.k8s_client.create_pod(pod_spec)\n            \n            if success:\n                self.logger.info(\n                    \"Runner pod deployed successfully\",\n                    runner_id=runner.id,\n                    pod_name=pod_name,\n                    profile=profile.name\n                )\n                return True\n            else:\n                self.logger.error(\n                    \"Failed to deploy runner pod\",\n                    runner_id=runner.id,\n                    pod_name=pod_name\n                )\n                return False\n                \n        except Exception as e:\n            self.logger.error(\n                \"Exception during pod deployment\",\n                runner_id=runner.id,\n                error=str(e)\n            )\n            SECURITY_EVENTS.labels(event_type=\"pod_deployment_error\", severity=\"medium\").inc()\n            return False\n            \n    async def _terminate_runner(self, runner: RunnerInstance) -> bool:\n        \"\"\"Gracefully terminate a runner with proper cleanup.\"\"\"\n        try:\n            self.logger.info(\n                \"Terminating runner\",\n                runner_id=runner.id,\n                pod_name=runner.pod_name\n            )\n            \n            # Unregister from GitLab if registered\n            if runner.gitlab_runner_id and self.gitlab_client:\n                await self.gitlab_client.unregister_runner(runner.gitlab_runner_id)\n                \n            # Delete Kubernetes pod\n            if runner.pod_name and self.k8s_client:\n                success = await self.k8s_client.delete_pod(runner.pod_name)\n                if not success:\n                    self.logger.warning(\n                        \"Failed to delete runner pod\",\n                        runner_id=runner.id,\n                        pod_name=runner.pod_name\n                    )\n                    \n            # Update runner status\n            runner.status = RunnerStatus.TERMINATED\n            \n            # Record lifecycle duration\n            if runner.started_at:\n                duration = (datetime.utcnow() - runner.started_at).total_seconds()\n                RUNNER_LIFECYCLE_DURATION.labels(\n                    phase=\"total\", \n                    profile=runner.profile_name\n                ).observe(duration)\n                \n            return True\n            \n        except Exception as e:\n            self.logger.error(\n                \"Failed to terminate runner\",\n                runner_id=runner.id,\n                error=str(e)\n            )\n            return False\n            \n    async def _cleanup_idle_runners(self) -> None:\n        \"\"\"Clean up idle and failed runners.\"\"\"\n        try:\n            max_idle_time = timedelta(seconds=self.config.scaling.max_idle_time)\n            current_time = datetime.utcnow()\n            \n            runners_to_remove = []\n            \n            for runner_id, runner in self.runners.items():\n                should_remove = False\n                \n                # Remove terminated runners\n                if runner.status == RunnerStatus.TERMINATED:\n                    should_remove = True\n                    \n                # Remove failed runners after delay\n                elif runner.status == RunnerStatus.FAILED:\n                    if current_time - runner.created_at > timedelta(minutes=5):\n                        should_remove = True\n                        \n                # Remove long-idle runners\n                elif runner.is_idle(max_idle_time):\n                    await self._terminate_runner(runner)\n                    should_remove = True\n                    \n                if should_remove:\n                    runners_to_remove.append(runner_id)\n                    \n            # Clean up runner objects\n            for runner_id in runners_to_remove:\n                del self.runners[runner_id]\n                \n        except Exception as e:\n            self.logger.error(\"Failed to cleanup idle runners\", error=str(e))\n            \n    async def _terminate_all_runners(self) -> None:\n        \"\"\"Terminate all runners during shutdown.\"\"\"\n        self.logger.info(\"Terminating all runners\", count=len(self.runners))\n        \n        for runner in list(self.runners.values()):\n            await self._terminate_runner(runner)\n            \n        self.runners.clear()\n        \n    def _update_runner_metrics(self) -> None:\n        \"\"\"Update Prometheus metrics for monitoring.\"\"\"\n        # Clear existing metrics\n        RUNNER_COUNT._metrics.clear()\n        \n        # Count runners by status and profile\n        status_counts: Dict[Tuple[str, str], int] = {}\n        \n        for runner in self.runners.values():\n            key = (runner.status.value, runner.profile_name)\n            status_counts[key] = status_counts.get(key, 0) + 1\n            \n        # Update metrics\n        for (status, profile), count in status_counts.items():\n            RUNNER_COUNT.labels(status=status, profile=profile).set(count)\n            \n    async def _monitor_security_events(self) -> None:\n        \"\"\"Monitor for security events and anomalies.\"\"\"\n        while self._running:\n            try:\n                # Check for repeated failures\n                for operation, count in self._failed_operations.items():\n                    if count > 10:  # Threshold for suspicious activity\n                        self.logger.warning(\n                            \"High failure rate detected\",\n                            operation=operation,\n                            failures=count\n                        )\n                        SECURITY_EVENTS.labels(\n                            event_type=\"high_failure_rate\", \n                            severity=\"medium\"\n                        ).inc()\n                        \n                # Reset failure counters periodically\n                self._failed_operations.clear()\n                self._rate_limit_violations.clear()\n                \n                await asyncio.sleep(300)  # Check every 5 minutes\n                \n            except Exception as e:\n                self.logger.error(\"Error in security monitoring\", error=str(e))\n                await asyncio.sleep(60)\n                \n    async def _detect_security_anomalies(self) -> None:\n        \"\"\"Detect security anomalies in runner behavior.\"\"\"\n        try:\n            # Check for runners with suspicious behavior\n            for runner in self.runners.values():\n                # Detect long-running startup\n                if (runner.status == RunnerStatus.STARTING and \n                    datetime.utcnow() - runner.created_at > timedelta(minutes=10)):\n                    \n                    self.logger.warning(\n                        \"Runner taking too long to start\",\n                        runner_id=runner.id,\n                        duration=(datetime.utcnow() - runner.created_at).total_seconds()\n                    )\n                    SECURITY_EVENTS.labels(\n                        event_type=\"slow_startup\", \n                        severity=\"low\"\n                    ).inc()\n                    \n                # Detect frequent failures for same runner\n                if runner.status == RunnerStatus.FAILED:\n                    failure_key = f\"runner_failure_{runner.profile_name}\"\n                    self._failed_operations[failure_key] = self._failed_operations.get(failure_key, 0) + 1\n                    \n        except Exception as e:\n            self.logger.debug(\"Error detecting security anomalies\", error=str(e))\n            \n    async def _cleanup_failed_runners(self) -> None:\n        \"\"\"Background task to clean up consistently failing runners.\"\"\"\n        while self._running:\n            try:\n                await self._cleanup_idle_runners()\n                await asyncio.sleep(60)  # Run every minute\n            except Exception as e:\n                self.logger.error(\"Error in cleanup task\", error=str(e))\n                await asyncio.sleep(60)\n                \n    async def _update_metrics(self) -> None:\n        \"\"\"Background task to update metrics.\"\"\"\n        while self._running:\n            try:\n                self._update_runner_metrics()\n                await asyncio.sleep(30)  # Update every 30 seconds\n            except Exception as e:\n                self.logger.error(\"Error updating metrics\", error=str(e))\n                await asyncio.sleep(30)\n                \n    # Public API methods for external management\n    \n    async def get_runner_status(self) -> Dict[str, Any]:\n        \"\"\"Get current status of all runners.\"\"\"\n        return {\n            \"total_runners\": len(self.runners),\n            \"runners_by_status\": {\n                status.value: len([r for r in self.runners.values() if r.status == status])\n                for status in RunnerStatus\n            },\n            \"runners_by_profile\": {\n                profile: len([r for r in self.runners.values() if r.profile_name == profile])\n                for profile in self.config.profiles.keys()\n            },\n            \"last_scaling_decision\": self.last_scaling_decision.isoformat(),\n        }\n        \n    async def manually_scale(self, target_count: int, profile_name: Optional[str] = None) -> bool:\n        \"\"\"Manually scale to target runner count with security validation.\"\"\"\n        # Validate request\n        if not self.rate_limiter.allow_request(\"manual_scale\"):\n            self.logger.warning(\"Manual scaling rate limited\")\n            return False\n            \n        if target_count < 0 or target_count > self.config.scaling.max_replicas:\n            self.logger.error(\n                \"Invalid target count for manual scaling\",\n                target_count=target_count,\n                max_allowed=self.config.scaling.max_replicas\n            )\n            return False\n            \n        try:\n            current_count = len([r for r in self.runners.values() \n                               if r.status in [RunnerStatus.READY, RunnerStatus.RUNNING]])\n            \n            if target_count > current_count:\n                await self._scale_up(target_count - current_count)\n            elif target_count < current_count:\n                await self._scale_down(current_count - target_count)\n                \n            self.logger.info(\n                \"Manual scaling completed\",\n                target_count=target_count,\n                current_count=current_count\n            )\n            \n            return True\n            \n        except Exception as e:\n            self.logger.error(\"Manual scaling failed\", error=str(e))\n            return False\n            \n    async def emergency_shutdown(self) -> None:\n        \"\"\"Emergency shutdown with immediate runner termination.\"\"\"\n        self.logger.warning(\"Emergency shutdown initiated\")\n        SECURITY_EVENTS.labels(event_type=\"emergency_shutdown\", severity=\"high\").inc()\n        \n        # Immediately terminate all runners\n        await self._terminate_all_runners()\n        \n        # Signal shutdown\n        await self.stop()"}
