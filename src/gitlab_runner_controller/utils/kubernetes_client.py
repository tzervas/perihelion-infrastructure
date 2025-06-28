"""
Secure Kubernetes client wrapper for GitLab Runner Controller.

This module provides a security-hardened wrapper around the Kubernetes
Python client with comprehensive validation, attack detection, and
defensive programming practices.
"""

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

import structlog
from kubernetes import client
from kubernetes.client.rest import ApiException

from ..models.runner import RunnerProfile
from .security import SecurityValidator


class KubernetesSecurityError(Exception):
    """Raised when Kubernetes security validation fails."""
    pass


class SecureKubernetesClient:
    """
    Security-hardened Kubernetes client wrapper.
    
    Provides secure interaction with Kubernetes API with:
    - Input validation and sanitization
    - Resource quota enforcement
    - Security policy validation
    - Attack detection and prevention
    - Comprehensive audit logging
    """
    
    def __init__(self, namespace: str, logger: Any) -> None:
        """
        Initialize secure Kubernetes client.
        
        Args:
            namespace: Kubernetes namespace for operations
            logger: Structured logger instance
            
        Raises:
            KubernetesSecurityError: If security validation fails
        """
        self.namespace = namespace
        self.logger = logger.bind(component="k8s_client", namespace=namespace)
        
        # Initialize Kubernetes clients
        self.v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.events_v1 = client.EventsV1Api()
        
        # Security validator
        self.security_validator = SecurityValidator()
        
        # Rate limiting and security tracking
        self._operation_counts: Dict[str, int] = {}
        self._last_validation = datetime.utcnow()
        
    async def validate_permissions(self) -> None:
        """
        Validate required Kubernetes permissions.
        
        Ensures the service account has minimal required permissions
        for secure operation.
        
        Raises:
            KubernetesSecurityError: If permissions are insufficient
        """
        try:
            # Test basic namespace access
            await self._validate_namespace_access()
            
            # Test pod operations
            await self._validate_pod_permissions()
            
            # Test events access
            await self._validate_events_permissions()
            
            self.logger.info("Kubernetes permissions validated successfully")
            
        except Exception as e:
            self.logger.error("Kubernetes permission validation failed", error=str(e))
            raise KubernetesSecurityError(f"Permission validation failed: {e}")
    
    async def validate_namespace_security(self) -> None:
        """
        Validate namespace security configuration.
        
        Checks for proper security policies, network policies,
        and resource quotas.
        
        Raises:
            KubernetesSecurityError: If security validation fails
        """
        try:
            # Get namespace details
            namespace_obj = self.v1.read_namespace(name=self.namespace)
            
            # Check for security labels
            labels = namespace_obj.metadata.labels or {}
            if "pod-security.kubernetes.io/enforce" not in labels:
                self.logger.warning(
                    "Namespace missing Pod Security Standards enforcement",
                    namespace=self.namespace
                )
            
            # Check for resource quotas
            quotas = self.v1.list_namespaced_resource_quota(namespace=self.namespace)
            if not quotas.items:
                self.logger.warning(
                    "Namespace has no resource quotas configured",
                    namespace=self.namespace
                )
            
            # Check for network policies
            try:
                networking_v1 = client.NetworkingV1Api()
                policies = networking_v1.list_namespaced_network_policy(
                    namespace=self.namespace
                )
                if not policies.items:
                    self.logger.warning(
                        "Namespace has no network policies configured",
                        namespace=self.namespace
                    )
            except Exception as e:
                self.logger.debug("Could not check network policies", error=str(e))
            
            self.logger.info("Namespace security validation completed")
            
        except Exception as e:
            self.logger.error("Namespace security validation failed", error=str(e))
            raise KubernetesSecurityError(f"Namespace security validation failed: {e}")
    
    async def create_runner_pod_spec(self, 
                                   name: str, 
                                   profile: RunnerProfile, 
                                   runner_id: str) -> Dict[str, Any]:
        """
        Create secure pod specification for GitLab runner.
        
        Args:
            name: Pod name (must be DNS-compatible)
            profile: Runner profile with security settings
            runner_id: Unique runner identifier
            
        Returns:
            Secure pod specification dictionary
            
        Raises:
            KubernetesSecurityError: If security validation fails
        """
        # Validate inputs
        if not self.security_validator.validate_kubernetes_name(name):
            raise KubernetesSecurityError(f"Invalid pod name: {name}")
        
        name = self.security_validator.sanitize_input(name, max_length=63)
        runner_id = self.security_validator.sanitize_input(runner_id, max_length=32)
        
        # Validate profile security
        security_issues = self.security_validator.validate_runner_profile(profile)
        if security_issues:
            self.logger.warning(
                "Runner profile has security issues",
                profile=profile.name,
                issues=security_issues
            )
            # In production, we might want to block profiles with critical issues
        
        # Build secure pod specification
        pod_spec = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": name,
                "namespace": self.namespace,
                "labels": {
                    "app": "gitlab-runner",
                    "profile": profile.name,
                    "runner-id": runner_id,
                    "managed-by": "gitlab-runner-controller",
                    "security.policy/enforce": "restricted"
                },
                "annotations": {
                    "seccomp.security.alpha.kubernetes.io/pod": "runtime/default",
                    "container.apparmor.security.beta.kubernetes.io/gitlab-runner": "runtime/default"
                }
            },
            "spec": {
                "restartPolicy": "Never",
                "serviceAccountName": "gitlab-runner",
                "automountServiceAccountToken": False,  # Security best practice
                "hostNetwork": False,
                "hostPID": False,
                "hostIPC": False,
                "shareProcessNamespace": False,
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": profile.security_context.run_as_user,
                    "runAsGroup": profile.security_context.run_as_group,
                    "fsGroup": profile.security_context.fs_group,
                    "seccompProfile": {
                        "type": profile.security_context.seccomp_profile_type
                    }
                },
                "containers": [
                    {
                        "name": "gitlab-runner",
                        "image": profile.image,
                        "imagePullPolicy": "Always",  # Always pull for security
                        "securityContext": {
                            "runAsNonRoot": profile.security_context.run_as_non_root,
                            "runAsUser": profile.security_context.run_as_user,
                            "runAsGroup": profile.security_context.run_as_group,
                            "allowPrivilegeEscalation": profile.security_context.allow_privilege_escalation,
                            "readOnlyRootFilesystem": profile.security_context.read_only_root_filesystem,
                            "capabilities": {
                                "drop": profile.security_context.capabilities_drop,
                                "add": profile.security_context.capabilities_add
                            },
                            "seccompProfile": {
                                "type": profile.security_context.seccomp_profile_type
                            }
                        },
                        "resources": {
                            "requests": {
                                "cpu": profile.resources.cpu_request,
                                "memory": profile.resources.memory_request,
                                "ephemeral-storage": profile.resources.ephemeral_storage_request
                            },
                            "limits": {
                                "cpu": profile.resources.cpu_limit,
                                "memory": profile.resources.memory_limit,
                                "ephemeral-storage": profile.resources.ephemeral_storage_limit
                            }
                        },
                        "env": self._build_environment_variables(profile, runner_id),
                        "volumeMounts": [
                            {
                                "name": "tmp",
                                "mountPath": "/tmp",
                                "readOnly": False
                            },
                            {
                                "name": "var-tmp",
                                "mountPath": "/var/tmp",
                                "readOnly": False
                            }
                        ],
                        "livenessProbe": {
                            "exec": {
                                "command": ["gitlab-runner", "status"]
                            },
                            "initialDelaySeconds": 30,
                            "periodSeconds": 10,
                            "timeoutSeconds": 5,
                            "failureThreshold": 3
                        },
                        "readinessProbe": {
                            "exec": {
                                "command": ["gitlab-runner", "status"]
                            },
                            "initialDelaySeconds": 5,
                            "periodSeconds": 5,
                            "timeoutSeconds": 3,
                            "failureThreshold": 3
                        }
                    }
                ],
                "volumes": [
                    {
                        "name": "tmp",
                        "emptyDir": {
                            "medium": "Memory",
                            "sizeLimit": "100Mi"
                        }
                    },
                    {
                        "name": "var-tmp",
                        "emptyDir": {
                            "medium": "Memory",
                            "sizeLimit": "100Mi"
                        }
                    }
                ],
                "tolerations": profile.tolerations or [],
                "nodeSelector": profile.node_selector or {},
                "affinity": profile.affinity or {},
                "terminationGracePeriodSeconds": 30
            }
        }
        
        # Validate pod specification security
        spec_issues = self.security_validator.validate_pod_spec(pod_spec)
        if spec_issues:
            self.logger.error(
                "Pod specification failed security validation",
                issues=spec_issues
            )
            raise KubernetesSecurityError(f"Pod spec security issues: {spec_issues}")
        
        self.logger.info(
            "Secure pod specification created",
            pod_name=name,
            profile=profile.name,
            runner_id=runner_id
        )
        
        return pod_spec
    
    def _build_environment_variables(self, 
                                   profile: RunnerProfile, 
                                   runner_id: str) -> List[Dict[str, str]]:
        """Build secure environment variables for runner container."""
        env_vars = [
            {
                "name": "RUNNER_ID",
                "value": runner_id
            },
            {
                "name": "RUNNER_PROFILE",
                "value": profile.name
            },
            {
                "name": "RUNNER_CONCURRENT",
                "value": str(profile.concurrent_jobs)
            },
            {
                "name": "RUNNER_TIMEOUT",
                "value": str(profile.job_timeout)
            }
        ]
        
        # Add profile-specific environment variables
        if profile.environment_variables:
            for key, value in profile.environment_variables.items():
                # Sanitize key and value
                safe_key = self.security_validator.sanitize_input(key, max_length=253)
                safe_value = self.security_validator.sanitize_input(value, max_length=1000)
                
                env_vars.append({
                    "name": safe_key,
                    "value": safe_value
                })
        
        return env_vars
    
    async def create_pod(self, pod_spec: Dict[str, Any]) -> bool:
        """
        Create pod with security validation and error handling.
        
        Args:
            pod_spec: Kubernetes pod specification
            
        Returns:
            True if pod created successfully, False otherwise
        """
        try:
            # Final security validation
            spec_issues = self.security_validator.validate_pod_spec(pod_spec)
            if spec_issues:
                self.logger.error(
                    "Pod specification failed final security check",
                    issues=spec_issues
                )
                return False
            
            # Create the pod
            response = self.v1.create_namespaced_pod(
                namespace=self.namespace,
                body=pod_spec
            )
            
            self.logger.info(
                "Pod created successfully",
                pod_name=response.metadata.name,
                uid=response.metadata.uid
            )
            
            # Track operation for monitoring
            self._operation_counts["pod_create"] = self._operation_counts.get("pod_create", 0) + 1
            
            return True
            
        except ApiException as e:
            self.logger.error(
                "Kubernetes API error creating pod",
                status_code=e.status,
                reason=e.reason,
                body=e.body
            )
            return False
        except Exception as e:
            self.logger.error("Unexpected error creating pod", error=str(e))
            return False
    
    async def delete_pod(self, pod_name: str, grace_period: int = 30) -> bool:
        """
        Delete pod with graceful termination.
        
        Args:
            pod_name: Name of pod to delete
            grace_period: Graceful termination period in seconds
            
        Returns:
            True if pod deleted successfully, False otherwise
        """
        try:
            # Validate pod name
            if not self.security_validator.validate_kubernetes_name(pod_name):
                self.logger.error("Invalid pod name for deletion", pod_name=pod_name)
                return False
            
            # Sanitize input
            safe_pod_name = self.security_validator.sanitize_input(pod_name, max_length=63)
            
            # Delete the pod
            self.v1.delete_namespaced_pod(
                name=safe_pod_name,
                namespace=self.namespace,
                grace_period_seconds=grace_period
            )
            
            self.logger.info(
                "Pod deletion initiated",
                pod_name=safe_pod_name,
                grace_period=grace_period
            )
            
            # Track operation for monitoring
            self._operation_counts["pod_delete"] = self._operation_counts.get("pod_delete", 0) + 1
            
            return True
            
        except ApiException as e:
            if e.status == 404:
                # Pod already deleted
                self.logger.info("Pod not found (already deleted)", pod_name=pod_name)
                return True
            else:
                self.logger.error(
                    "Kubernetes API error deleting pod",
                    pod_name=pod_name,
                    status_code=e.status,
                    reason=e.reason
                )
                return False
        except Exception as e:
            self.logger.error(
                "Unexpected error deleting pod",
                pod_name=pod_name,
                error=str(e)
            )
            return False
    
    async def list_runner_pods(self) -> List[Any]:
        """
        List GitLab runner pods with security filtering.
        
        Returns:
            List of pod objects managed by this controller
        """
        try:
            # List pods with label selector for security
            response = self.v1.list_namespaced_pod(
                namespace=self.namespace,
                label_selector="app=gitlab-runner,managed-by=gitlab-runner-controller"
            )
            
            # Filter out potentially suspicious pods
            valid_pods = []
            for pod in response.items:
                if self._validate_pod_ownership(pod):
                    valid_pods.append(pod)
                else:
                    self.logger.warning(
                        "Found suspicious pod with runner labels",
                        pod_name=pod.metadata.name,
                        labels=pod.metadata.labels
                    )
            
            self.logger.debug(
                "Listed runner pods",
                total_pods=len(response.items),
                valid_pods=len(valid_pods)
            )
            
            return valid_pods
            
        except ApiException as e:
            self.logger.error(
                "Kubernetes API error listing pods",
                status_code=e.status,
                reason=e.reason
            )
            return []
        except Exception as e:
            self.logger.error("Unexpected error listing pods", error=str(e))
            return []
    
    async def get_pod_events(self, pod_name: str) -> List[Any]:
        """
        Get events for a specific pod with security filtering.
        
        Args:
            pod_name: Name of the pod
            
        Returns:
            List of relevant events for the pod
        """
        try:
            # Validate and sanitize pod name
            if not self.security_validator.validate_kubernetes_name(pod_name):
                return []
            
            safe_pod_name = self.security_validator.sanitize_input(pod_name, max_length=63)
            
            # Get events for the pod
            response = self.v1.list_namespaced_event(
                namespace=self.namespace,
                field_selector=f"involvedObject.name={safe_pod_name}"
            )
            
            # Filter and validate events
            filtered_events = []
            for event in response.items:
                # Only include events for our pods
                if (event.involved_object.name == safe_pod_name and 
                    event.involved_object.kind == "Pod"):
                    filtered_events.append(event)
            
            return filtered_events
            
        except ApiException as e:
            self.logger.error(
                "Kubernetes API error getting pod events",
                pod_name=pod_name,
                status_code=e.status,
                reason=e.reason
            )
            return []
        except Exception as e:
            self.logger.error(
                "Unexpected error getting pod events",
                pod_name=pod_name,
                error=str(e)
            )
            return []
    
    def _validate_pod_ownership(self, pod: Any) -> bool:
        """
        Validate that pod is legitimately managed by this controller.
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            True if pod ownership is valid, False otherwise
        """
        try:
            labels = pod.metadata.labels or {}
            
            # Check required labels
            required_labels = ["app", "managed-by", "runner-id"]
            for label in required_labels:
                if label not in labels:
                    return False
            
            # Validate label values
            if labels.get("app") != "gitlab-runner":
                return False
            
            if labels.get("managed-by") != "gitlab-runner-controller":
                return False
            
            # Validate runner-id format
            runner_id = labels.get("runner-id", "")
            if not runner_id.startswith("runner-"):
                return False
            
            return True
            
        except Exception:
            return False
    
    async def _validate_namespace_access(self) -> None:
        """Validate basic namespace access permissions."""
        try:
            self.v1.read_namespace(name=self.namespace)
        except ApiException as e:
            raise KubernetesSecurityError(f"Cannot access namespace {self.namespace}: {e}")
    
    async def _validate_pod_permissions(self) -> None:
        """Validate pod management permissions."""
        try:
            # Test pod listing
            self.v1.list_namespaced_pod(namespace=self.namespace, limit=1)
        except ApiException as e:
            raise KubernetesSecurityError(f"Cannot list pods in namespace {self.namespace}: {e}")
    
    async def _validate_events_permissions(self) -> None:
        """Validate events access permissions."""
        try:
            # Test events listing
            self.v1.list_namespaced_event(namespace=self.namespace, limit=1)
        except ApiException as e:
            self.logger.warning(
                "Cannot access events (non-critical)",
                namespace=self.namespace,
                error=str(e)
            )
    
    async def close(self) -> None:
        """Close client connections and cleanup resources."""
        try:
            # Log operation statistics
            self.logger.info(
                "Kubernetes client closing",
                operation_counts=self._operation_counts
            )
            
            # Note: The official Kubernetes Python client doesn't require explicit cleanup
            # as it uses the requests library which handles connection pooling internally
            
        except Exception as e:
            self.logger.error("Error during Kubernetes client cleanup", error=str(e))
    
    def get_operation_stats(self) -> Dict[str, int]:
        """Get operation statistics for monitoring."""
        return self._operation_counts.copy()
