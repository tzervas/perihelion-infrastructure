"""
GitLab Runner Controller for Kubernetes.

A secure, production-grade GitLab runner controller that provides intelligent
scaling and lifecycle management for GitLab CI/CD runners in Kubernetes.

This package implements:
- Dynamic runner pool management with auto-scaling
- Security-first design with Pod Security Standards
- Comprehensive monitoring and observability
- Intelligent job routing and resource optimization
"""

__version__ = "0.1.0"
__author__ = "Tyler Zervas"
__email__ = "tyler@example.com"

from .controllers.runner_controller import GitLabRunnerController
from .models.runner import RunnerProfile, RunnerStatus, ScalingPolicy

__all__ = [
    "GitLabRunnerController",
    "RunnerProfile", 
    "RunnerStatus",
    "ScalingPolicy",
]
