"""
GitLab Runner Controller package.

This package contains the core controller implementation for managing
GitLab runners in Kubernetes with security-first design.
"""

from .runner_controller import GitLabRunnerController

__all__ = ["GitLabRunnerController"]
