"""
Command-line interface for GitLab Runner Controller.

This module provides a secure CLI for managing the GitLab runner controller
with comprehensive configuration validation and monitoring capabilities.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import structlog
import typer
from pydantic import ValidationError

from .controllers.runner_controller import GitLabRunnerController
from .models.runner import (
    ControllerConfiguration,
    GitLabConfiguration,
    RunnerProfile,
    ScalingConfiguration,
)

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

app = typer.Typer(
    name="gitlab-runner-controller",
    help="Secure GitLab Runner Controller for Kubernetes",
    no_args_is_help=True
)

logger = structlog.get_logger()


def load_configuration(config_path: str) -> ControllerConfiguration:
    """
    Load and validate configuration from file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Validated configuration object
        
    Raises:
        typer.Exit: If configuration is invalid
    """
    try:
        config_file = Path(config_path)
        
        if not config_file.exists():
            typer.echo(f"Error: Configuration file not found: {config_path}", err=True)
            raise typer.Exit(1)
        
        # Load configuration
        with open(config_file, 'r') as f:
            if config_path.endswith('.json'):
                config_data = json.load(f)
            else:
                import yaml
                config_data = yaml.safe_load(f)
        
        # Validate configuration
        config = ControllerConfiguration(**config_data)
        
        typer.echo(f"Configuration loaded successfully from {config_path}")
        return config
        
    except ValidationError as e:
        typer.echo(f"Configuration validation error:", err=True)
        for error in e.errors():
            typer.echo(f"  {error['loc']}: {error['msg']}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"Error loading configuration: {e}", err=True)
        raise typer.Exit(1)


def setup_logging(log_level: str, log_format: str = "json") -> None:
    """Setup structured logging with specified level and format."""
    # Configure log level
    import logging
    logging.basicConfig(level=getattr(logging, log_level.upper()))
    
    # Additional processors for different formats
    if log_format == "console":
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.dev.ConsoleRenderer()
            ]
        )


@app.command()
def run(
    config: str = typer.Option(
        "config.yaml",
        "--config", "-c",
        help="Path to configuration file",
        envvar="GITLAB_CONTROLLER_CONFIG"
    ),
    log_level: str = typer.Option(
        "INFO",
        "--log-level", "-l",
        help="Logging level",
        envvar="LOG_LEVEL"
    ),
    log_format: str = typer.Option(
        "json",
        "--log-format",
        help="Log format (json or console)",
        envvar="LOG_FORMAT"
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Validate configuration without starting controller"
    )
) -> None:
    """
    Start the GitLab Runner Controller.
    
    Loads configuration, validates security settings, and starts the
    controller with comprehensive monitoring and logging.
    """
    try:
        # Setup logging
        setup_logging(log_level, log_format)
        
        typer.echo("🚀 Starting GitLab Runner Controller")
        typer.echo(f"📄 Loading configuration from: {config}")
        
        # Load configuration
        controller_config = load_configuration(config)
        
        # Security validation
        if controller_config.enable_debug:
            typer.echo("⚠️  Debug mode is enabled - not recommended for production", err=True)
        
        if dry_run:
            typer.echo("✅ Configuration validation successful (dry run)")
            typer.echo(f"📊 Profiles configured: {len(controller_config.profiles)}")
            typer.echo(f"🔧 Default profile: {controller_config.default_profile}")
            typer.echo(f"📈 Scaling policy: {controller_config.scaling.policy}")
            typer.echo(f"🎯 Max replicas: {controller_config.scaling.max_replicas}")
            return
        
        # Start controller
        controller = GitLabRunnerController(controller_config)
        
        # Run async controller
        asyncio.run(_run_controller(controller))
        
    except KeyboardInterrupt:
        typer.echo("\n🛑 Shutdown requested by user")
    except Exception as e:
        typer.echo(f"❌ Controller failed: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def validate(
    config: str = typer.Option(
        "config.yaml",
        "--config", "-c",
        help="Path to configuration file"
    )
) -> None:
    """
    Validate configuration file without starting the controller.
    
    Performs comprehensive validation of configuration including
    security checks and profile validation.
    """
    try:
        typer.echo("🔍 Validating configuration...")
        
        # Load and validate configuration
        controller_config = load_configuration(config)
        
        # Additional security validation
        from .utils.security import SecurityValidator
        validator = SecurityValidator()
        
        security_issues = []
        for profile_name, profile in controller_config.profiles.items():
            issues = validator.validate_runner_profile(profile)
            if issues:
                security_issues.extend([f"{profile_name}: {issue}" for issue in issues])
        
        if security_issues:
            typer.echo("⚠️  Security issues found:", err=True)
            for issue in security_issues:
                typer.echo(f"  - {issue}", err=True)
        
        # Display configuration summary
        typer.echo("✅ Configuration validation successful")
        typer.echo(f"📊 Profiles: {len(controller_config.profiles)}")
        typer.echo(f"🔧 Default profile: {controller_config.default_profile}")
        typer.echo(f"📈 Scaling policy: {controller_config.scaling.policy}")
        typer.echo(f"🎯 Max replicas: {controller_config.scaling.max_replicas}")
        typer.echo(f"🔒 Metrics enabled: {controller_config.enable_metrics}")
        
        if security_issues:
            typer.echo(f"⚠️  Security warnings: {len(security_issues)}")
        else:
            typer.echo("🛡️  No security issues found")
            
    except Exception as e:
        typer.echo(f"❌ Validation failed: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def generate_config(
    output: str = typer.Option(
        "config.yaml",
        "--output", "-o",
        help="Output configuration file path"
    ),
    format: str = typer.Option(
        "yaml",
        "--format", "-f",
        help="Configuration format (yaml or json)"
    )
) -> None:
    """
    Generate a sample configuration file with security best practices.
    
    Creates a comprehensive configuration template with secure defaults
    and detailed comments for customization.
    """
    try:
        # Create sample configuration
        sample_config = {
            "namespace": "gitlab-runners",
            "gitlab": {
                "url": "https://gitlab.example.com",
                "registration_token": "REPLACE_WITH_ACTUAL_TOKEN",
                "api_token": "REPLACE_WITH_ACTUAL_API_TOKEN",
                "tls_verify": True
            },
            "default_profile": "default",
            "profiles": {
                "default": {
                    "name": "default",
                    "description": "Default secure runner profile",
                    "image": "gitlab/gitlab-runner:v16.9.0",
                    "concurrent_jobs": 1,
                    "job_timeout": 3600,
                    "resources": {
                        "cpu_request": "100m",
                        "cpu_limit": "1000m",
                        "memory_request": "256Mi",
                        "memory_limit": "2Gi",
                        "ephemeral_storage_request": "1Gi",
                        "ephemeral_storage_limit": "5Gi"
                    },
                    "security_context": {
                        "run_as_non_root": True,
                        "run_as_user": 1000,
                        "run_as_group": 1000,
                        "fs_group": 1000,
                        "allow_privilege_escalation": False,
                        "read_only_root_filesystem": True,
                        "capabilities_drop": ["ALL"],
                        "capabilities_add": [],
                        "seccomp_profile_type": "RuntimeDefault"
                    },
                    "tags": ["docker", "kubernetes"]
                },
                "large": {
                    "name": "large",
                    "description": "Large runner for resource-intensive jobs",
                    "image": "gitlab/gitlab-runner:v16.9.0",
                    "concurrent_jobs": 2,
                    "job_timeout": 7200,
                    "resources": {
                        "cpu_request": "500m",
                        "cpu_limit": "4000m",
                        "memory_request": "1Gi",
                        "memory_limit": "8Gi",
                        "ephemeral_storage_request": "2Gi",
                        "ephemeral_storage_limit": "20Gi"
                    },
                    "security_context": {
                        "run_as_non_root": True,
                        "run_as_user": 1000,
                        "run_as_group": 1000,
                        "fs_group": 1000,
                        "allow_privilege_escalation": False,
                        "read_only_root_filesystem": True,
                        "capabilities_drop": ["ALL"],
                        "capabilities_add": [],
                        "seccomp_profile_type": "RuntimeDefault"
                    },
                    "tags": ["docker", "kubernetes", "large"]
                }
            },
            "scaling": {
                "policy": "adaptive",
                "min_replicas": 0,
                "max_replicas": 50,
                "target_utilization": 0.8,
                "scale_up_threshold": 5,
                "scale_down_delay": 300,
                "scale_up_delay": 30,
                "max_idle_time": 1800,
                "cooldown_period": 300
            },
            "monitoring_port": 8080,
            "log_level": "INFO",
            "enable_metrics": True,
            "enable_debug": False
        }
        
        # Write configuration file
        output_path = Path(output)
        
        with open(output_path, 'w') as f:
            if format.lower() == 'json':
                json.dump(sample_config, f, indent=2)
            else:
                import yaml
                yaml.dump(sample_config, f, default_flow_style=False, indent=2)
        
        typer.echo(f"✅ Sample configuration generated: {output}")
        typer.echo("🔧 Please update the GitLab URL and tokens before use")
        typer.echo("🛡️  Configuration uses security best practices by default")
        
    except Exception as e:
        typer.echo(f"❌ Failed to generate configuration: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def status(
    config: str = typer.Option(
        "config.yaml",
        "--config", "-c",
        help="Path to configuration file"
    ),
    format: str = typer.Option(
        "table",
        "--format", "-f",
        help="Output format (table, json, yaml)"
    )
) -> None:
    """
    Display current controller status and runner information.
    
    Shows runner counts, scaling status, and health information
    in various output formats.
    """
    typer.echo("🔍 Controller status check not yet implemented")
    typer.echo("This will be available when the controller is running")


async def _run_controller(controller: GitLabRunnerController) -> None:
    """Run the controller with proper async handling."""
    try:
        # Start the controller
        await controller.start()
    except KeyboardInterrupt:
        logger.info("Shutdown signal received")
    except Exception as e:
        logger.error("Controller error", error=str(e))
        raise
    finally:
        # Ensure cleanup
        try:
            await controller.stop()
        except Exception as e:
            logger.error("Error during controller shutdown", error=str(e))


def main() -> None:
    """Main entry point for the CLI application."""
    app()


if __name__ == "__main__":
    main()
