# Use Python 3.12 slim image as base for security and minimal attack surface
FROM python:3.12-slim-bookworm

# Metadata
LABEL maintainer="Tyler Zervas <tyler@example.com>"
LABEL description="Secure development container for GitLab infrastructure project"
LABEL version="1.0.0"

# Set environment variables for security and reproducibility
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Create non-root user for security
RUN groupadd --gid 1000 developer \
    && useradd --uid 1000 --gid 1000 --shell /bin/bash --create-home developer

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Essential development tools
    git \
    curl \
    wget \
    gnupg \
    ca-certificates \
    # Build dependencies
    build-essential \
    gcc \
    g++ \
    make \
    # Network tools
    netcat-traditional \
    dnsutils \
    # Security tools
    openssl \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Install UV package manager for Python
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.cargo/bin:$PATH"

# Install additional security and development tools
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
    # Core development tools
    black==24.3.0 \
    mypy==1.9.0 \
    flake8==7.0.0 \
    pytest==8.1.1 \
    pytest-cov==5.0.0 \
    # Security tools
    bandit==1.7.8 \
    safety==3.1.0 \
    semgrep==1.66.2 \
    # Type checking and validation
    pydantic==2.6.4 \
    pydantic-settings==2.2.1 \
    # Kubernetes and cloud tools
    kubernetes==29.0.0 \
    pyyaml==6.0.1 \
    # Pre-commit hooks
    pre-commit==3.7.0

# Install Trivy for container security scanning
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install kubectl for Kubernetes management
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && chmod +x kubectl \
    && mv kubectl /usr/local/bin/

# Install Helm for package management
RUN curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Install Terraform for infrastructure as code
RUN curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor > /usr/share/keyrings/hashicorp-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list \
    && apt-get update \
    && apt-get install -y terraform \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories with proper permissions
RUN mkdir -p /home/developer/.kube \
    && mkdir -p /home/developer/.gnupg \
    && mkdir -p /home/developer/.cache \
    && mkdir -p /home/developer/.config \
    && chown -R developer:developer /home/developer

# Set up workspace directory
WORKDIR /workspace
RUN chown developer:developer /workspace

# Copy requirements file if it exists
COPY requirements*.txt* ./

# Install Python dependencies as developer user
USER developer

# Set up shell environment
RUN echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc \
    && echo 'export PYTHONPATH="/workspace/src:$PYTHONPATH"' >> ~/.bashrc \
    && echo 'alias ll="ls -la"' >> ~/.bashrc \
    && echo 'alias k="kubectl"' >> ~/.bashrc

# Configure git with security defaults
RUN git config --global init.defaultBranch main \
    && git config --global pull.rebase false \
    && git config --global commit.gpgsign true \
    && git config --global tag.gpgSign true \
    && git config --global user.name "Developer" \
    && git config --global user.email "developer@localhost"

# Health check to ensure container is functioning
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 --version && kubectl version --client=true || exit 1

# Default command
CMD ["/bin/bash"]
