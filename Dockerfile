# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install --no-cache-dir uv

# Copy manifests
COPY pyproject.toml .
COPY requirements.txt* ./

# Install deps
RUN uv pip install --system -r requirements.txt || pip install --no-cache-dir -r requirements.txt

# Copy source
COPY src ./src
COPY README.md LICENSE ./

# Install package
RUN pip install --no-cache-dir .

# Non root
RUN groupadd --gid 10001 controller && useradd --uid 10001 --gid 10001 --no-log-init --create-home controller
USER controller

EXPOSE 8080 8081

ENTRYPOINT ["gitlab-runner-controller"]
CMD ["--help"]
