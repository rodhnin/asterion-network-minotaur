# ============================================================================
# Asterion Network Security Auditor - Docker Image
# Multi-stage build: .NET 8 + Python 3.11
# Base path: /docker/
# ============================================================================

# Stage 1: Build .NET application
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy solution and project files
COPY Asterion.sln .
COPY src/Asterion/Asterion.csproj src/Asterion/

# Restore dependencies
RUN dotnet restore Asterion.sln

# Copy all source code
COPY . .

# Build application
WORKDIR /src/src/Asterion
RUN dotnet build Asterion.csproj -c Release -o /app/build
RUN dotnet publish Asterion.csproj -c Release -o /app/publish --self-contained false

# Stage 2: Runtime image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime

# Labels
LABEL maintainer="Rodney Dhavid Jimenez Chacin (rodhnin)"
LABEL version="0.2.0"
LABEL description="Asterion Network Security Auditor - The Minotaur of the Argos Suite"

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        sqlite3 \
        curl \
        iputils-ping \
        net-tools \
        dnsutils \
        smbclient \
        ldap-utils \
        nmap \
        openssh-client && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy .NET application
COPY --from=build /app/publish .

# Copy Python scripts, config, templates, and assets
COPY scripts/ /app/scripts/
COPY config/ /app/config/
COPY templates/ /app/templates/
COPY schema/ /app/schema/
COPY db/ /app/db/
COPY assets/ /app/assets/

# Install Python dependencies
RUN pip3 install --no-cache-dir -r /app/scripts/requirements.txt --break-system-packages

# Setup database
RUN python3 /app/scripts/db_migrate.py

# Create directories for persistent data
RUN mkdir -p /reports /data /logs && \
    mkdir -p /root/.asterion && \
    mkdir -p /root/.asterion/consent-proofs && \
    mkdir -p /root/.argos

# Create symlinks for persistent volumes
# Link database
RUN ln -sf /data/argos.db /root/.argos/argos.db

# Link reports directory (do NOT create /root/.asterion/reports as directory first)
RUN ln -sf /reports /root/.asterion/reports

# Copy entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set environment variables
ENV DOTNET_RUNNING_IN_CONTAINER=true \
    ASPNETCORE_ENVIRONMENT=Production \
    PATH="/app:${PATH}"

# Expose ports (reserved for future web dashboard)
# EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD dotnet /app/ast.dll version || exit 1

# Set working directory for scans
WORKDIR /workspace

# Use custom entrypoint for DB initialization
ENTRYPOINT ["/entrypoint.sh"]
CMD ["dotnet", "/app/ast.dll", "--help"]