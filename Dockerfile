# Multi-stage build for Barracuda MCP Server v2
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r mcpuser && \
    useradd -r -g mcpuser -u 1000 -d /app -s /sbin/nologin mcpuser

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application files
COPY --chown=mcpuser:mcpuser barracuda_server_v2.py ./barracuda_server.py
COPY --chown=mcpuser:mcpuser README*.md ./
COPY --chown=mcpuser:mcpuser LICENSE* ./
COPY --chown=mcpuser:mcpuser .env.example* ./

# Create directories for logs
RUN mkdir -p /app/logs && \
    chown -R mcpuser:mcpuser /app && \
    chmod 750 /app/logs

# Health check script
RUN echo '#!/usr/bin/env python3\n\
import sys\n\
try:\n\
    import mcp\n\
    import httpx\n\
    print("Health check passed")\n\
    sys.exit(0)\n\
except Exception as e:\n\
    print(f"Health check failed: {e}", file=sys.stderr)\n\
    sys.exit(1)' > /app/healthcheck.py && \
    chmod +x /app/healthcheck.py && \
    chown mcpuser:mcpuser /app/healthcheck.py

# Switch to non-root user
USER mcpuser

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python /app/healthcheck.py

# Labels
LABEL maintainer="your-email@example.com" \
      version="2.0.0" \
      description="Barracuda CloudGen Firewall MCP Server v2" \
      org.opencontainers.image.source="https://github.com/yourusername/barracuda-cgf-mcp-v2"

# Run the MCP server
ENTRYPOINT ["python", "-u", "barracuda_server.py"]