# EndPointHawk Docker Image
# Multi-stage build for optimized production image

# Build stage
FROM python:3.9-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.9-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash endpointhawk \
    && mkdir -p /app /reports /cache \
    && chown -R endpointhawk:endpointhawk /app /reports /cache

# Copy Python packages from builder
COPY --from=builder /root/.local /home/endpointhawk/.local

# Copy application code
COPY --chown=endpointhawk:endpointhawk . /app/

# Set environment variables
ENV PATH="/home/endpointhawk/.local/bin:$PATH"
ENV PYTHONPATH="/app:$PYTHONPATH"
ENV ENDPOINTHAWK_CACHE_DIR="/cache"
ENV ENDPOINTHAWK_REPORTS_DIR="/reports"

# Switch to non-root user
USER endpointhawk

# Set working directory
WORKDIR /app

# Create volume mounts
VOLUME ["/reports", "/cache"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)" || exit 1

# Default command
ENTRYPOINT ["python3", "endpointhawk.py"]

# Default arguments (can be overridden)
CMD ["--help"]