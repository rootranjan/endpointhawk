# EndPointHawk Docker Image
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash endpointhawk

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=endpointhawk:endpointhawk . .

# Install the application
RUN pip install --no-cache-dir -e .

# Create necessary directories with proper permissions
RUN mkdir -p /app/cache /app/reports && \
    chown -R endpointhawk:endpointhawk /app/cache /app/reports

# Switch to non-root user
USER endpointhawk

# Set environment variables
ENV PYTHONPATH="/app"
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Default command - use the main entry point directly
ENTRYPOINT ["python", "endpointhawk.py"]

# Default arguments (can be overridden)
CMD ["--help"]