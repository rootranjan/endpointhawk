# 🐳 EndPointHawk Docker Guide

EndPointHawk is available as a Docker image on GitHub Container Registry (GHCR), making it easy to run without installing Python dependencies locally.

## 📦 Quick Start

### Pull the Image
```bash
docker pull ghcr.io/rootranjan/endpointhawk:latest
```

### Basic Usage
```bash
# Scan a local repository
docker run --rm -v $(pwd):/workspace ghcr.io/rootranjan/endpointhawk:latest --repo-path /workspace

# Show help
docker run --rm ghcr.io/rootranjan/endpointhawk:latest --help
```

## 🔧 Common Use Cases

### 1. Scan Local Repository
```bash
# Mount your repository and scan it
docker run --rm \
  -v $(pwd):/workspace \
  ghcr.io/rootranjan/endpointhawk:latest \
  --repo-path /workspace \
  --output-format json \
  --output-dir /workspace/reports
```

### 2. Compare Two Directories
```bash
# Compare two local directories
docker run --rm \
  -v /path/to/source:/source \
  -v /path/to/target:/target \
  ghcr.io/rootranjan/endpointhawk:latest \
  --compare-dir /target \
  --repo-path /source \
  --include-commit-info \
  --output-format json
```

### 3. Scan Remote Repository
```bash
# Scan a GitHub repository
docker run --rm \
  ghcr.io/rootranjan/endpointhawk:latest \
  --remote-repo https://github.com/username/repo \
  --compare-tags v1.0.0,v2.0.0
```

### 4. Web Interface
```bash
# Run the web interface
docker run --rm \
  -p 5000:5000 \
  -v $(pwd):/workspace \
  ghcr.io/rootranjan/endpointhawk:latest \
  endpointhawk-web \
  --host 0.0.0.0 \
  --port 5000
```

## 🏷️ Available Tags

| Tag | Description |
|-----|-------------|
| `latest` | Latest stable release |
| `develop` | Development branch |
| `v1.0.0` | Specific version |
| `v1.0` | Major.minor version |
| `v1` | Major version |

## 🔐 Security Features

### Non-Root User
The Docker image runs as a non-root user (`endpointhawk`) for enhanced security.

### Security Scanning
Every image is automatically scanned with Trivy for vulnerabilities before publishing.

### Minimal Base Image
Uses Python 3.11-slim as the base image to minimize attack surface.

## 📊 Volume Mounts

### Recommended Mount Points
```bash
# Mount your repository
-v $(pwd):/workspace

# Mount for reports output
-v $(pwd)/reports:/app/reports

# Mount for cache (optional)
-v endpointhawk-cache:/app/cache
```

### Example with All Mounts
```bash
docker run --rm \
  -v $(pwd):/workspace \
  -v $(pwd)/reports:/app/reports \
  -v endpointhawk-cache:/app/cache \
  ghcr.io/rootranjan/endpointhawk:latest \
  --repo-path /workspace \
  --output-dir /app/reports
```

## 🌐 Network Access

### Git Operations
The container needs network access for:
- Cloning remote repositories
- Git operations (blame, log, etc.)
- AI analysis (if enabled)

### Example with Network
```bash
docker run --rm \
  --network host \
  -v $(pwd):/workspace \
  ghcr.io/rootranjan/endpointhawk:latest \
  --remote-repo https://github.com/username/repo
```

## 🔧 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PYTHONPATH` | Python module path | `/app` |
| `PYTHONUNBUFFERED` | Unbuffered Python output | `1` |
| `ENDPOINTHAWK_CACHE_DIR` | Cache directory | `/app/cache` |
| `ENDPOINTHAWK_REPORTS_DIR` | Reports directory | `/app/reports` |

### Example with Environment Variables
```bash
docker run --rm \
  -e ENDPOINTHAWK_CACHE_DIR=/app/cache \
  -e ENDPOINTHAWK_REPORTS_DIR=/app/reports \
  -v $(pwd):/workspace \
  ghcr.io/rootranjan/endpointhawk:latest \
  --repo-path /workspace
```

## 🚀 Advanced Usage

### Multi-Architecture Support
The image supports both AMD64 and ARM64 architectures:
```bash
# Automatically pulls the correct architecture
docker pull ghcr.io/rootranjan/endpointhawk:latest
```

### Custom Configuration
```bash
# Mount custom configuration
docker run --rm \
  -v $(pwd):/workspace \
  -v $(pwd)/config:/app/config \
  ghcr.io/rootranjan/endpointhawk:latest \
  --repo-path /workspace \
  --config /app/config/custom-config.yaml
```

### Batch Processing
```bash
# Process multiple repositories
docker run --rm \
  -v $(pwd):/workspace \
  ghcr.io/rootranjan/endpointhawk:latest \
  --batch-repos /workspace/repos.txt \
  --batch-workers 4
```

## 🔍 Troubleshooting

### Permission Issues
If you encounter permission issues:
```bash
# Run with current user ID
docker run --rm \
  -u $(id -u):$(id -g) \
  -v $(pwd):/workspace \
  ghcr.io/rootranjan/endpointhawk:latest \
  --repo-path /workspace
```

### Git Authentication
For private repositories:
```bash
# Mount SSH key
docker run --rm \
  -v $(pwd):/workspace \
  -v ~/.ssh:/home/endpointhawk/.ssh:ro \
  ghcr.io/rootranjan/endpointhawk:latest \
  --remote-repo git@github.com:username/repo.git
```

### Debug Mode
```bash
# Run with debug output
docker run --rm \
  -v $(pwd):/workspace \
  ghcr.io/rootranjan/endpointhawk:latest \
  --repo-path /workspace \
  --verbose
```

## 📈 Performance Tips

### Use Cache
```bash
# Create a named volume for cache
docker volume create endpointhawk-cache

# Use the cache volume
docker run --rm \
  -v endpointhawk-cache:/app/cache \
  -v $(pwd):/workspace \
  ghcr.io/rootranjan/endpointhawk:latest \
  --repo-path /workspace
```

### Parallel Processing
```bash
# Use multiple workers for large repositories
docker run --rm \
  -v $(pwd):/workspace \
  ghcr.io/rootranjan/endpointhawk:latest \
  --repo-path /workspace \
  --max-workers 8
```

## 🔄 CI/CD Integration

### GitHub Actions Example
```yaml
- name: Scan with EndPointHawk
  run: |
    docker run --rm \
      -v ${{ github.workspace }}:/workspace \
      ghcr.io/rootranjan/endpointhawk:latest \
      --repo-path /workspace \
      --output-format sarif \
      --output-dir /workspace/reports
```

### GitLab CI Example
```yaml
scan:
  image: ghcr.io/rootranjan/endpointhawk:latest
  script:
    - endpointhawk --repo-path . --output-format json
  artifacts:
    paths:
      - reports/
```

## 📚 Additional Resources

- [GitHub Container Registry](https://ghcr.io/rootranjan/endpointhawk)
- [Main Documentation](../README.md)
- [Configuration Guide](../config/)
- [Security Findings](../docs/security-findings.md)

## 🤝 Contributing

To build the Docker image locally:
```bash
# Build image
docker build -t endpointhawk:local .

# Test image
docker run --rm endpointhawk:local --help
```

For issues or questions, please [open an issue](https://github.com/rootranjan/endpointhawk/issues) on GitHub.