# EndPointHawk Installation Guide

## Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/rootranjan/endpointhawk.git
   cd endpointhawk
   ```

2. **Install dependencies:**
   ```bash
   python3 -m pip install -r requirements.txt
   ```

3. **Verify installation:**
   ```bash
   python3 endpointhawk.py --help
   ```

## Usage Options

### Option 1: Direct CLI Usage (Recommended)
```bash
# Scan a repository
python3 endpointhawk.py --repo-path /path/to/repo --frameworks auto

# Scan with specific frameworks
python3 endpointhawk.py --repo-path /path/to/repo --frameworks nextjs,express

# Generate different output formats
python3 endpointhawk.py --repo-path /path/to/repo --output-format json,csv,sarif
```

### Option 2: Web Interface
```bash
# Start the web interface
python3 web_cli_bridge.py

# Open in browser: http://localhost:8182
```

### Option 3: Package Installation (Optional)
```bash
# Install as package for global access
pip install -e .
endpointhawk --help
endpointhawk-web  # Web interface
```

## Troubleshooting

### Import Errors
If you see import errors like:
```
import rich.console could not be resolved
import flask_cors could not be resolved
```

**Solution:** Install the dependencies:
```bash
python3 -m pip install -r requirements.txt
```

### Common Issues

1. **"command not found: pip"**
   - Use `python3 -m pip` instead of `pip`
   - Or install pip: `python3 -m ensurepip --upgrade`

2. **Permission errors**
   - Use `python3 -m pip install --user -r requirements.txt`
   - Or use a virtual environment

3. **Python version issues**
   - Ensure Python 3.8+ is installed
   - Check with: `python3 --version`

### Virtual Environment (Recommended)
```bash
# Create virtual environment
python3 -m venv venv

# Activate (macOS/Linux)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Use EndPointHawk
python3 endpointhawk.py --help
```

## Dependencies

### Core Dependencies
- `click>=8.0.0` - CLI framework
- `rich>=13.0.0` - Terminal formatting and progress bars
- `pydantic>=2.0.0` - Data models and validation
- `pyyaml>=6.0` - YAML configuration files

### Web Interface Dependencies
- `flask>=2.3.0` - Web framework
- `flask-cors>=4.0.0` - Cross-origin resource sharing

### Configuration
- `pyyaml>=6.0` - YAML configuration files
- `schedule>=1.2.0` - Task scheduling

### AI Analysis
- `google-generativeai>=0.3.0` - Google Gemini AI integration

### Git Features
- `GitPython>=3.1.40` - Git repository operations
- `pathspec>=0.11.0` - Enhanced gitignore pattern matching
- `jsondiff>=2.0.0` - Enhanced JSON diffing

## Support

If you encounter issues:
1. Check this troubleshooting guide
2. Ensure all dependencies are installed
3. Try using a virtual environment
4. Check Python version compatibility
5. Open an issue on GitHub with error details 