# Contributing to EndPointHawk

Thank you for your interest in contributing to EndPointHawk! 🦅

## 🚀 Quick Start

### Development Setup

```bash
# Fork and clone
git clone https://github.com/rootranjan/endpointhawk.git
cd endpointhawk

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=endpointhawk tests/

# Run specific test file
pytest tests/test_detectors.py
```

## 🛠️ Development Guidelines

### Code Style
- Use **Black** for formatting: `black endpointhawk/`
- Use **flake8** for linting: `flake8 endpointhawk/`
- Follow **PEP 8** conventions
- Add **type hints** where possible

### Commit Messages
- Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`
- Be descriptive: `feat: add FastAPI route detection with async support`

### Adding Framework Support

1. Create detector in `detectors/your_framework_detector.py`
2. Inherit from `BaseDetector`
3. Implement required methods:
   ```python
   class YourFrameworkDetector(BaseDetector):
       def can_handle_file(self, file_path: str, content: str) -> bool:
           # Detection logic
           
       def detect_routes(self, file_path: str, content: str) -> List[RouteInfo]:
           # Route extraction logic
   ```
4. Add tests in `tests/test_detectors/`
5. Update documentation

## 🐛 Bug Reports

Please include:
- EndPointHawk version
- Python version
- Operating system
- Framework being scanned
- Minimal reproduction case
- Expected vs actual behavior

## 💡 Feature Requests

We welcome feature requests! Please:
- Search existing issues first
- Describe the use case
- Explain why it would benefit the community
- Consider contributing the implementation

## 📜 License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.

## 🙏 Recognition

Contributors will be recognized in:
- Release notes
- README acknowledgments
- Project documentation

Made with ❤️ by the EndPointHawk community
