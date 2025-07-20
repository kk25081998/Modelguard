# Contributing to ModelGuard

Thank you for your interest in contributing to ModelGuard! This document provides guidelines for contributing to the project.

## 🚀 Getting Started

### Development Setup

1. **Fork and Clone**

   ```bash
   git clone https://github.com/your-username/Modelguard.git
   cd Modelguard
   ```

2. **Install Development Dependencies**

   ```bash
   pip install -e ".[dev]"
   ```

3. **Run Tests**

   ```bash
   pytest tests/
   ```

4. **Verify Installation**
   ```bash
   python -c "import modelguard; print('✅ ModelGuard installed successfully')"
   modelguard --help
   ```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test categories
pytest tests/test_policy.py      # Policy engine
pytest tests/test_scanner.py     # Malware detection
pytest tests/test_loaders.py     # Framework loaders
pytest tests/test_performance.py # Performance benchmarks

# Run with coverage
pytest tests/ --cov=src/modelguard --cov-report=html
```

### Test Requirements

- All new features must include tests
- Maintain 80%+ code coverage
- Performance tests for security-critical code
- Cross-platform compatibility tests

## 📝 Code Style

### Python Standards

- Follow PEP 8 style guidelines
- Use type hints for all functions
- Maximum line length: 88 characters
- Use descriptive variable and function names

### Code Formatting

```bash
# Format code
black src/ tests/

# Check style
ruff check src/ tests/

# Type checking
mypy src/
```

## 🔒 Security Guidelines

### Security-First Development

- All security-related code must be thoroughly tested
- Performance tests for security features
- No hardcoded secrets or credentials
- Validate all external inputs

### Threat Model Considerations

- Pickle deserialization attacks
- Supply chain attacks
- Signature verification bypasses
- Policy enforcement bypasses

## 📋 Pull Request Process

### Before Submitting

1. **Run Tests**: Ensure all tests pass
2. **Code Quality**: Run linting and formatting
3. **Documentation**: Update relevant documentation
4. **Security Review**: Consider security implications

### PR Requirements

- Clear description of changes
- Reference related issues
- Include tests for new features
- Update documentation if needed
- Maintain backward compatibility

### Review Process

1. Automated tests must pass
2. Code review by maintainers
3. Security review for security-related changes
4. Performance review for performance-critical changes

## 🐛 Bug Reports

### Before Reporting

- Check existing issues
- Test with latest version
- Provide minimal reproduction case

### Bug Report Template

```markdown
**Description**
Brief description of the bug

**Reproduction Steps**

1. Step one
2. Step two
3. Step three

**Expected Behavior**
What should happen

**Actual Behavior**
What actually happens

**Environment**

- OS: [e.g., Windows 10, Ubuntu 20.04]
- Python: [e.g., 3.9.7]
- ModelGuard: [e.g., 0.1.0]
- Framework: [e.g., PyTorch 1.12.0]
```

## 💡 Feature Requests

### Feature Request Template

```markdown
**Problem Statement**
What problem does this solve?

**Proposed Solution**
How should this be implemented?

**Alternatives Considered**
What other approaches were considered?

**Additional Context**
Any other relevant information
```

## 🏗️ Architecture

### Project Structure

```
modelguard/
├── src/modelguard/          # Main package
│   ├── core/               # Core security components
│   ├── loaders/            # Framework-specific loaders
│   ├── cli.py              # Command-line interface
│   └── context.py          # Context manager
├── tests/                  # Test suite
├── examples/               # Usage examples
└── docs/                   # Documentation
```

### Key Components

- **Policy Engine**: Security policy management
- **Scanner**: Malware detection and analysis
- **Signature Manager**: Model signing and verification
- **Loaders**: Framework-specific safe loading
- **CLI**: Command-line interface

## 📚 Documentation

### Documentation Standards

- Clear, concise explanations
- Code examples for all features
- Security considerations
- Performance implications

### Building Documentation

```bash
# Install documentation dependencies
pip install -e ".[docs]"

# Build documentation
cd docs/
make html
```

## 🤝 Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Security Issues**: security@modelguard.dev

### Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Maintain professional communication

## 🏆 Recognition

Contributors are recognized in:

- Release notes
- Contributors section
- Special recognition for significant contributions

## 📄 License

By contributing to ModelGuard, you agree that your contributions will be licensed under the Apache License 2.0.

---

Thank you for contributing to ModelGuard! Together, we're making ML model security accessible to everyone. 🛡️
