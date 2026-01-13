# Contributing to Proc-Monitor

First off, thank you for considering contributing to Proc-Monitor! 🎉

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title** describing the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **System information**: OS, Python version, etc.
- **Error messages** or logs if applicable

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- **Clear title** describing the suggestion
- **Detailed description** of the proposed feature
- **Use case** explaining why this would be useful
- **Possible implementation** if you have ideas

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test your changes on a Linux system
5. Commit with clear messages (`git commit -m 'Add amazing feature'`)
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## Code Style

- Follow PEP 8 for Python code
- Use clear, descriptive variable names
- Add docstrings to functions
- Keep functions focused and small
- No external dependencies! Use only Python standard library

## Testing

Before submitting:

1. Test on a Linux system with `/proc` filesystem
2. Test with and without root privileges
3. Test with and without `config.json`
4. Verify JSON report generation

## Documentation

- Update README.md if adding features
- Update usage guides (USAGE_EN.md, USAGE_TR.md) for user-facing changes
- Update CHANGELOG.md with your changes

## Questions?

Feel free to open an issue for any questions!

---

Thank you for contributing! 🙏
