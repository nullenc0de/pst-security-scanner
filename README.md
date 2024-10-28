# PST Security Scanner

A comprehensive Python tool for scanning Microsoft Outlook PST files to detect potentially sensitive information and security risks.

## 🔍 Features

- **Advanced Pattern Detection**: Multi-category keyword scanning with regex support
- **Parallel Processing**: Efficient handling of large PST files using multiprocessing
- **Customizable Rules**: JSON-based configuration for custom keyword patterns
- **Detailed Reporting**: JSON reports with context-aware matches
- **Security Focused**: Proper handling of sensitive data with secure cleanup
- **Enterprise Ready**: Logging, error handling, and process monitoring

## 🚀 Quick Start

### Prerequisites

```bash
# Install required system package
sudo apt-get install pst-utils    # For Ubuntu/Debian
sudo yum install pst-utils        # For CentOS/RHEL

# Install Python dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
python pst_scanner.py /path/to/file.pst
```

### Using Custom Keywords

1. Create or modify `custom_keywords.json`
2. Run the scanner with custom keywords:
```bash
python pst_scanner.py /path/to/file.pst
```
## ⚙️ Configuration

### Custom Keywords
Keywords are organized by category in `custom_keywords.json`:

```json
{
  "authentication": [
    "password",
    "api_key"
  ],
  "financial": [
    "credit_card",
    "bank_account"
  ]
}
```

### Logging Configuration
Logs are written to both console and file:
- Log File: `pst_scan.log`
- Log Level: INFO (configurable)

## 📊 Output

The scanner generates a detailed JSON report containing:
- Scan timestamp
- Total matches found
- Detailed match information including:
  - Email ID
  - Subject
  - Matched keywords
  - Context
  - Timestamp

Example report structure:
```json
{
  "scan_timestamp": "20241028_153000",
  "total_matches": 12,
  "matches": [
    {
      "email_id": "MSG001",
      "subject": "Project Credentials",
      "matched_keywords": ["authentication:password"],
      "context": "Please find the updated password...",
      "timestamp": "2024-10-28 15:30:00"
    }
  ]
}
```

## 🔒 Security Considerations

- Temporary files are securely cleaned up after processing
- No sensitive data is stored in memory longer than necessary
- All file operations use secure handling practices
- Optional file type verification using python-magic

## 🤝 Contributing

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines on:
- Code style
- Testing requirements
- Pull request process
- Development setup

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- PST Utils team for the readpst utility
- Contributors and maintainers

## 📞 Support

- Open an issue for bug reports or feature requests
- Check existing issues before creating new ones
- Provide detailed information when reporting issues
