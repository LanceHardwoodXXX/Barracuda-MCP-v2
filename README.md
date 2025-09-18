# Barracuda CloudGen Firewall MCP Server v2

[![MCP Version](https://img.shields.io/badge/MCP-1.14.0-blue)](https://modelcontextprotocol.io/)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-green)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue)](https://www.docker.com/)
[![Version](https://img.shields.io/badge/Version-2.0.0-orange)]()

A Model Context Protocol (MCP) server for managing Barracuda CloudGen Firewalls through their REST API. Version 2 supports both **policy-driven** and **standard rule-based** firewalls with automatic mode detection.

## 🆕 What's New in v2

- **Automatic Mode Detection**: Detects if your firewall is policy-driven or standard rule-based
- **Dual Mode Support**: Works with both firewall types seamlessly
- **Enhanced Rule Management**: Create, modify, and delete rules on standard firewalls
- **Dynamic Rules Support**: List and manage dynamic firewall rules
- **Improved Error Handling**: Better feedback for mode-specific limitations
- **Extended API Coverage**: Support for more endpoints and operations

## 🎯 Features

### Universal Features (Both Modes)
- **System Monitoring**: Real-time health status and system metrics
- **Service Management**: List and monitor firewall services
- **Network Objects**: View, filter, and manage network objects
- **Service Objects**: Browse and manage service definitions
- **Mode Detection**: Automatically identify firewall operation mode

### Standard Mode Features
- **Rule Management**: Create, modify, and delete firewall rules
- **Rule Listing**: View all rules with detailed information
- **Dynamic Rules**: Manage dynamic firewall rules
- **Rule Search**: Find specific rules by name
- **Bidirectional Rules**: Configure bidirectional traffic rules

### Policy-Driven Mode Features
- **Status Monitoring**: System health and event monitoring
- **Object Management**: Network and service object configuration
- **Policy Status**: Check policy configuration status
- **Limited Rule Access**: View-only access to rule information

## 📋 Prerequisites

- Python 3.11+
- Docker (optional)
- Barracuda CloudGen Firewall with REST API enabled
- API Token for authentication
- Claude Desktop (for MCP integration)

## 🚀 Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/barracuda-cgf-mcp-v2.git
cd barracuda-cgf-mcp-v2

# Build the Docker image
docker build -t barracuda-mcp:v2 .

# Run with your firewall credentials
docker run -it --rm \
  -e BARRACUDA_HOST=http://your-firewall:8080 \
  -e BARRACUDA_API_TOKEN=your-token \
  barracuda-mcp:v2
```

### Option 2: Python

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export BARRACUDA_HOST="http://your-firewall:8080"
export BARRACUDA_API_TOKEN="your-api-token"

# Run the server
python barracuda_server_v2.py
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `BARRACUDA_HOST` | Firewall URL with protocol and port | `http://192.168.1.1:8080` |
| `BARRACUDA_API_TOKEN` | API authentication token | `your-api-token` |
| `LOG_LEVEL` | Logging level (optional) | `INFO`, `DEBUG` |

### Claude Desktop Integration

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "barracuda-cgf-v2": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--name", "barracuda-mcp-v2",
        "-e", "BARRACUDA_HOST=http://your-firewall:8080",
        "-e", "BARRACUDA_API_TOKEN=your-token",
        "barracuda-mcp:v2"
      ]
    }
  }
}
```

## 🛠️ Available Tools

### Universal Tools

| Tool | Description | Works In |
|------|-------------|----------|
| `get_system_status` | System health and status | Both modes |
| `detect_firewall_mode` | Identify firewall operation mode | Both modes |
| `list_services` | List all running services | Both modes |
| `list_network_objects` | List network objects with filtering | Both modes |
| `list_service_objects` | List service objects with filtering | Both modes |

### Rule Management Tools

| Tool | Description | Works In |
|------|-------------|----------|
| `list_firewall_rules` | List all firewall rules with details | Standard mode |
| `get_firewall_rule` | Get specific rule configuration | Standard mode |
| `create_firewall_rule` | Create new firewall rule | Standard mode |
| `delete_firewall_rule` | Delete existing rule | Standard mode |
| `list_dynamic_rules` | List dynamic firewall rules | Standard mode |

## 📝 Usage Examples

### Detect Firewall Mode
```
"What type of firewall am I connected to?"
"Detect the firewall mode"
```

### System Status
```
"Show me the system status"
"Check firewall health"
```

### Rule Management (Standard Mode)
```
"List all firewall rules"
"Show me the rule named 'BOX-LAN-2-INTERNET'"
"Create a rule to allow HTTP from LAN to Internet"
"Delete the test rule"
```

### Object Management
```
"List all network objects"
"Show service objects containing 'HTTP'"
"Filter network objects for 'VPN'"
```

## 🧪 Testing Your Firewall Type

### Test if Standard Mode (Rule-Based)
```bash
curl -X 'GET' \
  'http://your-firewall:8080/rest/config/v1/forwarding-firewall/rules?expand=false&envelope=false' \
  -H 'accept: application/json' \
  -H 'X-API-Token: your-token'
```

**Response for Standard Mode**: Returns rule list
**Response for Policy-Driven**: Returns 409 error

## 🔍 Firewall Mode Detection

The server automatically detects your firewall mode on startup:

- **Standard Mode**: Direct rule manipulation available
- **Policy-Driven Mode**: Rules managed through Control Center
- **Unknown Mode**: Some features may be limited

## 🐛 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Connection refused | Verify firewall URL and port |
| 401 Unauthorized | Check API token validity |
| 409 on rule operations | Firewall is policy-driven |
| Mode detection fails | Check API permissions |

### Debug Mode

Enable detailed logging:
```bash
export LOG_LEVEL=DEBUG
python barracuda_server_v2.py
```

## 🔒 Security

- API tokens are never logged in production mode
- Supports both HTTP and HTTPS connections
- Non-root user in Docker containers
- Input validation on all operations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📄 License

MIT License - see [LICENSE](LICENSE) file

## 🙏 Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io/) by Anthropic
- [Barracuda CloudGen Firewall API](https://campus.barracuda.com/product/cloudgenfirewall/api)

## 📊 Compatibility

### Tested Firewall Versions
- Barracuda CloudGen Firewall F-Series
- Barracuda CloudGen Firewall V-Series
- Firmware versions 8.x and above

### Supported Operations by Mode

| Operation | Standard Mode | Policy-Driven Mode |
|-----------|--------------|-------------------|
| View System Status | ✅ | ✅ |
| List Services | ✅ | ✅ |
| List Network Objects | ✅ | ✅ |
| List Service Objects | ✅ | ✅ |
| List Firewall Rules | ✅ | ❌ |
| Create Rules | ✅ | ❌ |
| Modify Rules | ✅ | ❌ |
| Delete Rules | ✅ | ❌ |
| Manage Dynamic Rules | ✅ | ❌ |

---

**Note**: This project is not affiliated with or endorsed by Barracuda Networks.