<div align="center">

# Image Metadata Ai MCP

**Image Metadata AI MCP Server**

[![PyPI](https://img.shields.io/pypi/v/meok-image-metadata-ai-mcp)](https://pypi.org/project/meok-image-metadata-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Image Metadata AI MCP Server
Image information and metadata tools powered by MEOK AI Labs.

## Tools

| Tool | Description |
|------|-------------|
| `detect_format` | Detect image format from file path or base64 data. |
| `get_dimensions` | Get width and height of an image file (supports PNG, JPEG, GIF, BMP). |
| `read_exif` | Read EXIF metadata from a JPEG image file. |
| `strip_metadata` | Strip all metadata from an image file for privacy. |

## Installation

```bash
pip install meok-image-metadata-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "image-metadata-ai": {
      "command": "python",
      "args": ["-m", "meok_image_metadata_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 4 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
