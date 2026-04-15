# Image Metadata AI

> By [MEOK AI Labs](https://meok.ai) — Image information and metadata tools

## Installation

```bash
pip install image-metadata-ai-mcp
```

## Usage

```bash
# Run standalone
python server.py

# Or via MCP
mcp install image-metadata-ai-mcp
```

## Tools

### `detect_format`
Detect image format from file path or base64 data. Supports PNG, JPEG, GIF, WebP, BMP, ICO, and TIFF.

**Parameters:**
- `file_path` (str): Path to image file
- `base64_data` (str): Base64-encoded image data (first 100 chars sufficient)

### `get_dimensions`
Get width and height of an image file (supports PNG, JPEG, GIF, BMP).

**Parameters:**
- `file_path` (str): Path to image file

### `read_exif`
Read EXIF metadata from a JPEG image file.

**Parameters:**
- `file_path` (str): Path to JPEG image file

### `strip_metadata`
Strip all metadata from an image file for privacy.

**Parameters:**
- `file_path` (str): Path to source image
- `output_path` (str): Output path (default: adds '_clean' suffix)

## Authentication

Free tier: 50 calls/day. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## License

MIT — MEOK AI Labs
