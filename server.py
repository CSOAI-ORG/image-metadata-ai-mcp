"""
Image Metadata AI MCP Server
Image information and metadata tools powered by MEOK AI Labs.
"""

import io
import struct
import base64
import time
from collections import defaultdict
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("image-metadata-ai-mcp")

_call_counts: dict[str, list[float]] = defaultdict(list)
FREE_TIER_LIMIT = 50
WINDOW = 86400

# Path traversal protection
BLOCKED_PATH_PATTERNS = ["/etc/", "/var/", "/proc/", "/sys/", "/dev/", ".."]


def _validate_file_path(file_path: str) -> str | None:
    """Validate file path against traversal attacks. Returns error message or None."""
    import os
    for pattern in BLOCKED_PATH_PATTERNS:
        if pattern in file_path:
            return f"Access denied: path contains blocked pattern '{pattern}'"
    real = os.path.realpath(file_path)
    if not os.path.isfile(real):
        return f"File not found: {file_path}"
    return None

def _check_rate_limit(tool_name: str) -> None:
    now = time.time()
    _call_counts[tool_name] = [t for t in _call_counts[tool_name] if now - t < WINDOW]
    if len(_call_counts[tool_name]) >= FREE_TIER_LIMIT:
        raise ValueError(f"Rate limit exceeded for {tool_name}. Free tier: {FREE_TIER_LIMIT}/day. Upgrade at https://meok.ai/pricing")
    _call_counts[tool_name].append(now)

SIGNATURES = {
    b'\x89PNG\r\n\x1a\n': "png", b'\xff\xd8\xff': "jpeg",
    b'GIF87a': "gif", b'GIF89a': "gif", b'RIFF': "webp",
    b'BM': "bmp", b'\x00\x00\x01\x00': "ico", b'\x49\x49\x2a\x00': "tiff",
    b'\x4d\x4d\x00\x2a': "tiff",
}


@mcp.tool()
def detect_format(file_path: str = "", base64_data: str = "") -> dict:
    """Detect image format from file path or base64 data.

    Args:
        file_path: Path to image file
        base64_data: Base64-encoded image data (first 100 chars sufficient)
    """
    _check_rate_limit("detect_format")
    header = b""
    if file_path:
        path_err = _validate_file_path(file_path)
        if path_err:
            return {"error": path_err}
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
        except Exception as e:
            return {"error": str(e)}
    elif base64_data:
        try:
            header = base64.b64decode(base64_data[:64])
        except Exception:
            return {"error": "Invalid base64 data"}
    else:
        return {"error": "Provide file_path or base64_data"}

    for sig, fmt in SIGNATURES.items():
        if header.startswith(sig):
            return {"format": fmt, "mime_type": f"image/{fmt}", "detected": True}
    if b'WEBP' in header[:16]:
        return {"format": "webp", "mime_type": "image/webp", "detected": True}
    return {"format": "unknown", "detected": False, "header_hex": header[:8].hex()}


@mcp.tool()
def get_dimensions(file_path: str) -> dict:
    """Get width and height of an image file (supports PNG, JPEG, GIF, BMP).

    Args:
        file_path: Path to image file
    """
    _check_rate_limit("get_dimensions")
    path_err = _validate_file_path(file_path)
    if path_err:
        return {"error": path_err}
    try:
        with open(file_path, 'rb') as f:
            header = f.read(32)
            # PNG
            if header[:8] == b'\x89PNG\r\n\x1a\n':
                w, h = struct.unpack('>II', header[16:24])
                return {"width": w, "height": h, "format": "png", "aspect_ratio": round(w/h, 3) if h else 0}
            # JPEG
            if header[:2] == b'\xff\xd8':
                f.seek(0)
                data = f.read()
                i = 2
                while i < len(data) - 9:
                    if data[i] == 0xFF:
                        marker = data[i+1]
                        if marker in (0xC0, 0xC1, 0xC2):
                            h = struct.unpack('>H', data[i+5:i+7])[0]
                            w = struct.unpack('>H', data[i+7:i+9])[0]
                            return {"width": w, "height": h, "format": "jpeg", "aspect_ratio": round(w/h, 3) if h else 0}
                        length = struct.unpack('>H', data[i+2:i+4])[0]
                        i += 2 + length
                    else:
                        i += 1
                return {"error": "Could not find JPEG dimensions"}
            # GIF
            if header[:4] in (b'GIF8'):
                w, h = struct.unpack('<HH', header[6:10])
                return {"width": w, "height": h, "format": "gif", "aspect_ratio": round(w/h, 3) if h else 0}
            # BMP
            if header[:2] == b'BM':
                w, h = struct.unpack('<ii', header[18:26])
                return {"width": w, "height": abs(h), "format": "bmp", "aspect_ratio": round(w/abs(h), 3) if h else 0}
            return {"error": "Unsupported format"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def read_exif(file_path: str) -> dict:
    """Read EXIF metadata from a JPEG image file.

    Args:
        file_path: Path to JPEG image file
    """
    _check_rate_limit("read_exif")
    path_err = _validate_file_path(file_path)
    if path_err:
        return {"error": path_err}
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        img = Image.open(file_path)
        exif_data = img._getexif()
        if not exif_data:
            return {"file": file_path, "exif": {}, "message": "No EXIF data found"}
        result = {}
        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            if isinstance(value, bytes):
                value = value.hex()[:50]
            result[str(tag)] = str(value)[:200]
        return {"file": file_path, "exif": result, "tag_count": len(result)}
    except ImportError:
        # Fallback: basic EXIF detection without PIL
        try:
            with open(file_path, 'rb') as f:
                data = f.read(2)
                if data != b'\xff\xd8':
                    return {"file": file_path, "error": "Not a JPEG file"}
            return {"file": file_path, "exif": {}, "note": "Install Pillow for full EXIF. File is valid JPEG."}
        except Exception as e:
            return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def strip_metadata(file_path: str, output_path: str = "") -> dict:
    """Strip all metadata from an image file for privacy.

    Args:
        file_path: Path to source image
        output_path: Output path (default: adds '_clean' suffix)
    """
    _check_rate_limit("strip_metadata")
    path_err = _validate_file_path(file_path)
    if path_err:
        return {"error": path_err}
    if not output_path:
        parts = file_path.rsplit('.', 1)
        output_path = f"{parts[0]}_clean.{parts[1]}" if len(parts) > 1 else f"{file_path}_clean"
    try:
        from PIL import Image
        img = Image.open(file_path)
        clean = Image.new(img.mode, img.size)
        clean.putdata(list(img.getdata()))
        clean.save(output_path)
        return {"input": file_path, "output": output_path, "stripped": True, "message": "Metadata removed"}
    except ImportError:
        return {"error": "Pillow required. Install with: pip install Pillow"}
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    mcp.run()
