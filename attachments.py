"""Attachment handling for Reti SDK."""

import base64
import hashlib
import mimetypes
import io
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


MAX_ATTACHMENT_SIZE = 5 * 1024 * 1024  # 5 MB per RIP-0005/0006/0007
MAX_AVATAR_SIZE = 1 * 1024 * 1024  # 1 MB per RIP-0002
MAX_AVATAR_ENCODED_SIZE = 50 * 1024  # 50 KB - fits in LXMF with base64 overhead
AVATAR_MAX_DIMENSION = 256  # Max width/height for avatars

IMAGE_MIME_TYPES = {
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp'
}


class AttachmentError(Exception):
    """Base exception for attachment errors."""
    pass


class FileTooLargeError(AttachmentError):
    """Raised when file exceeds maximum size."""
    pass


class FileReadError(AttachmentError):
    """Raised when file cannot be read."""
    pass


class AttachmentManager:
    """Manages file attachments for messages."""
    
    def __init__(self, storage_path: Optional[Path] = None):
        self.storage_path = storage_path
        if storage_path:
            storage_path.mkdir(parents=True, exist_ok=True)
    
    def read_file(self, file_path: str) -> Tuple[bytes, str, str]:
        """Read a file and return its content, MIME type, and filename."""
        path = Path(file_path)
        
        if not path.exists():
            raise FileReadError(f"File not found: {file_path}")
        
        if not path.is_file():
            raise FileReadError(f"Not a file: {file_path}")
        
        size = path.stat().st_size
        if size > MAX_ATTACHMENT_SIZE:
            raise FileTooLargeError(
                f"File too large: {size} bytes (max {MAX_ATTACHMENT_SIZE} bytes)"
            )
        
        try:
            with open(path, 'rb') as f:
                content = f.read()
        except Exception as e:
            raise FileReadError(f"Failed to read file: {e}")
        
        mime_type, _ = mimetypes.guess_type(str(path))
        if not mime_type:
            mime_type = 'application/octet-stream'
        
        return content, mime_type, path.name
    
    def encode_file(self, file_path: str) -> Dict[str, Any]:
        """Encode a file for transmission."""
        content, mime_type, filename = self.read_file(file_path)
        
        content_hash = hashlib.sha256(content).hexdigest()
        encoded_data = base64.b64encode(content).decode('utf-8')
        
        return {
            'name': filename,
            'mime': mime_type,
            'size': len(content),
            'hash': content_hash,
            'data': encoded_data
        }
    
    def decode_attachment(self, attachment: Dict[str, Any]) -> bytes:
        """Decode an attachment from base64."""
        data = attachment.get('data', '')
        return base64.b64decode(data)
    
    def save_attachment(self, attachment: Dict[str, Any], 
                        destination: Optional[str] = None) -> str:
        """Save an attachment to disk."""
        content = self.decode_attachment(attachment)
        filename = attachment.get('name', 'attachment')
        
        if destination:
            save_path = Path(destination)
        elif self.storage_path:
            hash_prefix = attachment.get('hash', '')[:8]
            safe_filename = f"{hash_prefix}_{filename}"
            save_path = self.storage_path / safe_filename
        else:
            save_path = Path(filename)
        
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(save_path, 'wb') as f:
            f.write(content)
        
        return str(save_path)
    
    def verify_attachment(self, attachment: Dict[str, Any]) -> bool:
        """Verify attachment integrity using hash."""
        expected_hash = attachment.get('hash', '')
        if not expected_hash:
            return True
        
        content = self.decode_attachment(attachment)
        actual_hash = hashlib.sha256(content).hexdigest()
        
        return actual_hash == expected_hash
    
    def is_image(self, mime_type: str) -> bool:
        """Check if MIME type is a displayable image."""
        return mime_type in IMAGE_MIME_TYPES
    
    def encode_avatar(self, file_path: str) -> Dict[str, Any]:
        """Encode an avatar image, resizing and compressing to fit LXMF limits.
        
        Avatars are resized to max 256x256 and compressed to ~50KB.
        Per RIP-0002, maximum avatar size is 1MB (we compress further for LXMF).
        """
        path = Path(file_path)
        if not path.exists():
            raise FileReadError(f"File not found: {file_path}")
        
        # Check raw file size against RIP-0002 1MB limit
        raw_size = path.stat().st_size
        if raw_size > MAX_AVATAR_SIZE:
            raise FileTooLargeError(
                f"Avatar too large: {raw_size} bytes (max {MAX_AVATAR_SIZE} bytes per RIP-0002)"
            )
        
        if not HAS_PIL:
            # Fall back to regular encoding if PIL not available
            return self.encode_file(file_path)
        
        try:
            with Image.open(file_path) as img:
                # Convert to RGB if necessary (handles RGBA, P mode, etc.)
                if img.mode in ('RGBA', 'P'):
                    img = img.convert('RGB')
                elif img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # Resize to fit within max dimensions while preserving aspect ratio
                img.thumbnail((AVATAR_MAX_DIMENSION, AVATAR_MAX_DIMENSION), Image.Resampling.LANCZOS)
                
                # Compress as JPEG with decreasing quality until under size limit
                quality = 85
                while quality >= 20:
                    buffer = io.BytesIO()
                    img.save(buffer, format='JPEG', quality=quality, optimize=True)
                    content = buffer.getvalue()
                    
                    if len(content) <= MAX_AVATAR_ENCODED_SIZE:
                        break
                    quality -= 10
                
                content_hash = hashlib.sha256(content).hexdigest()
                encoded_data = base64.b64encode(content).decode('utf-8')
                
                return {
                    'name': path.stem + '.jpg',
                    'mime': 'image/jpeg',
                    'size': len(content),
                    'hash': content_hash,
                    'data': encoded_data
                }
        except Exception as e:
            raise FileReadError(f"Failed to process avatar image: {e}")
    
    def format_size(self, size: int) -> str:
        """Format file size for display."""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"
    
    def prepare_attachments(self, file_paths: List[str], 
                             max_size: int = MAX_ATTACHMENT_SIZE) -> List[Dict[str, Any]]:
        """Prepare multiple files for sending.
        
        Args:
            file_paths: List of file paths to encode
            max_size: Maximum size per file (default 5MB per RIP-0005/0006/0007)
        """
        attachments = []
        for path in file_paths:
            try:
                # Check size before encoding
                file_size = Path(path).stat().st_size
                if file_size > max_size:
                    print(f"[Attachments] File too large ({file_size} > {max_size}): {path}")
                    continue
                attachment = self.encode_file(path)
                attachments.append(attachment)
            except AttachmentError as e:
                print(f"[Attachments] Failed to encode {path}: {e}")
        return attachments
    
    def validate_received_attachment(self, attachment: Dict[str, Any], 
                                     max_size: int = MAX_ATTACHMENT_SIZE) -> bool:
        """Validate a received attachment meets size requirements.
        
        Args:
            attachment: Attachment dict with size field
            max_size: Maximum allowed size (default 5MB)
        
        Returns:
            True if valid, False if exceeds size limit
        """
        size = attachment.get('size', 0)
        if size > max_size:
            print(f"[Attachments] Received attachment too large: {size} > {max_size}")
            return False
        return self.verify_attachment(attachment)
    
    def create_metadata(self, attachments: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Create metadata-only list for LXMF fields (without data)."""
        return [
            {
                'name': a['name'],
                'mime': a['mime'],
                'size': a['size'],
                'hash': a['hash']
            }
            for a in attachments
        ]
