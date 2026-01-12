"""Identity management for Reti SDK."""

import RNS
from pathlib import Path
from typing import Optional


class IdentityManager:
    """Manages Reticulum identity creation, loading, and persistence."""
    
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.config_path.mkdir(parents=True, exist_ok=True)
        self.identity_path = self.config_path / "identity"
        self._identity: Optional[RNS.Identity] = None
    
    def load_or_create(self) -> RNS.Identity:
        """Load existing identity or create a new one."""
        if self.identity_path.exists():
            self._identity = RNS.Identity.from_file(str(self.identity_path))
        else:
            self._identity = RNS.Identity()
            self._identity.to_file(str(self.identity_path))
        return self._identity
    
    @property
    def identity(self) -> Optional[RNS.Identity]:
        """Get the current identity."""
        return self._identity
    
    @property
    def hash(self) -> Optional[str]:
        """Get the identity hash as hex string."""
        if self._identity is None:
            return None
        return RNS.hexrep(self._identity.hash, delimit=False)
    
    @property
    def display_hash(self) -> Optional[str]:
        """Get a shortened display hash."""
        h = self.hash
        if h is None:
            return None
        return f"{h[:8]}...{h[-8:]}"
