"""Tests for RetiClient."""

import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path
import tempfile

from reti import RetiClient
from reti.types import Message, Post, Profile


class TestRetiClientInit:
    """Test client initialization."""
    
    def test_init_creates_config_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test_config"
            client = RetiClient(str(config_path))
            assert config_path.exists()
    
    def test_init_default_path(self):
        # Just verify it doesn't crash with default path
        client = RetiClient()
        assert client._config_path is not None


class TestRetiClientProfile:
    """Test profile operations."""
    
    def test_set_and_get_profile(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = RetiClient(tmpdir)
            # Mock identity hash
            client._identity._identity = MagicMock()
            client._identity._identity.hash = b'\x00' * 16
            
            client.set_profile("Test User", "Hello world", "avatar123")
            profile = client.get_profile()
            
            assert profile is not None
            assert profile.display_name == "Test User"
            assert profile.bio == "Hello world"
            assert profile.avatar_hash == "avatar123"


class TestRetiClientStorage:
    """Test storage operations."""
    
    def test_save_and_get_messages(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = RetiClient(tmpdir)
            
            # Directly test storage
            msg_data = {
                "source": "abc123",
                "destination": "def456",
                "content": "Hello",
                "timestamp": 1234567890.0,
                "fields": {}
            }
            client._storage.save_message(msg_data)
            
            messages = client.get_messages("abc123")
            assert len(messages) == 1
            assert messages[0].content == "Hello"


class TestRetiClientFollows:
    """Test follow operations."""
    
    def test_follow_storage(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = RetiClient(tmpdir)
            
            # Test storage directly
            client._storage.save_follow("user123", is_following=True, status="pending")
            following = client.get_following()
            
            assert len(following) == 1
            assert following[0]["identity_hash"] == "user123"
            assert following[0]["status"] == "pending"
    
    def test_block_user(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = RetiClient(tmpdir)
            
            client._storage.block_user("baduser")
            assert client._storage.is_blocked("baduser")
            
            client._storage.unblock_user("baduser")
            assert not client._storage.is_blocked("baduser")


class TestRetiClientGroups:
    """Test group operations."""
    
    def test_group_storage(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client = RetiClient(tmpdir)
            
            client._storage.create_group("group123", "Test Group", "creator", is_admin=True)
            client._storage.add_group_member("group123", "member1", "Member One")
            
            groups = client.get_groups()
            assert len(groups) == 1
            assert groups[0].name == "Test Group"
            
            members = client.get_group_members("group123")
            assert len(members) == 1
            assert members[0]["identity_hash"] == "member1"
