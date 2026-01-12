"""Data types for Reti SDK."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List
import time


class FollowStatus(Enum):
    """Status of a follow relationship."""
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    UNFOLLOWED = "unfollowed"
    BLOCKED = "blocked"


class DeliveryStatus(Enum):
    """Status of message delivery (RIP-0008)."""
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"


@dataclass
class Attachment:
    """File attachment."""
    name: str
    mime_type: str
    size: int
    hash: str
    data: Optional[str] = None  # Base64 encoded content


@dataclass
class Message:
    """Direct message."""
    id: str
    source: str
    destination: str
    content: str
    timestamp: float
    is_outbound: bool = False
    thread_id: Optional[str] = None
    reply_to: Optional[str] = None
    attachments: List[Attachment] = field(default_factory=list)
    delivery_status: str = "pending"  # RIP-0008: pending, sent, delivered, failed


@dataclass
class Post:
    """Feed post."""
    id: str
    author: str
    author_name: str
    content: str
    timestamp: float
    in_reply_to: Optional[str] = None
    thread_root: Optional[str] = None
    mentions: List[str] = field(default_factory=list)
    content_warnings: List[str] = field(default_factory=list)
    attachments: List[Attachment] = field(default_factory=list)


@dataclass
class Profile:
    """User profile."""
    identity_hash: str
    display_name: str = ""
    bio: str = ""
    avatar_hash: str = ""
    updated_at: float = field(default_factory=time.time)


@dataclass
class Follow:
    """Follow relationship."""
    identity_hash: str
    status: FollowStatus
    is_follower: bool = False
    is_following: bool = False
    is_blocked: bool = False
    created_at: float = field(default_factory=time.time)


@dataclass
class Group:
    """Group chat."""
    id: str
    name: str
    created_by: str
    created_at: float
    is_admin: bool = False


@dataclass
class GroupMember:
    """Group member."""
    identity_hash: str
    display_name: str = ""
    joined_at: float = field(default_factory=time.time)


@dataclass
class GroupMessage:
    """Group chat message."""
    id: str
    group_id: str
    sender: str
    sender_name: str
    content: str
    timestamp: float
    is_outbound: bool = False
    attachments: List[Attachment] = field(default_factory=list)


@dataclass
class BlogPost:
    """Blog post (long-form content)."""
    id: str
    author: str
    author_name: str
    title: str
    content: str
    summary: str = ""
    body_format: str = "markdown"
    tags: List[str] = field(default_factory=list)
    slug: str = ""
    published_at: float = field(default_factory=time.time)
    updated_at: Optional[float] = None
    attachments: List[Attachment] = field(default_factory=list)
