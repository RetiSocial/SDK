"""Main client for Reti SDK."""

import time
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable
import appdirs

from reti.identity import IdentityManager
from reti.transport import Transport
from reti.storage import Storage
from reti.attachments import AttachmentManager
from reti.types import Message, Post, Profile, Group, GroupMessage, Attachment, BlogPost


class RateLimiter:
    """Simple rate limiter for requests."""
    
    def __init__(self, max_requests: int = 10, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[str, List[float]] = {}
    
    def is_allowed(self, key: str) -> bool:
        now = time.time()
        if key not in self._requests:
            self._requests[key] = []
        
        self._requests[key] = [t for t in self._requests[key] if now - t < self.window_seconds]
        
        if len(self._requests[key]) >= self.max_requests:
            return False
        
        self._requests[key].append(now)
        return True


class RetiClient:
    """Main Reti Social client."""
    
    APP_NAME = "reti_social"
    
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = appdirs.user_data_dir(self.APP_NAME)
        
        self._config_path = Path(config_path)
        self._config_path.mkdir(parents=True, exist_ok=True)
        
        self._identity = IdentityManager(self._config_path)
        self._transport = Transport(self._identity, self._config_path)
        self._storage = Storage(self._config_path / "reti.db")
        self._attachments = AttachmentManager(self._config_path / "attachments")
        
        # Callbacks
        self._on_message_callbacks: List[Callable[[Message], None]] = []
        self._on_post_callbacks: List[Callable[[Post], None]] = []
        self._on_follow_callbacks: List[Callable[[str, str], None]] = []
        self._on_group_callbacks: List[Callable[[str, Dict[str, Any]], None]] = []
        self._on_profile_callbacks: List[Callable[[Profile], None]] = []
        self._on_blog_callbacks: List[Callable[[BlogPost], None]] = []
        self._on_delivery_callbacks: List[Callable[[str, str], None]] = []  # RIP-0008
        self._on_sync_callbacks: List[Callable[[str, Any], None]] = []  # RIP-0009
        
        # Rate limiters
        self._follow_limiter = RateLimiter(max_requests=10, window_seconds=60.0)
        self._profile_limiter = RateLimiter(max_requests=20, window_seconds=60.0)
    
    # Lifecycle
    def start(self) -> bool:
        """Start the client."""
        success = self._transport.start()
        if success:
            self._transport.on_message(self._handle_message)
            self._transport.on_delivery(self._handle_delivery)  # RIP-0008
            self._transport.on_sync(self._handle_sync)  # RIP-0009
        return success
    
    def stop(self):
        """Stop the client."""
        self._transport.stop()
    
    @property
    def is_running(self) -> bool:
        return self._transport.is_running
    
    @property
    def address(self) -> Optional[str]:
        """Get the LXMF address."""
        return self._transport.lxmf_address
    
    @property
    def identity_hash(self) -> Optional[str]:
        """Get the identity hash."""
        return self._identity.hash
    
    @property
    def display_hash(self) -> Optional[str]:
        """Get shortened display hash."""
        return self._identity.display_hash
    
    # Event decorators
    def on_message(self, callback: Callable[[Message], None]):
        """Register callback for incoming DMs."""
        self._on_message_callbacks.append(callback)
        return callback
    
    def on_post(self, callback: Callable[[Post], None]):
        """Register callback for incoming posts."""
        self._on_post_callbacks.append(callback)
        return callback
    
    def on_follow(self, callback: Callable[[str, str], None]):
        """Register callback for follow events (identity_hash, event_type)."""
        self._on_follow_callbacks.append(callback)
        return callback
    
    def on_group(self, callback: Callable[[str, Dict[str, Any]], None]):
        """Register callback for group events."""
        self._on_group_callbacks.append(callback)
        return callback
    
    def on_profile(self, callback: Callable[[Profile], None]):
        """Register callback for profile updates."""
        self._on_profile_callbacks.append(callback)
        return callback
    
    def on_blog(self, callback: Callable[[BlogPost], None]):
        """Register callback for incoming blog posts."""
        self._on_blog_callbacks.append(callback)
        return callback
    
    def on_delivery(self, callback: Callable[[str, str], None]):
        """Register callback for delivery status changes (RIP-0008).
        
        Callback signature: callback(message_hash, status)
        Status values: 'sent', 'delivered', 'failed'
        """
        self._on_delivery_callbacks.append(callback)
        return callback
    
    def on_sync(self, callback: Callable[[str, Any], None]):
        """Register callback for sync events (RIP-0009).
        
        Callback signature: callback(event, data)
        Events: 'started', 'complete', 'failed'
        """
        self._on_sync_callbacks.append(callback)
        return callback
    
    # Message handling
    def _handle_message(self, msg_data: Dict[str, Any]):
        """Route incoming messages."""
        print(f"[RetiClient] _handle_message: title={msg_data.get('title')}, rip={msg_data.get('fields', {}).get('rip')}")
        fields = msg_data.get("fields", {})
        rip = fields.get("rip")
        msg_type = fields.get("type")
        source = msg_data.get("source", "")
        
        if rip == "RIP-0005" and msg_type in ("post", "reply"):
            self._handle_post(msg_data)
        elif rip == "RIP-0004":
            self._handle_follow(msg_data)
        elif rip == "RIP-0006":
            self._handle_group(msg_data)
        elif rip == "RIP-0002":
            self._handle_profile(msg_data)
        elif rip == "RIP-0007":
            self._handle_blog(msg_data)
        else:
            self._handle_dm(msg_data)
    
    def _handle_delivery(self, message_hash: str, status: str):
        """Handle delivery status update (RIP-0008)."""
        self._storage.update_delivery_status(message_hash, status)
        
        for callback in self._on_delivery_callbacks:
            try:
                callback(message_hash, status)
            except Exception as e:
                print(f"[RetiClient] Delivery callback error: {e}")
    
    def _handle_sync(self, event: str, data: Any):
        """Handle sync event (RIP-0009)."""
        for callback in self._on_sync_callbacks:
            try:
                callback(event, data)
            except Exception as e:
                print(f"[RetiClient] Sync callback error: {e}")
    
    def _handle_blog(self, msg_data: Dict[str, Any]):
        """Handle incoming blog post."""
        fields = msg_data.get("fields", {})
        msg_type = fields.get("type")
        source = msg_data.get("source", "")
        
        if self._storage.is_blocked(source):
            return
        
        accepted = [f["identity_hash"] for f in self._storage.get_accepted_following()]
        if source not in accepted:
            return
        
        if msg_type == "blog_post":
            blog_data = {
                "blog_id": fields.get("blog_id"),
                "author_hash": source,
                "author_name": fields.get("author_name", ""),
                "title": fields.get("title", ""),
                "content": msg_data.get("content", ""),
                "summary": fields.get("summary", ""),
                "body_format": fields.get("body_format", "markdown"),
                "tags": fields.get("tags", []),
                "slug": fields.get("slug", ""),
                "published_at": fields.get("published_at", msg_data.get("timestamp", time.time()))
            }
            
            if self._storage.save_blog_post(blog_data):
                self._save_received_attachments(msg_data, blog_id=fields.get("blog_id"))
                
                blog = BlogPost(
                    id=blog_data["blog_id"],
                    author=source,
                    author_name=blog_data["author_name"],
                    title=blog_data["title"],
                    content=blog_data["content"],
                    summary=blog_data["summary"],
                    body_format=blog_data["body_format"],
                    tags=blog_data["tags"],
                    slug=blog_data["slug"],
                    published_at=blog_data["published_at"]
                )
                for callback in self._on_blog_callbacks:
                    try:
                        callback(blog)
                    except Exception as e:
                        print(f"[RetiClient] Blog callback error: {e}")
        
        elif msg_type == "blog_update":
            blog_id = fields.get("blog_id")
            existing = self._storage.get_blog_post(blog_id)
            if existing and existing["author_hash"] == source:
                blog_data = {
                    "blog_id": blog_id,
                    "title": fields.get("title", existing["title"]),
                    "content": msg_data.get("content", existing["content"]),
                    "summary": fields.get("summary", existing["summary"]),
                    "tags": fields.get("tags", existing["tags"]),
                    "updated_at": fields.get("updated_at", time.time())
                }
                self._storage.save_blog_post(blog_data)
        
        elif msg_type == "blog_delete":
            blog_id = fields.get("blog_id")
            existing = self._storage.get_blog_post(blog_id)
            if existing and existing["author_hash"] == source:
                self._storage.delete_blog_post(blog_id)
    
    def _handle_dm(self, msg_data: Dict[str, Any]):
        """Handle incoming DM."""
        message_hash = self._storage.save_message(msg_data)
        if message_hash:
            self._save_received_attachments(msg_data, message_hash=message_hash)
            
            msg = Message(
                id=message_hash,
                source=msg_data.get("source", ""),
                destination=msg_data.get("destination", ""),
                content=msg_data.get("content", ""),
                timestamp=msg_data.get("timestamp", time.time()),
                is_outbound=False
            )
            for callback in self._on_message_callbacks:
                try:
                    callback(msg)
                except Exception as e:
                    print(f"[RetiClient] Message callback error: {e}")
    
    def _handle_post(self, msg_data: Dict[str, Any]):
        """Handle incoming feed post."""
        fields = msg_data.get("fields", {})
        source = msg_data.get("source", "")
        
        if self._storage.is_blocked(source):
            return
        
        accepted = [f["identity_hash"] for f in self._storage.get_accepted_following()]
        if source not in accepted:
            return
        
        post_data = {
            "post_id": fields.get("post_id"),
            "author_hash": source,
            "author_name": fields.get("author_name", ""),
            "content": msg_data.get("content", ""),
            "timestamp": msg_data.get("timestamp", time.time()),
            "in_reply_to": fields.get("in_reply_to"),
            "thread_root": fields.get("thread_root"),
            "mentions": fields.get("mentions", []),
            "cw": fields.get("cw", [])
        }
        
        if self._storage.save_post(post_data):
            self._save_received_attachments(msg_data, post_id=fields.get("post_id"))
            
            post = Post(
                id=post_data["post_id"],
                author=source,
                author_name=post_data["author_name"],
                content=post_data["content"],
                timestamp=post_data["timestamp"],
                in_reply_to=post_data["in_reply_to"],
                thread_root=post_data["thread_root"],
                mentions=post_data["mentions"],
                content_warnings=post_data["cw"]
            )
            for callback in self._on_post_callbacks:
                try:
                    callback(post)
                except Exception as e:
                    print(f"[RetiClient] Post callback error: {e}")
    
    def _handle_follow(self, msg_data: Dict[str, Any]):
        """Handle follow protocol messages."""
        fields = msg_data.get("fields", {})
        msg_type = fields.get("type")
        source = msg_data.get("source", "")
        
        if self._storage.is_blocked(source):
            return
        
        if msg_type == "follow_request":
            if not self._follow_limiter.is_allowed(source):
                return
            self._storage.save_follow(source, is_follower=True, status="pending")
        elif msg_type == "follow_accept":
            self._storage.save_follow(source, is_following=True, status="accepted")
        elif msg_type == "follow_reject":
            self._storage.save_follow(source, is_following=False, status="rejected")
        elif msg_type == "unfollow":
            self._storage.save_follow(source, is_follower=False, status="unfollowed")
        elif msg_type == "block":
            self._storage.mark_blocked_by(source)
        
        for callback in self._on_follow_callbacks:
            try:
                callback(source, msg_type)
            except Exception as e:
                print(f"[RetiClient] Follow callback error: {e}")
    
    def _handle_group(self, msg_data: Dict[str, Any]):
        """Handle group messages."""
        print(f"[RetiClient] _handle_group called with: {msg_data}")
        fields = msg_data.get("fields", {})
        msg_type = fields.get("type")
        group_id = fields.get("group_id")
        source = msg_data.get("source", "")
        
        event_data = {"type": msg_type, "group_id": group_id, "source": source}
        
        if msg_type == "group_invite":
            group_name = fields.get("group_name", "Unknown Group")
            self._storage.create_group(group_id, group_name, source, is_admin=False)
            self._storage.add_group_member(group_id, self.address or "", self._get_display_name())
            
            # Add all members from the invite
            member_list = fields.get("members", [])
            for member_hash in member_list:
                if member_hash != self.address:
                    self._storage.add_group_member(group_id, member_hash)
            
            event_data["group_name"] = group_name
        
        elif msg_type == "group_message":
            group = self._storage.get_group(group_id)
            if not group:
                return
            members = self._storage.get_group_members(group_id)
            member_hashes = [m["identity_hash"] for m in members]
            
            # RIP-0006: Validate sender is a known group member (security requirement)
            if source not in member_hashes:
                print(f"[RetiClient] Rejecting group message from unknown sender: {source[:16]}...")
                return
            
            msg_save = {
                "sender": source,
                "sender_name": fields.get("sender_name", ""),
                "content": msg_data.get("content", ""),
                "timestamp": msg_data.get("timestamp", time.time())
            }
            msg_hash = self._storage.save_group_message(group_id, msg_save)
            if msg_hash:
                self._save_received_attachments(msg_data, group_message_hash=msg_hash)
            event_data["message"] = msg_save
        
        elif msg_type == "group_leave":
            self._storage.remove_group_member(group_id, source)
        
        elif msg_type == "group_kick":
            kicked = fields.get("kicked", "")
            if kicked == self.address:
                self._storage.delete_group(group_id)
            event_data["kicked"] = kicked
        
        for callback in self._on_group_callbacks:
            try:
                callback(group_id, event_data)
            except Exception as e:
                print(f"[RetiClient] Group callback error: {e}")
    
    def _handle_profile(self, msg_data: Dict[str, Any]):
        """Handle profile messages."""
        fields = msg_data.get("fields", {})
        msg_type = fields.get("type")
        source = msg_data.get("source", "")
        
        if msg_type == "profile_request":
            if not self._profile_limiter.is_allowed(source):
                return
            self._send_profile_response(source)
        
        elif msg_type == "profile":
            # Save avatar attachment if included
            avatar_hash = fields.get("avatar", "")
            avatar_data = fields.get("avatar_data")
            if avatar_data and avatar_hash:
                self._storage.save_attachment(
                    attachment_hash=avatar_data.get("hash", avatar_hash),
                    name=avatar_data.get("name", "avatar"),
                    mime_type=avatar_data.get("mime", "image/png"),
                    size=avatar_data.get("size", 0),
                    data=avatar_data.get("data", "")
                )
            
            self._storage.save_profile(
                source,
                fields.get("display_name", ""),
                fields.get("bio", ""),
                avatar_hash
            )
            profile = Profile(
                identity_hash=source,
                display_name=fields.get("display_name", ""),
                bio=fields.get("bio", ""),
                avatar_hash=avatar_hash,
                updated_at=fields.get("updated_at", time.time())
            )
            for callback in self._on_profile_callbacks:
                try:
                    callback(profile)
                except Exception as e:
                    print(f"[RetiClient] Profile callback error: {e}")
    
    def _save_received_attachments(self, msg_data: Dict[str, Any], message_hash: str = None,
                                    post_id: str = None, group_message_hash: str = None,
                                    blog_id: str = None):
        """Save attachments from received message."""
        fields = msg_data.get("fields", {})
        attachment_data = fields.get("attachment_data", [])
        
        for att in attachment_data:
            if not self._attachments.verify_attachment(att):
                continue
            self._storage.save_attachment(
                attachment_hash=att.get('hash', ''),
                name=att.get('name', 'attachment'),
                mime_type=att.get('mime', 'application/octet-stream'),
                size=att.get('size', 0),
                data=att.get('data', ''),
                message_hash=message_hash,
                post_id=post_id,
                group_message_hash=group_message_hash,
                blog_id=blog_id
            )
    
    def _get_display_name(self) -> str:
        """Get current user's display name."""
        profile = self._storage.get_profile(self.identity_hash or "")
        return profile.get("display_name", "") if profile else ""
    
    def _send_profile_response(self, destination: str) -> bool:
        """Send profile to requester."""
        profile = self._storage.get_profile(self.identity_hash or "")
        fields = {
            "rip": "RIP-0002",
            "rip_rev": 1,
            "type": "profile",
            "display_name": profile.get("display_name", "") if profile else "",
            "bio": profile.get("bio", "") if profile else "",
            "avatar": profile.get("avatar_hash", "") if profile else "",
            "updated_at": profile.get("updated_at", time.time()) if profile else time.time()
        }
        
        # Include avatar image data if available
        avatar_hash = profile.get("avatar_hash", "") if profile else ""
        if avatar_hash:
            avatar_att = self._storage.get_attachment(avatar_hash)
            if avatar_att:
                fields["avatar_data"] = {
                    "hash": avatar_hash,
                    "name": avatar_att.get("name", "avatar"),
                    "mime": avatar_att.get("mime_type", "image/png"),
                    "size": avatar_att.get("size", 0),
                    "data": avatar_att.get("data", "")
                }
        
        content = profile.get("bio", "")[:100] if profile else ""
        return self._transport.send_message(destination, content, title="profile", fields=fields)
    
    # Public API - Profile
    def set_profile(self, display_name: str, bio: str = "", avatar_hash: str = ""):
        """Set your profile."""
        if self.identity_hash:
            self._storage.save_profile(self.identity_hash, display_name, bio, avatar_hash)
    
    def get_profile(self, identity_hash: Optional[str] = None) -> Optional[Profile]:
        """Get a profile."""
        target = identity_hash or self.identity_hash
        if not target:
            return None
        data = self._storage.get_profile(target)
        if data:
            return Profile(
                identity_hash=data["identity_hash"],
                display_name=data.get("display_name", ""),
                bio=data.get("bio", ""),
                avatar_hash=data.get("avatar_hash", ""),
                updated_at=data.get("updated_at", 0)
            )
        return None
    
    def request_profile(self, identity_hash: str) -> bool:
        """Request profile from another user."""
        fields = {
            "rip": "RIP-0002",
            "rip_rev": 1,
            "type": "profile_request"
        }
        return self._transport.send_message(identity_hash, "Profile request", title="profile_request", fields=fields)
    
    # Public API - Propagation Node (RIP-0009)
    def set_propagation_node(self, node_hash: Optional[str]):
        """Set the preferred Propagation Node for store-and-forward messaging.
        
        Args:
            node_hash: Hash of the Propagation Node, or None to clear.
        """
        self._transport.set_propagation_node(node_hash)
    
    @property
    def propagation_node(self) -> Optional[str]:
        """Get the current Propagation Node hash."""
        return self._transport.propagation_node
    
    def sync_messages(self) -> bool:
        """Request pending messages from the configured Propagation Node.
        
        Returns:
            True if sync was initiated, False otherwise.
        """
        return self._transport.sync_messages()
    
    # Public API - DMs
    def send_dm(self, destination: str, content: str, thread_id: Optional[str] = None,
                reply_to: Optional[str] = None, attachments: Optional[List[str]] = None) -> Optional[str]:
        """Send a direct message.
        
        Returns:
            Message hash if sent successfully, None otherwise.
        """
        if self._storage.is_blocked(destination):
            return None
        
        fields = {
            "rip": "RIP-0003",
            "rip_rev": 1,
            "type": "dm"
        }
        if thread_id:
            fields["thread_id"] = thread_id
        if reply_to:
            fields["reply_to"] = reply_to
        
        attachment_list = []
        if attachments:
            attachment_list = self._attachments.prepare_attachments(attachments)
            if attachment_list:
                fields["attachments"] = self._attachments.create_metadata(attachment_list)
                fields["attachment_data"] = attachment_list
        
        # RIP-0008: Save message first to get hash for delivery tracking
        now = time.time()
        msg_data = {
            "source": self.identity_hash,
            "destination": destination,
            "content": content,
            "timestamp": now,
            "fields": fields
        }
        message_hash = self._storage.save_message(msg_data, is_outbound=True, delivery_status="pending")
        
        if not message_hash:
            return None
        
        # Send with message_hash for delivery tracking
        success = self._transport.send_message(destination, content, title="", fields=fields, message_hash=message_hash)
        
        if success:
            # Update status to sent
            self._storage.update_delivery_status(message_hash, "sent")
            
            if attachment_list:
                for att in attachment_list:
                    self._storage.save_attachment(
                        attachment_hash=att['hash'],
                        name=att['name'],
                        mime_type=att['mime'],
                        size=att['size'],
                        data=att['data'],
                        message_hash=message_hash
                    )
            return message_hash
        else:
            # Mark as failed if send failed immediately
            self._storage.update_delivery_status(message_hash, "failed")
            return None
    
    def get_messages(self, peer: Optional[str] = None) -> List[Message]:
        """Get messages, optionally filtered by peer."""
        data = self._storage.get_messages(peer)
        messages = []
        for m in data:
            atts = self._storage.get_attachments_for_message(m["message_hash"])
            messages.append(Message(
                id=m["message_hash"],
                source=m["source"],
                destination=m["destination"],
                content=m["content"],
                timestamp=m["timestamp"],
                is_outbound=m["is_outbound"],
                attachments=[Attachment(
                    name=a["name"],
                    mime_type=a["mime_type"],
                    size=a["size"],
                    hash=a["attachment_hash"],
                    data=a.get("data")
                ) for a in atts],
                delivery_status=m.get("delivery_status", "pending")
            ))
        return messages
    
    def mark_messages_read(self, peer_hash: str) -> int:
        """Mark all messages from a peer as read."""
        return self._storage.mark_messages_read(peer_hash)
    
    def get_unread_count(self, peer_hash: Optional[str] = None) -> int:
        """Get count of unread messages, optionally filtered by peer."""
        return self._storage.get_unread_count(peer_hash)
    
    def get_unread_peers(self) -> List[Dict[str, Any]]:
        """Get list of peers with unread message counts."""
        return self._storage.get_unread_peers()
    
    # Public API - Feed
    def post(self, content: str, content_warnings: Optional[List[str]] = None,
             reply_to: Optional[str] = None, attachments: Optional[List[str]] = None) -> bool:
        """Create a post and deliver to followers."""
        now = time.time()
        post_id = hashlib.sha256(f"{self.identity_hash}{content}{now}".encode()).hexdigest()
        author_name = self._get_display_name()
        
        fields = {
            "rip": "RIP-0005",
            "rip_rev": 1,
            "type": "reply" if reply_to else "post",
            "post_id": post_id,
            "author_name": author_name
        }
        if content_warnings:
            fields["cw"] = content_warnings
        if reply_to:
            fields["in_reply_to"] = reply_to
            parent = self._storage.get_post(reply_to)
            if parent:
                fields["thread_root"] = parent.get("thread_root") or reply_to
        
        attachment_list = []
        if attachments:
            attachment_list = self._attachments.prepare_attachments(attachments)
            if attachment_list:
                fields["attachments"] = self._attachments.create_metadata(attachment_list)
                fields["attachment_data"] = attachment_list
        
        post_data = {
            "post_id": post_id,
            "author_hash": self.identity_hash,
            "author_name": author_name,
            "content": content,
            "timestamp": now,
            "in_reply_to": reply_to,
            "thread_root": fields.get("thread_root"),
            "cw": content_warnings or []
        }
        self._storage.save_post(post_data)
        
        if attachment_list:
            for att in attachment_list:
                self._storage.save_attachment(
                    attachment_hash=att['hash'],
                    name=att['name'],
                    mime_type=att['mime'],
                    size=att['size'],
                    data=att['data'],
                    post_id=post_id
                )
        
        followers = self._storage.get_followers()
        success_count = 0
        for follower in followers:
            if self._storage.is_blocked(follower["identity_hash"]):
                continue
            if self._transport.send_message(follower["identity_hash"], content, title="post", fields=fields):
                success_count += 1
        
        return success_count > 0 or len(followers) == 0
    
    def get_feed(self) -> List[Post]:
        """Get feed posts."""
        data = self._storage.get_feed()
        posts = []
        for p in data:
            atts = self._storage.get_attachments_for_post(p["post_id"])
            posts.append(Post(
                id=p["post_id"],
                author=p["author_hash"],
                author_name=p["author_name"],
                content=p["content"],
                timestamp=p["timestamp"],
                in_reply_to=p["in_reply_to"],
                thread_root=p["thread_root"],
                mentions=p["mentions"],
                content_warnings=p["cw"],
                attachments=[Attachment(
                    name=a["name"],
                    mime_type=a["mime_type"],
                    size=a["size"],
                    hash=a["attachment_hash"],
                    data=a.get("data")
                ) for a in atts]
            ))
        return posts
    
    def get_post(self, post_id: str) -> Optional[Post]:
        """Get a single post."""
        p = self._storage.get_post(post_id)
        if p:
            atts = self._storage.get_attachments_for_post(post_id)
            return Post(
                id=p["post_id"],
                author=p["author_hash"],
                author_name=p["author_name"],
                content=p["content"],
                timestamp=p["timestamp"],
                in_reply_to=p["in_reply_to"],
                thread_root=p["thread_root"],
                mentions=p["mentions"],
                content_warnings=p["cw"],
                attachments=[Attachment(
                    name=a["name"],
                    mime_type=a["mime_type"],
                    size=a["size"],
                    hash=a["attachment_hash"],
                    data=a.get("data")
                ) for a in atts]
            )
        return None
    
    def get_replies(self, post_id: str) -> List[Post]:
        """Get replies to a post."""
        data = self._storage.get_replies(post_id)
        return [Post(
            id=p["post_id"],
            author=p["author_hash"],
            author_name=p["author_name"],
            content=p["content"],
            timestamp=p["timestamp"],
            in_reply_to=p["in_reply_to"],
            thread_root=p["thread_root"],
            mentions=p["mentions"],
            content_warnings=p["cw"]
        ) for p in data]
    
    def delete_post(self, post_id: str) -> bool:
        """Delete a post (only works for own posts)."""
        post = self._storage.get_post(post_id)
        if not post:
            return False
        if post["author_hash"] != self.identity_hash:
            return False
        return self._storage.delete_post(post_id)
    
    # Public API - Follows
    def follow(self, identity_hash: str, note: str = "") -> bool:
        """Send a follow request.
        
        Args:
            identity_hash: The identity to follow
            note: Optional note to include with the request (per RIP-0004)
        """
        fields = {
            "rip": "RIP-0004",
            "rip_rev": 1,
            "type": "follow_request"
        }
        if note:
            fields["note"] = note
        
        success = self._transport.send_message(identity_hash, "Follow request", title="follow_request", fields=fields)
        if success:
            self._storage.save_follow(identity_hash, is_following=True, status="pending")
        return success
    
    def accept_follow(self, identity_hash: str, policy: str = "") -> bool:
        """Accept a follow request.
        
        Args:
            identity_hash: The identity to accept
            policy: Optional policy summary (per RIP-0004)
        """
        fields = {
            "rip": "RIP-0004",
            "rip_rev": 1,
            "type": "follow_accept"
        }
        if policy:
            fields["policy"] = policy
        success = self._transport.send_message(identity_hash, "Follow accepted", title="follow_accept", fields=fields)
        if success:
            self._storage.save_follow(identity_hash, is_follower=True, status="accepted")
        return success
    
    def reject_follow(self, identity_hash: str, reason: str = "") -> bool:
        """Reject a follow request."""
        fields = {
            "rip": "RIP-0004",
            "rip_rev": 1,
            "type": "follow_reject"
        }
        if reason:
            fields["reason"] = reason
        success = self._transport.send_message(identity_hash, "Follow rejected", title="follow_reject", fields=fields)
        if success:
            self._storage.save_follow(identity_hash, is_follower=False, status="rejected")
        return success
    
    def unfollow(self, identity_hash: str) -> bool:
        """Unfollow a user."""
        fields = {
            "rip": "RIP-0004",
            "rip_rev": 1,
            "type": "unfollow"
        }
        success = self._transport.send_message(identity_hash, "Unfollow", title="unfollow", fields=fields)
        if success:
            self._storage.save_follow(identity_hash, is_following=False, status="unfollowed")
        return success
    
    def block(self, identity_hash: str) -> bool:
        """Block a user."""
        fields = {
            "rip": "RIP-0004",
            "rip_rev": 1,
            "type": "block"
        }
        self._transport.send_message(identity_hash, "Block", title="block", fields=fields)
        self._storage.block_user(identity_hash)
        return True
    
    def unblock(self, identity_hash: str) -> bool:
        """Unblock a user."""
        self._storage.unblock_user(identity_hash)
        return True
    
    def get_followers(self) -> List[Dict[str, Any]]:
        """Get list of followers."""
        return self._storage.get_followers()
    
    def get_following(self) -> List[Dict[str, Any]]:
        """Get list of accounts being followed."""
        return self._storage.get_following()
    
    def get_pending_followers(self) -> List[Dict[str, Any]]:
        """Get pending follow requests."""
        return self._storage.get_pending_followers()
    
    def get_blocked(self) -> List[Dict[str, Any]]:
        """Get blocked users."""
        return self._storage.get_blocked_users()
    
    # Public API - Groups
    def create_group(self, name: str, members: List[str]) -> Optional[str]:
        """Create a group and invite members."""
        if not self.address:
            return None
        
        group_id = hashlib.sha256(f"{self.address}{name}{time.time()}".encode()).hexdigest()
        
        self._storage.create_group(group_id, name, self.address, is_admin=True)
        self._storage.add_group_member(group_id, self.address, self._get_display_name())
        
        for member in members:
            self._storage.add_group_member(group_id, member)
            self._send_group_invite(group_id, name, member)
        
        return group_id
    
    def _send_group_invite(self, group_id: str, name: str, destination: str) -> bool:
        members = self._storage.get_group_members(group_id)
        member_list = [m["identity_hash"] for m in members]
        fields = {
            "rip": "RIP-0006",
            "rip_rev": 1,
            "type": "group_invite",
            "group_id": group_id,
            "group_name": name,
            "invited_by": self.address,
            "members": member_list
        }
        return self._transport.send_message(destination, f"Invited to group: {name}", title="group_invite", fields=fields)
    
    def send_group_message(self, group_id: str, content: str, 
                           attachments: Optional[List[str]] = None) -> bool:
        """Send a message to a group."""
        group = self._storage.get_group(group_id)
        if not group:
            return False
        
        members = self._storage.get_group_members(group_id)
        my_name = self._get_display_name()
        now = time.time()
        
        fields = {
            "rip": "RIP-0006",
            "rip_rev": 1,
            "type": "group_message",
            "group_id": group_id,
            "sender_name": my_name
        }
        
        attachment_list = []
        if attachments:
            attachment_list = self._attachments.prepare_attachments(attachments)
            if attachment_list:
                fields["attachments"] = self._attachments.create_metadata(attachment_list)
                fields["attachment_data"] = attachment_list
        
        msg_data = {
            "sender": self.address,
            "sender_name": my_name,
            "content": content,
            "timestamp": now
        }
        msg_hash = self._storage.save_group_message(group_id, msg_data, is_outbound=True)
        
        if attachment_list and msg_hash:
            for att in attachment_list:
                self._storage.save_attachment(
                    attachment_hash=att['hash'],
                    name=att['name'],
                    mime_type=att['mime'],
                    size=att['size'],
                    data=att['data'],
                    group_message_hash=msg_hash
                )
        
        success_count = 0
        print(f"[RetiClient] Sending group message to {len(members)} members, my address: {self.address}")
        for member in members:
            print(f"[RetiClient] Member: {member['identity_hash']}, is_self: {member['identity_hash'] == self.address}")
            if member["identity_hash"] != self.address:
                result = self._transport.send_message(member["identity_hash"], content, title="group_message", fields=fields)
                print(f"[RetiClient] Send to {member['identity_hash'][:16]}... result: {result}")
                if result:
                    success_count += 1
        
        print(f"[RetiClient] Group message sent to {success_count} members")
        return success_count > 0 or len(members) <= 1
    
    def get_groups(self) -> List[Group]:
        """Get all groups."""
        data = self._storage.get_groups()
        return [Group(
            id=g["group_id"],
            name=g["name"],
            created_by=g["created_by"],
            created_at=g["created_at"],
            is_admin=g["is_admin"]
        ) for g in data]
    
    def get_group(self, group_id: str) -> Optional[Group]:
        """Get a group by ID."""
        g = self._storage.get_group(group_id)
        if g:
            return Group(
                id=g["group_id"],
                name=g["name"],
                created_by=g["created_by"],
                created_at=g["created_at"],
                is_admin=g["is_admin"]
            )
        return None
    
    def get_group_members(self, group_id: str) -> List[Dict[str, Any]]:
        """Get group members."""
        return self._storage.get_group_members(group_id)
    
    def get_group_messages(self, group_id: str) -> List[GroupMessage]:
        """Get group messages."""
        data = self._storage.get_group_messages(group_id)
        messages = []
        for m in data:
            atts = self._storage.get_attachments_for_group_message(m["message_hash"])
            messages.append(GroupMessage(
                id=m["message_hash"],
                group_id=m["group_id"],
                sender=m["sender"],
                sender_name=m["sender_name"],
                content=m["content"],
                timestamp=m["timestamp"],
                is_outbound=m["is_outbound"],
                attachments=[Attachment(
                    name=a["name"],
                    mime_type=a["mime_type"],
                    size=a["size"],
                    hash=a["attachment_hash"],
                    data=a.get("data")
                ) for a in atts]
            ))
        return messages
    
    def add_group_member(self, group_id: str, identity_hash: str) -> bool:
        """Add member to group (admin only)."""
        group = self._storage.get_group(group_id)
        if not group or not group.get("is_admin"):
            return False
        
        self._storage.add_group_member(group_id, identity_hash)
        self._send_group_invite(group_id, group["name"], identity_hash)
        return True
    
    def leave_group(self, group_id: str) -> bool:
        """Leave a group."""
        group = self._storage.get_group(group_id)
        if not group or not self.address:
            return False
        
        members = self._storage.get_group_members(group_id)
        fields = {
            "rip": "RIP-0006",
            "rip_rev": 1,
            "type": "group_leave",
            "group_id": group_id
        }
        
        for member in members:
            if member["identity_hash"] != self.address:
                self._transport.send_message(member["identity_hash"], "Left the group", title="group_leave", fields=fields)
        
        self._storage.remove_group_member(group_id, self.address)
        self._storage.delete_group(group_id)
        return True
    
    def kick_member(self, group_id: str, identity_hash: str) -> bool:
        """Kick member from group (admin only)."""
        group = self._storage.get_group(group_id)
        if not group or not group.get("is_admin"):
            return False
        if identity_hash == self.address:
            return False
        
        fields = {
            "rip": "RIP-0006",
            "rip_rev": 1,
            "type": "group_kick",
            "group_id": group_id,
            "kicked": identity_hash
        }
        
        self._transport.send_message(identity_hash, "Removed from group", title="group_kick", fields=fields)
        
        members = self._storage.get_group_members(group_id)
        for member in members:
            if member["identity_hash"] not in (self.address, identity_hash):
                self._transport.send_message(member["identity_hash"], "Member removed", title="group_kick", fields=fields)
        
        self._storage.remove_group_member(group_id, identity_hash)
        return True
    
    # Utility
    def announce(self):
        """Announce presence on the network."""
        profile = self._storage.get_profile(self.identity_hash or "")
        app_data = {}
        if profile and profile.get("display_name"):
            app_data["name"] = profile["display_name"]
        self._transport.announce(app_data)
    
    def set_announces_enabled(self, enabled: bool):
        """Enable or disable network announces (privacy feature per RIP-0001)."""
        self._transport.set_announces_enabled(enabled)
    
    @property
    def announces_enabled(self) -> bool:
        """Check if announces are enabled."""
        return self._transport.announces_enabled
    
    def save_attachment(self, attachment_hash: str, destination: Optional[str] = None) -> Optional[str]:
        """Save an attachment to disk."""
        att = self._storage.get_attachment(attachment_hash)
        if not att:
            return None
        try:
            return self._attachments.save_attachment(att, destination)
        except Exception as e:
            print(f"[RetiClient] Failed to save attachment: {e}")
            return None
    
    # Public API - Blog
    def publish_blog(self, title: str, content: str, summary: str = "",
                     tags: Optional[List[str]] = None, slug: str = "",
                     attachments: Optional[List[str]] = None) -> Optional[str]:
        """Publish a blog post and deliver to followers."""
        now = time.time()
        blog_id = hashlib.sha256(f"{self.identity_hash}{title}{now}".encode()).hexdigest()
        author_name = self._get_display_name()
        
        fields = {
            "rip": "RIP-0007",
            "rip_rev": 1,
            "type": "blog_post",
            "blog_id": blog_id,
            "author_name": author_name,
            "title": title,
            "summary": summary,
            "body_format": "markdown",
            "tags": tags or [],
            "slug": slug or self._slugify(title),
            "published_at": now
        }
        
        attachment_list = []
        if attachments:
            attachment_list = self._attachments.prepare_attachments(attachments)
            if attachment_list:
                fields["attachments"] = self._attachments.create_metadata(attachment_list)
                fields["attachment_data"] = attachment_list
        
        blog_data = {
            "blog_id": blog_id,
            "author_hash": self.identity_hash,
            "author_name": author_name,
            "title": title,
            "content": content,
            "summary": summary,
            "body_format": "markdown",
            "tags": tags or [],
            "slug": fields["slug"],
            "published_at": now
        }
        self._storage.save_blog_post(blog_data)
        
        if attachment_list:
            for att in attachment_list:
                self._storage.save_attachment(
                    attachment_hash=att['hash'],
                    name=att['name'],
                    mime_type=att['mime'],
                    size=att['size'],
                    data=att['data'],
                    blog_id=blog_id
                )
        
        followers = self._storage.get_followers()
        success_count = 0
        for follower in followers:
            if self._storage.is_blocked(follower["identity_hash"]):
                continue
            if self._transport.send_message(follower["identity_hash"], content, title=title, fields=fields):
                success_count += 1
        
        return blog_id if (success_count > 0 or len(followers) == 0) else None
    
    def _slugify(self, text: str) -> str:
        """Convert text to URL-friendly slug."""
        import re
        slug = text.lower().strip()
        slug = re.sub(r'[^\w\s-]', '', slug)
        slug = re.sub(r'[-\s]+', '-', slug)
        return slug[:100]
    
    def update_blog(self, blog_id: str, title: str = None, content: str = None,
                    summary: str = None, tags: List[str] = None) -> bool:
        """Update an existing blog post."""
        existing = self._storage.get_blog_post(blog_id)
        if not existing or existing["author_hash"] != self.identity_hash:
            return False
        
        now = time.time()
        fields = {
            "rip": "RIP-0007",
            "rip_rev": 1,
            "type": "blog_update",
            "blog_id": blog_id,
            "updated_at": now
        }
        
        updated_content = content if content is not None else existing["content"]
        if title is not None:
            fields["title"] = title
        if summary is not None:
            fields["summary"] = summary
        if tags is not None:
            fields["tags"] = tags
        
        blog_data = {
            "blog_id": blog_id,
            "title": title if title is not None else existing["title"],
            "content": updated_content,
            "summary": summary if summary is not None else existing["summary"],
            "tags": tags if tags is not None else existing["tags"],
            "updated_at": now
        }
        self._storage.save_blog_post(blog_data)
        
        followers = self._storage.get_followers()
        for follower in followers:
            if not self._storage.is_blocked(follower["identity_hash"]):
                self._transport.send_message(follower["identity_hash"], updated_content, title=fields.get("title", ""), fields=fields)
        
        return True
    
    def delete_blog(self, blog_id: str) -> bool:
        """Delete a blog post."""
        existing = self._storage.get_blog_post(blog_id)
        if not existing or existing["author_hash"] != self.identity_hash:
            return False
        
        fields = {
            "rip": "RIP-0007",
            "rip_rev": 1,
            "type": "blog_delete",
            "blog_id": blog_id
        }
        
        followers = self._storage.get_followers()
        for follower in followers:
            if not self._storage.is_blocked(follower["identity_hash"]):
                self._transport.send_message(follower["identity_hash"], "Blog deleted", title="blog_delete", fields=fields)
        
        self._storage.delete_blog_post(blog_id)
        return True
    
    def get_blog_posts(self, author: str = None) -> List[BlogPost]:
        """Get blog posts, optionally filtered by author."""
        data = self._storage.get_blog_posts(author)
        blogs = []
        for b in data:
            atts = self._storage.get_attachments_for_blog(b["blog_id"])
            blogs.append(BlogPost(
                id=b["blog_id"],
                author=b["author_hash"],
                author_name=b["author_name"],
                title=b["title"],
                content=b["content"],
                summary=b["summary"],
                body_format=b["body_format"],
                tags=b["tags"],
                slug=b["slug"],
                published_at=b["published_at"],
                updated_at=b["updated_at"],
                attachments=[Attachment(
                    name=a["name"],
                    mime_type=a["mime_type"],
                    size=a["size"],
                    hash=a["attachment_hash"],
                    data=a.get("data")
                ) for a in atts]
            ))
        return blogs
    
    def get_blog_post(self, blog_id: str) -> Optional[BlogPost]:
        """Get a single blog post."""
        b = self._storage.get_blog_post(blog_id)
        if b:
            atts = self._storage.get_attachments_for_blog(blog_id)
            return BlogPost(
                id=b["blog_id"],
                author=b["author_hash"],
                author_name=b["author_name"],
                title=b["title"],
                content=b["content"],
                summary=b["summary"],
                body_format=b["body_format"],
                tags=b["tags"],
                slug=b["slug"],
                published_at=b["published_at"],
                updated_at=b["updated_at"],
                attachments=[Attachment(
                    name=a["name"],
                    mime_type=a["mime_type"],
                    size=a["size"],
                    hash=a["attachment_hash"],
                    data=a.get("data")
                ) for a in atts]
            )
        return None
