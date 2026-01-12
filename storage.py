"""Storage layer for Reti SDK - SQLite persistence."""

import time
import json
import hashlib
from pathlib import Path
from typing import Optional, List, Dict, Any

from sqlalchemy import create_engine, Column, String, Integer, Float, Boolean, Text, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.pool import StaticPool

Base = declarative_base()


def _ensure_str(value) -> str:
    """Ensure value is a string, decoding bytes if necessary."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


class ProfileModel(Base):
    __tablename__ = "profiles"
    
    identity_hash = Column(String(64), primary_key=True)
    display_name = Column(String(255), nullable=True)
    bio = Column(Text, nullable=True)
    avatar_hash = Column(String(64), nullable=True)
    updated_at = Column(Float, default=time.time)


class FollowModel(Base):
    __tablename__ = "follows"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    identity_hash = Column(String(64), nullable=False, index=True)
    status = Column(String(32), nullable=False)
    is_follower = Column(Boolean, default=False)
    is_following = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)
    is_blocked_by = Column(Boolean, default=False)
    created_at = Column(Float, default=time.time)
    updated_at = Column(Float, default=time.time)


class MessageModel(Base):
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    message_hash = Column(String(64), unique=True, index=True)
    source_hash = Column(String(64), nullable=False, index=True)
    destination_hash = Column(String(64), nullable=False)
    title = Column(String(255), nullable=True)
    content = Column(Text, nullable=True)
    timestamp = Column(Float, nullable=False)
    rip = Column(String(16), nullable=True)
    rip_rev = Column(Integer, nullable=True)
    msg_type = Column(String(32), nullable=True)
    fields_json = Column(Text, nullable=True)
    is_outbound = Column(Boolean, default=False)
    read = Column(Boolean, default=False)
    delivery_status = Column(String(16), default="pending")  # RIP-0008


class FeedPostModel(Base):
    __tablename__ = "feed_posts"
    
    post_id = Column(String(64), primary_key=True)
    author_hash = Column(String(64), nullable=False, index=True)
    author_name = Column(String(255), nullable=True)
    content = Column(Text, nullable=False)
    timestamp = Column(Float, nullable=False)
    in_reply_to = Column(String(64), nullable=True)
    thread_root = Column(String(64), nullable=True)
    mentions = Column(Text, nullable=True)
    cw = Column(Text, nullable=True)


class GroupModel(Base):
    __tablename__ = "groups"
    
    group_id = Column(String(64), primary_key=True)
    name = Column(String(255), nullable=False)
    created_by = Column(String(64), nullable=False)
    created_at = Column(Float, default=time.time)
    is_admin = Column(Boolean, default=False)


class GroupMemberModel(Base):
    __tablename__ = "group_members"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    group_id = Column(String(64), nullable=False, index=True)
    identity_hash = Column(String(64), nullable=False)
    display_name = Column(String(255), nullable=True)
    joined_at = Column(Float, default=time.time)


class GroupMessageModel(Base):
    __tablename__ = "group_messages"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    message_hash = Column(String(64), unique=True, index=True)
    group_id = Column(String(64), nullable=False, index=True)
    sender_hash = Column(String(64), nullable=False)
    sender_name = Column(String(255), nullable=True)
    content = Column(Text, nullable=False)
    timestamp = Column(Float, nullable=False)
    is_outbound = Column(Boolean, default=False)


class AttachmentModel(Base):
    __tablename__ = "attachments"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    attachment_hash = Column(String(64), unique=True, index=True)
    name = Column(String(255), nullable=False)
    mime_type = Column(String(128), nullable=False)
    size = Column(Integer, nullable=False)
    data = Column(Text, nullable=False)
    created_at = Column(Float, default=time.time)
    message_hash = Column(String(64), nullable=True, index=True)
    post_id = Column(String(64), nullable=True, index=True)
    group_message_hash = Column(String(64), nullable=True, index=True)
    blog_id = Column(String(64), nullable=True, index=True)


class BlogPostModel(Base):
    __tablename__ = "blog_posts"
    
    blog_id = Column(String(64), primary_key=True)
    author_hash = Column(String(64), nullable=False, index=True)
    author_name = Column(String(255), nullable=True)
    title = Column(String(512), nullable=False)
    content = Column(Text, nullable=False)
    summary = Column(Text, nullable=True)
    body_format = Column(String(32), default="markdown")
    tags = Column(Text, nullable=True)  # JSON list
    slug = Column(String(255), nullable=True)
    published_at = Column(Float, nullable=False)
    updated_at = Column(Float, nullable=True)


class Storage:
    """SQLite storage for Reti SDK."""
    
    def __init__(self, db_path: Optional[Path] = None):
        if db_path:
            self.engine = create_engine(f"sqlite:///{db_path}")
        else:
            self.engine = create_engine(
                "sqlite:///:memory:",
                connect_args={"check_same_thread": False},
                poolclass=StaticPool
            )
        
        Base.metadata.create_all(self.engine)
        self._session_factory = sessionmaker(bind=self.engine)
        self._run_migrations()
    
    def _run_migrations(self):
        """Run database migrations for schema updates."""
        with self.engine.connect() as conn:
            # Check if blog_id column exists in attachments table
            result = conn.execute(text("PRAGMA table_info(attachments)"))
            columns = [row[1] for row in result.fetchall()]
            
            if "blog_id" not in columns:
                conn.execute(text(
                    "ALTER TABLE attachments ADD COLUMN blog_id VARCHAR(64)"
                ))
                conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_attachments_blog_id ON attachments(blog_id)"
                ))
                conn.commit()
            
            # RIP-0008: Add delivery_status column to messages table
            result = conn.execute(text("PRAGMA table_info(messages)"))
            msg_columns = [row[1] for row in result.fetchall()]
            
            if "delivery_status" not in msg_columns:
                conn.execute(text(
                    "ALTER TABLE messages ADD COLUMN delivery_status VARCHAR(16) DEFAULT 'pending'"
                ))
                conn.commit()
    
    def _session(self) -> Session:
        return self._session_factory()
    
    # Profile methods
    def save_profile(self, identity_hash: str, display_name: str, bio: str = "", avatar_hash: str = ""):
        with self._session() as session:
            profile = session.get(ProfileModel, identity_hash)
            if profile:
                profile.display_name = display_name
                profile.bio = bio
                profile.avatar_hash = avatar_hash
                profile.updated_at = time.time()
            else:
                profile = ProfileModel(
                    identity_hash=identity_hash,
                    display_name=display_name,
                    bio=bio,
                    avatar_hash=avatar_hash
                )
                session.add(profile)
            session.commit()
    
    def get_profile(self, identity_hash: str) -> Optional[Dict[str, Any]]:
        with self._session() as session:
            profile = session.get(ProfileModel, identity_hash)
            if profile:
                return {
                    "identity_hash": profile.identity_hash,
                    "display_name": profile.display_name,
                    "bio": profile.bio,
                    "avatar_hash": profile.avatar_hash,
                    "updated_at": profile.updated_at
                }
            return None
    
    # Follow methods
    def save_follow(self, identity_hash: str, is_follower: bool = False, 
                    is_following: bool = False, status: str = "pending"):
        with self._session() as session:
            follow = session.query(FollowModel).filter_by(identity_hash=identity_hash).first()
            if follow:
                if is_follower:
                    follow.is_follower = True
                if is_following:
                    follow.is_following = True
                follow.status = status
                follow.updated_at = time.time()
            else:
                follow = FollowModel(
                    identity_hash=identity_hash,
                    is_follower=is_follower,
                    is_following=is_following,
                    status=status
                )
                session.add(follow)
            session.commit()
    
    def get_followers(self) -> List[Dict[str, Any]]:
        with self._session() as session:
            follows = session.query(FollowModel).filter_by(is_follower=True, status="accepted").all()
            return [{"identity_hash": f.identity_hash, "status": f.status} for f in follows]
    
    def get_following(self) -> List[Dict[str, Any]]:
        with self._session() as session:
            follows = session.query(FollowModel).filter(FollowModel.is_following == True).all()
            return [{"identity_hash": f.identity_hash, "status": f.status} for f in follows]
    
    def get_pending_followers(self) -> List[Dict[str, Any]]:
        with self._session() as session:
            follows = session.query(FollowModel).filter_by(is_follower=True, status="pending").all()
            return [{"identity_hash": f.identity_hash, "status": f.status} for f in follows]
    
    def get_accepted_following(self) -> List[Dict[str, Any]]:
        with self._session() as session:
            follows = session.query(FollowModel).filter(
                FollowModel.is_following == True,
                FollowModel.status == "accepted"
            ).all()
            return [{"identity_hash": f.identity_hash, "status": f.status} for f in follows]
    
    def is_blocked(self, identity_hash: str) -> bool:
        with self._session() as session:
            follow = session.query(FollowModel).filter_by(identity_hash=identity_hash).first()
            return follow.is_blocked if follow else False
    
    def block_user(self, identity_hash: str):
        with self._session() as session:
            follow = session.query(FollowModel).filter_by(identity_hash=identity_hash).first()
            if follow:
                follow.is_blocked = True
                follow.is_follower = False
                follow.is_following = False
                follow.status = "blocked"
                follow.updated_at = time.time()
            else:
                follow = FollowModel(
                    identity_hash=identity_hash,
                    is_blocked=True,
                    status="blocked"
                )
                session.add(follow)
            session.commit()
    
    def unblock_user(self, identity_hash: str):
        with self._session() as session:
            follow = session.query(FollowModel).filter_by(identity_hash=identity_hash).first()
            if follow:
                follow.is_blocked = False
                follow.status = "unblocked"
                follow.updated_at = time.time()
                session.commit()
    
    def mark_blocked_by(self, identity_hash: str):
        with self._session() as session:
            follow = session.query(FollowModel).filter_by(identity_hash=identity_hash).first()
            if follow:
                follow.is_blocked_by = True
                follow.updated_at = time.time()
            else:
                follow = FollowModel(
                    identity_hash=identity_hash,
                    is_blocked_by=True,
                    status="blocked_by"
                )
                session.add(follow)
            session.commit()
    
    def get_blocked_users(self) -> List[Dict[str, Any]]:
        with self._session() as session:
            follows = session.query(FollowModel).filter_by(is_blocked=True).all()
            return [{"identity_hash": f.identity_hash, "blocked_at": f.updated_at} for f in follows]
    
    # Message methods
    def is_message_seen(self, message_hash: str) -> bool:
        with self._session() as session:
            return session.query(MessageModel).filter_by(message_hash=message_hash).first() is not None
    
    def save_message(self, msg_data: Dict[str, Any], is_outbound: bool = False,
                     delivery_status: str = "pending") -> Optional[str]:
        content = msg_data.get('content', '')
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='replace')
        
        content_for_hash = f"{msg_data.get('source', '')}{content}{msg_data.get('timestamp', '')}"
        message_hash = hashlib.sha256(content_for_hash.encode()).hexdigest()
        
        if self.is_message_seen(message_hash):
            return None
        
        with self._session() as session:
            fields = msg_data.get("fields", {})
            message = MessageModel(
                message_hash=message_hash,
                source_hash=msg_data.get("source", ""),
                destination_hash=msg_data.get("destination", ""),
                title=msg_data.get("title", ""),
                content=content,
                timestamp=msg_data.get("timestamp", time.time()),
                rip=fields.get("rip"),
                rip_rev=fields.get("rip_rev"),
                msg_type=fields.get("type"),
                fields_json=json.dumps(fields),
                is_outbound=is_outbound,
                delivery_status=delivery_status
            )
            session.add(message)
            session.commit()
            return message_hash
    
    def get_messages(self, peer_hash: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        with self._session() as session:
            query = session.query(MessageModel)
            if peer_hash:
                query = query.filter(
                    (MessageModel.source_hash == peer_hash) | (MessageModel.destination_hash == peer_hash)
                )
            messages = query.order_by(MessageModel.timestamp.desc()).limit(limit).all()
            return [
                {
                    "message_hash": m.message_hash,
                    "source": m.source_hash,
                    "destination": m.destination_hash,
                    "title": _ensure_str(m.title),
                    "content": _ensure_str(m.content),
                    "timestamp": m.timestamp,
                    "rip": m.rip,
                    "type": m.msg_type,
                    "fields": json.loads(m.fields_json) if m.fields_json else {},
                    "is_outbound": m.is_outbound,
                    "read": m.read,
                    "delivery_status": m.delivery_status or "pending"
                }
                for m in messages
            ]
    
    def update_delivery_status(self, message_hash: str, status: str) -> bool:
        """Update the delivery status of a message (RIP-0008)."""
        with self._session() as session:
            message = session.query(MessageModel).filter_by(message_hash=message_hash).first()
            if message:
                message.delivery_status = status
                session.commit()
                return True
            return False
    
    def get_message_by_hash(self, message_hash: str) -> Optional[Dict[str, Any]]:
        """Get a single message by its hash."""
        with self._session() as session:
            m = session.query(MessageModel).filter_by(message_hash=message_hash).first()
            if m:
                return {
                    "message_hash": m.message_hash,
                    "source": m.source_hash,
                    "destination": m.destination_hash,
                    "title": _ensure_str(m.title),
                    "content": _ensure_str(m.content),
                    "timestamp": m.timestamp,
                    "rip": m.rip,
                    "type": m.msg_type,
                    "fields": json.loads(m.fields_json) if m.fields_json else {},
                    "is_outbound": m.is_outbound,
                    "read": m.read,
                    "delivery_status": m.delivery_status or "pending"
                }
            return None
    
    def mark_messages_read(self, peer_hash: str) -> int:
        """Mark all messages from a peer as read. Returns count of messages marked."""
        with self._session() as session:
            count = session.query(MessageModel).filter(
                MessageModel.source_hash == peer_hash,
                MessageModel.is_outbound == False,
                MessageModel.read == False
            ).update({"read": True})
            session.commit()
            return count
    
    def get_unread_count(self, peer_hash: Optional[str] = None) -> int:
        """Get count of unread messages, optionally filtered by peer."""
        with self._session() as session:
            query = session.query(MessageModel).filter(
                MessageModel.is_outbound == False,
                MessageModel.read == False
            )
            if peer_hash:
                query = query.filter(MessageModel.source_hash == peer_hash)
            return query.count()
    
    def get_unread_peers(self) -> List[Dict[str, Any]]:
        """Get list of peers with unread message counts."""
        with self._session() as session:
            from sqlalchemy import func
            results = session.query(
                MessageModel.source_hash,
                func.count(MessageModel.id).label('count')
            ).filter(
                MessageModel.is_outbound == False,
                MessageModel.read == False
            ).group_by(MessageModel.source_hash).all()
            return [{"identity_hash": r[0], "unread_count": r[1]} for r in results]
    
    # Feed methods
    def save_post(self, post_data: Dict[str, Any]) -> bool:
        post_id = post_data.get("post_id")
        if not post_id:
            return False
        
        with self._session() as session:
            if session.get(FeedPostModel, post_id):
                return False
            
            content = post_data.get("content", "")
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='replace')
            
            post = FeedPostModel(
                post_id=post_id,
                author_hash=post_data.get("author_hash", ""),
                author_name=post_data.get("author_name", ""),
                content=content,
                timestamp=post_data.get("timestamp", time.time()),
                in_reply_to=post_data.get("in_reply_to"),
                thread_root=post_data.get("thread_root"),
                mentions=json.dumps(post_data.get("mentions", [])),
                cw=json.dumps(post_data.get("cw", []))
            )
            session.add(post)
            session.commit()
            return True
    
    def get_feed(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._session() as session:
            posts = session.query(FeedPostModel).order_by(FeedPostModel.timestamp.desc()).limit(limit).all()
            return [
                {
                    "post_id": p.post_id,
                    "author_hash": p.author_hash,
                    "author_name": p.author_name or "",
                    "content": _ensure_str(p.content),
                    "timestamp": p.timestamp,
                    "in_reply_to": p.in_reply_to,
                    "thread_root": p.thread_root,
                    "mentions": json.loads(p.mentions) if p.mentions else [],
                    "cw": json.loads(p.cw) if p.cw else []
                }
                for p in posts
            ]
    
    def get_post(self, post_id: str) -> Optional[Dict[str, Any]]:
        with self._session() as session:
            p = session.get(FeedPostModel, post_id)
            if p:
                return {
                    "post_id": p.post_id,
                    "author_hash": p.author_hash,
                    "author_name": p.author_name or "",
                    "content": _ensure_str(p.content),
                    "timestamp": p.timestamp,
                    "in_reply_to": p.in_reply_to,
                    "thread_root": p.thread_root,
                    "mentions": json.loads(p.mentions) if p.mentions else [],
                    "cw": json.loads(p.cw) if p.cw else []
                }
            return None
    
    def get_replies(self, post_id: str) -> List[Dict[str, Any]]:
        with self._session() as session:
            posts = session.query(FeedPostModel).filter(
                (FeedPostModel.in_reply_to == post_id) | (FeedPostModel.thread_root == post_id)
            ).order_by(FeedPostModel.timestamp.asc()).all()
            return [
                {
                    "post_id": p.post_id,
                    "author_hash": p.author_hash,
                    "author_name": p.author_name or "",
                    "content": _ensure_str(p.content),
                    "timestamp": p.timestamp,
                    "in_reply_to": p.in_reply_to,
                    "thread_root": p.thread_root,
                    "mentions": json.loads(p.mentions) if p.mentions else [],
                    "cw": json.loads(p.cw) if p.cw else []
                }
                for p in posts
            ]
    
    def delete_post(self, post_id: str) -> bool:
        """Delete a post and its attachments."""
        with self._session() as session:
            post = session.get(FeedPostModel, post_id)
            if post:
                # Delete associated attachments
                session.query(AttachmentModel).filter_by(post_id=post_id).delete()
                session.delete(post)
                session.commit()
                return True
            return False
    
    # Group methods
    def create_group(self, group_id: str, name: str, created_by: str, is_admin: bool = True) -> bool:
        with self._session() as session:
            if session.get(GroupModel, group_id):
                return False
            group = GroupModel(
                group_id=group_id,
                name=name,
                created_by=created_by,
                is_admin=is_admin
            )
            session.add(group)
            session.commit()
            return True
    
    def get_groups(self) -> List[Dict[str, Any]]:
        with self._session() as session:
            groups = session.query(GroupModel).order_by(GroupModel.created_at.desc()).all()
            return [
                {
                    "group_id": g.group_id,
                    "name": g.name,
                    "created_by": g.created_by,
                    "created_at": g.created_at,
                    "is_admin": g.is_admin
                }
                for g in groups
            ]
    
    def get_group(self, group_id: str) -> Optional[Dict[str, Any]]:
        with self._session() as session:
            g = session.get(GroupModel, group_id)
            if g:
                return {
                    "group_id": g.group_id,
                    "name": g.name,
                    "created_by": g.created_by,
                    "created_at": g.created_at,
                    "is_admin": g.is_admin
                }
            return None
    
    def delete_group(self, group_id: str):
        with self._session() as session:
            session.query(GroupMessageModel).filter_by(group_id=group_id).delete()
            session.query(GroupMemberModel).filter_by(group_id=group_id).delete()
            session.query(GroupModel).filter_by(group_id=group_id).delete()
            session.commit()
    
    def add_group_member(self, group_id: str, identity_hash: str, display_name: str = ""):
        with self._session() as session:
            existing = session.query(GroupMemberModel).filter_by(
                group_id=group_id, identity_hash=identity_hash
            ).first()
            if existing:
                return
            member = GroupMemberModel(
                group_id=group_id,
                identity_hash=identity_hash,
                display_name=display_name
            )
            session.add(member)
            session.commit()
    
    def get_group_members(self, group_id: str) -> List[Dict[str, Any]]:
        with self._session() as session:
            members = session.query(GroupMemberModel).filter_by(group_id=group_id).all()
            return [
                {
                    "identity_hash": m.identity_hash,
                    "display_name": m.display_name or "",
                    "joined_at": m.joined_at
                }
                for m in members
            ]
    
    def remove_group_member(self, group_id: str, identity_hash: str):
        with self._session() as session:
            session.query(GroupMemberModel).filter_by(
                group_id=group_id, identity_hash=identity_hash
            ).delete()
            session.commit()
    
    def save_group_message(self, group_id: str, msg_data: Dict[str, Any], 
                           is_outbound: bool = False) -> Optional[str]:
        content_for_hash = f"{group_id}{msg_data.get('sender', '')}{msg_data.get('content', '')}{msg_data.get('timestamp', '')}"
        message_hash = hashlib.sha256(content_for_hash.encode()).hexdigest()
        
        with self._session() as session:
            if session.query(GroupMessageModel).filter_by(message_hash=message_hash).first():
                return None
            msg = GroupMessageModel(
                message_hash=message_hash,
                group_id=group_id,
                sender_hash=msg_data.get("sender", ""),
                sender_name=msg_data.get("sender_name", ""),
                content=msg_data.get("content", ""),
                timestamp=msg_data.get("timestamp", time.time()),
                is_outbound=is_outbound
            )
            session.add(msg)
            session.commit()
            return message_hash
    
    def get_group_messages(self, group_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self._session() as session:
            messages = session.query(GroupMessageModel).filter_by(
                group_id=group_id
            ).order_by(GroupMessageModel.timestamp.desc()).limit(limit).all()
            return [
                {
                    "message_hash": m.message_hash,
                    "group_id": m.group_id,
                    "sender": m.sender_hash,
                    "sender_name": m.sender_name or "",
                    "content": _ensure_str(m.content),
                    "timestamp": m.timestamp,
                    "is_outbound": m.is_outbound
                }
                for m in messages
            ]
    
    # Attachment methods
    def save_attachment(self, attachment_hash: str, name: str, mime_type: str,
                        size: int, data: str, message_hash: str = None,
                        post_id: str = None, group_message_hash: str = None,
                        blog_id: str = None) -> bool:
        with self._session() as session:
            if session.query(AttachmentModel).filter_by(attachment_hash=attachment_hash).first():
                return False
            
            attachment = AttachmentModel(
                attachment_hash=attachment_hash,
                name=name,
                mime_type=mime_type,
                size=size,
                data=data,
                message_hash=message_hash,
                post_id=post_id,
                group_message_hash=group_message_hash,
                blog_id=blog_id
            )
            session.add(attachment)
            session.commit()
            return True
    
    def get_attachment(self, attachment_hash: str) -> Optional[Dict[str, Any]]:
        with self._session() as session:
            a = session.query(AttachmentModel).filter_by(attachment_hash=attachment_hash).first()
            if a:
                return {
                    "attachment_hash": a.attachment_hash,
                    "name": a.name,
                    "mime_type": a.mime_type,
                    "size": a.size,
                    "data": a.data,
                    "created_at": a.created_at
                }
            return None
    
    def get_attachments_for_message(self, message_hash: str) -> List[Dict[str, Any]]:
        with self._session() as session:
            attachments = session.query(AttachmentModel).filter_by(message_hash=message_hash).all()
            return [
                {
                    "attachment_hash": a.attachment_hash,
                    "name": a.name,
                    "mime_type": a.mime_type,
                    "size": a.size,
                    "data": a.data
                }
                for a in attachments
            ]
    
    def get_attachments_for_post(self, post_id: str) -> List[Dict[str, Any]]:
        with self._session() as session:
            attachments = session.query(AttachmentModel).filter_by(post_id=post_id).all()
            return [
                {
                    "attachment_hash": a.attachment_hash,
                    "name": a.name,
                    "mime_type": a.mime_type,
                    "size": a.size,
                    "data": a.data
                }
                for a in attachments
            ]
    
    def get_attachments_for_group_message(self, group_message_hash: str) -> List[Dict[str, Any]]:
        with self._session() as session:
            attachments = session.query(AttachmentModel).filter_by(group_message_hash=group_message_hash).all()
            return [
                {
                    "attachment_hash": a.attachment_hash,
                    "name": a.name,
                    "mime_type": a.mime_type,
                    "size": a.size,
                    "data": a.data
                }
                for a in attachments
            ]
    
    # Blog methods
    def save_blog_post(self, blog_data: Dict[str, Any]) -> bool:
        blog_id = blog_data.get("blog_id")
        if not blog_id:
            return False
        
        with self._session() as session:
            existing = session.get(BlogPostModel, blog_id)
            if existing:
                # Update existing blog post
                existing.title = blog_data.get("title", existing.title)
                existing.content = blog_data.get("content", existing.content)
                existing.summary = blog_data.get("summary", existing.summary)
                existing.tags = json.dumps(blog_data.get("tags", []))
                existing.updated_at = blog_data.get("updated_at", time.time())
                session.commit()
                return True
            
            content = blog_data.get("content", "")
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='replace')
            
            blog = BlogPostModel(
                blog_id=blog_id,
                author_hash=blog_data.get("author_hash", ""),
                author_name=blog_data.get("author_name", ""),
                title=blog_data.get("title", ""),
                content=content,
                summary=blog_data.get("summary", ""),
                body_format=blog_data.get("body_format", "markdown"),
                tags=json.dumps(blog_data.get("tags", [])),
                slug=blog_data.get("slug", ""),
                published_at=blog_data.get("published_at", time.time()),
                updated_at=blog_data.get("updated_at")
            )
            session.add(blog)
            session.commit()
            return True
    
    def get_blog_posts(self, author_hash: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        with self._session() as session:
            query = session.query(BlogPostModel)
            if author_hash:
                query = query.filter_by(author_hash=author_hash)
            blogs = query.order_by(BlogPostModel.published_at.desc()).limit(limit).all()
            return [
                {
                    "blog_id": b.blog_id,
                    "author_hash": b.author_hash,
                    "author_name": b.author_name or "",
                    "title": _ensure_str(b.title),
                    "content": _ensure_str(b.content),
                    "summary": _ensure_str(b.summary),
                    "body_format": b.body_format or "markdown",
                    "tags": json.loads(b.tags) if b.tags else [],
                    "slug": b.slug or "",
                    "published_at": b.published_at,
                    "updated_at": b.updated_at
                }
                for b in blogs
            ]
    
    def get_blog_post(self, blog_id: str) -> Optional[Dict[str, Any]]:
        with self._session() as session:
            b = session.get(BlogPostModel, blog_id)
            if b:
                return {
                    "blog_id": b.blog_id,
                    "author_hash": b.author_hash,
                    "author_name": b.author_name or "",
                    "title": _ensure_str(b.title),
                    "content": _ensure_str(b.content),
                    "summary": _ensure_str(b.summary),
                    "body_format": b.body_format or "markdown",
                    "tags": json.loads(b.tags) if b.tags else [],
                    "slug": b.slug or "",
                    "published_at": b.published_at,
                    "updated_at": b.updated_at
                }
            return None
    
    def delete_blog_post(self, blog_id: str) -> bool:
        with self._session() as session:
            blog = session.get(BlogPostModel, blog_id)
            if blog:
                session.query(AttachmentModel).filter_by(blog_id=blog_id).delete()
                session.delete(blog)
                session.commit()
                return True
            return False
    
    def get_attachments_for_blog(self, blog_id: str) -> List[Dict[str, Any]]:
        with self._session() as session:
            attachments = session.query(AttachmentModel).filter_by(blog_id=blog_id).all()
            return [
                {
                    "attachment_hash": a.attachment_hash,
                    "name": a.name,
                    "mime_type": a.mime_type,
                    "size": a.size,
                    "data": a.data
                }
                for a in attachments
            ]
