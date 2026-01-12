"""Transport layer for Reti SDK - handles Reticulum and LXMF."""

import RNS
import LXMF
import time
import msgpack
from pathlib import Path
from typing import Optional, Callable, Dict, Any, List

from reti.identity import IdentityManager


def _decode_bytes_recursive(obj):
    """Recursively decode bytes to strings in nested structures."""
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    elif isinstance(obj, dict):
        return {_decode_bytes_recursive(k): _decode_bytes_recursive(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_decode_bytes_recursive(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(_decode_bytes_recursive(item) for item in obj)
    return obj


# RIP revision numbers for version negotiation
RIP_REVISIONS = {
    "RIP-0001": 1,
    "RIP-0002": 1,
    "RIP-0003": 1,
    "RIP-0004": 1,
    "RIP-0005": 1,
    "RIP-0006": 1,
    "RIP-0007": 1,
    "RIP-0008": 1,
    "RIP-0009": 1,
}


class Transport:
    """Handles Reticulum and LXMF transport."""
    
    APP_NAME = "reti_social"
    ASPECT_CONTROL = "control"
    
    def __init__(self, identity_manager: IdentityManager, storage_path: Path):
        self.identity_manager = identity_manager
        self.storage_path = storage_path
        
        self._reticulum: Optional[RNS.Reticulum] = None
        self._lxmf_router: Optional[LXMF.LXMRouter] = None
        self._lxmf_destination: Optional[RNS.Destination] = None
        self._control_destination: Optional[RNS.Destination] = None
        
        self._message_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self._control_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self._delivery_callbacks: List[Callable[[str, str], None]] = []  # RIP-0008
        self._sync_callbacks: List[Callable[[str, Any], None]] = []  # RIP-0009
        self._running = False
        self._announces_enabled = True  # Can be disabled for privacy
        self._propagation_node: Optional[str] = None  # RIP-0009
    
    def start(self) -> bool:
        """Initialize Reticulum and LXMF."""
        try:
            self._reticulum = RNS.Reticulum()
            identity = self.identity_manager.load_or_create()
            
            lxmf_path = self.storage_path / "lxmf"
            lxmf_path.mkdir(parents=True, exist_ok=True)
            
            self._lxmf_router = LXMF.LXMRouter(
                identity=identity,
                storagepath=str(lxmf_path)
            )
            
            self._lxmf_destination = self._lxmf_router.register_delivery_identity(
                identity,
                display_name=self.APP_NAME
            )
            self._lxmf_router.register_delivery_callback(self._handle_lxmf_message)
            
            self._control_destination = RNS.Destination(
                identity,
                RNS.Destination.IN,
                RNS.Destination.SINGLE,
                self.APP_NAME,
                self.ASPECT_CONTROL
            )
            self._control_destination.set_packet_callback(self._handle_control_packet)
            
            self._running = True
            return True
            
        except Exception as e:
            print(f"[Transport] Failed to start: {e}")
            return False
    
    def stop(self):
        """Shutdown transport."""
        self._running = False
        self._lxmf_router = None
    
    @property
    def is_running(self) -> bool:
        return self._running
    
    @property
    def lxmf_address(self) -> Optional[str]:
        """Get the LXMF address hash."""
        if self._lxmf_destination:
            return RNS.hexrep(self._lxmf_destination.hash, delimit=False)
        return None
    
    @property
    def control_address(self) -> Optional[str]:
        """Get the control destination hash."""
        if self._control_destination:
            return RNS.hexrep(self._control_destination.hash, delimit=False)
        return None
    
    def on_message(self, callback: Callable[[Dict[str, Any]], None]):
        """Register callback for incoming LXMF messages."""
        self._message_callbacks.append(callback)
    
    def on_control(self, callback: Callable[[Dict[str, Any]], None]):
        """Register callback for control packets."""
        self._control_callbacks.append(callback)
    
    def on_delivery(self, callback: Callable[[str, str], None]):
        """Register callback for delivery status changes (RIP-0008).
        
        Callback signature: callback(message_hash, status)
        Status values: 'sent', 'delivered', 'failed'
        """
        self._delivery_callbacks.append(callback)
    
    def on_sync(self, callback: Callable[[str, Any], None]):
        """Register callback for sync events (RIP-0009).
        
        Callback signature: callback(event, data)
        Events: 'started', 'complete', 'failed'
        """
        self._sync_callbacks.append(callback)
    
    def _handle_lxmf_message(self, message: LXMF.LXMessage):
        """Process incoming LXMF message."""
        # Decode bytes to str if needed
        title = message.title
        if isinstance(title, bytes):
            title = title.decode("utf-8", errors="replace")
        
        content = message.content
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
        
        # Recursively decode bytes in fields (msgpack may return bytes)
        fields = _decode_bytes_recursive(message.fields) if message.fields else {}
        
        msg_data = {
            "source": RNS.hexrep(message.source_hash, delimit=False),
            "destination": RNS.hexrep(message.destination_hash, delimit=False),
            "title": title,
            "content": content,
            "timestamp": message.timestamp,
            "fields": fields,
        }
        
        for callback in self._message_callbacks:
            try:
                callback(msg_data)
            except Exception as e:
                print(f"[Transport] Message callback error: {e}")
    
    def _handle_control_packet(self, data: bytes, packet: RNS.Packet):
        """Process incoming control packet."""
        try:
            control_data = msgpack.unpackb(data)
            control_data["source"] = RNS.hexrep(packet.source_hash, delimit=False)
            
            for callback in self._control_callbacks:
                try:
                    callback(control_data)
                except Exception as e:
                    print(f"[Transport] Control callback error: {e}")
        except Exception as e:
            print(f"[Transport] Failed to parse control packet: {e}")
    
    def send_message(
        self,
        destination_hash: str,
        content: str,
        title: str = "",
        fields: Optional[Dict[str, Any]] = None,
        message_hash: Optional[str] = None
    ) -> bool:
        """Send an LXMF message.
        
        Args:
            destination_hash: Target destination hash
            content: Message content
            title: Message title
            fields: LXMF fields dictionary
            message_hash: Optional hash for delivery tracking (RIP-0008)
        """
        if not self._lxmf_router or not self.identity_manager.identity:
            print(f"[Transport] Cannot send: router={self._lxmf_router is not None}, identity={self.identity_manager.identity is not None}")
            return False
        
        try:
            dest_hash = bytes.fromhex(destination_hash)
            print(f"[Transport] Sending to {destination_hash[:16]}...")
            
            # Check if we have a path to the destination
            if not RNS.Transport.has_path(dest_hash):
                print(f"[Transport] No path to destination, requesting...")
                RNS.Transport.request_path(dest_hash)
                # Wait for path with timeout
                timeout = 5
                start = time.time()
                while not RNS.Transport.has_path(dest_hash) and time.time() - start < timeout:
                    time.sleep(0.1)
            
            dest_identity = RNS.Identity.recall(dest_hash)
            if not dest_identity:
                print(f"[Transport] Cannot recall identity for {destination_hash[:16]}")
                return False
            
            print(f"[Transport] Identity recalled, creating destination...")
            destination = RNS.Destination(
                dest_identity,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "lxmf",
                "delivery"
            )
            
            lxm = LXMF.LXMessage(
                destination,
                self._lxmf_destination,
                content,
                title=title,
                fields=fields or {}
            )
            
            # RIP-0008: Set up delivery callback for status tracking
            if message_hash:
                lxm.delivery_callback = lambda msg: self._handle_delivery_callback(msg, message_hash)
            
            self._lxmf_router.handle_outbound(lxm)
            print(f"[Transport] Message queued for delivery")
            return True
            
        except Exception as e:
            print(f"[Transport] Failed to send message: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _handle_delivery_callback(self, lxm: LXMF.LXMessage, message_hash: str):
        """Handle LXMF delivery callback (RIP-0008)."""
        try:
            if lxm.state == LXMF.LXMessage.DELIVERED:
                status = "delivered"
            elif lxm.state == LXMF.LXMessage.FAILED:
                status = "failed"
            else:
                status = "sent"
            
            print(f"[Transport] Delivery status for {message_hash[:16]}: {status}")
            
            for callback in self._delivery_callbacks:
                try:
                    callback(message_hash, status)
                except Exception as e:
                    print(f"[Transport] Delivery callback error: {e}")
        except Exception as e:
            print(f"[Transport] Failed to handle delivery callback: {e}")
    
    def set_announces_enabled(self, enabled: bool):
        """Enable or disable network announces (privacy feature per RIP-0001)."""
        self._announces_enabled = enabled
    
    @property
    def announces_enabled(self) -> bool:
        """Check if announces are enabled."""
        return self._announces_enabled
    
    def announce(self, app_data: Optional[Dict[str, Any]] = None):
        """Announce presence on the network."""
        if not self._announces_enabled:
            print("[Transport] Announces disabled, skipping")
            return
        
        if self._control_destination:
            data = app_data or {}
            # RIP-0001: Include supported RIPs list
            data.setdefault("rips", list(RIP_REVISIONS.keys()))
            # RIP-0001: Include rips_rev map for version negotiation
            data.setdefault("rips_rev", RIP_REVISIONS)
            self._control_destination.announce(msgpack.packb(data))
        
        # Also announce LXMF destination so others can send messages
        if self._lxmf_router and self._lxmf_destination:
            self._lxmf_router.announce(self._lxmf_destination.hash)
            print(f"[Transport] Announced LXMF destination: {self.lxmf_address}")
    
    # RIP-0009: Propagation Node Support
    def set_propagation_node(self, node_hash: Optional[str]):
        """Set the preferred Propagation Node for store-and-forward messaging."""
        self._propagation_node = node_hash
        if self._lxmf_router and node_hash:
            try:
                node_bytes = bytes.fromhex(node_hash)
                self._lxmf_router.set_outbound_propagation_node(node_bytes)
                print(f"[Transport] Set propagation node: {node_hash[:16]}...")
            except Exception as e:
                print(f"[Transport] Failed to set propagation node: {e}")
        elif self._lxmf_router:
            self._lxmf_router.set_outbound_propagation_node(None)
            print("[Transport] Cleared propagation node")
    
    @property
    def propagation_node(self) -> Optional[str]:
        """Get the current Propagation Node hash."""
        return self._propagation_node
    
    def sync_messages(self) -> bool:
        """Request pending messages from the configured Propagation Node.
        
        Returns:
            True if sync was initiated, False otherwise.
        """
        if not self._lxmf_router or not self._propagation_node:
            print("[Transport] Cannot sync: no router or propagation node configured")
            return False
        
        try:
            # Notify sync started
            for callback in self._sync_callbacks:
                try:
                    callback("started", None)
                except Exception as e:
                    print(f"[Transport] Sync callback error: {e}")
            
            node_bytes = bytes.fromhex(self._propagation_node)
            node_identity = RNS.Identity.recall(node_bytes)
            
            if not node_identity:
                print(f"[Transport] Cannot recall propagation node identity, requesting path...")
                RNS.Transport.request_path(node_bytes)
                # Wait briefly for path
                timeout = 5
                start = time.time()
                while not RNS.Transport.has_path(node_bytes) and time.time() - start < timeout:
                    time.sleep(0.1)
                node_identity = RNS.Identity.recall(node_bytes)
            
            if not node_identity:
                for callback in self._sync_callbacks:
                    try:
                        callback("failed", "Cannot reach propagation node")
                    except Exception as e:
                        print(f"[Transport] Sync callback error: {e}")
                return False
            
            # Request messages from propagation node
            self._lxmf_router.request_messages_from_propagation_node(node_identity)
            print(f"[Transport] Requested messages from propagation node")
            
            # Note: Messages will arrive via normal delivery callback
            # We notify complete after initiating (actual messages come async)
            for callback in self._sync_callbacks:
                try:
                    callback("complete", 0)  # Count unknown at this point
                except Exception as e:
                    print(f"[Transport] Sync callback error: {e}")
            
            return True
            
        except Exception as e:
            print(f"[Transport] Sync failed: {e}")
            for callback in self._sync_callbacks:
                try:
                    callback("failed", str(e))
                except Exception as ex:
                    print(f"[Transport] Sync callback error: {ex}")
            return False
