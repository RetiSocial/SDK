"""Transport layer for Reti SDK - handles Reticulum and LXMF."""

import RNS
import LXMF
import time
import msgpack
from pathlib import Path
from typing import Optional, Callable, Dict, Any, List

from reti.identity import IdentityManager


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
        self._running = False
    
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
    
    def _handle_lxmf_message(self, message: LXMF.LXMessage):
        """Process incoming LXMF message."""
        msg_data = {
            "source": RNS.hexrep(message.source_hash, delimit=False),
            "destination": RNS.hexrep(message.destination_hash, delimit=False),
            "title": message.title,
            "content": message.content,
            "timestamp": message.timestamp,
            "fields": message.fields if message.fields else {},
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
        fields: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Send an LXMF message."""
        if not self._lxmf_router or not self.identity_manager.identity:
            return False
        
        try:
            dest_hash = bytes.fromhex(destination_hash)
            
            dest_identity = RNS.Identity.recall(dest_hash)
            if not dest_identity:
                RNS.Transport.request_path(dest_hash)
                time.sleep(2)
                dest_identity = RNS.Identity.recall(dest_hash)
                if not dest_identity:
                    return False
            
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
            
            self._lxmf_router.handle_outbound(lxm)
            return True
            
        except Exception as e:
            print(f"[Transport] Failed to send message: {e}")
            return False
    
    def announce(self, app_data: Optional[Dict[str, Any]] = None):
        """Announce presence on the network."""
        if self._control_destination:
            data = app_data or {}
            data.setdefault("rips", ["RIP-0001", "RIP-0002", "RIP-0003", "RIP-0004", "RIP-0005", "RIP-0006"])
            self._control_destination.announce(msgpack.packb(data))
