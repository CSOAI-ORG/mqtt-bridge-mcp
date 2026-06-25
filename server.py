#!/usr/bin/env python3
"""
MQTT / IoT Bridge MCP — CSOAI Layer-0 legacy-bridge family.
Parse MQTT publish packets/topics, map to modern telemetry, govern IoT/OT security.
Sibling of cobol-bridge-mcp; pairs with scada-bridge-mcp. Pairs with NIS2 / IEC 62443.
Tools: parse_mqtt · map_to_modern · govern_iot
"""
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import json

mcp = FastMCP("MQTT Bridge", instructions="Bridge MQTT / IoT messaging to ONE OS — parse, map, govern device security (IEC 62443 / NIS2).")


class MQTTParsed(BaseModel):
    topic: Optional[str] = None
    topic_levels: List[str] = Field(default_factory=list)
    qos: int = 0
    retain: bool = False
    payload_kind: str = "unknown"
    payload_keys: List[str] = Field(default_factory=list)
    is_command: bool = False


class Governance(BaseModel):
    risk_flags: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    attestable: bool = True
    note: str = ""


@mcp.tool()
def parse_mqtt(topic: str, payload: str = "", qos: int = 0, retain: bool = False) -> MQTTParsed:
    """Parse an MQTT message: topic hierarchy + payload shape. Command topics (set/cmd/write) are flagged."""
    levels = [l for l in (topic or "").split("/") if l]
    kind, keys = "text", []
    p = (payload or "").strip()
    if p.startswith("{"):
        try:
            obj = json.loads(p); kind = "json"; keys = list(obj.keys())[:20]
        except Exception:
            kind = "text"
    elif p.replace(".", "", 1).replace("-", "", 1).isdigit():
        kind = "numeric"
    is_cmd = any(t.lower() in ("set", "cmd", "command", "write", "actuate", "control") for t in levels)
    return MQTTParsed(topic=topic, topic_levels=levels, qos=qos, retain=retain,
                      payload_kind=kind, payload_keys=keys, is_command=is_cmd)


@mcp.tool()
def map_to_modern(topic: str, payload: str = "", qos: int = 0, retain: bool = False) -> Dict[str, Any]:
    """Map an MQTT message to a modern telemetry/command event for ONE OS."""
    m = parse_mqtt(topic, payload, qos, retain)
    return {"source": "MQTT", "namespace": m.topic_levels[:-1], "signal": m.topic_levels[-1] if m.topic_levels else None,
            "kind": "command" if m.is_command else "telemetry", "qos": m.qos, "retain": m.retain,
            "payload_kind": m.payload_kind}


@mcp.tool()
def govern_iot(topic: str, payload: str = "", qos: int = 0, retain: bool = False, tls: bool = False, authenticated: bool = False) -> Governance:
    """Governance: IoT/OT device security surface — auth, TLS, command authorisation (attestable)."""
    m = parse_mqtt(topic, payload, qos, retain)
    flags = []
    if not tls:
        flags.append("No TLS — MQTT in clear text; enforce TLS 1.2+ (mosquitto/broker config)")
    if not authenticated:
        flags.append("Unauthenticated publish — require client auth + topic ACL")
    if m.is_command:
        flags.append(f"Command topic ({m.topic}) — actuation requires authorisation + audit")
    if m.qos == 0 and m.is_command:
        flags.append("QoS 0 on a command — no delivery guarantee for an actuation")
    return Governance(risk_flags=flags,
                      frameworks=["IEC 62443 (IIoT)", "NIS2", "ETSI EN 303 645 (consumer IoT)", "NIST IoT (8259)"],
                      note="CSOAI governs the bridge: every device command attestable on the ledger.")


def main():
    mcp.run()


if __name__ == "__main__":
    main()
