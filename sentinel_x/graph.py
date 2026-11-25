"""Feature 1 — Evidence Graph (NetworkX).

No decision is ever made from a single alert. Every fact becomes a
node/edge in a graph: IP, user, device, login attempts, time, country.
A verdict is only supported if it is backed by edges in this graph.
"""
from __future__ import annotations
import networkx as nx

def evidence_score(trace: dict) -> float:
    """Transparent, documented scoring used ONLY in offline mode.

    Live mode: the LLM reasons over the graph, this score is not used
    as a verdict. Offline mode: this score is the (labelled) stand-in
    so the pipeline can be tested without a key.
    + failed logins >=30: 2.0, >=15: 1.5, >=8: 1.0, >=3: 0.5
    + night hour 00-05: 1.0; + unknown device: 1.0
    + country change: 1.0; + success after >=10 failures: 1.0
    """
    s = 0.0
    f = int(trace.get("failed_logins", 0))
    if f >= 30: s += 2.0
    elif f >= 15: s += 1.5
    elif f >= 8: s += 1.0
    elif f >= 3: s += 0.5
    if 0 <= int(trace.get("hour", 12)) <= 5: s += 1.0
    if not trace.get("device_known", True): s += 1.0
    if trace.get("country_change", False): s += 1.0
    if int(trace.get("successful_login", 0)) >= 1 and f >= 10: s += 1.0
    return s

def build_evidence_graph(trace: dict) -> nx.Graph:
    """Build the evidence graph for one trace. Returns a NetworkX graph.

    Nodes carry kind/attributes; edges carry a `relation` and a
    `supports` label ('malicious' / 'benign' / 'neutral').
    """
    g = nx.Graph()
    ip = str(trace.get("ip", "unknown"))
    g.add_node(f"ip:{ip}", kind="ip", label=ip)
    g.add_node("user:unknown-user", kind="user", label="unknown-user (synthetic)")
    g.add_node(f"device:{'known' if trace.get('device_known') else 'unknown'}",
               kind="device", label="known device" if trace.get("device_known") else "unknown device")
    g.add_node(f"event:failed-logins:{trace.get('failed_logins', 0)}", kind="event",
               label=f"{trace.get('failed_logins', 0)} failed logins")
    g.add_node(f"event:success:{trace.get('successful_login', 0)}", kind="event",
               label=f"{trace.get('successful_login', 0)} successful login(s)")
    g.add_node(f"time:{trace.get('hour', '?')}:00", kind="time", label=f"hour {trace.get('hour')}:00")
    g.add_node(f"country:{'changed' if trace.get('country_change') else 'same'}", kind="country",
               label="country changed" if trace.get("country_change") else "country unchanged")
    f = int(trace.get("failed_logins", 0))
    g.add_edge(f"ip:{ip}", f"event:failed-logins:{f}", relation="attempted_from",
               supports="malicious" if f >= 8 else "neutral", weight=2.0 if f >= 15 else 1.0)
    g.add_edge(f"ip:{ip}", f"event:success:{trace.get('successful_login', 0)}", relation="logged_in_from",
               supports="malicious" if (f >= 10 and int(trace.get("successful_login", 0)) >= 1) else "neutral")
    g.add_edge(f"ip:{ip}", f"device:{'known' if trace.get('device_known') else 'unknown'}",
               relation="used_device", supports="malicious" if not trace.get("device_known") else "benign")
    g.add_edge(f"ip:{ip}", f"time:{trace.get('hour', '?')}:00", relation="active_at",
               supports="malicious" if 0 <= int(trace.get("hour", 12)) <= 5 else "neutral")
    g.add_edge(f"ip:{ip}", f"country:{'changed' if trace.get('country_change') else 'same'}",
               relation="located_in", supports="malicious" if trace.get("country_change") else "benign")
    g.add_edge("user:unknown-user", f"ip:{ip}", relation="account_used_from", supports="neutral")
    g.add_edge("user:unknown-user", f"device:{'known' if trace.get('device_known') else 'unknown'}",
               relation="owns_device", supports="benign" if trace.get("device_known") else "malicious")
    return g

def supporting_edges(graph: nx.Graph, verdict: str) -> list:
    """Edges whose `supports` label backs the given verdict."""
    want = "malicious" if verdict == "MALICIOUS" else "benign"
    return [(u, v, d) for u, v, d in graph.edges(data=True) if d.get("supports") == want]

def graph_summary(graph: nx.Graph) -> dict:
    return {
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "node_list": sorted(graph.nodes()),
        "edge_list": [{"from": u, "to": v, "relation": d.get("relation"), "supports": d.get("supports")}
                      for u, v, d in sorted(graph.edges(data=True))],
        "malicious_supporting_edges": len([1 for _, _, d in graph.edges(data=True) if d.get("supports") == "malicious"]),
        "benign_supporting_edges": len([1 for _, _, d in graph.edges(data=True) if d.get("supports") == "benign"]),
    }
