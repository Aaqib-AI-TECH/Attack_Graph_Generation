import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
from pathlib import Path
import ipaddress

OUT = Path("artifacts")

def is_internal(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    return ip_obj.is_private or str(ip).startswith("143.88.")

def draw_focus(ip: str):
    df = pd.read_csv(OUT / f"focus_{ip}_edges.csv")
    G = nx.DiGraph()
    for _, r in df.iterrows():
        s, d = r["src_ip"], r["dst_ip"]
        G.add_node(s, role="internal" if is_internal(s) else "external")
        G.add_node(d, role="internal" if is_internal(d) else "external")
        G.add_edge(s, d, weight=int(r["events"]), tactic=r["tactic"], technique=r["technique"])

    pos = nx.spring_layout(G, k=0.9, seed=42)
    roles = nx.get_node_attributes(G, "role")
    node_colors = ["#4C9AFF" if roles[n]=="internal" else "#FF6B6B" for n in G.nodes()]
    edge_widths = [1 + (G[u][v]["weight"] ** 0.5) for u, v in G.edges()]

    plt.figure(figsize=(10, 7))
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=550, linewidths=0.5)
    nx.draw_networkx_labels(G, pos, font_size=8)
    nx.draw_networkx_edges(G, pos, width=edge_widths, arrows=True, alpha=0.7)
    plt.axis("off")
    out = OUT / f"focus_{ip}.png"
    plt.tight_layout()
    plt.savefig(out, dpi=200)
    plt.close()
    print("Wrote", out)

def main():
    ips = pd.read_csv(OUT / "interesting_ips.csv")["ip"].head(3)
    for ip in ips:
        draw_focus(ip)

if __name__ == "__main__":
    main()
