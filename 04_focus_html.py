import pandas as pd
from pyvis.network import Network
from pathlib import Path
import ipaddress

OUT = Path("artifacts")

def role_of(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return "unknown"
    if ip_obj.is_private or str(ip).startswith("143.88."):
        return "internal"
    return "external"

def render_html_for_focus(ip: str):
    edges_path = OUT / f"focus_{ip}_edges.csv"
    if not edges_path.exists():
        print(f"Missing {edges_path}")
        return
    edges = pd.read_csv(edges_path)

    # notebook=False prevents the Jupyter template path
    net = Network(height="700px", width="100%", directed=True, notebook=False)
    net.barnes_hut()

    seen = set()
    for _, r in edges.iterrows():
        s, d = r["src_ip"], r["dst_ip"]
        for n in (s, d):
            if n not in seen:
                net.add_node(n, label=f"{n}\n({role_of(n)})")
                seen.add(n)
        title = (
            f"Tactic: {r['tactic']} | Technique: {r['technique']}<br>"
            f"Events: {r['events']}<br>"
            f"{r['first_seen']} → {r['last_seen']}"
        )
        net.add_edge(s, d, title=title, value=int(r["events"]))

    out_file = OUT / f"focus_{ip}.html"
    # use write_html (not show) and set notebook=False
    net.write_html(str(out_file), notebook=False)
    print("Wrote", out_file)

def main():
    # You already created this in Step 4
    ips = pd.read_csv(OUT / "interesting_ips.csv")["ip"].head(3)
    for ip in ips:
        render_html_for_focus(ip)

if __name__ == "__main__":
    main()
