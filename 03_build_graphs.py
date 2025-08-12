import pandas as pd
import networkx as nx
from pathlib import Path
import ipaddress

IN = Path("data/processed/events.parquet")
OUT = Path("artifacts"); OUT.mkdir(exist_ok=True, parents=True)

# mark your internal network(s) here
ORG_CIDRS = ["143.88.0.0/16"]  # add RFC1918 automatically below
TOP_K = 3  # how many top IPs to export focus subgraphs for

def is_internal(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    for cidr in ORG_CIDRS:
        if ip_obj in ipaddress.ip_network(cidr):
            return True
    return ip_obj.is_private  # count RFC1918 as internal too

def main():
    df = pd.read_parquet(IN)
    mal = df[df["is_malicious"] == True].copy()
    mal["tactic"] = mal["tactic"].astype(str).str.strip()
    mal["technique"] = mal["technique"].astype(str).str.strip()

    # aggregate edges across all tactics/techniques
    grp = mal.groupby(["src_ip","dst_ip","tactic","technique"], dropna=False)
    edges = grp.agg(
        events=("ts_utc","count"),
        first_seen=("ts_utc","min"),
        last_seen=("ts_utc","max")
    ).reset_index()
    edges.to_csv(OUT / "overall_edges.csv", index=False)

    # overall graph (optional to export, can be large)
    G = nx.MultiDiGraph()
    for _, r in edges.iterrows():
        s, d = r["src_ip"], r["dst_ip"]
        G.add_node(s, role="internal" if is_internal(s) else "external")
        G.add_node(d, role="internal" if is_internal(d) else "external")
        G.add_edge(s, d,
                   tactic=r["tactic"],
                   technique=r["technique"],
                   events=int(r["events"]),
                   first_seen=str(r["first_seen"]),
                   last_seen=str(r["last_seen"]))
    # nx.write_gexf(G, OUT / "overall_graph.gexf")  # enable if you want the whole graph

    # choose top IPs (from the file produced in step 4)
    ips = pd.read_csv(OUT / "interesting_ips.csv")
    ips = ips.sort_values(["distinct_malicious_tactics","total_malicious_events"], ascending=[False, False]).head(TOP_K)

    for ip in ips["ip"]:
        sub = edges[(edges["src_ip"] == ip) | (edges["dst_ip"] == ip)].copy()
        sub.to_csv(OUT / f"focus_{ip}_edges.csv", index=False)

        SG = nx.MultiDiGraph()
        for _, r in sub.iterrows():
            s, d = r["src_ip"], r["dst_ip"]
            SG.add_node(s, role="internal" if is_internal(s) else "external")
            SG.add_node(d, role="internal" if is_internal(d) else "external")
            SG.add_edge(s, d,
                        tactic=r["tactic"],
                        technique=r["technique"],
                        events=int(r["events"]),
                        first_seen=str(r["first_seen"]),
                        last_seen=str(r["last_seen"]))
        nx.write_gexf(SG, OUT / f"focus_{ip}_subgraph.gexf")

if __name__ == "__main__":
    main()
