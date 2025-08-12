import pandas as pd
from pathlib import Path
from collections import Counter, defaultdict

IN = Path("data/processed/events.parquet")
OUT = Path("artifacts"); OUT.mkdir(exist_ok=True, parents=True)

def main():
    df = pd.read_parquet(IN)
    mal = df[df["is_malicious"] == True].copy()
    mal["tactic"] = mal["tactic"].astype(str).str.strip()

    ip_tactics = defaultdict(set)
    src_count = Counter(); dst_count = Counter(); evt_count = Counter()

    for src, dst, tac in zip(mal["src_ip"], mal["dst_ip"], mal["tactic"]):
        if isinstance(src, str) and src:
            ip_tactics[src].add(tac); src_count[src] += 1; evt_count[src] += 1
        if isinstance(dst, str) and dst:
            ip_tactics[dst].add(tac); dst_count[dst] += 1; evt_count[dst] += 1

    rows = []
    for ip, tset in ip_tactics.items():
        rows.append({
            "ip": ip,
            "distinct_malicious_tactics": len({t for t in tset if t.lower() != "none"}),
            "malicious_src_events": src_count.get(ip, 0),
            "malicious_dst_events": dst_count.get(ip, 0),
            "total_malicious_events": evt_count.get(ip, 0)
        })

    ips = pd.DataFrame(rows).sort_values(
        ["distinct_malicious_tactics","total_malicious_events"],
        ascending=[False, False]
    )
    ips.to_csv(OUT / "all_ips_stats.csv", index=False)
    ips[ips["distinct_malicious_tactics"] >= 2].to_csv(OUT / "interesting_ips.csv", index=False)

if __name__ == "__main__":
    main()
