import pandas as pd
from pathlib import Path
import ipaddress
from textwrap import indent

ART = Path("artifacts")
REP = Path("reports")
REP.mkdir(exist_ok=True, parents=True)

# Adjust if your org ranges differ
ORG_CIDRS = ["143.88.0.0/16"]  # treat RFC1918 as internal too
TOP_K = 5  # how many top IPs to describe

def is_internal(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    for cidr in ORG_CIDRS:
        if ip_obj in ipaddress.ip_network(cidr):
            return True
    return ip_obj.is_private

def role_guess(ip: str, edges: pd.DataFrame) -> str:
    # basic heuristic: external + mostly source across multiple tactics => attacker/C2
    src_ct = (edges["src_ip"] == ip).sum()
    dst_ct = (edges["dst_ip"] == ip).sum()
    internal = is_internal(ip)
    distinct_tactics = edges["tactic"].dropna().astype(str).str.lower().unique()
    multi_phase = len([t for t in distinct_tactics if t and t != "none"]) >= 2
    if not internal and src_ct >= dst_ct and multi_phase:
        return "likely attacker / C2"
    if internal and dst_ct >= src_ct and multi_phase:
        return "likely victim / internal asset"
    return "unclear (needs analyst review)"

def load_focus_edges(ip: str) -> pd.DataFrame:
    p = ART / f"focus_{ip}_edges.csv"
    if p.exists():
        df = pd.read_csv(p)
    else:
        # fallback to overall edges if focus file missing
        overall = ART / "overall_edges.csv"
        if not overall.exists():
            raise FileNotFoundError("Missing focus edges and overall_edges.csv. Run 03_build_graphs.py first.")
        df = pd.read_csv(overall)
        df = df[(df["src_ip"] == ip) | (df["dst_ip"] == ip)].copy()
    # parse times
    for c in ["first_seen", "last_seen"]:
        if c in df.columns:
            df[c] = pd.to_datetime(df[c], errors="coerce", utc=True)
    return df

def summarize_timeline(edges: pd.DataFrame, ip: str):
    # Order phases by first time seen
    tmp = (edges.assign(tactic=edges["tactic"].astype(str).str.strip())
                 .groupby("tactic", dropna=False)["first_seen"].min()
                 .sort_values())
    ordered = [t for t in tmp.index if t and t.lower() != "none"]
    return ordered

def top_counterparts(edges: pd.DataFrame, ip: str, k=5):
    # Who this IP talks to the most (by events)
    m = edges.copy()
    m["counterpart"] = m.apply(lambda r: r["dst_ip"] if r["src_ip"] == ip else r["src_ip"], axis=1)
    grp = m.groupby("counterpart", dropna=False)["events"].sum().sort_values(ascending=False)
    return grp.head(k)

def technique_map(edges: pd.DataFrame):
    # tactics -> {technique: total_events}
    m = edges.copy()
    m["technique"] = m["technique"].astype(str).str.strip()
    m["tactic"] = m["tactic"].astype(str).str.strip()
    grp = m.groupby(["tactic","technique"], dropna=False)["events"].sum().reset_index()
    out = {}
    for tac in grp["tactic"].unique():
        if not tac or tac.lower() == "none":
            continue
        sub = grp[grp["tactic"] == tac].sort_values("events", ascending=False)
        out[tac] = [(row["technique"], int(row["events"])) for _, row in sub.iterrows()]
    return out

def make_paragraph(ip: str, edges: pd.DataFrame) -> str:
    edges = edges.copy()
    edges["events"] = edges["events"].astype(int)
    role = role_guess(ip, edges)
    start = pd.to_datetime(edges["first_seen"], utc=True).min()
    end   = pd.to_datetime(edges["last_seen"],  utc=True).max()
    ordered_phases = summarize_timeline(edges, ip)
    counterparts = top_counterparts(edges, ip)
    techs = technique_map(edges)

    # Build readable blocks
    hdr = f"### {ip} — {role}\n"
    timing = f"- **Window:** {start.isoformat()} → {end.isoformat()}\n"
    phases = f"- **Observed phases:** " + (" → ".join(ordered_phases) if ordered_phases else "n/a") + "\n"
    victims = "- **Top counterparts (by events):**\n" + indent("\n".join([f"- {c} ({int(n)} events)" for c, n in counterparts.items()]), "  ") + "\n"

    tech_lines = []
    for tac, pairs in techs.items():
        top = ", ".join([f"{tech} ({ev})" for tech, ev in pairs[:5]])
        tech_lines.append(f"  - {tac}: {top if top else 'n/a'}")
    techniques = "- **Techniques by phase (top):**\n" + ("\n".join(tech_lines) if tech_lines else "  - n/a") + "\n"

    # Short narrative
    narrative = (
        f"**Narrative:** Activity involving **{ip}** spans {len(ordered_phases)} MITRE phase(s)"
        f"{' (' + ' → '.join(ordered_phases) + ')' if ordered_phases else ''}. "
        f"Across the observation window, {ip} interacted with {counterparts.size} distinct counterpart(s), "
        f"most frequently {counterparts.index[0]} ({int(counterparts.iloc[0])} events) if not an alias. "
        f"Edge attributes indicate the tactics/techniques above; review timeline and volumes to confirm"
        f" whether this endpoint represents adversary infrastructure or a targeted internal host."
    )

    return hdr + timing + phases + victims + techniques + "\n" + narrative + "\n"

def main():
    ips_path = ART / "interesting_ips.csv"
    if not ips_path.exists():
        raise FileNotFoundError("Missing artifacts/interesting_ips.csv. Run 02_interesting_ips.py first.")
    ips = pd.read_csv(ips_path).sort_values(
        ["distinct_malicious_tactics","total_malicious_events"],
        ascending=[False, False]
    )["ip"].head(TOP_K)

    report_md = ["# Attack Graph Narratives\n"]
    rows = []
    for ip in ips:
        edges = load_focus_edges(ip)
        para = make_paragraph(ip, edges)
        report_md.append(para)

        # CSV summary row
        role = role_guess(ip, edges)
        start = pd.to_datetime(edges["first_seen"], utc=True).min()
        end   = pd.to_datetime(edges["last_seen"],  utc=True).max()
        phases = summarize_timeline(edges, ip)
        rows.append({
            "ip": ip,
            "role_guess": role,
            "start_utc": start.isoformat() if pd.notna(start) else None,
            "end_utc": end.isoformat() if pd.notna(end) else None,
            "phases_sequence": " -> ".join(phases) if phases else "",
            "distinct_counterparts": int(top_counterparts(edges, ip, k=9999).shape[0]),
            "total_events": int(edges["events"].sum())
        })

    # Write outputs
    (REP / "attack_narratives.md").write_text("\n".join(report_md), encoding="utf-8")
    pd.DataFrame(rows).to_csv(ART / "attack_narratives.csv", index=False)
    print("Wrote reports/attack_narratives.md and artifacts/attack_narratives.csv")

if __name__ == "__main__":
    main()
