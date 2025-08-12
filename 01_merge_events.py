import pandas as pd
from pathlib import Path

RAW = Path("data/raw")
OUT_DIR = Path("data/processed")
REP_DIR = Path("reports")
OUT_DIR.mkdir(parents=True, exist_ok=True)
REP_DIR.mkdir(parents=True, exist_ok=True)

CANON = ["ts_utc","src_ip","dst_ip","uid","service","tactic","technique","is_malicious","source_file"]

def normalize_chunk(df: pd.DataFrame, source_file: str) -> pd.DataFrame:
    needed = ["src_ip_zeek","dest_ip_zeek","label_tactic","label_technique","label_binary","datetime","ts","uid","service"]
    for c in needed:
        if c not in df.columns:
            df[c] = pd.NA

    # Parse datetime → UTC, fallback to ts (epoch seconds)
    dt = pd.to_datetime(df["datetime"], errors="coerce", utc=True)
    fallback = pd.to_datetime(df["ts"], errors="coerce", utc=True, unit="s")
    dt = dt.fillna(fallback)

    # Coerce label_binary to bool
    is_mal = df["label_binary"]
    if is_mal.dtype != bool:
        is_mal = is_mal.astype(str).str.lower().isin(["true","1","t","yes"])

    out = pd.DataFrame({
        "ts_utc": dt,
        "src_ip": df["src_ip_zeek"],
        "dst_ip": df["dest_ip_zeek"],
        "uid": df["uid"].astype(str),
        "service": df["service"].astype(str),
        "tactic": df["label_tactic"].astype(str).str.strip(),
        "technique": df["label_technique"].astype(str).str.strip(),
        "is_malicious": is_mal,
        "source_file": source_file
    })
    out = out.dropna(subset=["src_ip","dst_ip"])
    return out

def main():
    parts = []
    per_file_counts = []
    for f in RAW.glob("*.csv"):
        count = 0
        for chunk in pd.read_csv(f, chunksize=200_000, low_memory=False):
            norm = normalize_chunk(chunk, f.name)
            parts.append(norm)
            count += len(norm)
        per_file_counts.append((f.name, count))

    events = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=CANON)
    events = events.sort_values("ts_utc")
    events.to_parquet(OUT_DIR / "events.parquet")

    with open(REP_DIR / "01_eda.md", "w") as fh:
        fh.write("# Quick EDA\n\n")
        fh.write(f"- Rows in canonical events: {len(events):,}\n")
        fh.write(f"- Distinct src IPs: {events['src_ip'].nunique()}\n")
        fh.write(f"- Distinct dst IPs: {events['dst_ip'].nunique()}\n")
        fh.write(f"- Time range: {events['ts_utc'].min()} → {events['ts_utc'].max()}\n\n")
        fh.write("## Rows per input file\n")
        for name, c in per_file_counts:
            fh.write(f"- {name}: {c:,}\n")
        fh.write("\n## Rows per tactic (malicious only)\n")
        mal = events[events["is_malicious"] == True]
        fh.write(mal["tactic"].value_counts().to_string())

if __name__ == "__main__":
    main()
