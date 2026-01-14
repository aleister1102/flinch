import pandas as pd
import os
import sys
import argparse


def format_count(n: int) -> str:
    if n % 1_000_000 == 0:
        return f"{n // 1_000_000}m"
    if n % 1_000 == 0:
        return f"{n // 1_000}k"
    return str(n)


def main():
    parser = argparse.ArgumentParser(description="Download Majestic Million domains")
    parser.add_argument(
        "--limit",
        type=int,
        default=1_000_000,
        help="Number of domains to fetch (default: 1000000)",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Output CSV path (default: data/majestic_<limit>.csv)",
    )
    args = parser.parse_args()

    url = "http://downloads.majestic.com/majestic_million.csv"
    if args.limit < 1:
        print("Error: --limit must be >= 1")
        sys.exit(1)

    output_file = args.output.strip() or f"data/majestic_{format_count(args.limit)}.csv"
    
    print(f"Downloading Majestic Million from {url}...")
    try:
        df = pd.read_csv(url, nrows=args.limit)
        
        print(f"Columns found: {df.columns.tolist()}")
        
        if 'Domain' in df.columns:
            domains = df['Domain']
        else:
            if len(df.columns) > 2:
                domains = df.iloc[:, 2]
            else:
                print("Could not identify Domain column. Using first column.")
                domains = df.iloc[:, 0]
        
        domains.to_csv(output_file, index=False, header=False)
        print(f"Saved top {len(domains):,} domains to {output_file}")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if not os.path.exists("data"):
        os.makedirs("data")
    main()
