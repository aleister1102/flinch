import pandas as pd
import os
import sys

def main():
    url = "http://downloads.majestic.com/majestic_million.csv"
    output_file = "data/majestic_100k.csv"
    
    print(f"Downloading Majestic Million from {url}...")
    try:
        df = pd.read_csv(url, nrows=100000)
        
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
        print(f"Saved top 100,000 domains to {output_file}")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if not os.path.exists("data"):
        os.makedirs("data")
    main()
