# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pandas",
# ]
# ///

import pandas as pd
import random

# Read the CSV
df = pd.read_csv('data/majestic_million.csv')

# The paper selects 350,000 random domains
# We will select a smaller sample (e.g., 100) for a quick test, 
# or the user can change this to 350000
SAMPLE_SIZE = 100 

# Sample the domains
sampled_domains = df['Domain'].sample(n=SAMPLE_SIZE, random_state=42)

# Save to CSV (single column as expected by survey tool)
sampled_domains.to_csv('data/targets.csv', index=False, header=False)

print(f"Created data/targets.csv with {SAMPLE_SIZE} random domains from Majestic Million list.")
