import csv
import sys

def generate_map(request_file, output_file):
    with open(request_file, 'r') as f:
        lines = f.readlines()

    unique_types = set()
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 5:
            req_type = parts[-1]
            unique_types.add(req_type)

    print(f"Found {len(unique_types)} unique request types.")

    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        # Pad with 6 empty columns, then Key (req_type), then Value (ID)
        # rec[6] is key, rec[7] is value
        id_counter = 10000
        for req_type in sorted(unique_types):
            writer.writerow(['', '', '', '', '', '', req_type, str(id_counter)])
            id_counter += 1

if __name__ == "__main__":
    generate_map("data/request_set.txt", "data/map.csv")
