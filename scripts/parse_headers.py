#!/usr/bin/python
import glob
import os
import json
import io
import argparse
# importing the module
import collections

unique_headers = set()
unique_status_code = set()
unique_status_message = set()
unique_header_values = set()

headers_list = []


def save_json(name, dictionary):
    with open(name, 'w') as fp:
        json.dump(dictionary, fp)


def make_ids(param_set):
    json_obj = {}
    start_value = 10001
    for item in param_set:
        json_obj[item] = start_value
        start_value += 1
    return json_obj


def parse_response_body(response_body):
    if not response_body.lstrip().startswith("{"):
        return

    cnt = 0
    for line in response_body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue

        resp = rec.get("response") if isinstance(rec, dict) else None
        if not isinstance(resp, dict):
            continue

        sc = resp.get("status_code")
        if sc is not None:
            unique_status_code.add(str(sc))

        sm = resp.get("status")
        if sm:
            unique_status_message.add(str(sm).rstrip())

        headers = resp.get("headers", [])
        if isinstance(headers, list):
            for kv in headers:
                if not isinstance(kv, dict):
                    continue
                header_name = kv.get("k")
                header_value = kv.get("v")
                if header_name:
                    unique_headers.add(str(header_name).lower())
                    headers_list.append(str(header_name))
                if header_value is not None:
                    unique_header_values.add(str(header_value))

        cnt += 1

    print('lines finished: ' + str(cnt))
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse response headers to generate ID maps")
    parser.add_argument("--input", required=True, help="Input directory containing response files")
    parser.add_argument("--out-dir", required=True, help="Output directory for JSON files")
    args = parser.parse_args()

    path = args.input
    if not os.path.exists(path):
        print(f"Error: Input directory {path} does not exist.")
        exit(1)
        
    if not os.path.exists(args.out_dir):
        os.makedirs(args.out_dir)

    files = os.listdir(path)
    for file in files:
        if os.path.isfile(os.path.join(path, file)):
            with open(os.path.join(path, file), encoding='ISO8859-1') as f:
                response = f.read()
                parse_response_body(response)
                print("done with: " + str(file))
                print("-----------------------------------------------")
                f.close()

    frequency_of_headers = collections.Counter(headers_list)

    # VM below 
    unique_headers_ids = make_ids(unique_headers)
    unique_status_code_ids = make_ids(unique_status_code)
    unique_status_message_ids = make_ids(unique_status_message)
    unique_header_values_ids = make_ids(unique_header_values)
    
    print("-----------------------------------------------")
    print(f"Saving to {args.out_dir}")
    
    save_json(os.path.join(args.out_dir, "vm_unique_headers_ids.json"), unique_headers_ids)
    save_json(os.path.join(args.out_dir, "vm_unique_status_code_ids.json"), unique_status_code_ids)
    save_json(os.path.join(args.out_dir, "vm_unique_status_message_ids.json"), unique_status_message_ids)
    save_json(os.path.join(args.out_dir, "vm_unique_header_values_ids.json"), unique_header_values_ids)
