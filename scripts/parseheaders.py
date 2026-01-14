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
    split_underscore = response_body.split('\n______________\n')
    cnt = 0
    for single_response in split_underscore:
        try:
            if not single_response:
                break
            if single_response.lower().startswith('exit status'):
                continue
            elif single_response.lower().startswith("unidentified error"):
                continue
            else:
                separate_body = single_response.split('cool_delimiter_333')
                hb = separate_body[1].strip()
                if not hb.lower().startswith('http'):
                    continue
                else:
                    hb_splitted = ''
                    responses_new_line = hb.split("\n\n")
                    for body in responses_new_line:
                        scl = body.split("\n")[0].split(" ")
                        if scl[0].lower().startswith('http'):
                            if scl[1].lower().startswith('3'):
                                continue
                            else:
                                hb_splitted = body
                                break
                    # hb_splitted = [0]
                    each_header = hb_splitted.split("\n")
                    ##if "30" in each_header[0]:
                    ##  hb_splitted = hb.split("\n\n")[1]
                    ## each_header = hb_splitted.split("\n")
                    for line in each_header:
                        if line.lower().startswith('http'):
                            response_http_line = line.split(" ")
                            if len(response_http_line) > 1:
                                resp_status_code = response_http_line[1]
                                unique_status_code.add(resp_status_code)
                            if len(response_http_line) > 2:
                                i = 2
                                status_message = ''
                                while i < len(response_http_line):
                                    status_message = status_message + response_http_line[i] + " "
                                    i += 1
                                unique_status_message.add(status_message.rstrip())
                            # pass
                        elif ":" in line:
                            line_hv = line.split(":")
                            header_name = line_hv[0]
                            header_value = line_hv[1]
                            unique_header_values.add(header_value)
                            unique_headers.add(header_name.lower())
                            headers_list.append(header_name)
                        elif len(line.strip()) == 0:
                            break
            cnt += 1
        except Exception as e:
            print("Exception at iteration: " + str(cnt))
            print(e)

    print('lines finished: ' + str(cnt))


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
