import os
import math
import ipaddress
import argparse

root_dir = os.getenv("HOME")
if not root_dir:
    raise RuntimeError("Set $HOME")
filter_fp_in = f"{root_dir}/malicious_site_list.txt"
filter_fp_out = f"{root_dir}/malicious_sites_trunc.txt"

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        prog='Filter String Generator (HTTP Malicious Domains)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-n',
        type=int,
        default=2,
        help='Number of filter strings to generate')

    args = parser.parse_args()
    print(f"Generating {args.n} filters")

    with open(filter_fp_in, 'r') as file:
        lines = file.readlines()

    if args.n > len(lines):
        raise ValueError(f"n ({args.n}) > number of available filters ({len(lines)})")

    filters = "\n".join([line.strip() for line in lines[:args.n]])

    with open(filter_fp_out, 'w') as file:
        file.write(filters)
