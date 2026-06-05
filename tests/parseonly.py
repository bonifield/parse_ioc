import argparse
import json
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from parse_ioc import map_fields, parse_multi, ParseIOC, to_sqlite


def get_arguments():
	"""Retrieves argparse values."""
	parser = argparse.ArgumentParser(description="script description")
	parser.add_argument("-f", "--file", dest="filename", default="test_in.txt", type=str, help="input filename", required=True)
	parser.add_argument("-m", "--map", dest="map_only", action="store_true", help="show mapped format")
	parser.add_argument("-j", "--json", dest="json_output", action="store_true", help="display indented JSON")
	return parser.parse_args()


def main():
	args = get_arguments()
	iocs = False
	try:
		if args.map_only:
			iocs = map_fields(args.filename, "map_ecs.toml")
		else:
			iocs = parse_multi(args.filename, mode="combined")
	except Exception as e:
		print(str(e))
	if iocs:
		if args.json_output:
			print(json.dumps(iocs, indent=4))
		else:
			print(iocs)
		#
		# example Polars usage (note this project does not require Polars)
		#import polars as pl
		#df = pl.from_records(list(iocs.items()), orient="row").rename(
		#	{"column_0":"ioc_type","column_1":"ioc"}
		#).explode("ioc")
		#print(df)
		#with pl.Config(tbl_rows=-1, set_fmt_str_lengths=100):
		#	print(df)


if __name__ == "__main__":
	main()
