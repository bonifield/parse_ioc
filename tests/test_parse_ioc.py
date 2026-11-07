import inspect
import json
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from parse_ioc import ParseIOC


TEST_IOC_FILE = "tests/ioc_examples.txt"
TEST_MAP_FILE = "map_ecs.toml"
PRINT_ENABLED = True


def test_parse_one():
	# Parse a single item using the static method (no class instantiation needed)
	function_name = inspect.currentframe().f_code.co_name
	p = ParseIOC.parse_one("https://user:password@bad.local:8080")
	
	assert "ioc" in p.to_dict
	assert "ioc_type" in p.to_dict
	
	if PRINT_ENABLED:
		print(f" {function_name} ".center(80, "="))
		print("dict:", p.to_dict)
		print("json:", p.to_json)
		print("type only:", p.ioc_type)


def test_parse_many_combined():
	# Instantiate the parser once with the file state, then call parse_many
	function_name = inspect.currentframe().f_code.co_name
	parser = ParseIOC(TEST_IOC_FILE)
	p = parser.parse_many(mode="combined")
	
	assert isinstance(p, dict)
	assert "domain" in p
	
	if PRINT_ENABLED:
		print(f" {function_name} ".center(80, "="))
		print(json.dumps(p, indent=4))


def test_parse_many_single():
	function_name = inspect.currentframe().f_code.co_name
	parser = ParseIOC(TEST_IOC_FILE)
	p = parser.parse_many(mode="single")
	
	assert isinstance(p, list)
	assert isinstance(p[0], dict)
	
	if PRINT_ENABLED:
		print(f" {function_name} ".center(80, "="))
		print(json.dumps(p, indent=4))


def test_map_fields_without_types():
	function_name = inspect.currentframe().f_code.co_name
	parser = ParseIOC(TEST_IOC_FILE)
	list_of_dicts = parser.parse_many(mode="single")
	
	p = parser.map_fields(list_of_dicts, map_file=TEST_MAP_FILE)
	assert isinstance(p, dict)
	
	if PRINT_ENABLED:
		print(f" {function_name} ".center(80, "="))
		print(json.dumps(p, indent=4))


def test_map_fields_with_types():
	function_name = inspect.currentframe().f_code.co_name
	parser = ParseIOC(TEST_IOC_FILE)
	list_of_dicts = parser.parse_many(mode="single")
	
	p = parser.map_fields(list_of_dicts, map_file=TEST_MAP_FILE, keep_types=True)
	assert isinstance(p, dict)
	
	if PRINT_ENABLED:
		print(f" {function_name} ".center(80, "="))
		print(json.dumps(p, indent=4))


def test_map_fields_list_without_types():
	function_name = inspect.currentframe().f_code.co_name
	parser = ParseIOC(["192.168.20.20", "bob@domain.local"])
	list_of_dicts = parser.parse_many(mode="single")
	
	p = parser.map_fields(list_of_dicts, map_file=TEST_MAP_FILE)
	assert isinstance(p, dict)
	
	if PRINT_ENABLED:
		print(f" {function_name} ".center(80, "="))
		print(json.dumps(p, indent=4))


def test_map_fields_list_with_types():
	function_name = inspect.currentframe().f_code.co_name
	parser = ParseIOC(["192.168.20.20", "bob@domain.local"])
	list_of_dicts = parser.parse_many(mode="single")
	
	p = parser.map_fields(list_of_dicts, map_file=TEST_MAP_FILE, keep_types=True)
	assert isinstance(p, dict)
	
	if PRINT_ENABLED:
		print(f" {function_name} ".center(80, "="))
		print(json.dumps(p, indent=4))


def test_map_fields_parse_one_without_types():
	function_name = inspect.currentframe().f_code.co_name
	# note - parsing a single string value here instead of the file path string
	p_record = ParseIOC.parse_one("192.168.1.1").to_dict
	p = ParseIOC().map_fields(p_record, map_file=TEST_MAP_FILE)
	
	if PRINT_ENABLED:
		print(f" {function_name} ".center(80, "="))
		print(json.dumps(p, indent=4))


def test_map_fields_parse_one_with_types():
	function_name = inspect.currentframe().f_code.co_name
	p_record = ParseIOC.parse_one("192.168.1.1").to_dict
	p = ParseIOC().map_fields(p_record, map_file=TEST_MAP_FILE, keep_types=True)
	
	assert isinstance(p, dict)
	if PRINT_ENABLED:
		print(f" {function_name} ".center(80, "="))
		print(json.dumps(p, indent=4))


def test_map_fields_parse_one_without_types_linebyline():
	function_name = inspect.currentframe().f_code.co_name
	if PRINT_ENABLED:
		print(f" {function_name} ".center(80, "="))
		
	with open(TEST_IOC_FILE, "r") as f:
		for line in f:
			if line.strip() and not line.startswith(("#", "=")):
				parsed_line = ParseIOC.parse_one(line).to_dict
				mapped_line = ParseIOC().map_fields(parsed_line, map_file=TEST_MAP_FILE)
				assert isinstance(mapped_line, dict)
				if PRINT_ENABLED:
					print(json.dumps(mapped_line, indent=4))


def test_map_fields_parse_one_with_types_linebyline():
	function_name = inspect.currentframe().f_code.co_name
	if PRINT_ENABLED:
		print(f" {function_name} ".center(80, "="))
		
	with open(TEST_IOC_FILE, "r") as f:
		for line in f:
			if line.strip() and not line.startswith(("#", "=")):
				parsed_line = ParseIOC.parse_one(line).to_dict
				mapped_line = ParseIOC().map_fields(parsed_line, map_file=TEST_MAP_FILE, keep_types=True)
				assert isinstance(mapped_line, dict)
				if PRINT_ENABLED:
					print(json.dumps(mapped_line, indent=4))
