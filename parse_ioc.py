import ipaddress
import json
import re
import sqlite3
import sys
import tomllib
from dataclasses import dataclass, field, asdict
from typing import Any, BinaryIO, List, TextIO
from urllib.parse import urlparse
# for a future release
# https://github.com/JoshData/python-email-validator
#from email_validator import validate_email


# TODO
# imphash, ssdeep, ja3+
# filenames from a filepath


# demos
# uv run tests/parseonly.py -f tests/ioc_examples.txt [-m] [-j]
# uv run ioc_parse.py


@dataclass
class ParseIOC:
	"""Determines the type of an indicator of compromise (IOC), such as ipv4, domain, MD5, etc."""
	ioc: str
	ioc_type: str | None = None
	# using field(default_factory=list) for mutable default lists
	extra: list[dict[str, Any]] = field(default_factory=list)

	def __post_init__(self) -> None:
		"""Runs cleaning and processing automatically after __init__.

		Runs .strip() on the IOC and processes the IOC.
		"""
		self.ioc = self.ioc.strip()
		self._process()

	@property
	def to_dict(self) -> dict[str, Any]:
		"""Returns a dictionary of the class attributes."""
		out = asdict(self)
		if not self.extra:
			out.pop("extra")
		return out

	@property
	def to_json(self) -> str:
		"""Returns a JSON object of the class attributes."""
		out = asdict(self)
		if not self.extra:
			out.pop("extra")
		return json.dumps(out)

	def _preclean(self) -> None:
		"""Suppresses multiple forward and backward slashes. Does not affect _check_domain()."""
		if "//" in self.ioc:
			self.ioc = self.ioc.replace("//", "/")
			self._preclean()
		elif "\\\\" in self.ioc:
			self.ioc = self.ioc.replace("\\\\", "\\")
			self._preclean()
		self.ioc = self.ioc.lower().replace("hxxp", "http").replace("[://]", "://").replace("**.", "").replace("*.", "")
		return

	def _check_punycode(self, item) -> str:
		"""International punycode checks; searches each character individually and decodes the IOC if needed."""
		is_it_punycode = False
		for char in self.ioc:
			#if not re.search("[A-Za-z0-9.-]", char):
			if ord(char) > 127:
				is_it_punycode = True
				return item.encode("idna").decode().strip()

	def _check_file(self) -> bool:
		"""Checks if the IOC is a file path for either Windows or Linux.

		All unknown strings are considered file names at the end of _process().

		Handles absolute paths, relative paths, and paths with alternative data streams. AI helped write both large regex statements in this function.
		"""
		# remove quotes common in Windows
		ioc = self.ioc.strip('"')
		# Windows regex
		# check for drive letter (C:\ etc), backslashes, alternative data streams, extensions at the end of the path
		windows_path_pattern = re.compile(
			r"^(?:[a-zA-Z]:(?:\\|/)|\\\\|/)?(?:[^<>:\"/\\|?*\n]+\\?|[^<>:\"/\\|?*\n]+/)*[^<>:\"/\\|?*\n]+(?:\.[a-zA-Z0-9]+)?(?::[^<>:\"/\\|?*\n]+)?$")
		# Linux regex
		# check for leading forward slashes (/home/user), forward slashes as path separators, file extension at the end
		linux_path_pattern = re.compile(
			r"^(?:/|~)?(?:(?:[^<>:\"/\\|?*\n]+/)*[^<>:\"/\\|?*\n]+)?(?:\.[a-zA-Z0-9]+)?$")
		# Windows check
		if (re.search(r"^[a-zA-Z]:\\", ioc) or "\\" in ioc or ":" in ioc) and windows_path_pattern.search(ioc):
			# additional interesting extension paths
			#if re.search(r"\.(exe|dll|txt|pdf|docx|zip|py|sh|bat|jpg|png|mshta)$", ioc, re.IGNORECASE):
			self.ioc_type = "file_path_windows"
			return True
		# Linux check
		elif "/" in ioc and linux_path_pattern.search(ioc):
			#if re.search(r"\.(sh|py|txt|conf|log|bin|deb|rpm|tar\.gz)$", ioc, re.IGNORECASE) or ioc.startswith('/'):
			self.ioc_type = "file_path_linux"
			return True
		# final return
		return False

	def _check_sha512(self) -> bool:
		"""Check for SHA-512 hash, only based on string length."""
		if re.search("^[A-Za-z0-9]{128}$", self.ioc):
			self.ioc_type = "sha512"
			return True

	def _check_sha256(self) -> bool:
		"""Check for SHA-256 hash, only based on string length."""
		if re.search("^[A-Za-z0-9]{64}$", self.ioc):
			self.ioc_type = "sha256"
			return True

	def _check_md5(self) -> bool:
		"""Check for MD5 hash, only based on string length."""
		if re.search("^[A-Za-z0-9]{32}$", self.ioc):
			self.ioc_type = "md5"
			return True

	def _check_email(self) -> bool:
		"""Loosely check for email addresses based on regex."""
		# future: use email_validator like this: validate_email(self.ioc, check_deliverability=False)
		# English characters only; misses international characters
		#if re.search(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", self.ioc):
		# unsafe check for "@" to use _check_punycode() - WILL IMPROVE IN A FUTURE RELEASE
		if "@" in self.ioc and ":/" not in self.ioc:
			self.ioc_type = "email"
			email_username = self.ioc.split("@")[0]
			email_domain = self.ioc.split("@")[1]
			# punycode check here
			try:
				checked_email_username = self._check_punycode(email_username)
				checked_email_domain = self._check_punycode(email_domain)
				if checked_email_username:
					email_username = checked_email_username
				if checked_email_domain:
					email_domain = checked_email_domain
				# reconstruct the decoded email components
				self.ioc = email_username + "@" + email_domain
			except Exception as e:
				# explicit pass as to keep the international string rather than lose it entirely
				pass
			self.extra.append({"ioc":email_domain, "ioc_type":"domain"})
			return True

	def _check_ip(self) -> bool:
		"""Checks for an IPv4 or IPv6 address or network."""
		try:
			addr = ipaddress.ip_network(self.ioc, strict=False)
			# start with IPv4, assume it's a network unless /32
			if isinstance(addr, ipaddress.IPv4Network):
				self.ioc_type = "ipv4_network"
				if addr.prefixlen == 32:
					self.ioc_type = "ipv4"
					return True
			# next assume IPv6 network unless /128
			elif isinstance(addr, ipaddress.IPv6Network):
				self.ioc_type = "ipv6_network"
				if addr.prefixlen == 128:
					self.ioc_type = "ipv6"
					return True
			return True
		except ValueError:
			return False

	def _check_domain(self) -> bool:
		"""Checks if the IOC is a URL or domain."""
		try:
			# create local semi-cleaned version of self.ioc
			# several .strip() because of edge cases with malformed strings needing safeguards
			url = self.ioc.lower().lstrip("htxps:/")
			# add schema to urlparse properly parses netloc (domain)
			url = "https://" + url
			parsed = urlparse(url)
			if not parsed.hostname:
				return False
			# patch to only keep domains with a dot in them, thus passing all other strings to the file checker
			if "." not in parsed.hostname:
				return False
			# ignore what may be a common file extension
			file_extensions = re.compile(r"\.(?:exe|dll|msi|bat|cmd|elf|scr|cpl|ps1|vbs|pdf|docx|xlsx|pptx|doc|xls|ppt|rtf|csv|txt|log|xml|zip|rar|7z|tar|gz|iso|img|dmg|cab|png|jpg|jpeg|gif|ico|bmp|svg|mp3|mp4|wav|avi|mov|js|php|css|html|htm|sql|conf|ini|yaml|yml|json)$", re.IGNORECASE)
			if file_extensions.search(parsed.hostname):
				return False
			# continue domain handling below this
			if parsed.username:
				creds = parsed.username
				if parsed.password:
					creds += f":{parsed.password}"
				self.extra.append({"ioc":creds, "ioc_type":"credentials"})
			if parsed.port:
				# possible future feature, to optionally remove "common" high ports via argument
				#if port > 1024 and port != [5353, 8000, 8080, 8443]:
				self.extra.append({"ioc":parsed.port, "ioc_type":"port"})
			# final check for if the domain is an IP
			try:
				# anything except an IP will trigger exception
				ipaddress.ip_address(parsed.hostname)
				# if no exception, update self.ioc and run _check_ip()
				self.ioc = parsed.hostname
				self._check_ip()
				#print("A"*20, parsed.hostname)
				return True
			except ValueError:
				self.ioc = parsed.hostname
				self.ioc_type = "domain"
				# punycode check here
				try:
					temp_check_punycode_domain = self._check_punycode(parsed.hostname)
					if temp_check_punycode_domain:
						self.ioc = temp_check_punycode_domain
				except Exception as e:
					# explicit pass as to keep the international domain rather than lose it entirely
					pass
				return True
		except Exception as e:
			return False

	def _process(self) -> None:
		"""Main processing logic."""
		self._preclean()
		# if adding more check functions, add them here without ()
		checks = [
			self._check_sha512,
			self._check_sha256,
			self._check_md5,
			self._check_email,
			self._check_ip,
			self._check_file,
			self._check_domain
		]
		# check the checks
		for check in checks:
			# add () to "check", since it's a function name
			# if a check function returns True, return
			if check():
				return
		# fallback for all otherwise unknown strings
		if not self.ioc_type:
			self.ioc_type = "file"


def parse_multi(input_object: List[str] | TextIO, mode="combined") -> dict[str, Any] | List[Any]:
	"""Parse list or file of indicators into a large combined structure or individual lines.

	Args:
		input_object: list of IOCs, or path to a text file containing IOCs
		mode: "combined" produces a single returned object, "single" produces individual lines
	"""
	for_assembler = []
	# read a list
	if isinstance(input_object, list):
		for item in input_object:
			#item = repr(item)
			if not item.startswith("#") and not item.startswith("="):
				ioc = ParseIOC(item)
				for_assembler.append(ioc.to_dict)
	# read a file
	else:
		try:
			with open(input_object) as input_file:
				for line in input_file:
					if not line.startswith("#") and not line.startswith("="):
						ioc = ParseIOC(line)
						for_assembler.append(ioc.to_dict)
		except Exception as e:
			print(str(e))
			return for_assembler
	# dict
	if mode == "combined":
		return _assembler(for_assembler)
	# return list of dicts
	elif mode == "single":
		return for_assembler


def to_sqlite(input_object: List[str] | TextIO, db_path: str = "iocs.db") -> None:
	"""Parse list or file of indicators into a SQLite database.

	Args:
		input_object: list of IOCs, or path to a text file containing IOCs
		db_path: path to the output database; default "iocs.db"
	"""
	# get the combined dict using parse_multi() in combined mode
	ioc_data = parse_multi(input_object, mode="combined")

	conn = sqlite3.connect(db_path)
	cursor = conn.cursor()

	# create table if it doesn't exist
	cursor.execute("CREATE TABLE IF NOT EXISTS indicators (ioc TEXT PRIMARY KEY, type TEXT NOT NULL)")

	# prep for insert
	to_insert = []
	for ioc_type, iocs in ioc_data.items():
		for ioc in iocs:
			to_insert.append((ioc, ioc_type))

	# insert and commit
	cursor.executemany("INSERT OR IGNORE INTO indicators (ioc, type) VALUES (?, ?)", to_insert)
	conn.commit()
	conn.close()
	print(f"exported {len(to_insert)} indicators to {db_path}")


def _field_mapper(iocs: dict, map_file_name: str, keep_types: bool=False) -> dict:
	"""Match field mapping to provided ioc_parse output.

	This is the worker function that maps indicators to SIEM field  names.

	Args:
		ioc: the post-processed IOCs in a dictionary
		map_file_name: path to the TOML mapping file
		keep_types: preserve the types of the fields being processes, such as ipv4, email, etc
		  - this changes the structure of the output dictionary to field_type[field_name]:[vals, ...]
	"""
	try:
		with open(map_file_name, "rb") as f:
			map_data = tomllib.load(f)
	except Exception as e:
		return str(e)+": cannot open TOML field mapping file."
	# dict to be returned
	out = {}
	# list to store subdicts, if keep_types is True
	out_with_types = {}
	if map_data.get("field_map"):
		# the type of field, ipv4, domain, etc
		for field_type in map_data["field_map"]:
			# hold the field type in a list-of-dictionaries, in case the user wants to keep them
			out_with_types[field_type] = {}
			# if the key (ioc type) exists in the parsed IOCs
			if iocs.get(field_type):
				# each field we want in the final output, from map toml
				for field_name in map_data["field_map"][field_type]:
					# build the dict that keeps field types defined in the toml
					# make a key if not already there
					if not out_with_types[field_type].get(field_name):
						out_with_types[field_type][field_name] = []
					out_with_types[field_type][field_name].extend(iocs[field_type])
					# build a simpler output dict that only returns the new field:[vals]
					# make a key if not already there
					if not out.get(field_name):
						out[field_name] = []
					# extend the IOCs into the output mapping via shared key
					out[field_name].extend(iocs[field_type])
	else:
		return "error: no key field_map in loaded TOML file"
	if keep_types:
		return out_with_types
	return out


def map_fields(input_object: List[str] | TextIO, map_file_name: str, keep_types: bool=False) -> dict:
	"""Callable function to map IOCs to the fields in the TOML configuration.

	This is the friendly entrypoint to the field-to-mapping functions.

	Args:
		input_object: list of IOCs, or path to a text file containing IOCs
		map_file_name: path to the TOML mapping file
		keep_types: preserve the types of the fields being processes, such as ipv4, email, etc
		  - this changes the structure of the output dictionary to field_type[field_name]:[vals, ...]
	"""
	parsed_iocs_combined = parse_multi(input_object, mode="combined")
	return _field_mapper(parsed_iocs_combined, map_file_name, keep_types)


def _assembler(l: List[str]) -> dict:
	"""Combines all IOCs, including nested "extra" entries, into one dictionary.

	Use this dictionary with mappings to field names for automated SIEM or database queries.

	Args:
		l: list of IOCs to be assembled into the combined structure.
	"""
	out = {}
	def inner(d):
		if d["ioc_type"] not in out:
			out[d["ioc_type"]] = []
			out[d["ioc_type"]].append(d["ioc"])
		else:
			out[d["ioc_type"]].append(d["ioc"])
	for d in l:
		inner(d)
		if d.get("extra"):
			for dd in d["extra"]:
				inner(dd)
	# clean output
	for k,v in out.items():
		out[k] = list(set(v))
	return out


if __name__ == "__main__":
	#
	ioc_list = ["bob@email.local", "website.local", "https://anotherwebsite.local:9443", "https://username:password@securewebsite.local:8443", "192.168.1.1", "192.168.1.0/24", "https://192.168.20.20/bad.txt", "NHKやさしいことばニュース.com"]
	#
	# categorize a single IOC
	print(" categorize a single indicator ".center(80, "="))
	parsed_indicator = ParseIOC("https://192.168.20.20/bad.txt")
	print(".to_dict:", type(parsed_indicator.to_dict), parsed_indicator.to_dict)
	print(".to_json:", type(parsed_indicator.to_json), parsed_indicator.to_json)
	#
	# THIS IS THE FIRST PRIMARY OUTPUT
	# parse a list or file IOCs into a large dict or json structure using parse_multi()
	print(" parse a list of IOCs into a combined structure ".center(80, "="))
	iocs_from_list = parse_multi(ioc_list, mode="combined")
	print(json.dumps(iocs_from_list, indent=4))
	print(" parse a file of IOCs into a combined structure ".center(80, "="))
	iocs_from_file = parse_multi("tests/ioc_examples.txt", mode="combined")
	print(json.dumps(iocs_from_file, indent=4))
	#
	# alternatively parse a file line by line (mode=single) into dicts, instead of calling ParseIOC(indicator)
	print(" yield dictionaries from a list or file, instead of a combined structure ".center(80, "="))
	for item in parse_multi("tests/ioc_examples.txt", mode="single"):
		print(item)
	#
	# THIS IS THE SECOND PRIMARY OUTPUT
	# use a field map to stage siem or database queries
	print(" provide IOC (file or list) and TOML config (path) map_fields() ".center(80, "="))
	#m = map_fields(ioc_list, "map_ecs.toml")
	m = map_fields("tests/ioc_examples.txt", "map_ecs.toml")
	print(json.dumps(m, indent=4))
	#
	# THIS IS THE SECOND PRIMARY OUTPUT, BUT KEEPING THE ORIGINAL FIELD TYPES (ipv4, etc)
	print(" map_fields() and keep IOC types ".center(80, "="))
	m2 = map_fields("tests/ioc_examples.txt", "map_ecs.toml", keep_types=True)
	print(json.dumps(m2, indent=4))
	#
	# create sqlite db - the default name is iocs.db
	print(" output to Sqlite database ".center(80, "="))
	to_sqlite("tests/ioc_examples.txt", "out.db")
	connection = sqlite3.connect("out.db")
	cursor = connection.cursor()
	cursor.execute("SELECT * FROM indicators")
	rows = cursor.fetchall()
	for row in rows:
		print(row)
	connection.close()
