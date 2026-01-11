import ipaddress
import json
import re
import sys
import tomllib
from dataclasses import dataclass, field, asdict
from typing import Any, BinaryIO, List, TextIO
from urllib.parse import urlparse
# https://github.com/JoshData/python-email-validator
#from email_validator import validate_email


# TODO
# imphash, ssdeep, ja3+
# filenames from a filepath


# uv run -m tests.test -f tests/ioc_examples.txt
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

		Runs .strip() on the IOC, checks for Punycode (IDNA), and then processes the IOC.
		"""
		self.ioc = self.ioc.strip()
		self._check_punycode()
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

	def _check_punycode(self) -> str:
		"""International punycode checks; searches each character individually and decodes the IOC if needed."""
		is_it_punycode = False
		for char in self.ioc:
			#if not re.search("[A-Za-z0-9.-]", char):
			if ord(char) > 127:
				is_it_punycode = True
				self.ioc = self.ioc.encode("idna").decode().strip()
				break

	def _check_file(self) -> bool:
		"""Checks if the IOC is a file path for either Windows or Linux.

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
		# False if not a path
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
		if re.search(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", self.ioc):
			self.ioc_type = "email"
			try:
				ed = self.ioc.split("@")[1]
				self.extra.append({"ioc":ed, "ioc_type":"domain"})
			except:
				return False
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
				return True
		except Exception as e:
			#print("URL_EXCEPTION", str(e))
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
		# fallback
		if not self.ioc_type:
			self.ioc_type = "unknown"


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
	#print(json.dumps(a, indent=4))


def _field_mapper(iocs: dict, map_file_name: str, chunk_size: int=0) -> dict:
	"""Match field mapping to provided ioc_parse output.

	This is the worker function that maps indicators to SIEM field  names.

	Args:
		ioc: the post-processed IOCs in a dictionary
		map_file_name: path to the TOML mapping file
		chunk_size (unused): split IOCs into chunks of n-size
	"""
	try:
		with open(map_file_name, "rb") as f:
			map_data = tomllib.load(f)
	except Exception as e:
		return str(e)+": cannot open TOML field mapping file."
	# inner chunking function
	# chunking should be a user responsibility; may add helper function
	def _inner_chunk(l, n) -> list:
		"""Split a large list into smaller lists of n items, with one list of remainders."""
		for i in range(0, len(l), n):
			yield l[i:i+n]
	out = {}
	if map_data.get("field_map"):
		# the type of field, ipv4, domain, etc
		for field_type in map_data["field_map"]:
			# if the key (ioc type) exists in the parsed IOCs
			if iocs.get(field_type):
				# each field we want in the final output, from map toml
				for field_name in map_data["field_map"][field_type]:
					# make a key if not already there
					if not out.get(field_name):
						out[field_name] = []
					# extend the IOCs into the output mapping via shared key
					out[field_name].extend(iocs[field_type])
	else:
		return "error: no key field_map in loaded TOML file"
	# chunking should be a user responsibility; may add helper function
	#if chunk_size > 0:
	#	for key in out:
	#		out[key]["values"] = list(_inner_chunk(out[key]["values"], chunk_size))
	#		out[key]["chunk_size"] = len(out[key]["values"])
	#
	#print("="*50)
	#print(json.dumps(out, indent=4))
	#mapper(map_data["field_map"], ioc_data, chunk_size=2)
	return out


def map_fields(input_object: List[str] | TextIO, map_file_name: str) -> dict:
	"""Callable function to map IOCs to the fields in the TOML configuration.

	This is the friendly entrypoint to the field-to-mapping functions.

	Args:
		input_object: list of IOCs, or path to a text file containing IOCs
		map_file_name: path to the TOML mapping file
	"""
	parsed_iocs_combined = parse_multi(input_object, mode="combined")
	return _field_mapper(parsed_iocs_combined, map_file_name)


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
	#print(json.dumps(out, indent=4))
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
	print(" parse a list or file of IOCs into a combined structure ".center(80, "="))
	iocs_from_list = parse_multi(ioc_list, mode="combined")
	iocs_from_file = parse_multi("ioc_examples.txt", mode="combined")
	print(json.dumps(iocs_from_list, indent=4))
	print(json.dumps(iocs_from_file, indent=4))
	#
	# alternatively parse a file line by line (mode=single) into dicts, instead of calling ParseIOC(indicator)
	print(" yield dictionaries from a list or file, instead of a combined structure ".center(80, "="))
	for item in parse_multi("ioc_examples.txt", mode="single"):
		print(item)
	#
	# THIS IS THE SECOND PRIMARY OUTPUT
	# use a field map to stage siem or database queries
	print(" provide IOC (file or list) and TOML config (path) map_fields() ".center(80, "="))
	#m = map_fields(ioc_list, "map_ecs.toml")
	m = map_fields("ioc_examples.txt", "map_ecs.toml")
	print(json.dumps(m, indent=4))
