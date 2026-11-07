import ipaddress
import json
import re
import sqlite3
import sys
import tomllib
from dataclasses import dataclass, field, asdict
from typing import Any, BinaryIO, TextIO, Union
from urllib.parse import urlparse


@dataclass
class _IOCRecord:
	"""Determines the type of an indicator of compromise (IOC), such as ipv4, domain, MD5, etc."""
	ioc: str
	ioc_type: str | None = None
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
		while "//" in self.ioc:
			self.ioc = self.ioc.replace("//", "/")
		while "\\\\" in self.ioc:
			self.ioc = self.ioc.replace("\\\\", "\\")
		self.ioc = self.ioc.lower().replace("hxxp", "http").replace("[://]", "://").replace("**.", "").replace("*.", "")
		return

	def _check_punycode(self, item) -> str:
		"""International punycode checks; searches each character individually and decodes the IOC if needed."""
		for char in self.ioc:
			if ord(char) > 127:
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

	def _check_sha1(self) -> bool:
		"""Check for SHA-1 hash, only based on string length."""
		if re.search("^[A-Za-z0-9]{40}$", self.ioc):
			self.ioc_type = "sha1"
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
			self.extra.append({"ioc": email_domain, "ioc_type": "domain"})
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
			# patch to only keep domains with a dot in them, thus passing all other strings to the file checker
			if not parsed.hostname or "." not in parsed.hostname:
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
				self.extra.append({"ioc": creds, "ioc_type": "credentials"})
			if parsed.port:
				# possible future feature, to optionally remove "common" high ports via argument
				#if port > 1024 and port != [5353, 8000, 8080, 8443]:
				self.extra.append({"ioc": parsed.port, "ioc_type": "port"})
			# final check for if the domain is an IP
			try:
				# anything except an IP will trigger exception
				ipaddress.ip_address(parsed.hostname)
				# if no exception, update self.ioc and run _check_ip()
				self.ioc = parsed.hostname
				self._check_ip()
				return True
			except ValueError:
				self.ioc = parsed.hostname
				self.ioc_type = "domain"
				# punycode check here
				try:
					temp_check_punycode_domain = self._check_punycode(parsed.hostname)
					if temp_check_punycode_domain:
						self.ioc = temp_check_punycode_domain
				except Exception:
					# explicit pass as to keep the international domain rather than lose it entirely
					pass
				return True
		except Exception:
			return False

	def _process(self) -> None:
		"""Main processing logic."""
		self._preclean()
		# if adding more check functions, add them here without ()
		checks = [
			self._check_sha512,
			self._check_sha256,
			self._check_sha1,
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


class ParseIOC:
	"""Parser class managing IOC parsing operations and external functions.

	Can be initialized with an input source (file path, list, or stream)
	for batch processing, or used with static methods for single strings.
	"""

	def __init__(self, input_source: Union[str, list[str], TextIO, None] = None) -> None:
		self.input_source = input_source

	@staticmethod
	def parse_one(ioc_str: str) -> _IOCRecord:
		"""Parses a single indicator string on the fly (stateless).

		Can be called directly as ParseIOC.parse_one(ioc_str) without instantiating the class.
		"""
		return _IOCRecord(ioc_str)

	def parse_many(self, input_source: list[str] | TextIO | None = None, mode="combined") -> dict[str, Any] | list[Any]:
		"""Parse a list of strings, or a text file.

		Args:
			input_source: list of IOCs, or path to a text file containing IOCs
			mode: "combined" produces a single returned object, "single" produces individual lines
		"""

		# use the passed input_source if provided, otherwise fall back to the instance variable
		source = input_source if input_source is not None else self.input_source
		if source is None:
			raise ValueError("No input source provided to ParseIOC parser.")

		for_assembler = []
		# read a list
		if isinstance(source, list):
			for item in source:
				#item = repr(item)
				if not item.startswith("#") and not item.startswith("="):
					ioc = _IOCRecord(item)
					for_assembler.append(ioc.to_dict)
		# read a file
		else:
			with open(source) as input_file:
				for line in input_file:
					if not line.startswith("#") and not line.startswith("="):
						ioc = _IOCRecord(line)
						for_assembler.append(ioc.to_dict)
		# return a single dictionary
		if mode == "combined":
			return self._assembler(for_assembler)
		# return list of dicts, with "extra" items split into their own list entries (not nested)
		elif mode == "single":
			return self._single_extra_helper(for_assembler)

	def _assembler(self, l: list[str]) -> dict:
		"""Combines all IOCs, including nested "extra" entries, into one deduped dictionary."""
		out = {}
		def inner(x):
			out.setdefault(x["ioc_type"], []).append(x["ioc"])
		for d in l:
			inner(d)
			if d.get("extra"):
				for dd in d["extra"]:
					inner(dd)
		for k, v in out.items():
			out[k] = list(set(v))
		return out

	def _single_extra_helper(self, l: list[str]) -> list[Any]:
		"""Helper function for moving "extra" nested keys into a flat list."""
		out = []
		for item in l:
			if item.get("extra"):
				for extra_item in item["extra"]:
					out.append(extra_item)
				item.pop("extra")
		out.extend(l)
		return out

	def map_fields(self, iocs: dict[str, Any] | list[dict[str, Any]], map_file: str, keep_types: bool = False) -> dict[str, Any]:
		"""Maps parsed IOC fields to a schema defined in an external TOML mapping file.

		Args:
			iocs: A list of IOC dictionaries parse_many(mode="single"), or the dictionary returned by parse_one().
			map_file: Path to a TOML configuration file containing a field map.
			keep_types: If True, nests mapped fields under their respective IOC types.

		Returns:
			A dictionary mapping of SIEM fields and their unique indicator values, to be queried by other processes.
		"""

		# un-nest "extra" items, and wrap the single dict from parse_one() into a list
		if isinstance(iocs, dict):
			list_for_extras = []
			if iocs.get("extra"):
				for ex in iocs["extra"]:
					list_for_extras.append(ex)
				iocs.pop("extra")
			iocs = [iocs] + list_for_extras 

		out = {}
		try:
			with open(map_file, "rb") as f:
				map_data = tomllib.load(f)
		except (FileNotFoundError, PermissionError) as e:
			raise FileNotFoundError(f"cannot open TOML field mapping file {map_file}: {e}") from e
		except Exception as e:
			raise RuntimeError(f"failed to parse TOML mapping file {map_file}: {e}") from e
		# stop if there isn't a field mapping
		if map_data.get("field_map"):
			field_map = map_data["field_map"]
			for item in iocs:
				if item.get("ioc_type") and item.get("ioc"):
					ioc_type = item["ioc_type"]
					ioc = item["ioc"]
					# handle ioc_type values that are in the mapping
					if ioc_type in field_map:
						for field in field_map[ioc_type]:
							if keep_types:
								out.setdefault(ioc_type, {}).setdefault(field, []).append(ioc)
							else:
								out.setdefault(field, []).append(ioc)
					# handle ioc_type values that are NOT in the mapping
					else:
						out.setdefault("no_mapping", {}).setdefault(ioc_type, []).append(ioc)
		# clean "without types" dict
		for field_name, values in out.items():
			if isinstance(values, list):
				out[field_name] = list(dict.fromkeys(values))
		# clean "with types" dict
		for type_name, fields_dict in out.items():
			if isinstance(fields_dict, dict):
				for field_name, values in fields_dict.items():
					if isinstance(values, list):
						fields_dict[field_name] = list(dict.fromkeys(values))
		return out

	def _NYI_to_sqlite(self, db_path: str = "iocs.db") -> None:
		"""NOT YET IMPLEMENTED: Exports indicators to a SQLite database."""
		if self.input_source is None:
			raise ValueError("No input source provided to ParseIOC parser.")
		
		#ioc_data = self.parse_many(mode="combined")
		ioc_data = "TODO: PROVIDE AN INPUT OBJECT (SINGLE MODE) TO THIS METHOD"

		conn = sqlite3.connect(db_path)
		cursor = conn.cursor()
		cursor.execute("CREATE TABLE IF NOT EXISTS indicators (ioc TEXT PRIMARY KEY, ioc_type TEXT NOT NULL)")

		to_insert = []
		if isinstance(ioc_data, dict):
			for ioc_type, iocs in ioc_data.items():
				for ioc in iocs:
					to_insert.append((ioc, ioc_type))

		cursor.executemany("INSERT OR IGNORE INTO indicators (ioc, ioc_type) VALUES (?, ?)", to_insert)
		conn.commit()
		conn.close()
		print(f"exported {len(to_insert)} indicators to {db_path}")


if __name__ == "__main__":

	# parse a single item
	single_result = ParseIOC.parse_one("https://user:password@bad.local:8080")
	print(" parse_one ".center(80, "="))
	print(f"{single_result.to_dict=}")
	print(f"{single_result.to_json=}")
	print(f"{single_result.ioc_type}")

	# parse many items from a file using the parser
	file_parser = ParseIOC("tests/ioc_examples.txt")

	print(" parse_many - combined ".center(80, "="))
	print(json.dumps(file_parser.parse_many(mode="combined"), indent=4))

	# parse many items from a file using the parser in single mode
	print(" parse_many - single ".center(80, "="))
	list_of_dicts = file_parser.parse_many(mode="single")
	print(json.dumps(list_of_dicts, indent=4))

	print(" map_fields - without types ".center(80, "="))
	map_without_types = file_parser.map_fields(list_of_dicts, map_file="map_ecs.toml")
	print(json.dumps(map_without_types, indent=4))

	print(" map_fields - with types ".center(80, "="))
	map_with_types = file_parser.map_fields(list_of_dicts, map_file="map_ecs.toml", keep_types=True)
	print(json.dumps(map_with_types, indent=4))

	print(" parse_one map_fields - without types ".center(80, "="))
	single_map_without_types = file_parser.map_fields(single_result.to_dict, map_file="map_ecs.toml")
	print(json.dumps(single_map_without_types, indent=4))

	print(" parse_one map_fields - with types ".center(80, "="))
	single_map_with_types = file_parser.map_fields(single_result.to_dict, map_file="map_ecs.toml", keep_types=True)
	print(json.dumps(single_map_with_types, indent=4))

	print(" read a whole file, then parse_one+map_fields - without types ".center(80, "="))
	with open("tests/ioc_examples.txt", "r") as f:
		for line in f:
			parsed_line = ParseIOC.parse_one(line).to_dict
			mapped_line = file_parser.map_fields(parsed_line, map_file="map_ecs.toml")
			print(json.dumps(mapped_line, indent=4))

	print(" read a whole file, then parse_one+map_fields - with types ".center(80, "="))
	with open("tests/ioc_examples.txt", "r") as f:
		for line in f:
			parsed_line = ParseIOC.parse_one(line).to_dict
			mapped_line = file_parser.map_fields(parsed_line, map_file="map_ecs.toml", keep_types=True)
			print(json.dumps(mapped_line, indent=4))
