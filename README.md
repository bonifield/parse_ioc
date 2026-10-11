# ParseIOC

Parse a list of indicators into a dictionary, JSON structure, or Sqlite database for programmatic use.

Handles:
- emails and their domains
- URL domains, and username+password and ports if present
- ipv4 and ipv6 addresses and networks
- md5, sha1, sha256, and sha512 hashes

...with the goal of **mapping this dictionary to fields in a SIEM** or similar database.

This enables programatic use of an IOC file to quickly query specific values in a SIEM, such as `source.ip` or `file.hash.sha256`.

This tool will support more formats (imphash, ssdeep, ja3+) "eventually".

**Otherwise-unidentifiable strings are categorized as "file".**

IOCs are categorized as one of these types:
- `domain`
- `email`
- `file_path_linux`
- `file_path_windows`
- `ipv4`
- `ipv4_network`
- `ipv6`
- `ipv6_network`
- `md5`
- `sha1`
- `sha256`
- `sha512`
- extra: `credentials`
- extra: `port`

## Setup

```
uv add parse_ioc
# or
python3 -m pip install parse_ioc
```

## Usage

### Imports

```
from parse_ioc import ParseIOC, parse_multi, map_fields, to_sqlite
```
- `ParseIOC`: class that parses each indicator
- `parse_multi`: function that wraps `ParseIOC` to create one large dictionary, or a list of dictionaries, containing the parsed indicators
- `map_fields`: function that maps parsed indicators by type to fields used in a SIEM, specified a TOML config
- `to_sqlite`: writes parsed indicators to a simple Sqlite3 database

### Categorize a single indicator using `ParseIOC()`
```
>>> i = ParseIOC("https://192.168.20.20/bad")
>>> i.to_dict
{'ioc': '192.168.20.20', 'ioc_type': 'ipv4'}
>>> i.to_json
'{"ioc": "192.168.20.20", "ioc_type": "ipv4"}'
```

"extra" details are added when appropriate, such as credentials in a URL, ports, or domains in email addresses
```
>>> e = ParseIOC("alice@email.local")
>>> print(json.dumps(e.to_dict, indent=4))
{
    "ioc": "alice@email.local",
    "ioc_type": "email",
    "extra": [
        {
            "ioc": "email.local",
            "ioc_type": "domain"
            ...
```

### Categorize a **list** or **file** of indicators using `parse_multi()`

using `mode="combined"` produces one massive dictionary of categorized indicators
```
>>> p = parse_multi(ioc_list, mode="combined")
# or
>>> p = parse_multi("ioc_examples.txt", mode="combined")
>>> import json
>>> print(json.dumps(p, indent=4))
{
    "email": [
        "xn--bob--o4d3g5c@xn--c1a3a5a.xn--p1ai",
        "alice@email.local",
        ...
```

using `mode="single"` produces a **list of dictionaries**, similar to calling `ParseIOC(ioc)` by itself in a loop and putting the results in a list
```
>>> p = parse_multi("tests/ioc_examples.txt", mode="single")
>>> print(json.dumps(p, indent=4))
[
    {
        "ioc": "website.local",
        "ioc_type": "domain"
    },
    {
        "ioc": "anotherwebsite.local",
        "ioc_type": "domain",
        "extra": [
            {
                "ioc": 9443,
                "ioc_type": "port"
            }
        ]
    },
    {
        "ioc": "bob@email.local",
        "ioc_type": "email",
        "extra": [
            {
                "ioc": "email.local",
                "ioc_type": "domain"
            }
```

### Map a **list** or **file** of indicators to SIEM fields using `map_fields()`

- use the `map_ecs.toml` file as a reference or template

example shows parsing a file into [Elastic Common Schema (ECS)](https://www.elastic.co/docs/reference/ecs/ecs-field-reference) fields
```
>>> m = map_fields("tests/ioc_examples.txt", "map_ecs.toml")
>>> print(json.dumps(m, indent=4))
{
    "email.from.address": [
        "xn--bob--o4d3g5c@xn--c1a3a5a.xn--p1ai",
        "alice@email.local",
        "bob@emailsubdomain.bad.local.xn--p1ai",
        "bob@email.local",
        ...
```

specify `keep_types=True` in `map_fields()` to nest the SIEM values under the original type categorizations
```
>>> m = map_fields("tests/ioc_examples.txt", "map_ecs.toml", keep_types=True)
>>> print(json.dumps(m, indent=4))
{
    "email": {
        "email.from.address": [
            "xn--bob--o4d3g5c@xn--c1a3a5a.xn--p1ai",
            "alice@email.local",
             ...
```

### Create Sqlite database of parsed indicators using `to_sqlite()`
- table name: `indicators`
- columns: `ioc` (`TEXT`, primary key) and `type` (`TEXT`)
- uses `parse_multi(input_object, mode="combined")`
- `extra` data has its own row, not linked to its parent data
	- ex. a port won't have any reference to the original URL it came from
```
>>> to_sqlite("tests/ioc_examples.txt", "iocs.db")
exported 41 indicators to iocs.db
```

example output using `sqlite3`
```
$ sqlite3 iocs.db "SELECT ioc,type FROM indicators;"
xn--bob--o4d3g5c@xn--c1a3a5a.xn--p1ai|email
alice@email.local|email
bob@emailsubdomain.bad.local.xn--p1ai|email
bob@email.local|email
192.168.1.1|ipv4
...
9443|port
email.local|domain
...
```

## Gotchas
- Domain names must have a period (`.`) otherwise the string will be considered a file
- This regex in the domain checker, determines if the parsed domain name drops further down to the `file` checker or not:
```
file_extensions = re.compile(r"\.(?:exe|dll|msi|bat|cmd|elf|scr|cpl|ps1|vbs|pdf|docx|xlsx|pptx|doc|xls|ppt|rtf|csv|txt|log|xml|zip|rar|7z|tar|gz|iso|img|dmg|cab|png|jpg|jpeg|gif|ico|bmp|svg|mp3|mp4|wav|avi|mov|js|php|css|html|htm|sql|conf|ini|yaml|yml|json)$", re.IGNORECASE)
```

## Known Issues

- need to streamline and optimize code
- remove the filepath regex statements created by AI

## Expected sample output from running `tests/parse_ioc.py`
```
$ uv run tests/parseonly.py -f tests/ioc_examples.txt -h
usage: parseonly.py [-h] -f FILENAME [-m] [-j] [-k]

parse indicators

options:
  -h, --help           show this help message and exit
  -f, --file FILENAME  input filename
  -m, --map            show mapped format
  -j, --json           display indented JSON
  -k, --keep-types     keep field types in output dict
```

```
$ uv run tests/parseonly.py -f tests/ioc_examples.txt -mjk
{
    "email": {
        "email.from.address": [
            "xn--bob--o4d3g5c@xn--c1a3a5a.xn--p1ai",
            "bob@emailsubdomain.bad.local",
            "alice@email.local",
            "bob@emailsubdomain.bad.local.xn--p1ai",
            "bob@email.local"
        ],
        "email.sender.address": [
            "xn--bob--o4d3g5c@xn--c1a3a5a.xn--p1ai",
            "bob@emailsubdomain.bad.local",
    ...
    "ipv4": {
        "source.ip": [
            "192.168.20.20",
            "8.8.8.8",
            "1.2.3.4",
            "192.168.1.1"
        ],
    ...
    "ipv4_network": {
        "source.ip": [
            "192.168.1.0/24",
            "8.8.8.0/24"
    ...
```

## TODO

- add optional type conversions to match TheHive5 default observable types
	- change the list of categorizations in README to a markdown table, showing the converted types
