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


### Import

```
from parse_ioc import ParseIOC
```

### Categorize a single indicator using `ParseIOC.parse_one()`

available attributes:
- `ioc_type`: the categorization (string)
- `to_dict`: the categorized IOC as a dictionary (contains `ioc` and `ioc_type`)
- `to_json`: the categorized IOC as a JSON string (contains `ioc` and `ioc_type`)

```
>>> from parse_ioc import ParseIOC
>>> p = ParseIOC.parse_one("https://192.168.20.20/")
>>> p.ioc_type
'ipv4'
>>> p.to_dict
{'ioc': '192.168.20.20', 'ioc_type': 'ipv4'}
>>> p.to_json
'{"ioc": "192.168.20.20", "ioc_type": "ipv4"}'
```

"extra" details are added when appropriate, such as credentials in a URL, ports, or domains in email addresses
```
>>> e = ParseIOC.parse_one("alice@email.local").to_dict
>>> print(json.dumps(e, indent=4))
{
    "ioc": "alice@email.local",
    "ioc_type": "email",
    "extra": [
        {
            "ioc": "email.local",
            "ioc_type": "domain"
        }
    ]
}
```


### Categorize a **list** or **file** of indicators using `ParseIOC()` methods

Instantiate the class with your file path once using `ParseIOC(<path>)`, then use class methods.

Using `mode="combined"` produces one dictionary of categorized indicators
```
>>> parser = ParseIOC("tests/ioc_examples.txt")
>>> p = parser.parse_many(mode="combined")
>>> print(json.dumps(p, indent=4))
{
    "email": [
        "bob@email.local",
        "bob@emailsubdomain.bad.local.xn--p1ai",
        "xn--bob--o4d3g5c@xn--c1a3a5a.xn--p1ai",
        ...
```

Using `mode="single"` produces a list of dictionaries in the `parse_one()` style
- **this is the required input type for `map_fields()` below**
```
>>> parser = ParseIOC("tests/ioc_examples.txt")
>>> p = parser.parse_many(mode="single")
>>> print(json.dumps(p, indent=4))
[
    {
        "ioc": "bob@email.local",
        "ioc_type": "email"
    },
    {
        "ioc": "email.local",
        "ioc_type": "domain"
    },
    {
        "ioc": 9443,
        "ioc_type": "port"
    },
    {
        "ioc": "username:password",
        "ioc_type": "credentials"
    },
    ...
```


### Map a **list** or **file** of indicators to SIEM fields using `map_fields()`

These examples use `map_ecs.toml` as a reference for parsing a file into [Elastic Common Schema (ECS)](https://www.elastic.co/docs/reference/ecs/ecs-field-reference) fields
```
>>> parser = ParseIOC("tests/ioc_examples.txt")
>>> list_of_dicts = parser.parse_many(mode="single")
>>> mapped_fields = parser.map_fields(list_of_dicts, map_file="map_ecs.toml")
>>> print(json.dumps(mapped_fields, indent=4))
{
    "destination.domain": [
        "email.local",
        "emailsubdomain.bad.local",
        "emailsubdomain.bad.local.xn--p1ai",
        ...
```

Specify `keep_types=True` in `map_fields()` to nest the SIEM values under the original type categorizations
```
>>> parser = ParseIOC("tests/ioc_examples.txt")
>>> list_of_dicts = parser.parse_many(mode="single")
>>> mapped_fields = parser.map_fields(list_of_dicts, map_file="map_ecs.toml", keep_types=True)
>>> print(json.dumps(mapped_fields, indent=4))
{
    "domain": {
        "destination.domain": [
            "email.local",
            "emailsubdomain.bad.local",
            "emailsubdomain.bad.local.xn--p1ai",
             ...
```


## Gotchas
- Domain names must have a period (`.`) otherwise the string will be considered a file.
- This regex in the domain checker, determines if the parsed domain name drops further down to the `file` checker or not:
```
file_extensions = re.compile(r"\.(?:exe|dll|msi|bat|cmd|elf|scr|cpl|ps1|vbs|pdf|docx|xlsx|pptx|doc|xls|ppt|rtf|csv|txt|log|xml|zip|rar|7z|tar|gz|iso|img|dmg|cab|png|jpg|jpeg|gif|ico|bmp|svg|mp3|mp4|wav|avi|mov|js|php|css|html|htm|sql|conf|ini|yaml|yml|json)$", re.IGNORECASE)
```


## TODO

- add optional type conversions to match TheHive5 default observable types
	- change the list of categorizations in README to a markdown table, showing the converted types
- need to streamline and optimize code
- remove the filepath regex statements created by AI
