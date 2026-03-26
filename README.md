# ParseIOC

Parse a list of indicators into a dictionary, JSON structure, or Sqlite database for programmatic use.

Handles:
- emails and their domains
- URL domains, and username+password and ports if present
- ipv4 and ipv6 addresses and networks
- md5, sha256, and sha512 hashes

...with the goal of **mapping this dictionary to fields in a SIEM** or similar database.

This enables programatic use of an IOC file to quickly query specific values in a SIEM, such as `source.ip` or `file.hash.sha256`.

This tool will support more formats (imphash, ssdeep, ja3+) "eventually".

**Otherwise-unidentifiable strings are categorized as "file".**

## Setup

```
uv add parse_ioc
# or
pip3 install parse_ioc
```

## Usage
`from parse_ioc import ParseIOC, map_fields, parse_multi, to_sqlite`


### Categorize a single indicator
```
i = ParseIOC("https://192.168.20.20/bad.txt")
i.to_dict
i.to_json
```

### Categorize a **list** or **file** of indicators
setting `mode="single"` will produce the same results as calling `ParseIOC(ioc)` by itself
```
p = parse_multi(ioc_list, mode="combined")
# or
p = parse_multi("ioc_examples.txt", mode="combined")

print(json.dumps(p, indent=4))
```

### Map a **list** or **file** of indicators to a TOML of SIEM fields
```
m = map_fields("ioc_examples.txt", "map_ecs.toml")
print(json.dumps(m, indent=4))
```

### Create Sqlite database of parsed indicators
The schema is simply "ioc" and "type"; the dict/JSON keys, are the type values
```
to_sqlite("ioc_examples.txt", "iocs.db")
```

## Gotchas
- Domain names must have a period (`.`) otherwise the string will be considered a file
- This regex in the domain checker, determines if the parsed domain name drops further down to the "file" bucket or not:
```
file_extensions = re.compile(r"\.(?:exe|dll|msi|bat|cmd|elf|scr|cpl|ps1|vbs|pdf|docx|xlsx|pptx|doc|xls|ppt|rtf|csv|txt|log|xml|zip|rar|7z|tar|gz|iso|img|dmg|cab|png|jpg|jpeg|gif|ico|bmp|svg|mp3|mp4|wav|avi|mov|js|php|css|html|htm|sql|conf|ini|yaml|yml|json)$", re.IGNORECASE)
```

## Known Issues

- need to streamline and optimize code
- remove both regex statements created by AI

## Expected sample output from running `parse_ioc.py` directly
```
======================== categorize a single indicator =========================
.to_dict: <class 'dict'> {'ioc': '192.168.20.20', 'ioc_type': 'ipv4'}
.to_json: <class 'str'> {"ioc": "192.168.20.20", "ioc_type": "ipv4"}
================ parse a list of IOCs into a combined structure ================
{
    "email": [
        "bob@email.local"
    ],
    "domain": [
        "anotherwebsite.local",
        "securewebsite.local",
        "n--nhk-u63b1cko2lyc6jrwxgom6k.com",
        "website.local",
        "email.local"
    ],
    "port": [
        9443,
        8443
    ],
    "credentials": [
        "username:password"
    ],
    "ipv4": [
        "192.168.20.20",
        "192.168.1.1"
    ],
    "ipv4_network": [
        "192.168.1.0/24"
    ]
}
================ parse a file of IOCs into a combined structure ================
{
    "email": [
        "bad.username@subdomain.bad.local",
        "bob@email.local"
    ],
    "domain": [
        "anotherwebsite.local",
        "securewebsite.local",
        "bad.local",
        "n--nhk-u63b1cko2lyc6jrwxgom6k.com",
        "website.local",
        "subdomain.bad.local",
        "email.local"
    ],
    "ipv4": [
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.8",
        "192.168.1.1"
    ],
    "port": [
        9443,
        8443
    ],
    "credentials": [
        "username:password"
    ],
    "ipv4_network": [
        "192.168.1.0/24",
        "8.8.8.0/24"
    ],
    "ipv6": [
        "fe80::"
    ],
    "file_path_linux": [
        "/home/bob/file.txt"
    ],
    "file": [
        "aaaaaaaaaaaaaaaa",
        "file.txt",
        "bob documents.pdf",
        "rc:\\users\\bob smith\\desktop\\file.txt:alt.exe",
        "not-an-ioc"
    ],
    "file_path_windows": [
        "c:/users/bob smith/desktop/file.txt:alt.exe",
        "c:\\users\\bob\\desktop\\test.txt",
        "file.txt:alt.exe",
        "c:\\users\\bob smith\\desktop\\file.txt:alt.exe",
        "c:\\users\\bob smith\\desktop\\file2.txt:alt.exe",
        "c:\\users\\bob smith\\desktop\\file.txt"
    ],
    "md5": [
        "6cd3556deb0da54bca060b4c39479839"
    ],
    "sha256": [
        "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
    ],
    "sha512": [
        "c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421"
    ]
}
=== yield dictionaries from a list or file, instead of a combined structure ====
{'ioc': 'bob@email.local', 'ioc_type': 'email', 'extra': [{'ioc': 'email.local', 'ioc_type': 'domain'}]}
{'ioc': 'bad.username@subdomain.bad.local', 'ioc_type': 'email', 'extra': [{'ioc': 'subdomain.bad.local', 'ioc_type': 'domain'}]}
{'ioc': '8.8.8.8', 'ioc_type': 'ipv4'}
{'ioc': '1.2.3.4', 'ioc_type': 'ipv4'}
{'ioc': 'website.local', 'ioc_type': 'domain'}
{'ioc': 'anotherwebsite.local', 'ioc_type': 'domain', 'extra': [{'ioc': 9443, 'ioc_type': 'port'}]}
{'ioc': 'securewebsite.local', 'ioc_type': 'domain', 'extra': [{'ioc': 'username:password', 'ioc_type': 'credentials'}, {'ioc': 8443, 'ioc_type': 'port'}]}
{'ioc': '192.168.1.1', 'ioc_type': 'ipv4'}
{'ioc': '192.168.1.0/24', 'ioc_type': 'ipv4_network'}
{'ioc': '8.8.8.0/24', 'ioc_type': 'ipv4_network'}
{'ioc': '192.168.20.20', 'ioc_type': 'ipv4'}
{'ioc': 'fe80::', 'ioc_type': 'ipv6'}
{'ioc': 'n--nhk-u63b1cko2lyc6jrwxgom6k.com', 'ioc_type': 'domain'}
{'ioc': 'bad.local', 'ioc_type': 'domain'}
{'ioc': '/home/bob/file.txt', 'ioc_type': 'file_path_linux'}
{'ioc': 'rc:\\users\\bob smith\\desktop\\file.txt:alt.exe', 'ioc_type': 'file'}
{'ioc': 'file.txt', 'ioc_type': 'file'}
{'ioc': 'file.txt:alt.exe', 'ioc_type': 'file_path_windows'}
{'ioc': 'bob documents.pdf', 'ioc_type': 'file'}
{'ioc': '/home/bob/file.txt', 'ioc_type': 'file_path_linux'}
{'ioc': 'c:\\users\\bob\\desktop\\test.txt', 'ioc_type': 'file_path_windows'}
{'ioc': 'c:\\users\\bob smith\\desktop\\file.txt', 'ioc_type': 'file_path_windows'}
{'ioc': 'c:\\users\\bob smith\\desktop\\file.txt', 'ioc_type': 'file_path_windows'}
{'ioc': 'c:\\users\\bob smith\\desktop\\file.txt:alt.exe', 'ioc_type': 'file_path_windows'}
{'ioc': 'c:\\users\\bob smith\\desktop\\file.txt:alt.exe', 'ioc_type': 'file_path_windows'}
{'ioc': 'c:\\users\\bob smith\\desktop\\file.txt:alt.exe', 'ioc_type': 'file_path_windows'}
{'ioc': 'c:\\users\\bob smith\\desktop\\file2.txt:alt.exe', 'ioc_type': 'file_path_windows'}
{'ioc': 'c:/users/bob smith/desktop/file.txt:alt.exe', 'ioc_type': 'file_path_windows'}
{'ioc': 'not-an-ioc', 'ioc_type': 'file'}
{'ioc': 'aaaaaaaaaaaaaaaa', 'ioc_type': 'file'}
{'ioc': '6cd3556deb0da54bca060b4c39479839', 'ioc_type': 'md5'}
{'ioc': '315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3', 'ioc_type': 'sha256'}
{'ioc': 'c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421', 'ioc_type': 'sha512'}
======== provide IOC (file or list) and TOML config (path) map_fields() ========
{
    "email.from.address": [
        "bad.username@subdomain.bad.local",
        "bob@email.local"
    ],
    "email.sender.address": [
        "bad.username@subdomain.bad.local",
        "bob@email.local"
    ],
    "email.to.address": [
        "bad.username@subdomain.bad.local",
        "bob@email.local"
    ],
    "email.reply_to.address": [
        "bad.username@subdomain.bad.local",
        "bob@email.local"
    ],
    "email.cc.address": [
        "bad.username@subdomain.bad.local",
        "bob@email.local"
    ],
    "email.bcc.address": [
        "bad.username@subdomain.bad.local",
        "bob@email.local"
    ],
    "destination.domain": [
        "anotherwebsite.local",
        "securewebsite.local",
        "bad.local",
        "n--nhk-u63b1cko2lyc6jrwxgom6k.com",
        "website.local",
        "subdomain.bad.local",
        "email.local"
    ],
    "url.domain": [
        "anotherwebsite.local",
        "securewebsite.local",
        "bad.local",
        "n--nhk-u63b1cko2lyc6jrwxgom6k.com",
        "website.local",
        "subdomain.bad.local",
        "email.local"
    ],
    "tls.client.server_name": [
        "anotherwebsite.local",
        "securewebsite.local",
        "bad.local",
        "n--nhk-u63b1cko2lyc6jrwxgom6k.com",
        "website.local",
        "subdomain.bad.local",
        "email.local"
    ],
    "dns.question.registered_domain": [
        "anotherwebsite.local",
        "securewebsite.local",
        "bad.local",
        "n--nhk-u63b1cko2lyc6jrwxgom6k.com",
        "website.local",
        "subdomain.bad.local",
        "email.local"
    ],
    "file.origin_referrer_url": [
        "anotherwebsite.local",
        "securewebsite.local",
        "bad.local",
        "n--nhk-u63b1cko2lyc6jrwxgom6k.com",
        "website.local",
        "subdomain.bad.local",
        "email.local"
    ],
    "file.origin_url": [
        "anotherwebsite.local",
        "securewebsite.local",
        "bad.local",
        "n--nhk-u63b1cko2lyc6jrwxgom6k.com",
        "website.local",
        "subdomain.bad.local",
        "email.local"
    ],
    "source.ip": [
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.8",
        "192.168.1.1",
        "192.168.1.0/24",
        "8.8.8.0/24",
        "fe80::"
    ],
    "destination.ip": [
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.8",
        "192.168.1.1",
        "192.168.1.0/24",
        "8.8.8.0/24",
        "fe80::"
    ],
    "dns.resolved_ip": [
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.8",
        "192.168.1.1",
        "192.168.1.0/24",
        "8.8.8.0/24",
        "fe80::"
    ],
    "host.ip": [
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.8",
        "192.168.1.1",
        "192.168.1.0/24",
        "8.8.8.0/24",
        "fe80::"
    ],
    "network.forwarded_ip": [
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.8",
        "192.168.1.1",
        "192.168.1.0/24",
        "8.8.8.0/24",
        "fe80::"
    ],
    "related.ip": [
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.8",
        "192.168.1.1",
        "192.168.1.0/24",
        "8.8.8.0/24",
        "fe80::"
    ],
    "client.ip": [
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.8",
        "192.168.1.1",
        "192.168.1.0/24",
        "8.8.8.0/24",
        "fe80::"
    ],
    "server.ip": [
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.8",
        "192.168.1.1",
        "192.168.1.0/24",
        "8.8.8.0/24",
        "fe80::"
    ],
    "server.nat.ip": [
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.8",
        "192.168.1.1",
        "192.168.1.0/24",
        "8.8.8.0/24",
        "fe80::"
    ],
    "threat.enrichments.indicator.ip": [
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.8",
        "192.168.1.1",
        "192.168.1.0/24",
        "8.8.8.0/24",
        "fe80::"
    ],
    "file.path": [
        "/home/bob/file.txt",
        "c:/users/bob smith/desktop/file.txt:alt.exe",
        "c:\\users\\bob\\desktop\\test.txt",
        "file.txt:alt.exe",
        "c:\\users\\bob smith\\desktop\\file.txt:alt.exe",
        "c:\\users\\bob smith\\desktop\\file2.txt:alt.exe",
        "c:\\users\\bob smith\\desktop\\file.txt"
    ],
    "file.name": [
        "/home/bob/file.txt",
        "c:/users/bob smith/desktop/file.txt:alt.exe",
        "c:\\users\\bob\\desktop\\test.txt",
        "file.txt:alt.exe",
        "c:\\users\\bob smith\\desktop\\file.txt:alt.exe",
        "c:\\users\\bob smith\\desktop\\file2.txt:alt.exe",
        "c:\\users\\bob smith\\desktop\\file.txt"
    ],
    "dll.hash.md5": [
        "6cd3556deb0da54bca060b4c39479839"
    ],
    "email.attachments.file.hash.md5": [
        "6cd3556deb0da54bca060b4c39479839"
    ],
    "file.hash.md5": [
        "6cd3556deb0da54bca060b4c39479839"
    ],
    "process.hash.md5": [
        "6cd3556deb0da54bca060b4c39479839"
    ],
    "dll.hash.sha256": [
        "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
    ],
    "email.attachments.file.hash.sha256": [
        "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
    ],
    "file.hash.sha256": [
        "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
    ],
    "process.hash.sha256": [
        "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
    ],
    "dll.hash.sha512": [
        "c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421"
    ],
    "email.attachments.file.hash.sha512": [
        "c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421"
    ],
    "file.hash.sha512": [
        "c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421"
    ],
    "process.hash.sha512": [
        "c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421"
    ],
    "source.port": [
        9443,
        8443
    ],
    "destination.port": [
        9443,
        8443
    ]
}
========================== output to Sqlite database ===========================
exported 34 indicators to out.db
('bad.username@subdomain.bad.local', 'email')
('bob@email.local', 'email')
('n--nhk-u63b1cko2lyc6jrwxgom6k.com', 'domain')
('website.local', 'domain')
('email.local', 'domain')
('securewebsite.local', 'domain')
('bad.local', 'domain')
('subdomain.bad.local', 'domain')
('anotherwebsite.local', 'domain')
('8.8.8.8', 'ipv4')
('192.168.20.20', 'ipv4')
('192.168.1.1', 'ipv4')
('1.2.3.4', 'ipv4')
('9443', 'port')
('8443', 'port')
('username:password', 'credentials')
('192.168.1.0/24', 'ipv4_network')
('8.8.8.0/24', 'ipv4_network')
('fe80::', 'ipv6')
('/home/bob/file.txt', 'file_path_linux')
('file.txt', 'file')
('rc:\\users\\bob smith\\desktop\\file.txt:alt.exe', 'file')
('aaaaaaaaaaaaaaaa', 'file')
('bob documents.pdf', 'file')
('not-an-ioc', 'file')
('c:\\users\\bob smith\\desktop\\file.txt', 'file_path_windows')
('c:/users/bob smith/desktop/file.txt:alt.exe', 'file_path_windows')
('file.txt:alt.exe', 'file_path_windows')
('c:\\users\\bob smith\\desktop\\file.txt:alt.exe', 'file_path_windows')
('c:\\users\\bob smith\\desktop\\file2.txt:alt.exe', 'file_path_windows')
('c:\\users\\bob\\desktop\\test.txt', 'file_path_windows')
('6cd3556deb0da54bca060b4c39479839', 'md5')
('315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3', 'sha256')
('c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421', 'sha512')
```
