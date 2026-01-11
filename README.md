# ParseIOC

Parse a list of indicators into a dictionary or JSON structure for programmatic use.

Converts a plain list of indicators into a dictionary of:
- emails and their domains
- URL domains, and username+password and ports if present
- ipv4 and ipv6 addresses and networks
- md5, sha256, and sha512 hashes

...with the goal of **mapping this dictionary to fields in a SIEM** or similar database.

This enables programatic use of an IOC file to quickly query specific values in a SIEM, such as `source.ip` or `file.hash.sha256`.

This tool will support more formats (imphash, ssdeep, ja3+) "eventually".

**Otherwise-unidentifiable strings are categorized as domains.**

## Setup

```
uv add parse_ioc
# or
pip3 install parse_ioc
```

## Usage
`from parse_ioc import ParseIOC, map_fields, parse_multi`


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

## Output from running `parse_ioc.py` directly
```
======================== categorize a single indicator =========================
.to_dict: <class 'dict'> {'ioc': '192.168.20.20', 'ioc_type': 'ipv4'}
.to_json: <class 'str'> {"ioc": "192.168.20.20", "ioc_type": "ipv4"}
============ parse a list or file of IOCs into a combined structure ============
{
    "email": [
        "bob@email.local"
    ],
    "domain": [
        "securewebsite.local",
        "email.local",
        "anotherwebsite.local",
        "n--nhk-u63b1cko2lyc6jrwxgom6k.com",
        "website.local"
    ],
    "port": [
        9443,
        8443
    ],
    "credentials": [
        "username:password"
    ],
    "ipv4": [
        "192.168.1.1",
        "192.168.20.20"
    ],
    "ipv4_network": [
        "192.168.1.0/24"
    ]
}
{
    "email": [
        "bad.username@subdomain.bad.local",
        "bob@email.local"
    ],
    "domain": [
        "securewebsite.local",
        "email.local",
        "bob documents.pdf",
        "file.txt",
        "bad.local",
        "not-an-ioc",
        "anotherwebsite.local",
        "n--nhk-u63b1cko2lyc6jrwxgom6k.com",
        "subdomain.bad.local",
        "website.local",
        "aaaaaaaaaaaaaaaa"
    ],
    "ipv4": [
        "8.8.8.8",
        "192.168.1.1",
        "192.168.20.20",
        "1.2.3.4"
    ],
    "port": [
        9443,
        8443
    ],
    "credentials": [
        "username:password"
    ],
    "ipv4_network": [
        "8.8.8.0/24",
        "192.168.1.0/24"
    ],
    "ipv6": [
        "fe80::"
    ],
    "file_path_linux": [
        "/home/bob/file.txt"
    ],
    "unknown": [
        "rc:\\users\\bob smith\\desktop\\file.txt:alt.exe"
    ],
    "file_path_windows": [
        "c:\\users\\bob\\desktop\\test.txt",
        "c:/users/bob smith/desktop/file.txt:alt.exe",
        "c:\\users\\bob smith\\desktop\\file.txt:alt.exe",
        "file.txt:alt.exe",
        "c:\\users\\bob smith\\desktop\\file.txt",
        "c:\\users\\bob smith\\desktop\\file2.txt:alt.exe"
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
{'ioc': 'rc:\\users\\bob smith\\desktop\\file.txt:alt.exe', 'ioc_type': 'unknown'}
{'ioc': 'file.txt', 'ioc_type': 'domain'}
{'ioc': 'file.txt:alt.exe', 'ioc_type': 'file_path_windows'}
{'ioc': 'bob documents.pdf', 'ioc_type': 'domain'}
{'ioc': '/home/bob/file.txt', 'ioc_type': 'file_path_linux'}
{'ioc': 'c:\\users\\bob\\desktop\\test.txt', 'ioc_type': 'file_path_windows'}
{'ioc': 'c:\\users\\bob smith\\desktop\\file.txt', 'ioc_type': 'file_path_windows'}
{'ioc': 'c:\\users\\bob smith\\desktop\\file.txt', 'ioc_type': 'file_path_windows'}
{'ioc': 'c:\\users\\bob smith\\desktop\\file.txt:alt.exe', 'ioc_type': 'file_path_windows'}
{'ioc': 'c:\\users\\bob smith\\desktop\\file.txt:alt.exe', 'ioc_type': 'file_path_windows'}
{'ioc': 'c:\\users\\bob smith\\desktop\\file.txt:alt.exe', 'ioc_type': 'file_path_windows'}
{'ioc': 'c:\\users\\bob smith\\desktop\\file2.txt:alt.exe', 'ioc_type': 'file_path_windows'}
{'ioc': 'c:/users/bob smith/desktop/file.txt:alt.exe', 'ioc_type': 'file_path_windows'}
{'ioc': 'not-an-ioc', 'ioc_type': 'domain'}
{'ioc': 'aaaaaaaaaaaaaaaa', 'ioc_type': 'domain'}
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
        "securewebsite.local",
        "email.local",
        "bob documents.pdf",
        "file.txt",
        "bad.local",
        "not-an-ioc",
        "anotherwebsite.local",
        "n--nhk-u63b1cko2lyc6jrwxgom6k.com",
        "subdomain.bad.local",
        "website.local",
        "aaaaaaaaaaaaaaaa"
    ],
    "url.domain": [
        "securewebsite.local",
        "email.local",
        "bob documents.pdf",
        "file.txt",
        "bad.local",
        "not-an-ioc",
        "anotherwebsite.local",
        "n--nhk-u63b1cko2lyc6jrwxgom6k.com",
        "subdomain.bad.local",
        "website.local",
        "aaaaaaaaaaaaaaaa"
    ],
    "tls.client.server_name": [
        "securewebsite.local",
        "email.local",
        "bob documents.pdf",
        "file.txt",
        "bad.local",
        "not-an-ioc",
        "anotherwebsite.local",
        "n--nhk-u63b1cko2lyc6jrwxgom6k.com",
        "subdomain.bad.local",
        "website.local",
        "aaaaaaaaaaaaaaaa"
    ],
    "dns.question.registered_domain": [
        "securewebsite.local",
        "email.local",
        "bob documents.pdf",
        "file.txt",
        "bad.local",
        "not-an-ioc",
        "anotherwebsite.local",
        "n--nhk-u63b1cko2lyc6jrwxgom6k.com",
        "subdomain.bad.local",
        "website.local",
        "aaaaaaaaaaaaaaaa"
    ],
    "file.origin_referrer_url": [
        "securewebsite.local",
        "email.local",
        "bob documents.pdf",
        "file.txt",
        "bad.local",
        "not-an-ioc",
        "anotherwebsite.local",
        "n--nhk-u63b1cko2lyc6jrwxgom6k.com",
        "subdomain.bad.local",
        "website.local",
        "aaaaaaaaaaaaaaaa"
    ],
    "file.origin_url": [
        "securewebsite.local",
        "email.local",
        "bob documents.pdf",
        "file.txt",
        "bad.local",
        "not-an-ioc",
        "anotherwebsite.local",
        "n--nhk-u63b1cko2lyc6jrwxgom6k.com",
        "subdomain.bad.local",
        "website.local",
        "aaaaaaaaaaaaaaaa"
    ],
    "source.ip": [
        "8.8.8.8",
        "192.168.1.1",
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.0/24",
        "192.168.1.0/24",
        "fe80::"
    ],
    "destination.ip": [
        "8.8.8.8",
        "192.168.1.1",
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.0/24",
        "192.168.1.0/24",
        "fe80::"
    ],
    "dns.resolved_ip": [
        "8.8.8.8",
        "192.168.1.1",
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.0/24",
        "192.168.1.0/24",
        "fe80::"
    ],
    "host.ip": [
        "8.8.8.8",
        "192.168.1.1",
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.0/24",
        "192.168.1.0/24",
        "fe80::"
    ],
    "network.forwarded_ip": [
        "8.8.8.8",
        "192.168.1.1",
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.0/24",
        "192.168.1.0/24",
        "fe80::"
    ],
    "related.ip": [
        "8.8.8.8",
        "192.168.1.1",
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.0/24",
        "192.168.1.0/24",
        "fe80::"
    ],
    "client.ip": [
        "8.8.8.8",
        "192.168.1.1",
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.0/24",
        "192.168.1.0/24",
        "fe80::"
    ],
    "server.ip": [
        "8.8.8.8",
        "192.168.1.1",
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.0/24",
        "192.168.1.0/24",
        "fe80::"
    ],
    "server.nat.ip": [
        "8.8.8.8",
        "192.168.1.1",
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.0/24",
        "192.168.1.0/24",
        "fe80::"
    ],
    "threat.enrichments.indicator.ip": [
        "8.8.8.8",
        "192.168.1.1",
        "192.168.20.20",
        "1.2.3.4",
        "8.8.8.0/24",
        "192.168.1.0/24",
        "fe80::"
    ],
    "file.path": [
        "/home/bob/file.txt",
        "c:\\users\\bob\\desktop\\test.txt",
        "c:/users/bob smith/desktop/file.txt:alt.exe",
        "c:\\users\\bob smith\\desktop\\file.txt:alt.exe",
        "file.txt:alt.exe",
        "c:\\users\\bob smith\\desktop\\file.txt",
        "c:\\users\\bob smith\\desktop\\file2.txt:alt.exe"
    ],
    "file.name": [
        "/home/bob/file.txt",
        "c:\\users\\bob\\desktop\\test.txt",
        "c:/users/bob smith/desktop/file.txt:alt.exe",
        "c:\\users\\bob smith\\desktop\\file.txt:alt.exe",
        "file.txt:alt.exe",
        "c:\\users\\bob smith\\desktop\\file.txt",
        "c:\\users\\bob smith\\desktop\\file2.txt:alt.exe"
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
```

## Known Issues

- need to streamline and optimize code
- remove both regex statements created by AI
