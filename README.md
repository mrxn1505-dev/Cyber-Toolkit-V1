# Cyber-Toolkit-V1
# MRXN1505 Cyber Toolkit

A lightweight, terminal-based defensive security toolkit for Linux and Termux.
Built with Python's standard library—no third-party packages required.

## Features

- URL security-header review (for sites you own or are authorized to assess)
- DNS lookup
- TLS certificate expiry and issuer check
- Local network information
- SHA-256 / SHA-1 / MD5 file hashes
- Local password-strength estimate (input is not transmitted)

## Requirements

- Python 3.8+
- Linux, macOS, or Android with Termux

## Run

```bash
git clone https://github.com/mrxn1505-dev/mrxn1505-cyber-toolkit.git
cd mrxn1505-cyber-toolkit
python3 toolkit.py
```

In Termux, install Python if needed:

```bash
pkg update
pkg install python git
```

## Safety

Use the URL review and DNS/TLS checks only for systems you own or have permission to assess.
This project does not perform exploitation, credential collection, stealth, or destructive actions.

## License

MIT
