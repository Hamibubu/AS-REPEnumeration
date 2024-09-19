# AS-REQ Enumeration Tool

This Python script performs enumeration of Kerberos accounts by sending AS-REQ requests to the KDC (Key Distribution Center) without pre-authentication. It uses the Impacket library to create and send Kerberos AS-REQ packets to identify valid users in a domain.

## Features
- Enumerates Kerberos user accounts without requiring credentials.
- Supports checking multiple users from a provided wordlist.
- Outputs valid users and, if pre-authentication is not required, prints the AS-REP hash for further offline cracking.

## Requirements
- Python 3.6+
- Impacket library
- PyASN1 library

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/your_username/your_repository.git
    cd your_repository
    ```

2. Install the Impacket library and pyasn1:

    ```bash
    pip install impacket pyasn1
    ```

## Usage

Run the script with the following command:

```bash
python asreq_enum.py -k <KDC IP> -d <DOMAIN> -w <WORDLIST>
```
