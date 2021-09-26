# CVE-2021-38647: Omigod
Another exploit for Omigod written quick and dirty in Go.

The exploit uses and is based on:
- the research by wiz: https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure
- the SOAP payload by midoxnet: https://github.com/midoxnet/CVE-2021-38647
- the Python Proof of Concept by horizon3ai: https://github.com/horizon3ai/CVE-2021-38647



## Usage
```
Usage:   go run main.go <IP> <command>
Example: go run main.go 192.168.2.115 'cat /etc/shadow/'
```