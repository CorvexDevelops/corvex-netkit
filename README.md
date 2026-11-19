# corvex-netkit

Author: CorvexDevelops

Small network and vulnerability utilities from [Corvex](https://corvex.dev), the team of security agents that tests your web platforms, code, network and computer. Corvex uses them every day: its traffic agent reads captures with `pcapread`, its posture agent checks installed programs with `nvdmatch`, and its network agents look up addresses with `netlists`.

Written from public specifications (pcap and pcapng formats, RFCs, IANA registries). Python 3.9+ with the standard library only, no dependencies.

| Tool | What it does |
|---|---|
| [`pcapread/`](pcapread/README.md) | reads .pcap and .pcapng and decodes Ethernet, VLAN, IPv4, IPv6, TCP, UDP, ARP, DNS and TLS hellos |
| [`pcapgen/`](pcapgen/README.md) | builds deterministic captures with one example of 21 common attacks, plus a clean baseline, to test any traffic analyser |
| [`nvdmatch/`](nvdmatch/README.md) | tells which CVEs really affect an installed version, using only NVD matches with an explicit version bound |
| [`netlists/`](netlists/README.md) | fast lookup of addresses in huge lists of networks, and a generator of the shared CDN and cloud provider networks |

## Quick start

```bash
python3 pcapgen/pcapgen.py attacks attacks.pcap
python3 pcapread/pcapread.py attacks.pcap --list
python3 nvdmatch/nvdmatch.py lookup mozilla firefox 115.0     # the only tool that goes online (NVD API)
python3 -m unittest discover -s tests -v                       # offline
```

## Licence

Apache License 2.0, see `LICENSE` and `NOTICE`.
