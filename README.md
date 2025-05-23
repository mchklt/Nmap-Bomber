# Nmap-Bomber
Port scanning is crucial in recon, but running it manually on big scopes? Nope. That’s why I made **Nmap Bomber** — a Python script that runs fast and furious parallel nmap scans on your subdomains.
**Why Nmap Bomber?**

Because it bombs targets with speedy scans without frying your machine. It keeps up to **15 scans running at once**, starting a new scan as soon as one finishes.

### Killer nmap command it uses:

```
nmap --min-rate 4500 --max-rtt-timeout 1500ms -p- -sSCV <target>
```

* `--min-rate 4500`  -- send packets fast, no crawling
* `--max-rtt-timeout 1500ms`  -- timeout slow hosts quickly
* `-p-`  -- scan all ports, no exceptions
* `-sS -sC -sV`  -- stealth SYN scan, default scripts, and version detection

### Why this script rocks

* Handles **thousands** of subdomains without breaking a sweat
* No more manual runs or waiting hours
* Saves output separately for each target, easy to analyze later
* Keeps your CPU safe — no flooding, just smart parallel scans

using that one i scanned 30 host in 3m
[![bskR4.gif](https://s14.gifyu.com/images/bskR4.gif)](https://gifyu.com/image/bskR4)


### Usage

```bash
python3 nmap_bomber.py subdomains.txt &
```
i prefer 

```bash
nohup python3 nmap_bomber.py subdomains.txt &
```
Feed it your list, sit back, and watch the magic happen.

---

Ready to blast your scope? Let’s go.
