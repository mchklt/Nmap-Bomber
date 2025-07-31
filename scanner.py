#!/usr/bin/env python3

import os
import time
import subprocess
import queue
import threading
import sys
import re
from typing import List, Dict, Optional
from collections import Counter

def read_subdomains(filename: str) -> List[str]:
    try:
        with open(filename, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return []
    except Exception as e:
        print(f"Error reading file: {e}")
        return []

def parse_nmap_output(content: str) -> List[tuple]:
    results = []
    blocks = content.split("Starting Nmap")
    for block in blocks:
        host_match = re.search(r"Nmap scan report for (.+)", block)
        if host_match:
            host = host_match.group(1).strip()
            host = re.sub(r"\s*\(.+?\)", "", host)  # remove IP inside parentheses
            ports = re.findall(r"(\d+)/tcp\s+open", block)
            for port in ports:
                results.append((host, port))
    return results

def filter_hosts(results: List[tuple], max_occurrences: int = 100) -> List[tuple]:
    host_counts = Counter(host for host, port in results)
    filtered = [(host, port) for host, port in results if host_counts[host] <= max_occurrences]
    return filtered

def nuclei_file(subdomains: List[str]) -> None:
    all_results = []
    for subdomain in subdomains:
        output_file = f"{subdomain}.out"
        try:
            with open(output_file, 'r') as f:
                content = f.read()
                results = parse_nmap_output(content)
                all_results.extend(results)
        except FileNotFoundError:
            print(f"Output file for {subdomain} not found.")
            continue
        except Exception as e:
            print(f"Error reading output file for {subdomain}: {e}")
            continue

    filtered_results = filter_hosts(all_results)
    
    try:
        with open("good_ports.txt", "w") as f:
            for host, port in filtered_results:
                f.write(f"{host}:{port}\n")
        print("Created good_ports.txt with filtered host:port combinations.")
    except Exception as e:
        print(f"Error writing to good_ports.txt: {e}")

class SubdomainScanner:
    def __init__(self, max_concurrent: int = 10):
        self.max_concurrent = max_concurrent
        self.active_processes: Dict[str, subprocess.Popen] = {}
        self.queue = queue.Queue()
        self.lock = threading.Lock()
        self.running = True

    def add_subdomains(self, subdomains: List[str]) -> None:
        for subdomain in subdomains:
            self.queue.put(subdomain)

    def start_scan(self, subdomain: str) -> Optional[subprocess.Popen]:
        try:
            output_file = f"{subdomain}.out"
            command = [
                "nohup",
                "nmap",
                "--min-rate", "4500",
                "--max-rtt-timeout", "1500ms",
                "-p-",
                "-sSCV",
                subdomain
            ]
            process = subprocess.Popen(
                command,
                stdout=open(output_file, "w"),
                stderr=subprocess.STDOUT,
                preexec_fn=os.setpgrp,
                bufsize=0
            )
            print(f"Started scan for {subdomain} (PID: {process.pid})")
            return process
        except Exception as e:
            print(f"Error starting scan for {subdomain}: {e}")
            return None

    def monitor_processes(self) -> None:
        while self.running or self.active_processes or not self.queue.empty():
            completed_subdomains = []
            with self.lock:
                for subdomain, process in list(self.active_processes.items()):
                    if process.poll() is not None:
                        exit_code = process.returncode
                        status = "completed successfully" if exit_code == 0 else f"failed with exit code {exit_code}"
                        print(f"Scan for {subdomain} {status}")
                        completed_subdomains.append(subdomain)
                        del self.active_processes[subdomain]
            while len(self.active_processes) < self.max_concurrent and not self.queue.empty():
                try:
                    subdomain = self.queue.get_nowait()
                    process = self.start_scan(subdomain)
                    if process:
                        with self.lock:
                            self.active_processes[subdomain] = process
                    self.queue.task_done()
                except queue.Empty:
                    break
                except Exception as e:
                    print(f"Error processing queue: {e}")
            time.sleep(0.5)

    def start(self, subdomains: List[str]) -> None:
        self.running = True
        monitor_thread = threading.Thread(target=self.monitor_processes)
        monitor_thread.daemon = True
        monitor_thread.start()
        try:
            self.queue.join()
            while self.active_processes:
                time.sleep(1)
            nuclei_file(subdomains)  # Call nuclei_file after all scans are complete
        except KeyboardInterrupt:
            print("\nShutting down gracefully...")
        finally:
            self.running = False
            monitor_thread.join(timeout=5)
            with self.lock:
                for subdomain, process in list(self.active_processes.items()):
                    try:
                        print(f"Terminating scan for {subdomain}")
                        process.terminate()
                    except:
                        pass

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 script.py <subdomains_file>")
        sys.exit(1)

    subdomains_file = sys.argv[1]
    max_concurrent_scans = 15
    subdomains = read_subdomains(subdomains_file)
    total = len(subdomains)
    if not subdomains:
        print("No subdomains to scan. Exiting.")
        return
    print(f"Found {total} subdomains to scan. Starting scanner with {max_concurrent_scans} concurrent scans.")
    scanner = SubdomainScanner(max_concurrent=max_concurrent_scans)
    scanner.add_subdomains(subdomains)
    scanner.start(subdomains)
    print("All scans completed!")

if __name__ == "__main__":
    main()
