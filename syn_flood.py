#!/usr/bin/env python3
"""
eth0 Network Interface Flood Script
Use responsibly and only on networks you have permission to test.
"""

import socket
import time
import random
import argparse
import sys
import os
from scapy.all import sendp, Ether, IP, UDP, TCP, RandIP, RandMAC
import multiprocessing
import signal

def check_root():
    """Check if the script is running with root privileges"""
    if os.geteuid() != 0:
        print("This script requires root privileges to send raw packets.")
        print("Please run with sudo.")
        sys.exit(1)

def generate_packet(packet_type, size, dst_ip=None, dst_port=None):
    """Generate a packet of specified type and size"""
    if packet_type == "udp":
        if dst_ip is None:
            dst_ip = RandIP()
        if dst_port is None:
            dst_port = random.randint(1, 65535)
        
        # Create UDP packet with random payload to reach desired size
        payload_size = max(0, size - 42)  # Subtract Ethernet+IP+UDP header sizes
        payload = os.urandom(payload_size)
        
        packet = Ether()/IP(dst=dst_ip)/UDP(dport=dst_port)/payload
        
    elif packet_type == "tcp":
        if dst_ip is None:
            dst_ip = RandIP()
        if dst_port is None:
            dst_port = random.randint(1, 65535)
        
        # Create TCP packet with random payload to reach desired size
        payload_size = max(0, size - 54)  # Subtract Ethernet+IP+TCP header sizes
        payload = os.urandom(payload_size)
        
        packet = Ether()/IP(dst=dst_ip)/TCP(dport=dst_port)/payload
        
    elif packet_type == "icmp":
        if dst_ip is None:
            dst_ip = RandIP()
        
        # Create ICMP packet with random payload to reach desired size
        from scapy.all import ICMP
        payload_size = max(0, size - 42)  # Subtract Ethernet+IP+ICMP header sizes
        payload = os.urandom(payload_size)
        
        packet = Ether()/IP(dst=dst_ip)/ICMP()/payload
        
    else:  # Raw Ethernet frames
        payload_size = max(0, size - 14)  # Subtract Ethernet header size
        payload = os.urandom(payload_size)
        
        packet = Ether(dst=RandMAC())/payload
    
    return packet

def flood_worker(interface, packet_type, packet_size, packets_per_second, duration, dst_ip, dst_port):
    """Worker function to send packets"""
    start_time = time.time()
    packets_sent = 0
    sleep_time = 1.0 / packets_per_second if packets_per_second > 0 else 0
    
    print(f"Worker started on {interface}, sending {packet_type} packets")
    
    try:
        while duration <= 0 or time.time() - start_time < duration:
            packet = generate_packet(packet_type, packet_size, dst_ip, dst_port)
            sendp(packet, iface=interface, verbose=0)
            packets_sent += 1
            
            if packets_per_second > 0:
                time.sleep(sleep_time)
            
            # Print status every second
            if packets_sent % max(1, packets_per_second) == 0:
                elapsed = time.time() - start_time
                rate = packets_sent / elapsed if elapsed > 0 else 0
                print(f"Sent {packets_sent} packets ({rate:.2f} pps)")
    
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error in worker: {e}")
    
    elapsed = time.time() - start_time
    rate = packets_sent / elapsed if elapsed > 0 else 0
    print(f"Worker finished. Sent {packets_sent} packets in {elapsed:.2f} seconds ({rate:.2f} pps)")
    return packets_sent

def main():
    parser = argparse.ArgumentParser(description="Network Interface Flood Utility")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface to use (default: eth0)")
    parser.add_argument("-t", "--type", choices=["udp", "tcp", "icmp", "raw"], default="udp", 
                        help="Packet type to send (default: udp)")
    parser.add_argument("-s", "--size", type=int, default=64, 
                        help="Packet size in bytes (default: 64)")
    parser.add_argument("-c", "--count", type=int, default=-1, 
                        help="Number of packets to send, -1 for infinite (default: -1)")
    parser.add_argument("-r", "--rate", type=int, default=1000, 
                        help="Packets per second, 0 for no limit (default: 1000)")
    parser.add_argument("-d", "--duration", type=int, default=10, 
                        help="Duration in seconds, 0 for no limit (default: 10)")
    parser.add_argument("-w", "--workers", type=int, default=1, 
                        help="Number of worker processes (default: 1)")
    parser.add_argument("--dst-ip", default=None, 
                        help="Destination IP (default: random)")
    parser.add_argument("--dst-port", type=int, default=None, 
                        help="Destination port (default: random)")
    
    args = parser.parse_args()
    
    check_root()
    
    print(f"Starting flood on {args.interface} with {args.workers} workers")
    print(f"Packet type: {args.type}, Size: {args.size} bytes, Rate: {args.rate} pps")
    print(f"Duration: {args.duration if args.duration > 0 else 'unlimited'} seconds")
    print(f"Destination IP: {args.dst_ip if args.dst_ip else 'random'}")
    print(f"Destination port: {args.dst_port if args.dst_port else 'random'}")
    print("Press Ctrl+C to stop")
    
    # Create worker processes
    processes = []
    try:
        for _ in range(args.workers):
            p = multiprocessing.Process(
                target=flood_worker,
                args=(args.interface, args.type, args.size, args.rate // args.workers, 
                      args.duration, args.dst_ip, args.dst_port)
            )
            processes.append(p)
            p.start()
        
        # Wait for all processes to complete
        for p in processes:
            p.join()
            
    except KeyboardInterrupt:
        print("Interrupted by user, stopping all workers...")
        for p in processes:
            if p.is_alive():
                p.terminate()
    
    print("Flood completed")

if __name__ == "__main__":
    main()