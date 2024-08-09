
# Comprehensive Guide to Projects and Assignments

This repository includes a collection of projects and assignments covering various topics such as LeetCode problems, computer network assignments, a BitTorrent client, Wireshark analysis, a detailed explanation of the process when typing "www.google.com" into a browser, and Packet Tracer exercises.

## Table of Contents

1. [Understanding LeetCode Problems](#understanding-leetcode-problems)
2. [Computer Network Assignments](#computer-network-assignments)
3. [BitTorrent Client](#bittorrent-client)
4. [Wireshark Analysis](#wireshark-analysis)
5. [What Happens When You Type www.google.com](#what-happens-when-you-type-wwwgooglecom)
6. [Packet Tracer Exercises](#packet-tracer-exercises)
7. [Running the Projects Locally](#running-the-projects-locally)

## Understanding LeetCode Problems

### Network Delay Time Problem

Given a network of `n` nodes linked by directed edges, where each edge represents a connection with a specific travel time. You are also given a source node `k`. The problem asks to find the minimum time it takes for a signal sent from `k` to reach all other nodes in the network. If it's impossible for all nodes to receive the signal, the output is -1.

### Cheapest Flights with K Stops

Find the cheapest price for a flight from a source city to a destination city with at most K stops. If there is no such route, output -1.

### Finding the City with the Smallest Number of Neighbors

Given a graph representing cities and distances between them, find the city with the smallest number of neighbors within a given distance threshold.

Refer to the document [Understanding LeetCode Problems](Leetcode/readme.md) for detailed explanations and code.

## Computer Network Assignments

### Network Delay Time

This problem involves finding the minimum time for a signal to travel through a network of nodes and edges using Dijkstra's algorithm.

### Packet Tracer Exercises

Exercises using Cisco Packet Tracer to simulate and analyze network behavior, configurations, and protocols.

Refer to the document [Computer Network Assignments](Assignment_Details/ReadMe.md) for detailed explanations and configurations.

## BitTorrent Client

A project to build a BitTorrent client using Python. The client allows downloading and uploading files using the BitTorrent protocol.

Refer to the document [BitTorrent Client](Bittorrent_client/Readme) for detailed explanations and code.

## Wireshark Analysis

Using Wireshark to capture and analyze network packets to understand the behavior of network protocols and identify issues.

Refer to the document [Wireshark Analysis](wireshark) for detailed explanations and analysis results.

## What Happens When You Type www.google.com

A detailed step-by-step explanation of what happens when you type "www.google.com" into a browser, including DNS resolution, TCP/IP stack operations, and HTTP request/response cycle.

Refer to the document [What Happens When You Type www.google.com](URL_browser/ReadMe.md) for a comprehensive explanation.

## Packet Tracer Exercises

### Overview

Exercises using Cisco Packet Tracer to simulate network scenarios, including configuration of routers, switches, and other network devices, and analysis of network protocols.

Refer to the document [Packet Tracer Exercises](Packet_Tracer) for detailed configurations and analysis.

## Running the Projects Locally

### Prerequisites

Ensure you have the following software installed on your machine:
- Python (version 3.6 or higher)
- Git
- Wireshark (for packet analysis)
- Cisco Packet Tracer (for network simulations)

### Clone the Repository

```bash
git clone https://github.com/Aasthapaudel/Computer-Network-assignment.git
cd Computer-Network-assignment
```

### Setting Up the BitTorrent Client

1. Navigate to the BitTorrent client directory:
    ```bash
    cd Bittorrent_client
    ```

2. Run the client:
    ```bash
    python downloadTorrent.py
    ```





## Contributing

Contributions are welcome! Please read the [CONTRIBUTING.md]() for guidelines on how to contribute to this repository.

## License

This repository is licensed under the MIT License. See the [LICENSE]() file for more information.

