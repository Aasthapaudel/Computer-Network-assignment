
# Network Assignment Details

## Overview

This repository contains Packet Tracer practice files and detailed explanations on various network configurations, including DHCP, DNS, and IP address assignments. The files cover practical implementations and theoretical aspects of network protocols.

## Packet Tracer Practice Files

### 1. **`dhcp-dns-webserver.pkt`**
   - **Description**: Demonstrates the setup of a DHCP server, DNS server, and web server within Packet Tracer. Includes automatic IP address assignment and integration with a web server.
   - **Contents**:
     - **DHCP Server Configuration**: Automates IP address assignment to devices within the network.
     - **DNS Server Setup**: Configures DNS to resolve domain names to IP addresses.
     - **Web Server Integration**: Hosts a web server and ensures proper network connectivity.
     - **Networking Between Devices**: Configures devices across different subnets to interact seamlessly.

### 2. **`dhcp-server-two-networks.pkt`**
   - **Description**: Illustrates a DHCP server managing IP addresses across two different networks. Shows how to configure a DHCP server to handle multiple IP address pools.
   - **Contents**:
     - **DHCP Configuration**: Setup for handling IP assignments across different network segments.
     - **IP Address Pools**: Configurations for each network segment.
     - **Routing and Subnetting**: Ensures proper routing between networks and correct IP address allocation.

## Theory and Comparison

### 1. **DHCP (Dynamic Host Configuration Protocol)**
   - **Function**: Automatically assigns IP addresses and network configuration to devices in a network.
   - **Key Components**:
     - **DHCP Server**: Manages IP address pools and assignment.
     - **DHCP Client**: Requests and receives IP addresses from the DHCP server.
     - **IP Address Pool**: Range of IP addresses available for assignment.

### 2. **DNS (Domain Name System)**
   - **Function**: Resolves human-readable domain names to IP addresses.
   - **Types of DNS Records**:
     - **A Record**: Maps a domain name to an IPv4 address.
     - **AAAA Record**: Maps a domain name to an IPv6 address.
     - **CNAME Record**: Alias for one domain to another domain.
     - **MX Record**: Specifies mail exchange servers for email delivery.
     - **PTR Record**: Provides reverse DNS lookups to map IP addresses back to domain names.

### 3. **TCP vs UDP**

**Transmission Control Protocol (TCP)**
   - **Characteristics**:
     - **Connection-Oriented**: Establishes a connection before data transfer.
     - **Reliable Data Transfer**: Ensures all data is received correctly and in order.
     - **Error Checking and Recovery**: Detects and corrects errors during transmission.
     - **Ordered Data Delivery**: Maintains the sequence of packets.
   - **Header Fields**:
     - **Source Port**
     - **Destination Port**
     - **Sequence Number**
     - **Acknowledgment Number**
     - **Flags** (SYN, ACK, FIN, etc.)
     - **Window Size**
     - **Checksum**

**User Datagram Protocol (UDP)**
   - **Characteristics**:
     - **Connectionless**: Sends data without establishing a connection.
     - **Faster Data Transfer**: Lower latency compared to TCP.
     - **No Error Checking or Recovery**: Does not ensure data integrity or order.
   - **Header Fields**:
     - **Source Port**
     - **Destination Port**
     - **Length**
     - **Checksum**

### 4. **IP Address Assignment**

**Automatic IP Address Assignment**:
   - **Using DHCP**: Automatically assigns IP addresses from a pool of addresses.
   - **Benefits**:
     - **Reduced Manual Configuration**: Minimizes human error.
     - **Prevents IP Address Conflicts**: Ensures unique IP addresses.
     - **Simplifies Network Management**: Eases administration and maintenance.

**Static IP Assignment**:
   - **Manual Configuration**: Assigns specific IP addresses to devices.
   - **Benefits**:
     - **Fixed Address for Critical Devices**: Useful for servers and network equipment.
     - **Simpler Network Management for Certain Scenarios**: Easier to manage devices with fixed addresses.

### Comparison of TCP and UDP
- **TCP**: Provides reliable, ordered, and error-checked delivery of data, but with higher latency. Suitable for applications where data integrity is crucial (e.g., web browsing, email).
- **UDP**: Offers faster, connectionless communication without guarantees for data integrity or order. Ideal for applications where speed is preferred over reliability (e.g., video streaming, online gaming).

## Conclusion

This assignment covers both practical network configurations and theoretical concepts, providing a comprehensive understanding of DHCP and DNS setups, as well as a comparison of TCP and UDP protocols. The Packet Tracer files offer hands-on experience with network configurations, while the theoretical sections provide in-depth knowledge of networking principles.

