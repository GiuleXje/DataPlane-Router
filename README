## Routing Process

The code performs the following steps to handle IP packet routing:

- Parses the packet and validates the checksum
- Checks if the TTL is less than or equal to 1; if so, sends an **ICMP Time Exceeded** message (`Type 11`)
- Looks up the next hop in the routing trie; if no route is found, sends an **ICMP Destination Unreachable** message (`Type 3, Code 0`)
- Attempts to resolve the next hop’s MAC address using the ARP table; if not present:
  - Sends an **ARP Request** on the appropriate interface
  - Enqueues the packet until the MAC address is known
- Once the MAC address is available, forwards the packet to the next destination

---

## Longest Prefix Match

To implement longest prefix matching:

- All routing table entries are inserted into a binary trie
  - Each node has two children: one for bit `0`, one for bit `1`
  - When the full prefix of an entry is inserted, the terminal node is marked with the corresponding routing info
- During lookup:
  - The trie is traversed bit-by-bit using the destination IP address
  - The most specific (longest) prefix is the last node visited that has a non-null `node->info`

---

## ARP Protocol

Steps for ARP handling:

- When the MAC address for a next hop is missing from the ARP cache:
  - Send an **ARP Request** on the corresponding interface
  - Queue the original packet for future transmission
- Upon receiving an **ARP Reply**:
  - Add the mapping to the ARP cache
  - Dequeue and send any packets waiting for that MAC address
  - Requeue others if necessary
- If the router receives an **ARP Request** for one of its own IP addresses:
  - Respond with an **ARP Reply** containing the MAC address of the target interface

---

## ICMP Protocol

The router handles ICMP messages in the following scenarios:

- **TTL expired** (`ttl <= 1`): Send **ICMP Time Exceeded** (`Type 11`)
- **Destination unreachable** (no route found): Send **ICMP Destination Unreachable** (`Type 3, Code 0`)
- **ICMP Echo Request**: If addressed to the router, respond with an **ICMP Echo Reply**
