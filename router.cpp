#include <iostream>
#include <bitset>
#include <cstring>
#include <unordered_map>
#include <stdio.h>
#include <stdint.h>
#include <cstring>
#include <arpa/inet.h>
#include <time.h>
#include <queue>
#include <vector>

using namespace std;

extern "C" {
	#include "protocols.h"
	#include "lib.h"
	#include <stdlib.h>
	#include <cstddef>
}

#define ADDRESS_SIZE 32
#define MAX_ENTRANCE 100000
#define ETH_IP 0x800
#define ETH_ARP 0x806

// return the mask size(for 255.255.255.0 = 24)
int mask_size(uint32_t mask) { // computes a mask's size
    bitset<ADDRESS_SIZE> bits(mask);
    int size = 0;
    for (int i = 0; i < ADDRESS_SIZE; i++) {
        if (!bits[i])
            break;
        size++;
    }

    return size;
}

class TrieNode {
public:
	TrieNode *one;
	TrieNode *zero;
	route_table_entry *info;

	TrieNode() {
		one = nullptr;
		zero = nullptr;
		info = nullptr;
	}

	TrieNode(route_table_entry *&val) {
		info = val;
		one = nullptr;
		zero = nullptr;
	}

};

class Trie {
	public:
		TrieNode *root;
	
		Trie() {
			root = new TrieNode();
		}
	
		void insert_address(route_table_entry *entry) {
			bitset<ADDRESS_SIZE> bits(entry->prefix);
			TrieNode *node = root;
			int size = mask_size(entry->mask);

			for (int i = 0; i < size; i++) {
				if (bits[i]) {
					if (!node->one) {
						node->one = new TrieNode();
					}
					node = node->one;
				} else {
					if (!node->zero) {
						node->zero = new TrieNode();
					}
					node = node->zero;
				}
			}
			node->info = entry; // terminal node for this entry
		}
	
		route_table_entry* get_destination(uint32_t dest_ip) {
			bitset<ADDRESS_SIZE> bits(dest_ip);
			TrieNode *node = root;
			route_table_entry *best_match = nullptr;

			for (int i = 0; i < ADDRESS_SIZE && node; i++) { // find LCP
				if (node->info) {
					best_match = node->info; // update best match
				}
				if (bits[i]) {
					node = node->one;
				} else {
					node = node->zero;
				}
			}
			if (node && node->info) { // check final node
				best_match = node->info;
			}

			return best_match;
		}
	};

//debug
void print_mac_add(uint8_t *mac) {
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n", 
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// ttl <= 1
void icmp_tle(char *buf, size_t interface, ether_hdr *eth_hdr, ip_hdr *iphdr, size_t len) {
    char icmp_buf[MAX_PACKET_LEN];
    memset(icmp_buf, 0, sizeof(icmp_buf));

    // ethernet header
    ether_hdr *new_eth_hdr = (ether_hdr *)icmp_buf;
    memcpy(new_eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
    get_interface_mac(interface, new_eth_hdr->ethr_shost);
    new_eth_hdr->ethr_type = htons(ETH_IP);

    // IP header
    ip_hdr *new_ip_hdr = (ip_hdr *)(icmp_buf + sizeof(ether_hdr));
    new_ip_hdr->ver = 4;
    new_ip_hdr->ihl = 5;
    new_ip_hdr->tos = 0;
    new_ip_hdr->tot_len = htons(sizeof(ip_hdr) + sizeof(icmp_hdr) + sizeof(ip_hdr) + 8);
    new_ip_hdr->id = htons(0);
    new_ip_hdr->frag = 0;
    new_ip_hdr->ttl = 64;
    new_ip_hdr->proto = 1; // ICMP
    new_ip_hdr->source_addr = inet_addr(get_interface_ip(interface)); // router's IP
    new_ip_hdr->dest_addr = iphdr->source_addr;
    new_ip_hdr->checksum = 0;
    new_ip_hdr->checksum = htons(checksum((uint16_t *)new_ip_hdr, sizeof(ip_hdr)));

    // ICMP header
    icmp_hdr *new_icmp_hdr = (icmp_hdr *)(icmp_buf + sizeof(ether_hdr) + sizeof(ip_hdr));
    new_icmp_hdr->mtype = 11; // time exceeded code
    new_icmp_hdr->mcode = 0;
    new_icmp_hdr->check = 0;
    memcpy((char *)new_icmp_hdr + sizeof(icmp_hdr), iphdr, sizeof(ip_hdr) + 8);
    size_t icmp_len = sizeof(icmp_hdr) + sizeof(ip_hdr) + 8;
    new_icmp_hdr->check = htons(checksum((uint16_t *)new_icmp_hdr, icmp_len));

    // send packet
    size_t total_len = sizeof(ether_hdr) + ntohs(new_ip_hdr->tot_len);
    send_to_link(total_len, icmp_buf, interface);
}

void send_icmp_error(char *buf, size_t interface, ether_hdr *eth_hdr, ip_hdr *iphdr, size_t len) {
    char icmp_buf[MAX_PACKET_LEN];
    memset(icmp_buf, 0, sizeof(icmp_buf));

    // Ethernet header
    ether_hdr *new_eth_hdr = (ether_hdr *)icmp_buf;
    memcpy(new_eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);  // response to source
    get_interface_mac(interface, new_eth_hdr->ethr_shost); // router interface mac
    new_eth_hdr->ethr_type = htons(ETH_IP);

    // IP header
    ip_hdr *new_ip_hdr = (ip_hdr *)(icmp_buf + sizeof(ether_hdr));
    new_ip_hdr->ver = 4;
    new_ip_hdr->ihl = 5;
    new_ip_hdr->tos = 0;
    new_ip_hdr->tot_len = htons(sizeof(ip_hdr) + sizeof(icmp_hdr) + sizeof(ip_hdr) + 8);
    new_ip_hdr->id = htons(0);
    new_ip_hdr->frag = 0;
    new_ip_hdr->ttl = 64;
    new_ip_hdr->proto = 1; // ICMP
    new_ip_hdr->source_addr = inet_addr(get_interface_ip(interface));
    new_ip_hdr->dest_addr = iphdr->source_addr;
    new_ip_hdr->checksum = 0;
    new_ip_hdr->checksum = htons(checksum((uint16_t *)new_ip_hdr, sizeof(ip_hdr)));

    // ICMP header
    icmp_hdr *new_icmp_hdr = (icmp_hdr *)(icmp_buf + sizeof(ether_hdr) + sizeof(ip_hdr));
    new_icmp_hdr->mtype = 3;
    new_icmp_hdr->mcode = 0;
    new_icmp_hdr->check = 0;
    memcpy((char *)new_icmp_hdr + sizeof(icmp_hdr), iphdr, sizeof(ip_hdr) + 8);
    size_t icmp_len = sizeof(icmp_hdr) + sizeof(ip_hdr) + 8;
    new_icmp_hdr->check = htons(checksum((uint16_t *)new_icmp_hdr, icmp_len));

    // send packet
    size_t total_len = sizeof(ether_hdr) + ntohs(new_ip_hdr->tot_len);
    send_to_link(total_len, icmp_buf, interface);
}

void send_arp_request(uint32_t ip, size_t interface) {
    uint8_t buf[sizeof(ether_hdr) + sizeof(arp_hdr)];
    ether_hdr *eth_hdr = (ether_hdr *)buf;
    arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(ether_hdr));

    memset(eth_hdr->ethr_dhost, 0xFF, 6); // broadcast
    get_interface_mac(interface, eth_hdr->ethr_shost);
    eth_hdr->ethr_type = htons(ETH_ARP);

    arp_hdr->hw_type = htons(1); // ethernet
    arp_hdr->proto_type = htons(ETH_IP); // IPv4
    arp_hdr->hw_len = 6;
    arp_hdr->proto_len = 4;
    arp_hdr->opcode = htons(1); // ARP Request
    get_interface_mac(interface, arp_hdr->shwa);
    arp_hdr->sprotoa = inet_addr(get_interface_ip(interface)); // convert to uint32_t
    memset(arp_hdr->thwa, 0, 6);
    arp_hdr->tprotoa = ip;

    send_to_link(sizeof(buf), (char *)buf, interface);
}

void send_arp_reply(const char *recv_buf, size_t len, size_t interface) {
    arp_hdr *arp_req = (arp_hdr *)(recv_buf + sizeof(ether_hdr));

    if (arp_req->tprotoa != inet_addr(get_interface_ip(interface))) {
        return; // not for this interface
    }

    char buf[sizeof(ether_hdr) + sizeof(arp_hdr)];
    ether_hdr *eth_hdr = (ether_hdr *)recv_buf;
    ether_hdr *eth_reply = (ether_hdr *)buf;

    memcpy(eth_reply->ethr_dhost, eth_hdr->ethr_shost, 6);
    get_interface_mac(interface, eth_reply->ethr_shost);
    eth_reply->ethr_type = htons(ETH_ARP);

    arp_hdr *arp_reply = (arp_hdr *)(buf + sizeof(ether_hdr));
    arp_reply->hw_type = htons(1);
    arp_reply->proto_type = htons(ETH_IP);
    arp_reply->hw_len = 6;
    arp_reply->proto_len = 4;
    arp_reply->opcode = htons(2); // ARP Reply
    get_interface_mac(interface, arp_reply->shwa);
    arp_reply->sprotoa = arp_req->tprotoa;
    memcpy(arp_reply->thwa, arp_req->shwa, 6);
    arp_reply->tprotoa = arp_req->sprotoa;

    
    send_to_link(sizeof(buf), buf, interface);
}

void send_icmp_echo_reply(char *buf, size_t len, int interface) {
    ether_hdr *eth_hdr = (ether_hdr *)buf;
    ip_hdr *iphdr = (ip_hdr *)(buf + sizeof(ether_hdr));
    icmp_hdr *icmp = (icmp_hdr *)(buf + sizeof(ether_hdr) + sizeof(ip_hdr));

    // swap MAC
    uint8_t tmp_mac[6];
    memcpy(tmp_mac, eth_hdr->ethr_dhost, 6);
    memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
    memcpy(eth_hdr->ethr_shost, tmp_mac, 6);

    // swap dest and source
    swap(iphdr->dest_addr, iphdr->source_addr);

    //ICMP reply
    icmp->mtype = 0;
    icmp->check = 0;
    icmp->check = htons(checksum((uint16_t *)icmp, len - sizeof(ether_hdr) - sizeof(ip_hdr)));

    // recalculate IP checksum
    iphdr->ttl = 64;
    iphdr->checksum = 0;
    iphdr->checksum = htons(checksum((uint16_t *)iphdr, sizeof(ip_hdr)));

    send_to_link(len, buf, interface);
}

#define ARP_CACHE_SIZE 32

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
} arp_entry;

arp_entry arp_cache[ARP_CACHE_SIZE];

int get_mac_from_arp_cache(uint32_t ip, uint8_t *mac_out) {
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].ip == ip) {
            memcpy(mac_out, arp_cache[i].mac, 6);
            return 1; //found
        }
    }
    return 0;// no mac in the cache
}

struct QueuedPacket {
    uint32_t next_hop_ip; // IP of the next hop awaiting MAC resolution
    char *packet; // packet data
    size_t len; // packet length
    int interface; // output interface
};

int main(int argc, char *argv[]) {
    char buf[MAX_PACKET_LEN];

    // Initialization
    init(argv + 2, argc - 2);

    // routing table
    route_table_entry *r_table = new route_table_entry[MAX_ENTRANCE];
    DIE(!r_table, "Memory allocation failed for route table!\n");

    int r_table_size = read_rtable(argv[1], r_table);
    DIE(r_table_size <= 0, "Failed to read route table!\n");

    // the trie which holds all the routes from the routing table
    Trie *trie = new Trie();
    for (int i = 0; i < r_table_size; i++) {
        trie->insert_address(&r_table[i]);
    }

    queue<QueuedPacket> packet_queue;

    while (true) {
        size_t interface, len;
        interface = recv_from_any_link(buf, &len);
        printf("Received packet on interface %zu, len=%zu\n", interface, len);
        DIE(interface < 0, "Failed to receive packet!\n");

        if (len < sizeof(ether_hdr)) {
            cout << "pachet prea scurt\n";
            continue;
        }

        ether_hdr *eth_hdr = (ether_hdr *)buf;
        uint8_t mac[6];
        get_interface_mac(interface, mac);

        if (memcmp(mac, eth_hdr->ethr_dhost, 6) != 0 &&
            memcmp(eth_hdr->ethr_dhost, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0) {
            continue;
        }

        printf("Packet received for MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
            eth_hdr->ethr_dhost[0], eth_hdr->ethr_dhost[1], eth_hdr->ethr_dhost[2],
            eth_hdr->ethr_dhost[3], eth_hdr->ethr_dhost[4], eth_hdr->ethr_dhost[5]);

        uint16_t eth_type = ntohs(eth_hdr->ethr_type);

        // neither IP or ARP
        if (eth_type != ETH_IP && eth_type != ETH_ARP) continue;

        if (eth_type == ETH_IP) {
            if (len < sizeof(ether_hdr) + sizeof(ip_hdr)) continue;

            ip_hdr *iphdr = (ip_hdr *)(buf + sizeof(ether_hdr));
            uint16_t old_checksum = ntohs(iphdr->checksum);
            iphdr->checksum = 0;
            uint16_t computed_checksum = checksum((uint16_t *)iphdr, sizeof(ip_hdr));
            iphdr->checksum = old_checksum;

            if (computed_checksum != old_checksum) {
                printf("Dropped packet due to invalid checksum\n");
                continue;
            }

            if (iphdr->ttl <= 1) {
                icmp_tle(buf, interface, eth_hdr, iphdr, len);
                continue;
            }

            char *router_ip_str = get_interface_ip(interface);
            uint32_t router_ip = inet_addr(router_ip_str);

            if (iphdr->dest_addr == router_ip) {
                // it's for the router
                uint8_t *payload = (uint8_t *)iphdr + sizeof(ip_hdr);
                size_t ip_payload_len = ntohs(iphdr->tot_len) - sizeof(ip_hdr);

                // is it echo request?
                if (ip_payload_len >= sizeof(icmp_hdr)) {
                    icmp_hdr *icmp = (icmp_hdr *)payload;
                    if (icmp->mtype == 8) { // code for echo request
                        send_icmp_echo_reply(buf, len, interface);
                        continue;
                    }
                }
                // other types do not matter
                continue;
            }


            iphdr->ttl--;
            iphdr->checksum = 0;
            iphdr->checksum = htons(checksum((uint16_t *)iphdr, sizeof(ip_hdr)));
            cout << "Suma de control este: " << iphdr->checksum << endl;

            route_table_entry *best_route = trie->get_destination(iphdr->dest_addr);

            if (!best_route) {
                printf("No route found for destination IP: %s\n", inet_ntoa(*(struct in_addr *)&iphdr->dest_addr));
                send_icmp_error(buf, interface, eth_hdr, iphdr, len);
                continue;
            }

            uint8_t next_hop_mac[6];
            if (get_mac_from_arp_cache(best_route->next_hop, next_hop_mac)) {
                memcpy(eth_hdr->ethr_dhost, next_hop_mac, 6);
                eth_hdr->ethr_type = htons(ETH_IP);
                get_interface_mac(best_route->interface, eth_hdr->ethr_shost);
                send_to_link(len, buf, best_route->interface);
            } else {
                QueuedPacket qp;
                qp.next_hop_ip = best_route->next_hop;
                qp.packet = new char[len];
                memcpy(qp.packet, buf, len);
                qp.len = len;
                qp.interface = best_route->interface;
                packet_queue.push(qp);
                send_arp_request(best_route->next_hop, best_route->interface);
            }
        } else if (eth_type == ETH_ARP) {
            arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(ether_hdr));

            if (ntohs(arp_hdr->opcode) == 1) {  // ARP Request
                if (arp_hdr->tprotoa == inet_addr(get_interface_ip(interface))) {
                    send_arp_reply(buf, len, interface);
                }
            } else if (ntohs(arp_hdr->opcode) == 2) {  // ARP Reply
                for (int i = 0; i < ARP_CACHE_SIZE; i++) {
                    if (arp_cache[i].ip == 0 || arp_cache[i].ip == arp_hdr->sprotoa) {
                        arp_cache[i].ip = arp_hdr->sprotoa;
                        memcpy(arp_cache[i].mac, arp_hdr->shwa, 6);
                        break;
                    }
                }
                arp_table_entry entry = {arp_hdr->sprotoa, {0}};
                memcpy(entry.mac, arp_hdr->shwa, 6);

                std::queue<QueuedPacket> aux_queue;
                while (!packet_queue.empty()) {
                    QueuedPacket qp = packet_queue.front();
                    packet_queue.pop();
                    if (qp.next_hop_ip == arp_hdr->sprotoa) {
                        ether_hdr *p_eth_hdr = (ether_hdr *)qp.packet;
                        memcpy(p_eth_hdr->ethr_dhost, arp_hdr->shwa, 6);
                        get_interface_mac(qp.interface, p_eth_hdr->ethr_shost);
                        send_to_link(qp.len, qp.packet, qp.interface);
                        delete[] qp.packet;
                    } else {
                        aux_queue.push(qp);
                    }
                }
                packet_queue = aux_queue;
            }
        }
    }

    delete[] r_table;
    delete trie;
    return 0;
}
