/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* sanity check */
  if(len<0 || len > 1514 ){
    printf("Invalid packet size.\n");
    return;
  }
    struct sr_if *inter = sr_get_interface(sr, interface);
  if (ethertype(packet)== ethertype_arp){
    printf("check arp packet.\n");
    if(len > sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t)){
        printf("Invalid arp request length.\n");
        return;
    }
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    if(ntohs(arp_hdr->ar_pro)!= ethertype_ip){
        printf("Invalid Protocol Address Type.\n");
        return;
    }

    if(inter == NULL){
        printf("Invalid interface.\n");
        return;
    }
    struct sr_if* if_walker;
    int counter = 0;
    if_walker = sr->if_list;
    while(if_walker){
        print_hdr_arp(packet);
        if(if_walker->ip==arp_hdr->ar_tip){
            counter = 1;
        }
         if_walker = if_walker->next;
    }
    sr_print_if_list(sr);
    if(counter ==1){
        if(ntohs(arp_hdr->ar_op)==arp_op_request){
                printf("Handle Arp request.\n");
                sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)(packet);
                memcpy(new_eth_hdr->ether_dhost,new_eth_hdr->ether_shost,ETHER_ADDR_LEN);
                memcpy(new_eth_hdr->ether_shost,inter->addr,ETHER_ADDR_LEN);
                new_eth_hdr->ether_type = ethertype_ip;
                memcpy(arp_hdr->ar_tha,arp_hdr->ar_sha,ETHER_ADDR_LEN);
                arp_hdr->ar_tip = arp_hdr->ar_sip;
                memcpy(arp_hdr->ar_sha,inter->addr,ETHER_ADDR_LEN);
                arp_hdr->ar_sip = inter->ip;
                arp_hdr->ar_op = htons(arp_op_reply);
                print_hdrs(packet,len);
                sr_send_packet(sr,packet,len,interface);
        }else if(ntohs(arp_hdr->ar_op)==arp_op_reply){
            printf("Handle Arp reply.\n");
            struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
            if(req != NULL){
                struct sr_packet *packet = NULL;
                for(packet = req->packets;packet;packet = packet->next){
                    printf("Sending out pending packets.\n");
                    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)(packet->buf);
                    memcpy(new_eth_hdr->ether_dhost,arp_hdr->ar_sha,ETHER_ADDR_LEN);
                    print_hdrs(packet->buf,len);
                    sr_send_packet(sr, packet->buf, packet->len, packet->iface);
                }
                sr_arpreq_destroy(&(sr->cache),req);
            }
        }
        }else{
            handle_routing(sr,packet,len,interface);
        }
  }
  else if (ethertype(packet) == ethertype_ip){
    printf("check ip packet.\n");
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(packet);
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    if(len < sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)){
        printf("Invalid IP header length.");
        return;
    }
    if(ip_hdr->ip_v !=4){
        printf("Invalid Protocol Type.\n");
        return;
    }
    if(cksum(ip_hdr,ip_hdr->ip_hl*4)!=0){
        printf("Incorrect Checksum.\n");
        /*TO DO: test checksum*/
        return;
    }
    struct sr_if* if_walker = 0;
    int counter = 0;
    if_walker = sr->if_list;
    while(if_walker->next){
        if_walker = if_walker->next;
        if(if_walker->ip== ip_hdr->ip_dst){
            counter = 1;
        }
    }
    if(counter ==1){
        if (ntohs(ip_hdr->ip_p)==ip_protocol_icmp){
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
            if (ntohs(icmp_hdr->icmp_type)== 8 && ntohs(icmp_hdr->icmp_code)==0){
                printf("Icmp echo reply.\n");
                icmp_hdr->icmp_type=0;
                ip_hdr->ip_dst = ip_hdr->ip_src;
                ip_hdr->ip_src = inter->ip;
                memcpy(eth_hdr->ether_shost,inter->addr,ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_dhost,&ip_hdr->ip_src,ETHER_ADDR_LEN);
                print_hdrs(packet, len);
                sr_send_packet(sr, packet, len, interface);
            }
        }
        else if(ntohs(ip_hdr->ip_p)==0x0006 || ntohs(ip_hdr->ip_p)==0x0011){
                icmp_error(sr,packet,3,3);
        }
    }else{
        handle_routing(sr,packet,len,interface);
    }

  }
  return;
}/* end sr_ForwardPacket */

void icmp_error(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        uint8_t type,
        uint8_t code)
{
    unsigned int new_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t * new_packet = malloc(new_length);

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(new_packet);
    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));

    sr_icmp_t3_hdr_t *new_icmp_hdr = (sr_icmp_t3_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    new_icmp_hdr->next_mtu = 0;

    new_ip_hdr->ip_dst = ip_hdr->ip_src;
    new_ip_hdr->ip_tos = 0;
    new_ip_hdr->ip_id = 0;
    new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    new_ip_hdr->ip_off = htons(IP_DF);
    new_ip_hdr->ip_ttl = 64;
    new_ip_hdr->ip_p = ip_protocol_icmp;
    new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

    new_icmp_hdr->icmp_type = type;
    new_icmp_hdr->icmp_code = code;
    new_icmp_hdr->unused = 0;
    /*need to think about this*/
    memcpy(new_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);

    new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

    struct sr_rt *entry = find_routing_entry(sr,ip_hdr->ip_src);
    if(!entry){
        return;
    }

    struct sr_arpentry *arp_check = sr_arpcache_lookup(&sr->cache, entry->gw.s_addr);
    if(arp_check){
        printf("Cache found. Forwarding packet.\n");
        struct sr_if *out_ip = sr_get_interface(sr, entry->interface);
        eth_hdr->ether_type = ethertype_ip;
        memcpy(eth_hdr->ether_dhost,arp_check->mac,ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost,out_ip->addr,ETHER_ADDR_LEN);
        new_ip_hdr->ip_src = out_ip->ip;
        print_hdrs(new_packet,new_length);
        sr_send_packet(sr, new_packet, new_length,entry->interface);
        free(arp_check);
    }
    return;
}

void handle_routing(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    if(ip_hdr->ip_ttl==0){
        icmp_error(sr,packet,11,0);
    }

    struct sr_rt *entry = find_routing_entry(sr,ip_hdr->ip_dst);
    char *out_int = entry->interface;
    if(!entry){
       printf("No entry found in the routing table.\n");
       icmp_error(sr,packet,3,0);
    }
    ip_hdr->ip_ttl -= 1;
    ip_hdr->ip_sum=0;
    ip_hdr->ip_sum = cksum(ip_hdr,len);

    struct sr_arpentry *arp_check = sr_arpcache_lookup(&sr->cache, (uint32_t) entry->gw.s_addr);
    if(arp_check){
        printf("Cache found. Forwarding packet.\n");
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(packet);
        struct sr_if *out_ip = sr_get_interface(sr, out_int);
        memcpy(eth_hdr->ether_dhost,arp_check->mac,ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost,out_ip->addr,ETHER_ADDR_LEN);
        print_hdrs(packet,len);
        sr_send_packet(sr, packet, len, out_int);
        free(arp_check);
    }else{
        struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache,(uint32_t) entry->gw.s_addr, packet,len,out_int);
        handle_arpreq(sr, req);
    }
}

struct sr_rt *find_routing_entry(struct sr_instance* sr,uint32_t ip_dst){
    struct sr_rt *routing_entry = sr->routing_table;
    struct sr_rt *entry;
    struct in_addr *counter = NULL;
    while(routing_entry){
        if((routing_entry->mask.s_addr & ip_dst) == routing_entry->dest.s_addr){
            if(counter == NULL){
                counter->s_addr = routing_entry->mask.s_addr;
            }
            else if(routing_entry->mask.s_addr > counter->s_addr){
                counter->s_addr = routing_entry->mask.s_addr;
            }
            entry = routing_entry;
        }

        routing_entry = routing_entry->next;

    }
    return entry;
}
