#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdlib.h>
#include <string.h>
#include "extract.h"
#include "log.h"

enum ethertypes {
    APERMON_ETHER_INET = 0x0800,
    APERMON_ETHER_INET6 = 0x86dd,
    APERMON_ETHER_VLAN = 0x8100,
};

enum l3proto {
    APERNET_L3_TCP = 6,
    APERNET_L3_UDP = 17,
};

static inline int parse_inet(const uint8_t *buffer, size_t sz, apermon_flow_record **to) {
    const uint8_t *ptr = buffer;
    if (sz < sizeof(struct iphdr)) {
        log_warn("sampled or orig frame too short.\n");
        return 0;
    }

    const struct iphdr *hdr = (const struct iphdr *) ptr;

    ptr += sizeof(const struct iphdr);

    apermon_flow_record *parsed = (apermon_flow_record *) malloc(sizeof(apermon_flow_record));

    parsed->flow_af = SFLOW_AF_INET;
    parsed->mf_bit = ntohs(hdr->frag_off) & 0x2000;
    parsed->frag_off = ntohs(hdr->frag_off) & 0x1fff;
    parsed->l3_proto = hdr->protocol;
    parsed->dst_inet = hdr->daddr;
    parsed->src_inet = hdr->saddr;

    // try parse port - valid only if first 32 bits are src/dst port (e.g., tcp/udp)
    if ((ptr - buffer) + 2 * sizeof(uint16_t) <= sz) {
        parsed->src_port = ntohs(* (const uint16_t *) ptr);
        ptr += sizeof(uint16_t);
        parsed->dst_port = ntohs(* (const uint16_t *) ptr);
    }

    *to = parsed;
    return 1;
}

static inline int parse_inet6(const uint8_t *buffer, size_t sz, apermon_flow_record **to) {
    const uint8_t *ptr = buffer;
    if (sz < sizeof(struct ip6_hdr)) {
        log_warn("sampled or orig frame too short.\n");
        return 0;
    }

    const struct ip6_hdr *hdr = (const struct ip6_hdr *) ptr;

    ptr += sizeof(const struct ip6_hdr);

    apermon_flow_record *parsed = (apermon_flow_record *) malloc(sizeof(apermon_flow_record));

    parsed->flow_af = SFLOW_AF_INET6;
    parsed->l3_proto = hdr->ip6_nxt;

    memcpy(parsed->dst_inet6, &hdr->ip6_dst, sizeof(parsed->dst_inet6));
    memcpy(parsed->src_inet6, &hdr->ip6_src, sizeof(parsed->dst_inet6));

    // try parse port - valid only if first 32 bits are src/dst port (e.g., tcp/udp)
    if ((ptr - buffer) + 2 * sizeof(uint16_t) <= sz) {
        parsed->src_port = ntohs(* (const uint16_t *) ptr);
        ptr += sizeof(uint16_t);
        parsed->dst_port = ntohs(* (const uint16_t *) ptr);
    }

    *to = parsed;
    return 1;
}

static inline int parse_hdr(const sflow_sample_element_hdr *from, apermon_flow_record **to) {
    uint32_t len = ntohl(from->len);
    const uint8_t *buffer = from->hdr_bytes;
    uint16_t ethertype;

    // len 18 assumes vlan tag - but even w/o vlan tag, pkt smaller then 18 will not provide l3 header anyway so it's
    // useless and safe to skip.
    if (ntohl(from->orig_frame_len) < 14 + 20 || len < 18) {
        log_warn("sampled or orig frame too short.\n");
        return 0;
    }
    
    // skip src/dst ether
    buffer += 12;
    ethertype = ntohs(* (const uint16_t *) buffer);
    buffer += sizeof(uint16_t);

    // skip vlan if exist
    if (ethertype == APERMON_ETHER_VLAN) {
        buffer += sizeof(uint16_t);
        ethertype = ntohs(* (const uint16_t *) buffer);
        buffer += sizeof(uint16_t);
    }

    if (ethertype == APERMON_ETHER_INET) {
        return parse_inet(buffer, len - (buffer - from->hdr_bytes), to);
    }

    if (ethertype == APERMON_ETHER_INET6) {
        return parse_inet6(buffer, len - (buffer - from->hdr_bytes), to);
    }

    return 0;
}

int extract_flows(const sflow_parsed *parsed, apermon_flows **flows) {
    apermon_flows *extracted = (apermon_flows *) malloc(sizeof(apermon_flows));
    apermon_flow_record *last_record = extracted->records = NULL, *record;

    int ret;

    extracted->agent_af = ntohl(parsed->common_hdr->agent_af);

    if (extracted->agent_af == SFLOW_AF_INET) {
        extracted->agent_inet = parsed->inet_hdr->agent_inet;
        extracted->sub_agent_id = ntohl(parsed->inet_hdr->sub_agent_id);
        extracted->seq = ntohl(parsed->inet_hdr->seq);
        extracted->uptime = ntohl(parsed->inet_hdr->uptime);
    } else if (extracted->agent_af == SFLOW_AF_INET6) {
        memcpy(extracted->agent_inet6, parsed->inet6_hdr->agent_inet6, sizeof(extracted->agent_inet6));
        extracted->sub_agent_id = ntohl(parsed->inet6_hdr->sub_agent_id);
        extracted->seq = ntohl(parsed->inet6_hdr->seq);
        extracted->uptime = ntohl(parsed->inet6_hdr->uptime);
    } else {
        log_error("invalid agent af: %u\n", extracted->agent_af);
        goto extract_err;
    }

    const sflow_parsed_samples *sample = parsed->samples;
    while (sample != NULL) {
        const sflow_parsed_elements *element = sample->elements;
        while (element != NULL) {
            if (ntohl(element->common_element_hdr->format) == SFLOW_SAMPLE_FORMAT_RAW && ntohl(element->hdr_element->proto) == SFLOW_PROTO_ETHER) {
                ret = parse_hdr(element->hdr_element, &record);
                
                if (ret < 0) {
                    goto extract_err;
                }

                if (ret > 0) {
                    record->frame_length = ntohl(element->hdr_element->orig_frame_len);
                    record->in_ifindex = ntohl(sample->sample->in_ifindex);
                    record->out_ifindex = ntohl(sample->sample->out_ifindex);
                    record->pool = ntohl(sample->sample->pool);
                    record->rate = ntohl(sample->sample->rate);
                    record->seq = ntohl(sample->sample->seq);
                    record->next = NULL;

                    if (last_record == NULL) {
                        last_record = extracted->records = record;
                    } else {
                        last_record->next = record;
                        last_record = record;
                    }
                }
            } else {
                // type not supported - skip for now
            }

            element = element->next;
        }

        sample = sample->next;
    }

    *flows = extracted;
    return 0;

extract_err:
    free_apermon_flows(extracted);
    return -1;
}

void free_apermon_flows(apermon_flows *flows) {
    if (flows == NULL) {
        return;
    }

    apermon_flow_record *record = flows->records, *last_record = NULL;
    while (record != NULL) {
        if (last_record != NULL) {
            free(last_record);
        }

        last_record = record;
        record = record->next;
    }

    if (last_record != NULL) {
        free(last_record);
    }

    free(flows);
}