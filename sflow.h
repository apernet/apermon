#ifndef APERMON_SFLOW_H
#define APERMON_SFLOW_H
#include <stdint.h>
#include <unistd.h>
#include "config.h"

/* infomation types */
typedef uint32_t net_uint32_t;
typedef uint16_t net_uint16_t;

/* sflow protocol structs */

enum sflow_sample_proto {
    SFLOW_PROTO_ETHER = 1,
};

typedef struct _sflow_sample_element_common {
    net_uint32_t format;
    net_uint32_t len;
} sflow_sample_element_common;

typedef struct _sflow_sample_element_hdr {
    net_uint32_t format;
    net_uint32_t len;
    net_uint32_t proto; /* enum sflow_sample_proto */
    net_uint32_t orig_frame_len;
    net_uint32_t stripped;
    net_uint32_t hdr_len;
    uint8_t hdr_bytes[];
} sflow_sample_element_hdr;

enum sflow_sampletype {
    SFLOW_SAMPLETYPE_HDR = 1,
};

typedef struct _sflow_sample {
    net_uint32_t tag; /* enum sflow_sampletype */
    net_uint32_t len;
    net_uint32_t seq;
    net_uint32_t source_id;
    net_uint32_t rate;
    net_uint32_t pool;
    net_uint32_t drops;
    net_uint32_t in_ifindex;
    net_uint32_t out_ifindex;
    net_uint32_t n_elements;
} sflow_sample;

enum sflow_af {
    SFLOW_AF_UNDEFINED = 0,
    SFLOW_AF_INET = 1,
    SFLOW_AF_INET6 = 2,
};

typedef struct _sflow_common_hdr {
    net_uint32_t ver;
    net_uint32_t agent_af; /* enum sflow_af */
} sflow_common_hdr;

typedef struct _sflow_inet_hdr {
    net_uint32_t ver;
    net_uint32_t agent_af; /* enum sflow_af */
    uint32_t agent_inet;
    net_uint32_t sub_agent_id;
    net_uint32_t seq;
    net_uint32_t uptime;
    net_uint32_t n_samples;
} sflow_inet_hdr;

typedef struct _sflow_inet6_hdr {
    net_uint32_t ver;
    net_uint32_t agent_af; /* enum sflow_af */
    uint8_t agent_inet6[16];
    net_uint32_t sub_agent_id;
    net_uint32_t seq;
    net_uint32_t uptime;
    net_uint32_t n_samples;
} sflow_inet6_hdr;

/* sflow protocol structs, parsed */

typedef struct _sflow_parsed_elements {
    union {
        const sflow_sample_element_common *common_element_hdr;
        const sflow_sample_element_hdr *hdr_element;
    };
    struct _sflow_parsed_elements *next;
} sflow_parsed_elements;

typedef struct _sflow_parsed_samples {
    const sflow_sample *sample;
    sflow_parsed_elements *elements;
    struct _sflow_parsed_samples *next;
} sflow_parsed_samples;

typedef struct _sflow_parsed {
    union {
        const sflow_common_hdr *common_hdr;
        const sflow_inet_hdr *inet_hdr;
        const sflow_inet6_hdr *inet6_hdr;
    };
    sflow_parsed_samples *samples;
} sflow_parsed;

/* functions */
ssize_t parse_sflow(const uint8_t *packet, size_t packet_len, sflow_parsed **output);
void free_sflow(sflow_parsed *parsed_pkt);

void sflow_use_config(const apermon_config *config);
ssize_t handle_sflow_packet(const uint8_t *packet, size_t packet_len);

#endif // APERMON_SFLOW_H