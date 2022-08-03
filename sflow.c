#include <stdlib.h>
#include <arpa/inet.h>
#include "sflow.h"
#include "log.h"

ssize_t parse_sflow(const uint8_t *packet, size_t packet_len, sflow_parsed **output) {
    const uint8_t *ptr = packet;

    sflow_parsed *parsed_pkt = (sflow_parsed *) malloc(sizeof(sflow_parsed));
    sflow_parsed_samples *last_sample = parsed_pkt->samples = NULL;

    uint32_t n_samples, i, ver, agent_af, sample_len;

    if (packet_len < sizeof(sflow_common_hdr)) {
        log_debug("packet too short (got size %zu)\n", packet_len);
        goto parse_err;
    }

    parsed_pkt->common_hdr = (const sflow_common_hdr *) ptr;

    ver = ntohl(parsed_pkt->common_hdr->ver);
    agent_af = ntohl(parsed_pkt->common_hdr->agent_af);

    if (ver != 5) {
        log_warn("unsupported sflow version %lu\n", ver);
        goto parse_err;
    }

    if (agent_af == SFLOW_AF_INET) {
        if (packet_len < sizeof(sflow_inet_hdr)) {
            log_warn("bad sflow header length for inet af - want at least %zu, got %zu\n", sizeof(sflow_inet_hdr), packet_len);
            goto parse_err;
        }

        n_samples = ntohl(parsed_pkt->inet_hdr->n_samples);
        ptr += sizeof(sflow_inet_hdr);
    } else if (agent_af == SFLOW_AF_INET6) {
        if (packet_len < sizeof(sflow_inet6_hdr)) {
            log_warn("bad sflow header length for inet af - want at least %zu, got %zu\n", sizeof(sflow_inet6_hdr), packet_len);
            goto parse_err;
        }

        n_samples = ntohl(parsed_pkt->inet6_hdr->n_samples);
        ptr += sizeof(sflow_inet6_hdr);
    } else {
        log_warn("unsupported sflow agent af %lu\n", parsed_pkt->common_hdr->agent_af);
        goto parse_err;
    }

    for (i = 0; i < n_samples; ++i) {
        sflow_parsed_samples *parsed_sample = (sflow_parsed_samples *) malloc(sizeof(sflow_parsed_samples));

        if (last_sample == NULL) {
            last_sample = parsed_pkt->samples = parsed_sample;
        } else {
            last_sample->next = parsed_sample;
            last_sample = parsed_sample;
        }

        if ((packet_len - (ptr - packet)) < sizeof(sflow_sample)) {
            log_warn(
                "unexpected end of packet when parsing sample %lu; expecting %lu samples, "
                "and min record size should be %zu, but only %zu bytes left in packet.", 
                i, n_samples, sizeof(sflow_sample), packet_len - (ptr - packet)
            );
            goto parse_err;
        }

        parsed_sample->sample = (const sflow_sample *) ptr;

        sample_len = ntohl(parsed_sample->sample->len);

        if ((packet_len - (ptr - packet)) < sample_len) {
            log_warn(
                "unexpected end of packet when parsing sample %lu; expecting %lu samples, "
                "the record has size %lu, but only %zu bytes left in packet.", 
                i, n_samples, parsed_sample->sample->len, packet_len - (ptr - packet)
            );
            goto parse_err;
        }

        ptr += sample_len;
    }

    *output = parsed_pkt;
    return packet_len - (ptr - packet);

parse_err:
    free_sflow(parsed_pkt);
    return -1;
}

void free_sflow(sflow_parsed *parsed_pkt) {
    sflow_parsed_samples *sample = parsed_pkt->samples, *last = NULL;
    while (sample != NULL) {
        if (last != NULL) {
            free(last);
        }
        last = sample;
        sample = sample->next;
    }
}