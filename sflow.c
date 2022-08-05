#include <stdlib.h>
#include <arpa/inet.h>
#include "sflow.h"
#include "log.h"
#include "extract.h"
#include "trigger.h"

static const apermon_config *_config;

ssize_t parse_sflow(const uint8_t *packet, size_t packet_len, sflow_parsed **output) {
    const uint8_t *ptr = packet;

    sflow_parsed *parsed_pkt = (sflow_parsed *) malloc(sizeof(sflow_parsed));
    sflow_parsed_samples *last_sample = parsed_pkt->samples = NULL;

    uint32_t n_samples, n_elements, i, j, offset, ver, agent_af, sample_len, element_len;

    if (packet_len < sizeof(sflow_common_hdr)) {
        log_debug("packet too short (got size %zu)\n", packet_len);
        goto parse_err;
    }

    parsed_pkt->common_hdr = (const sflow_common_hdr *) ptr;

    ver = ntohl(parsed_pkt->common_hdr->ver);
    agent_af = ntohl(parsed_pkt->common_hdr->agent_af);

    if (ver != 5) {
        log_warn("unsupported sflow version %u\n", ver);
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
        log_warn("unsupported sflow agent af %u\n", parsed_pkt->common_hdr->agent_af);
        goto parse_err;
    }

    // parse sample
    for (i = 0; i < n_samples; ++i) {
        sflow_parsed_samples *parsed_sample = (sflow_parsed_samples *) malloc(sizeof(sflow_parsed_samples));
        sflow_parsed_elements *last_element = parsed_sample->elements = NULL;
        parsed_sample->next = NULL;

        if (last_sample == NULL) {
            last_sample = parsed_pkt->samples = parsed_sample;
        } else {
            last_sample->next = parsed_sample;
            last_sample = parsed_sample;
        }

        if ((packet_len - (ptr - packet)) < sizeof(sflow_sample)) {
            log_warn(
                "unexpected end of packet when parsing sample %u; expecting %u samples, "
                "and min record size should be %zu, but only %zu bytes left in packet.\n", 
                i, n_samples, sizeof(sflow_sample), packet_len - (ptr - packet)
            );
            goto parse_err;
        }

        parsed_sample->sample = (const sflow_sample *) ptr;

        sample_len = ntohl(parsed_sample->sample->len);
        n_elements = ntohl(parsed_sample->sample->n_elements);

        if ((packet_len - (ptr - packet)) < sample_len) {
            log_warn(
                "unexpected end of packet when parsing sample %u; expecting %u samples, "
                "the record has size %u, but only %zu bytes left in packet.\n", 
                i, n_samples, parsed_sample->sample->len, packet_len - (ptr - packet)
            );
            goto parse_err;
        }

        ptr += sizeof(sflow_sample);

        for (j = 0, offset = 0; j < n_elements; ++j) {
            sflow_parsed_elements *parsed_element = (sflow_parsed_elements *) malloc(sizeof(sflow_parsed_elements));
            parsed_element->next = NULL;

            if (last_element == NULL) {
                last_element = parsed_sample->elements = parsed_element;
            } else {
                last_element->next = parsed_element;
                last_element = parsed_element;
            }

            if (sample_len - j < sizeof(sflow_sample_element_common)) {
                log_warn(
                    "unexpected end of sample when parsing element %u in sample %u; expecting %u elements: "
                    "no space left for element at byte %u of sample (byte %zu of packet) - cannot fit element header. "
                    "want size %zu, but only %u bytes left.\n", 
                    j, i, n_elements, offset, (size_t) (ptr - packet), sizeof(sflow_sample_element_common), sample_len - offset
                );
                goto parse_err;
            }

            parsed_element->common_element_hdr = (const sflow_sample_element_common *) ptr;

            offset += sizeof(sflow_sample_element_common);
            ptr += sizeof(sflow_sample_element_common);

            element_len = ntohl(parsed_element->common_element_hdr->len);

            if (sample_len - j < element_len) {
                log_warn(
                    "unexpected end of sample when parsing element %u in sample %u; expecting %u samples: "
                    "no space left for element at byte %u of sample (byte %zu of packet) - element length is %u, "
                    "but only %u bytes left.\n", 
                    j, i, n_elements, offset, (size_t) (ptr - packet), element_len, sample_len - offset
                );
                goto parse_err;
            }

            ptr += element_len;
            offset += element_len;
        }
    }

    *output = parsed_pkt;
    return ptr - packet;

parse_err:
    free_sflow(parsed_pkt);
    return -1;
}

void free_sflow(sflow_parsed *parsed_pkt) {
    if (parsed_pkt == NULL) {
        return;
    }

    sflow_parsed_samples *sample = parsed_pkt->samples, *last_sample = NULL;
    while (sample != NULL) {
        if (last_sample != NULL) {
            free(last_sample);
        }

        sflow_parsed_elements *element = sample->elements, *last_element = NULL;
        while (element != NULL) {
            if (last_element != NULL) {
                free(last_element);
            }

            last_element = element;
            element = element->next;
        }

        free(last_element);

        last_sample = sample;
        sample = sample->next;
    }

    free(last_sample);
    free(parsed_pkt);
}

void sflow_use_config(const apermon_config *config) {
    _config = config;
}

ssize_t handle_sflow_packet(const uint8_t *packet, size_t packet_len) {
    sflow_parsed *parsed = NULL;
    apermon_flows *flows = NULL;
    ssize_t ret;

    apermon_config_triggers *trigger = _config->triggers;

    char agent_addr[INET6_ADDRSTRLEN + 1];

    ret = parse_sflow(packet, packet_len, &parsed);

    if (ret < 0) {
        return ret;
    }

    ret = extract_flows(parsed, &flows);

    if (ret < 0) {
        return ret;
    }

    if (flows->agent_af == SFLOW_AF_INET) {
        inet_ntop(AF_INET, &flows->agent_inet, agent_addr, sizeof(agent_addr));
    } else {
        inet_ntop(AF_INET6, flows->agent_inet6, agent_addr, sizeof(agent_addr));
    }
    
    log_debug("sflow packet from %s\n", agent_addr);

    while (trigger != NULL) {
        run_trigger(trigger, flows);
        trigger = trigger->next;
    }

    free_apermon_flows(flows);
    free_sflow(parsed);

    return ret;
}