#include <stdlib.h>
#include "config.h"
#include "condition.h"

static void free_cond_list(apermon_cond_list *cl) {
    apermon_cond_func_list *f = NULL, *prev_f = NULL;
    f = cl->funcs, prev_f = NULL;

    while (f != NULL) {
        if (prev_f != NULL) {
            free(prev_f);
        }

        if (f->arg != NULL) {
            if (f->func == cond_list) {
                free_cond_list(f->arg);
            } else {
                free(f->arg);
            }
        }
        
        prev_f = f;
        f = f->next;
    }

    if (prev_f != NULL) {
        free(prev_f);
    }

    free(cl);
}

void free_config(apermon_config *config) {
    apermon_config_listens *l = config->listens, *prev_l = NULL;
    apermon_config_agents *a = config->agents, *prev_a = NULL;
    apermon_config_agent_addresses *addr = NULL, *prev_addr = NULL;
    apermon_config_interfaces *i = config->interfaces, *prev_i = NULL; 
    apermon_config_ifindexes *ifindex = NULL, *prev_ifindex = NULL;
    apermon_config_prefix_lists *pl = config->prefix_lists, *prev_pl = NULL;
    apermon_config_prefix_list_elements *pe = NULL, *prev_pe = NULL;
    apermon_config_actions *ac = config->actions, *prev_ac = NULL;
    apermon_config_action_scripts *as = NULL, *prev_as = NULL;
    apermon_config_triggers *t = config->triggers, *prev_t = NULL;
    apermon_config_prefix_lists_set *ps = NULL, *prev_ps = NULL;

    if (config->status_file) {
        free(config->status_file);
    }
    
    while (l != NULL) {
        if (prev_l != NULL) {
            free(prev_l);
        }

        if (l->addr != NULL) {
            freeaddrinfo(l->addr);
        }

        prev_l = l;
        l = l->next;
    }

    if (prev_l != NULL) {
        free(prev_l);
    }

    while (a != NULL) {
        if (prev_a != NULL) {
            free(prev_a);
        }

        if (a->name != NULL) {
            free(a->name);
        }

        addr = a->addresses, prev_addr = NULL;

        while (addr != NULL) {
            if (prev_addr != NULL) {
                free(prev_addr);
            }

            prev_addr = addr;
            addr = addr->next;
        }

        if (prev_addr != NULL) {
            free(prev_addr);
        }

        prev_a = a;
        a = a->next;
    }

    if (prev_a != NULL) {
        free(prev_a);
    }

    while (i != NULL) {
        if (prev_i != NULL) {
            free(prev_i);
        }

        if (i->name != NULL) {
            free(i->name);
        }

        ifindex = i->ifindexes, prev_ifindex = NULL;
        while (ifindex != NULL) {
            if (prev_ifindex != NULL) {
                free(prev_ifindex);
            }

            prev_ifindex = ifindex;
            ifindex = ifindex->next;
        }

        if (prev_ifindex != NULL) {
            free(prev_ifindex);
        }

        prev_i = i;
        i = i->next;
    }

    if (prev_i != NULL) {
        free(prev_i);
    }

    while (pl != NULL) {
        if (prev_pl != NULL) {
            free(prev_pl);
        }

        if (pl->name != NULL) {
            free(pl->name);
        }

        pe = pl->elements, prev_pe = NULL;
        while (pe != NULL) {
            if (prev_pe != NULL) {
                free(prev_pe);
            }

            if (pe->prefix != NULL) {
                free_prefix(pe->prefix);
            }

            prev_pe = pe;
            pe = pe->next;
        }

        if (prev_pe != NULL) {
            free(prev_pe);
        }

        prev_pl = pl;
        pl = pl->next;
    }

    if (prev_pl != NULL) {
        free(prev_pl);
    }

    while (ac != NULL) {
        if (prev_ac != NULL) {
            free(prev_ac);
        }

        if (ac->name != NULL) {
            free(ac->name);
        }
        
        as = ac->scripts, prev_as = NULL;
        while (as != NULL) {
            if (prev_as != NULL) {
                free(prev_as);
            }

            if (as->name != NULL) {
                free(as->name);
            }
            
            prev_as = as;
            as = as->next;
        }
        
        if (prev_as != NULL) {
            free(prev_as);
        }
        
        prev_ac = ac;
        ac = ac->next;
    }

    if (prev_ac != NULL) {
        free(prev_ac);
    }

    while (t != NULL) {
        if (prev_t != NULL) {
            free(prev_t);
        }

        if (t->name != NULL) {
            free(t->name);
        }

        if (t->ctx != NULL) {
            free_context(t->ctx);
        }

        if (t->conds != NULL) {
            free_cond_list(t->conds);
        }

        if (t->networks != NULL) {
            ps = t->networks, prev_ps = NULL;

            while (ps != NULL) {
                if (prev_ps != NULL) {
                    free(prev_ps);
                }

                prev_ps = ps;
                ps = ps->next;
            }

            if (prev_ps != NULL) {
                free(prev_ps);
            }
        }

        prev_t = t;
        t = t->next;
    }

    if (prev_t != NULL) {
        free(prev_t);
    }

    if (config->agents_hash != NULL) {
        free_hash(config->agents_hash, NULL);
    }

    free(config);
}