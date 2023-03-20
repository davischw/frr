/* TODO: license, authors */
#ifndef PIM_ADDRESS_ALIAS_H
#define PIM_ADDRESS_ALIAS_H

#include "lib/address_alias.h"

struct  msdp_named_peer {
	char alias_name[ADDRESS_ALIAS_NAME_LONGEST];
	struct pim_instance *pim;
	struct in_addr local_address;
	struct pim_msdp_peer peer_data;
	
	SLIST_ENTRY(msdp_named_peer) entry;
};

SLIST_HEAD(msdp_named_peer_list, msdp_named_peer);

struct pim_msdp_peer *pim_msdp_named_peer_new(struct pim_instance *pim,
					      const struct in_addr *local_address,
					      const char *peer_name,
					      const char *mesh_group_name);

void pim_msdp_named_peer_free(struct pim_msdp_peer *msdp_peer);

struct pim_msdp_peer *pim_msdp_named_peer_lookup(const struct pim_instance *pim,
						 const char *name);

void pim_address_alias_init(void);

void pim_msdp_address_alias_exit(struct pim_instance *pim);

#endif /* PIM_ADDRESS_ALIAS */

