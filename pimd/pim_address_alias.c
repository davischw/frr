/* TODO: license and authors */
#include <zebra.h>

#include "lib/queue.h"
#include "lib/address_alias.h"
#include "lib/memory.h"
#include "lib/prefix.h"
#include "lib/vrf.h"

#include "pimd/pimd.h"
#include "pimd/pim_address_alias.h"
#include "pimd/pim_msdp_packet.h"
#include "pimd/pim_instance.h"
#include "pimd/pim_str.h"
#include "pimd/pim_msdp.h"

DEFINE_MTYPE_STATIC(PIMD, PIM_MSDP_NAMED_PEER, "MSDP named peer context");











void pim_address_alias_init(void)
{
	hook_register(address_alias_changed, pim_changed_address);
}

void pim_msdp_address_alias(struct pim_instance *pim)
{
	struct msdp_named_peer *peer = NULL;

	while (!SLIST_EMPTY(&pim->msdp_named_peer_list)) {
		peer = SLIST_FIRST(&pim->msdp_named_peer_list);
		pim_msdp_naed_peer_free(&peer->peer_data);
	}
}
