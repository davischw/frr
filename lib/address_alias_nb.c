/* TODO: Do you have a loicense for this code? */

#include "lib/northbound.h"
#include "lib/address_alias.h"

DECLARE_MTYPE(ADDRESS_ALIAS);
DECLARE_MTYPE(ADDRESS_ALIAS_IP);

DEFINE_MTYPE_STATIC(LIB, ADDRESS_ALIAS, "Address alias");
DEFINE_MTYPE_STATIC(LIB, ADDRESS_ALIAS_IP, "Address alias IP address");

DEFINE_HOOK(address_alias_changed, (const struct address_alias *aa), (aa));
DEFINE_HOOK(address_alias_deleted, (const struct address_alias *aa), (aa));

TAILQ_HEAD(, address_alias) aa_list = TAILQ_HEAD_INITIALIZER(aa_list);

static struct address_alias *address_alias_new(const char *name)
{
	struct address_alias *aa = NULL;

	if (name) {
		aa = XCALLOC(MTYPE_ADDRESS_ALIAS, sizeof(struct address_alias));
		if (aa) {
			strlcpy(aa->aa_name, name, sizeof(aa->aa_name));
			TAILQ_INSERT_TAIL(&aa_list, aa, aa_entry);
		}
	}

	return aa;
}

static void address_alias_free(struct address_alias **aa)
{
	if ((*aa)) {
		TAILQ_REMOVE(&aa_list, (*aa), aa_entry);
		hook_call(address_alias_deleted, (*aa));
		XFREE(MTYPE_ADDRESS_ALIAS, (*aa));
	}
}

static void address_alias_address_new(struct address_alias *aa)
{
	struct ipaddr *aa_ip;

	if (aa) {
		aa_ip = XCALLOC(MTYPE_ADDRESS_ALLIAS_IP, sizeof(struct ipaddr));
		if (aa_ip) {
			(*aa)->aa_ip = aa_ip;
			hook_call(aadress_alias_changed, aa);
		}
	}
}

static void address_alias_address_free(struct address_alias *aa)
{
	if (aa) {
		if (aa->aa_ip) {
			XFREE(MTYPE_ADDRESS_ALIAS_IP, aa->aa_ip);
			hook_call(address_alias_changed, aa);
		}
	}
}

struct address_alias *address_alias_lookup(const char *name)
{
	struct address_alias *aa = NULL;

	if (name) {
		TAILQ_FOREACH (aa, &aa_list, aa_entry) {
			if (strcmp(aa->aa_name, name))
				continue;

			return aa;
		}

		aa = NULL;
	}

	return aa;
}

static int lib_address_alias_create(struct nb_cb_create_args *args)
{
	struct address_alias *aa = NULL;

	if (args) {
		if (args->event == NB_EV_APPLY) {
			aa = address_alias_new(yang_dnode_get_string(args->dnode,
								     "./name"));
			if (aa) {
				nb_running_set_entry(args->dnode, aa);
				hook_call(address_alias_changed, aa);
			}
		}
	}

	return NB_OK;
}

static int lib_address_alias_destroy(struct nb_cb_destroy_args *args)
{
	struct address_alias *aa = NULL;

	if (args) {
		if (args->event == NB_EV_APPLY) {
			aa = nb_running_get_entry(args->dnode, NULL, true);
			if (aa) {
				if (aa->aa_ip)
					address_alias_address_free(aa);

				address_alias_free(&aa);
			}
		}
	}

	return NB_OK;
}


static int lib_address_alias_address_modify(struct nb_cb_modify_args *args)
{
	struct address_alias *aa = NULL;

	if (args) {
		if (args->event == NB_EV_APPLY) {
			aa = nb_running_get_entry(args->dnode, NULL, true);
			if (aa) {
				/* TODO: Implemenet. */

				address_alias_address_new(&aa);
				/*
				yang_dnode_get_ip(&aa->aa_ip, args->dnode,
						  "./address");

				hook_call(address_alias_changed, aa);
				*/
			}
		}
	}

	return NB_OK;
}


static int lib_address_alias_address_destroy(struct nb_cb_destroy_args *args)
{
	struct address_alias *aa = NULL;

	if (args) {
		if (args->event == NB_EV_APPLY) {
			aa = nb_running_unset_entry(args->dnode);
			if (aa) {
				/* TODO: Implement */

				address_alias_address_free(&aa);
			}
		}
	}

	return NB_OK;
}


const struct frr_yang_module_info frr_address_alias_info = {
	.name = "frr-address-alias",
	.nodes = {
		{
			.xpath = "/frr-address-alias:lib/address-alias",
			.cbs = {
				.create = lib_address_alias_create,
				.destroy = lib_address_alias_destroy,
				.cli_show = address_alias_show,
			}
		},
		{
			.xpath = "/frr-address-alias:lib/address-alias/address",
			.cbs = {
				.modify = lib_address_alias_address_modify,
				.destroy = lib_address_alias_address_destroy,
				.cli_show = address_alias_address_show,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
