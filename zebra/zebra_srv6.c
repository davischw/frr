// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra SRv6 definitions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
 * Copyright (C) 2020  Masakazu Asama
 */

#include <zebra.h>

#include "network.h"
#include "prefix.h"
#include "stream.h"
#include "srv6.h"
#include "zebra/debug.h"
#include "zebra/zapi_msg.h"
#include "zebra/zserv.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_srv6.h"
#include "zebra/zebra_errors.h"
#include "zebra/ge_netlink.h"
#include "zebra/interface.h"
#include "typesafe.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>


DEFINE_MGROUP(SRV6_MGR, "SRv6 Manager");
DEFINE_MTYPE_STATIC(SRV6_MGR, SRV6M_CHUNK, "SRv6 Manager Chunk");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID_BLOCK, "SRv6 SID block");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID_FUNC, "SRv6 SID function");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_USID_WLIB,
		    "SRv6 uSID Wide LIB information");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID, "SRv6 SID");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID_CTX, "SRv6 SID context");
DEFINE_MTYPE_STATIC(SRV6_MGR, ZEBRA_SRV6_SID_ENTRY_INFO, "SRv6 SID entry information");

static struct zebra_srv6 g_srv6;

/* Prototypes */
static void release_srv6_sid_func(const struct zebra_srv6_sid_ctx *zctx);

static bool zebra_srv6_sid_compose(struct in6_addr *sid_value, struct srv6_locator *locator,
				   uint32_t sid_func, uint32_t sid_func_wide, bool is_localonly);

/* define hooks for the basic API, so that it can be specialized or served
 * externally
 */

DEFINE_HOOK(srv6_manager_client_connect,
	    (struct zserv *client, vrf_id_t vrf_id),
	    (client, vrf_id));
DEFINE_HOOK(srv6_manager_client_disconnect,
	    (struct zserv *client), (client));
DEFINE_HOOK(srv6_manager_get_chunk,
	    (struct srv6_locator **loc,
	     struct zserv *client,
	     const char *locator_name,
	     vrf_id_t vrf_id),
	    (loc, client, locator_name, vrf_id));
DEFINE_HOOK(srv6_manager_release_chunk,
	    (struct zserv *client,
	     const char *locator_name,
	     vrf_id_t vrf_id),
	    (client, locator_name, vrf_id));

DEFINE_HOOK(srv6_manager_get_sid,
	    (struct zebra_srv6_sid **sid, struct zserv *client, struct srv6_sid_ctx *ctx,
	     struct in6_addr *sid_value, const char *locator_name, bool is_localonly),
	    (sid, client, ctx, sid_value, locator_name, is_localonly));
DEFINE_HOOK(srv6_manager_release_sid,
	    (struct zserv *client, struct srv6_sid_ctx *ctx, const char *locator_name,
	     bool is_localonly),
	    (client, ctx, locator_name, is_localonly));
DEFINE_HOOK(srv6_manager_get_locator,
	    (struct srv6_locator **locator, struct zserv *client,
	     const char *locator_name),
	    (locator, client, locator_name));

/* define wrappers to be called in zapi_msg.c (as hooks must be called in
 * source file where they were defined)
 */

void srv6_manager_client_connect_call(struct zserv *client, vrf_id_t vrf_id)
{
	hook_call(srv6_manager_client_connect, client, vrf_id);
}

void srv6_manager_get_locator_chunk_call(struct srv6_locator **loc,
					 struct zserv *client,
					 const char *locator_name,
					 vrf_id_t vrf_id)
{
	hook_call(srv6_manager_get_chunk, loc, client, locator_name, vrf_id);
}

void srv6_manager_release_locator_chunk_call(struct zserv *client,
					     const char *locator_name,
					     vrf_id_t vrf_id)
{
	hook_call(srv6_manager_release_chunk, client, locator_name, vrf_id);
}

int srv6_manager_client_disconnect_cb(struct zserv *client)
{
	hook_call(srv6_manager_client_disconnect, client);
	return 0;
}


void srv6_manager_get_sid_call(struct zebra_srv6_sid **sid, struct zserv *client,
			       struct srv6_sid_ctx *ctx, struct in6_addr *sid_value,
			       const char *locator_name, bool is_localonly)
{
	hook_call(srv6_manager_get_sid, sid, client, ctx, sid_value, locator_name, is_localonly);
}

void srv6_manager_release_sid_call(struct zserv *client, struct srv6_sid_ctx *ctx,
				   const char *locator_name, bool is_localonly)
{
	hook_call(srv6_manager_release_sid, client, ctx, locator_name, is_localonly);
}

void srv6_manager_get_locator_call(struct srv6_locator **locator,
				   struct zserv *client,
				   const char *locator_name)
{
	hook_call(srv6_manager_get_locator, locator, client, locator_name);
}

static int zebra_srv6_cleanup(struct zserv *client)
{
	/* Client has disconnected, let's release all the SIDs allocated by it. */
	release_daemon_srv6_sids(client);
	return 0;
}

/* --- Zebra SRv6 SID context management functions -------------------------- */

struct zebra_srv6_sid_ctx *zebra_srv6_sid_ctx_alloc(void)
{
	struct zebra_srv6_sid_ctx *ctx = NULL;

	ctx = XCALLOC(MTYPE_ZEBRA_SRV6_SID_CTX,
		      sizeof(struct zebra_srv6_sid_ctx));

	return ctx;
}

void zebra_srv6_sid_ctx_free(struct zebra_srv6_sid_ctx *ctx)
{
	XFREE(MTYPE_ZEBRA_SRV6_SID_CTX, ctx);
}

/**
 * Free an SRv6 SID context.
 *
 * @param val SRv6 SID context to be freed
 */
void delete_zebra_srv6_sid_ctx(void *val)
{
	zebra_srv6_sid_ctx_free((struct zebra_srv6_sid_ctx *)val);
}

struct zebra_srv6_sid_ctx *zebra_srv6_sid_ctx_lookup(const struct srv6_sid_ctx *ctx,
						     struct zebra_srv6_sid_block *block)
{
	struct zebra_srv6_sid_ctx *zctx;

	frr_each (zebra_srv6_sid_ctx_list, &block->sids, zctx)
		if (memcmp(&zctx->ctx, ctx, sizeof(struct srv6_sid_ctx)) == 0)
			return zctx;

	return NULL;
}

/* --- Zebra SRv6 SID format management functions --------------------------- */

void srv6_sid_format_register(struct srv6_sid_format *format)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	/* Ensure that the format is registered only once */
	assert(!srv6_sid_format_lookup(format->name));

	listnode_add(srv6->sid_formats, format);
}

void srv6_sid_format_unregister(struct srv6_sid_format *format)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	listnode_delete(srv6->sid_formats, format);
}

struct srv6_sid_format *srv6_sid_format_lookup(const char *name)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_sid_format *format;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6->sid_formats, node, format))
		if (!strncmp(name, format->name, sizeof(format->name)))
			return format;

	return NULL;
}

static void zebra_srv6_sid_entry_del_by_locator(struct zebra_srv6_sid *sid,
						struct srv6_locator *locator)
{
	struct zebra_srv6_sid_entry *entry;
	struct zebra_srv6_sid_block *block;

	if (!locator->sid_block)
		return;

	block = locator->sid_block;

	frr_each_safe (zebra_srv6_sid_entry_list, &sid->entries, entry)
		if (entry->locator == locator) {
			zebra_srv6_sid_entry_list_del(&sid->entries, entry);
			zebra_srv6_sid_entry_free(entry);
		}

	if (zebra_srv6_sid_entry_list_count(&sid->entries) == 0) {
		zebra_srv6_sid_ctx_list_del(&block->sids, sid->ctx);
		zebra_srv6_sid_ctx_free(sid->ctx);

		zebra_srv6_sid_free(sid);
	}
}

void zebra_srv6_sid_entry_del_by_locator_all_sids(struct srv6_locator *locator)
{
	struct zebra_srv6_sid_ctx *ctx;
	struct zebra_srv6_sid_block *block;

	if (!locator->sid_block)
		return;

	block = locator->sid_block;

	frr_each_safe (zebra_srv6_sid_ctx_list, &block->sids, ctx)
		zebra_srv6_sid_entry_del_by_locator(ctx->sid, locator);
}

/*
 * Called to change the SID format of a locator.
 *
 * After switching the locator to a different format, the SIDs allocated
 * from the locator may no longer be valid; we need to notify the
 * interested zclient that the locator has changed, so that the
 * zclients can withdraw/uninstall the old SIDs, allocate/advertise/program
 * the new SIDs.
 */
void zebra_srv6_locator_format_set(struct srv6_locator *locator,
				   struct srv6_sid_format *format)
{
	if (!locator)
		return;

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: Locator %s format has changed, old=%s new=%s",
			   __func__, locator->name,
			   locator->sid_format ? ((struct srv6_sid_format *)
							  locator->sid_format)
							 ->name
					       : NULL,
			   format ? format->name : NULL);

	/* Notify zclients that the locator is no longer valid */
	zebra_notify_srv6_locator_delete(locator);

	zebra_srv6_sid_entry_del_by_locator_all_sids(locator);

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: Locator %s format has changed, send SRV6_LOCATOR_DEL notification to zclients",
			   __func__, locator->name);

	/* Release the current parent block */
	zebra_srv6_sid_locator_block_release(locator);

	/* Change format */
	locator->sid_format = format;

	/* Allocate the new parent block */
	zebra_srv6_sid_locator_block_alloc(locator);

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: Locator %s format has changed, send SRV6_LOCATOR_ADD notification to zclients",
			   __func__, locator->name);

	/* Notify zclients about the updated locator */
	zebra_srv6_locator_add(locator);
}

/*
 * Called when a SID format is modified by the user.
 *
 * After modifying a SID format, the SIDs that are using that format may no
 * longer be valid.
 * This function walks through the list of locators that are using the SID format
 * and notifies the zclients that the locator has changed, so that the zclients
 * can withdraw/uninstall the old SIDs, allocate/program/advertise the new SIDs.
 */
void zebra_srv6_sid_format_changed_cb(struct srv6_sid_format *format)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *locator;
	struct listnode *node;

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: SID format %s has changed. Notifying zclients.",
			   __func__, format->name);

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator)) {
		if (locator->sid_format == format) {
			if (IS_ZEBRA_DEBUG_SRV6)
				zlog_debug("%s: Locator %s has changed because its format (%s) has been modified. Notifying zclients.",
					   __func__, locator->name,
					   format->name);

			/* Notify zclients that the locator is no longer valid */
			zebra_notify_srv6_locator_delete(locator);

			zebra_srv6_sid_entry_del_by_locator_all_sids(locator);

			/* Notify zclients about the updated locator */
			zebra_notify_srv6_locator_add(locator);
		}
	}
}

/*
 * Helper function to create the SRv6 compressed format `usid-f3216`.
 */
static struct srv6_sid_format *create_srv6_sid_format_usid_f3216(void)
{
	struct srv6_sid_format *format = NULL;

	format = srv6_sid_format_alloc(SRV6_SID_FORMAT_USID_F3216_NAME);

	format->type = SRV6_SID_FORMAT_TYPE_USID;

	/* Define block/node/function length */
	format->block_len = SRV6_SID_FORMAT_USID_F3216_BLOCK_LEN;
	format->node_len = SRV6_SID_FORMAT_USID_F3216_NODE_LEN;
	format->function_len = SRV6_SID_FORMAT_USID_F3216_FUNCTION_LEN;
	format->argument_len = SRV6_SID_FORMAT_USID_F3216_ARGUMENT_LEN;

	/* Define the ranges from which the SID function can be allocated */
	format->config.usid.lib_start = SRV6_SID_FORMAT_USID_F3216_LIB_START;
	format->config.usid.elib_start = SRV6_SID_FORMAT_USID_F3216_ELIB_START;
	format->config.usid.elib_end = SRV6_SID_FORMAT_USID_F3216_ELIB_END;
	format->config.usid.wlib_start = SRV6_SID_FORMAT_USID_F3216_WLIB_START;
	format->config.usid.wlib_end = SRV6_SID_FORMAT_USID_F3216_WLIB_END;
	format->config.usid.ewlib_start = SRV6_SID_FORMAT_USID_F3216_EWLIB_START;

	return format;
}

/*
 * Helper function to create the SRv6 compressed format `usid-f4816`.
 */
static struct srv6_sid_format *create_srv6_sid_format_usid_f4816(void)
{
	struct srv6_sid_format *format = NULL;

	format = srv6_sid_format_alloc(SRV6_SID_FORMAT_USID_F4816_NAME);

	format->type = SRV6_SID_FORMAT_TYPE_USID;

	/* Define block/node/function length */
	format->block_len = SRV6_SID_FORMAT_USID_F4816_BLOCK_LEN;
	format->node_len = SRV6_SID_FORMAT_USID_F4816_NODE_LEN;
	format->function_len = SRV6_SID_FORMAT_USID_F4816_FUNCTION_LEN;
	format->argument_len = SRV6_SID_FORMAT_USID_F4816_ARGUMENT_LEN;

	/* Define the ranges from which the SID function can be allocated */
	format->config.usid.lib_start = SRV6_SID_FORMAT_USID_F4816_LIB_START;
	format->config.usid.elib_start = SRV6_SID_FORMAT_USID_F4816_ELIB_START;
	format->config.usid.elib_end = SRV6_SID_FORMAT_USID_F4816_ELIB_END;
	format->config.usid.wlib_start = SRV6_SID_FORMAT_USID_F4816_WLIB_START;
	format->config.usid.wlib_end = SRV6_SID_FORMAT_USID_F4816_WLIB_END;
	format->config.usid.ewlib_start = SRV6_SID_FORMAT_USID_F4816_EWLIB_START;

	return format;
}

/*
 * Helper function to create the SRv6 uncompressed format.
 */
static struct srv6_sid_format *create_srv6_sid_format_uncompressed(void)
{
	struct srv6_sid_format *format = NULL;

	format = srv6_sid_format_alloc(SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NAME);

	format->type = SRV6_SID_FORMAT_TYPE_UNCOMPRESSED;

	/* Define block/node/function length */
	format->block_len = SRV6_SID_FORMAT_UNCOMPRESSED_F4024_BLOCK_LEN;
	format->node_len = SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NODE_LEN;
	format->function_len = SRV6_SID_FORMAT_UNCOMPRESSED_F4024_FUNCTION_LEN;
	format->argument_len = SRV6_SID_FORMAT_UNCOMPRESSED_F4024_ARGUMENT_LEN;

	/* Define the ranges from which the SID function can be allocated */
	format->config.uncompressed.explicit_start =
		SRV6_SID_FORMAT_UNCOMPRESSED_F4024_EXPLICIT_RANGE_START;

	return format;
}

/* --- Zebra SRv6 SID function management functions ---------------------------- */

uint32_t *zebra_srv6_sid_func_alloc(uint32_t func)
{
	uint32_t *sid_func_ptr;

	sid_func_ptr = XCALLOC(MTYPE_ZEBRA_SRV6_SID_FUNC, sizeof(uint32_t));
	*sid_func_ptr = func;

	return sid_func_ptr;
}

void zebra_srv6_sid_func_free(uint32_t *func)
{
	XFREE(MTYPE_ZEBRA_SRV6_SID_FUNC, func);
}

/**
 * Free an SRv6 SID function.
 *
 * @param val SRv6 SID function to be freed
 */
void delete_zebra_srv6_sid_func(void *val)
{
	zebra_srv6_sid_func_free((uint32_t *)val);
}

/* --- Zebra SRv6 SID block management functions ---------------------------- */

static struct zebra_srv6_sid_block *zebra_srv6_sid_block_alloc_internal(void)
{
	struct zebra_srv6_sid_block *block = NULL;

	block = XCALLOC(MTYPE_ZEBRA_SRV6_SID_BLOCK,
			sizeof(struct zebra_srv6_sid_block));

	return block;
}

struct zebra_srv6_sid_block *
zebra_srv6_sid_block_alloc(struct srv6_sid_format *format,
			   struct prefix_ipv6 *prefix)
{
	struct zebra_srv6_sid_block *block;

	block = zebra_srv6_sid_block_alloc_internal();
	block->sid_format = format;
	block->prefix = *prefix;

	/* Init list to store SRv6 SIDs */
	zebra_srv6_sid_ctx_list_init(&block->sids);

	if (format) {
		if (format->type == SRV6_SID_FORMAT_TYPE_USID) {
			uint32_t wlib_start, wlib_end, func;

			/* Init uSID LIB */
			block->u.usid.lib.func_allocated = list_new();
			block->u.usid.lib.func_allocated->del =
				delete_zebra_srv6_sid_func;
			block->u.usid.lib.func_released = list_new();
			block->u.usid.lib.func_released->del =
				delete_zebra_srv6_sid_func;
			block->u.usid.lib.first_available_func =
				format->config.usid.lib_start;

			/* Init uSID Wide LIB */
			wlib_start = block->sid_format->config.usid.wlib_start;
			wlib_end = block->sid_format->config.usid.wlib_end;
			block->u.usid.wide_lib =
				XCALLOC(MTYPE_ZEBRA_SRV6_USID_WLIB,
					(wlib_end - wlib_start + 1) *
						sizeof(struct wide_lib));
			for (func = 0; func < wlib_end - wlib_start + 1;
			     func++) {
				block->u.usid.wide_lib[func].func_allocated =
					list_new();
				block->u.usid.wide_lib[func].func_allocated->del =
					delete_zebra_srv6_sid_func;
				block->u.usid.wide_lib[func].func_released =
					list_new();
				block->u.usid.wide_lib[func].func_released->del =
					delete_zebra_srv6_sid_func;
				block->u.usid.wide_lib[func].func = func;
			}
		} else if (format->type == SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
			block->u.uncompressed.func_allocated = list_new();
			block->u.uncompressed.func_allocated->del =
				delete_zebra_srv6_sid_func;
			block->u.uncompressed.func_released = list_new();
			block->u.uncompressed.func_released->del =
				delete_zebra_srv6_sid_func;
			block->u.uncompressed.first_available_func =
				SRV6_SID_FORMAT_UNCOMPRESSED_F4024_FUNC_UNRESERVED_MIN;
		} else {
			/* We should never arrive here */
			assert(0);
		}
	} else {
		block->u.uncompressed.func_allocated = list_new();
		block->u.uncompressed.func_allocated->del =
			delete_zebra_srv6_sid_func;
		block->u.uncompressed.func_released = list_new();
		block->u.uncompressed.func_released->del =
			delete_zebra_srv6_sid_func;
		block->u.uncompressed.first_available_func = 1;
	}

	return block;
}

void zebra_srv6_sid_block_free(struct zebra_srv6_sid_block *block)
{
	if (block->sid_format) {
		if (block->sid_format->type == SRV6_SID_FORMAT_TYPE_USID) {
			uint32_t wlib_start, wlib_end, func;

			/* Free uSID LIB */
			list_delete(&block->u.usid.lib.func_allocated);
			list_delete(&block->u.usid.lib.func_released);

			/* Free uSID Wide LIB */
			wlib_start = block->sid_format->config.usid.wlib_start;
			wlib_end = block->sid_format->config.usid.wlib_end;
			for (func = 0; func < wlib_end - wlib_start + 1;
			     func++) {
				list_delete(&block->u.usid.wide_lib[func]
						     .func_allocated);
				list_delete(&block->u.usid.wide_lib[func]
						     .func_released);
			}
			XFREE(MTYPE_ZEBRA_SRV6_USID_WLIB,
			      block->u.usid.wide_lib);
		} else if (block->sid_format->type ==
			   SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
			list_delete(&block->u.uncompressed.func_allocated);
			list_delete(&block->u.uncompressed.func_released);
		} else {
			/* We should never arrive here */
			assert(0);
		}
	} else {
		list_delete(&block->u.uncompressed.func_allocated);
		list_delete(&block->u.uncompressed.func_released);
	}

	XFREE(MTYPE_ZEBRA_SRV6_SID_BLOCK, block);
}

/**
 * Free an SRv6 SID block.
 *
 * @param val SRv6 SID block to be freed
 */
void delete_zebra_srv6_sid_block(void *val)
{
	zebra_srv6_sid_block_free((struct zebra_srv6_sid_block *)val);
}

struct zebra_srv6_sid_block *
zebra_srv6_sid_block_lookup(struct prefix_ipv6 *prefix)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_sid_block *block;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6->sid_blocks, node, block))
		if (prefix_match(prefix, &block->prefix))
			return block;

	return NULL;
}

static void zebra_srv6_sid_block_refcnt_increment(struct zebra_srv6_sid_block *block)
{
	block->refcnt++;
}

static void zebra_srv6_sid_block_refcnt_decrement(struct zebra_srv6_sid_block *block)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_sid_ctx *zctx;

	assert(block->refcnt > 0);

	block->refcnt--;
	if (block->refcnt == 0) {
		frr_each_safe (zebra_srv6_sid_ctx_list, &block->sids, zctx) {
			if (zctx->sid)
				zebra_srv6_sid_free(zctx->sid);

			zebra_srv6_sid_ctx_list_del(&block->sids, zctx);
			zebra_srv6_sid_ctx_free(zctx);
		}
		zebra_srv6_sid_ctx_list_fini(&block->sids);
		listnode_delete(srv6->sid_blocks, block);
		zebra_srv6_sid_block_free(block);
	}
}

void zebra_srv6_sid_locator_block_alloc(struct srv6_locator *locator)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_srv6_sid_block *block_new;
	struct prefix_ipv6 block_pfx_new;
	struct srv6_sid_format *format;

	format = locator->sid_format;

	block_pfx_new = locator->prefix;
	if (format)
		block_pfx_new.prefixlen = format->block_len;
	else
		block_pfx_new.prefixlen = locator->block_bits_length;
	apply_mask(&block_pfx_new);

	/* Allocate the new parent block */
	block_new = zebra_srv6_sid_block_lookup(&block_pfx_new);
	if (!block_new) {
		block_new = zebra_srv6_sid_block_alloc(format, &block_pfx_new);
		listnode_add(srv6->sid_blocks, block_new);
	}

	zebra_srv6_sid_block_refcnt_increment(block_new);
	locator->sid_block = block_new;
}

void zebra_srv6_sid_locator_block_release(struct srv6_locator *locator)
{
	if (!locator->sid_block)
		return;

	zebra_srv6_sid_block_refcnt_decrement(locator->sid_block);
	locator->sid_block = NULL;
}

/* --- Zebra SRv6 SID management functions ---------------------------------- */

/**
 * Alloc and fill an SRv6 SID.
 *
 * @param ctx Context associated with the SID to be created
 * @param locator Parent locator of the SID to be created
 * @param sid_block Block from which the SID value has been allocated
 * @param sid_func Function part of the SID to be created
 * @param alloc_mode Allocation mode of the Function (dynamic vs explicit)
 * @return The requested SID
 */
struct zebra_srv6_sid *zebra_srv6_sid_alloc(struct zebra_srv6_sid_ctx *ctx,
					    struct srv6_locator *locator,
					    struct zebra_srv6_sid_block *sid_block,
					    uint32_t sid_func, enum srv6_sid_alloc_mode alloc_mode)
{
	struct zebra_srv6_sid *sid;

	if (!ctx)
		return NULL;

	sid = XCALLOC(MTYPE_ZEBRA_SRV6_SID, sizeof(struct zebra_srv6_sid));
	sid->ctx = ctx;
	sid->block = sid_block;
	sid->func = sid_func;
	sid->alloc_mode = alloc_mode;
	zebra_srv6_sid_entry_list_init(&sid->entries);

	return sid;
}

void zebra_srv6_sid_free(struct zebra_srv6_sid *sid)
{
	struct zebra_srv6_sid_entry *entry;

	frr_each_safe (zebra_srv6_sid_entry_list, &sid->entries, entry) {
		zebra_srv6_sid_entry_list_del(&sid->entries, entry);
		zebra_srv6_sid_entry_free(entry);
	}
	zebra_srv6_sid_entry_list_fini(&sid->entries);
	XFREE(MTYPE_ZEBRA_SRV6_SID, sid);
}

/**
 * Free an SRv6 SID.
 *
 * @param val SRv6 SID to be freed
 */
void delete_zebra_srv6_sid(void *val)
{
	zebra_srv6_sid_free((struct zebra_srv6_sid *)val);
}

static void zebra_srv6_sid_clients_notify_single(struct zebra_srv6_sid *sid,
						 struct srv6_locator *locator,
						 struct zserv *client, bool is_localonly,
						 enum zapi_srv6_sid_notify notify)
{
	struct zebra_srv6_sid_entry *entry;
	struct in6_addr sid_value = {};

	entry = zebra_srv6_sid_entry_lookup(sid, locator->name, is_localonly);
	if (!entry)
		return;

	zebra_srv6_sid_compose(&sid_value, locator, sid->func, sid->wide_func, is_localonly);
	zsend_srv6_sid_notify(client, &sid->ctx->ctx, &sid_value, sid->func, sid->wide_func,
			      locator->name, notify);
}

static void zebra_srv6_sid_clients_release_notify_all(struct zebra_srv6_sid *sid)
{
	struct zebra_srv6_sid_entry *entry;
	struct zebra_srv6_sid_client *zclient;

	frr_each (zebra_srv6_sid_entry_list, &sid->entries, entry)
		frr_each (zebra_srv6_sid_client_list, &entry->clients_list, zclient)
			zsend_srv6_sid_notify(zclient->client, &sid->ctx->ctx, &entry->sid_value,
					      sid->func, sid->wide_func, entry->locator->name,
					      ZAPI_SRV6_SID_RELEASED);
}

static void zebra_srv6_sid_clients_notify_all(struct zebra_srv6_sid *sid,
					      struct srv6_locator *locator, bool is_localonly,
					      enum zapi_srv6_sid_notify notify)
{
	struct in6_addr sid_value = {};
	struct zebra_srv6_sid_entry *entry;
	struct zebra_srv6_sid_client *zclient;

	entry = zebra_srv6_sid_entry_lookup(sid, locator->name, is_localonly);
	if (!entry)
		return;

	zebra_srv6_sid_compose(&sid_value, locator, sid->func, sid->wide_func, is_localonly);

	frr_each (zebra_srv6_sid_client_list, &entry->clients_list, zclient)
		zsend_srv6_sid_notify(zclient->client, &sid->ctx->ctx, &sid_value, sid->func,
				      sid->wide_func, locator->name, notify);
}

void zebra_srv6_sid_client_add(struct zebra_srv6_sid *sid, bool is_localonly,
			       struct srv6_locator *locator, struct zserv *client)
{
	struct zebra_srv6_sid_entry *entry;
	struct zebra_srv6_sid_client *zclient;

	entry = zebra_srv6_sid_entry_lookup(sid, locator->name, is_localonly);
	if (!entry)
		return;

	zclient = zebra_srv6_sid_client_lookup(sid, entry, client);
	if (!zclient) {
		zclient = XCALLOC(MTYPE_ZEBRA_SRV6_SID_ENTRY_INFO,
				  sizeof(struct zebra_srv6_sid_client));
		zclient->client = client;

		zebra_srv6_sid_client_list_add_tail(&entry->clients_list, zclient);
	}
}

struct zebra_srv6_sid_entry *zebra_srv6_sid_entry_alloc(void)
{
	struct zebra_srv6_sid_entry *entry = NULL;

	entry = XCALLOC(MTYPE_ZEBRA_SRV6_SID_ENTRY_INFO, sizeof(struct zebra_srv6_sid_entry));

	return entry;
}

void zebra_srv6_sid_entry_free(struct zebra_srv6_sid_entry *entry)
{
	struct zebra_srv6_sid_client *sclient;

	frr_each_safe (zebra_srv6_sid_client_list, &entry->clients_list, sclient) {
		zebra_srv6_sid_client_list_del(&entry->clients_list, sclient);
		XFREE(MTYPE_ZEBRA_SRV6_SID_ENTRY_INFO, sclient);
	}
	zebra_srv6_sid_client_list_fini(&entry->clients_list);
	XFREE(MTYPE_ZEBRA_SRV6_SID_ENTRY_INFO, entry);
}

struct zebra_srv6_sid_entry *zebra_srv6_sid_entry_lookup(struct zebra_srv6_sid *sid,
							 const char *locator_name,
							 bool is_localonly)
{
	struct zebra_srv6_sid_entry *entry;

	if (!locator_name)
		return NULL;

	frr_each (zebra_srv6_sid_entry_list, &sid->entries, entry)
		if (!strncmp(entry->locator->name, locator_name, SRV6_LOCNAME_SIZE) &&
		    entry->is_localonly == is_localonly)
			return entry;

	return NULL;
}

void zebra_srv6_sid_client_del(struct zebra_srv6_sid *sid, struct zebra_srv6_sid_entry *entry,
			       struct zebra_srv6_sid_client *sclient)
{
	zebra_srv6_sid_client_list_del(&entry->clients_list, sclient);
	XFREE(MTYPE_ZEBRA_SRV6_SID_ENTRY_INFO, sclient);
	if (zebra_srv6_sid_client_list_count(&entry->clients_list) == 0) {
		zebra_srv6_sid_entry_list_del(&sid->entries, entry);
		zebra_srv6_sid_entry_free(entry);
	}
}

void zebra_srv6_sid_client_del_all(struct zebra_srv6_sid *sid, struct zserv *client)
{
	struct zebra_srv6_sid_entry *entry;
	struct zebra_srv6_sid_client *zclient;
	struct zebra_srv6_sid_block *block;

	block = sid->block;

	frr_each_safe (zebra_srv6_sid_entry_list, &sid->entries, entry) {
		zclient = zebra_srv6_sid_client_lookup(sid, entry, client);
		if (!zclient)
			continue;

		/* Remove the client from the list of clients using the SID */
		zebra_srv6_sid_client_list_del(&entry->clients_list, zclient);
		XFREE(MTYPE_ZEBRA_SRV6_SID_ENTRY_INFO, zclient);
		if (zebra_srv6_sid_client_list_count(&entry->clients_list) == 0) {
			zebra_srv6_sid_entry_list_del(&sid->entries, entry);
			zebra_srv6_sid_entry_free(entry);
		}
	}

	/*
	 * If the SID is not used by any other client, then deallocate it
	 * and remove it from the SRv6 database.
	 */
	if (zebra_srv6_sid_entry_list_count(&sid->entries) == 0) {
		release_srv6_sid_func(sid->ctx);

		/* Remove the SID context from the list and free memory */
		zebra_srv6_sid_ctx_list_del(&block->sids, sid->ctx);
		zebra_srv6_sid_ctx_free(sid->ctx);

		/* Free the SID */
		zebra_srv6_sid_free(sid);
	}
}

static void zebra_srv6_sid_entry_delete_all(struct zebra_srv6_sid *sid)
{
	struct zebra_srv6_sid_entry *entry;

	frr_each_safe (zebra_srv6_sid_entry_list, &sid->entries, entry)
		zebra_srv6_sid_entry_list_del(&sid->entries, entry);
}

struct zebra_srv6_sid_entry *zebra_srv6_sid_entry_add(struct zebra_srv6_sid *sid,
						      const char *locator_name,
						      struct in6_addr *sid_value, bool is_localonly)
{
	struct zebra_srv6_sid_entry *entry;
	struct srv6_locator *locator;

	locator = zebra_srv6_locator_lookup(locator_name);
	if (!locator)
		return NULL;

	entry = zebra_srv6_sid_entry_lookup(sid, locator_name, is_localonly);
	if (entry)
		return entry;

	entry = zebra_srv6_sid_entry_alloc();
	entry->locator = locator;
	entry->sid_value = *sid_value;
	entry->is_localonly = is_localonly;
	zebra_srv6_sid_client_list_init(&entry->clients_list);
	zebra_srv6_sid_entry_list_add_tail(&sid->entries, entry);

	return entry;
}

void zebra_srv6_locator_add(struct srv6_locator *locator)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *tmp;
	struct zserv *client;

	tmp = zebra_srv6_locator_lookup(locator->name);
	if (!tmp)
		listnode_add(srv6->locators, locator);

	/*
	 * Notify new locator info to zclients.
	 *
	 * The srv6 locators and their prefixes are managed by zserv(zebra).
	 * And an actual configuration the srv6 sid in the srv6 locator is done
	 * by zclient(bgpd, isisd, etc). The configuration of each locator
	 * allocation and specify it by zserv and zclient should be
	 * asynchronous. For that, zclient should be received the event via
	 * ZAPI when a srv6 locator is added on zebra.
	 * Basically, in SRv6, adding/removing SRv6 locators is performed less
	 * frequently than adding rib entries, so a broad to all zclients will
	 * not degrade the overall performance of FRRouting.
	 */
	frr_each (zserv_client_list, &zrouter.client_list, client) {
		zsend_zebra_srv6_locator_add(client, locator);
	}
}

void zebra_srv6_locator_delete(struct srv6_locator *locator)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zserv *client;

	/*
	 * Notify deleted locator info to zclients if needed.
	 *
	 * zclient(bgpd,isisd,etc) allocates a sid from srv6 locator chunk and
	 * uses it for its own purpose. For example, in the case of BGP L3VPN,
	 * the SID assigned to vpn unicast rib will be given.
	 * And when the locator is deleted by zserv(zebra), those SIDs need to
	 * be withdrawn. The zclient must initiate the withdrawal of the SIDs
	 * by ZEBRA_SRV6_LOCATOR_DELETE, and this notification is sent to the
	 * owner of each chunk.
	 */
	frr_each (zserv_client_list, &zrouter.client_list, client) {
		zsend_zebra_srv6_locator_delete(client, locator);
	}

	listnode_delete(srv6->locators, locator);
	srv6_locator_free(locator);
}

struct srv6_locator *zebra_srv6_locator_lookup(const char *name)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *locator;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, locator))
		if (!strncmp(name, locator->name, SRV6_LOCNAME_SIZE))
			return locator;
	return NULL;
}

void zebra_notify_srv6_locator_add(struct srv6_locator *locator)
{
	struct zserv *client;

	/*
	 * Notify new locator info to zclients.
	 *
	 * The srv6 locators and their prefixes are managed by zserv(zebra).
	 * And an actual configuration the srv6 sid in the srv6 locator is done
	 * by zclient(bgpd, isisd, etc). The configuration of each locator
	 * allocation and specify it by zserv and zclient should be
	 * asynchronous. For that, zclient should be received the event via
	 * ZAPI when a srv6 locator is added on zebra.
	 * Basically, in SRv6, adding/removing SRv6 locators is performed less
	 * frequently than adding rib entries, so a broad to all zclients will
	 * not degrade the overall performance of FRRouting.
	 */
	frr_each (zserv_client_list, &zrouter.client_list, client) {
		zsend_zebra_srv6_locator_add(client, locator);
	}
}

void zebra_notify_srv6_locator_delete(struct srv6_locator *locator)
{
	struct zserv *client;

	/*
	 * Notify deleted locator info to zclients if needed.
	 *
	 * zclient(bgpd,isisd,etc) allocates a sid from srv6 locator chunk and
	 * uses it for its own purpose. For example, in the case of BGP L3VPN,
	 * the SID assigned to vpn unicast rib will be given.
	 * And when the locator is deleted by zserv(zebra), those SIDs need to
	 * be withdrawn. The zclient must initiate the withdrawal of the SIDs
	 * by ZEBRA_SRV6_LOCATOR_DELETE, and this notification is sent to the
	 * owner of each chunk.
	 */
	frr_each (zserv_client_list, &zrouter.client_list, client) {
		zsend_zebra_srv6_locator_delete(client, locator);
	}
}

struct zebra_srv6 *zebra_srv6_get_default(void)
{
	static bool first_execution = true;
	struct srv6_sid_format *format_usidf3216;
	struct srv6_sid_format *format_usidf4816;
	struct srv6_sid_format *format_uncompressed;

	if (first_execution) {
		first_execution = false;
		g_srv6.locators = list_new();

		/* Initialize list of SID formats */
		g_srv6.sid_formats = list_new();
		g_srv6.sid_formats->del = delete_srv6_sid_format;

		/* Create SID format `usid-f3216` */
		format_usidf3216 = create_srv6_sid_format_usid_f3216();
		srv6_sid_format_register(format_usidf3216);

		/* Create SID format `usid-f4816` */
		format_usidf4816 = create_srv6_sid_format_usid_f4816();
		srv6_sid_format_register(format_usidf4816);

		/* Create SID format `uncompressed` */
		format_uncompressed = create_srv6_sid_format_uncompressed();
		srv6_sid_format_register(format_uncompressed);

		/* Init list to store SRv6 SID blocks */
		g_srv6.sid_blocks = list_new();
		g_srv6.sid_blocks->del = delete_zebra_srv6_sid_block;
	}
	return &g_srv6;
}

/**
 * Core function, assigns srv6-locator chunks
 *
 * It first searches through the list to check if there's one available
 * (previously released). Otherwise it creates and assigns a new one
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param session_id SessionID of client
 * @param name Name of SRv6-locator
 * @return Pointer to the assigned srv6-locator chunk,
 *         or NULL if the request could not be satisfied
 */
static struct srv6_locator *
assign_srv6_locator_chunk(uint8_t proto,
			  uint16_t instance,
			  uint32_t session_id,
			  const char *locator_name)
{
	bool chunk_found = false;
	struct listnode *node = NULL;
	struct srv6_locator *loc = NULL;
	struct srv6_locator_chunk *chunk = NULL;

	loc = zebra_srv6_locator_lookup(locator_name);
	if (!loc) {
		zlog_info("%s: locator %s was not found",
			  __func__, locator_name);
		return NULL;
	}

	for (ALL_LIST_ELEMENTS_RO((struct list *)loc->chunks, node, chunk)) {
		if (chunk->proto != NO_PROTO && chunk->proto != proto)
			continue;
		chunk_found = true;
		break;
	}

	if (!chunk_found) {
		zlog_info("%s: locator is already owned", __func__);
		return NULL;
	}

	chunk->proto = proto;
	chunk->instance = instance;
	chunk->session_id = session_id;
	return loc;
}

static int zebra_srv6_manager_get_locator_chunk(struct srv6_locator **loc,
						struct zserv *client,
						const char *locator_name,
						vrf_id_t vrf_id)
{
	int ret = 0;

	*loc = assign_srv6_locator_chunk(client->proto, client->instance,
					 client->session_id, locator_name);

	if (!*loc)
		zlog_err("Unable to assign locator chunk to %s instance %u",
			 zebra_route_string(client->proto), client->instance);
	else if (IS_ZEBRA_DEBUG_SRV6)
		zlog_info("Assigned locator chunk %s to %s instance %u",
			  (*loc)->name, zebra_route_string(client->proto),
			  client->instance);

	if (*loc && (*loc)->status_up)
		ret = zsend_srv6_manager_get_locator_chunk_response(client,
								    vrf_id,
								    *loc);
	return ret;
}

/**
 * Core function, release no longer used srv6-locator chunks
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @param session_id Zclient session ID, to identify the zclient session
 * @param locator_name SRv6-locator name, to identify the actual locator
 * @return 0 on success, -1 otherwise
 */
static int release_srv6_locator_chunk(uint8_t proto, uint16_t instance,
				      uint32_t session_id,
				      const char *locator_name)
{
	int ret = -1;
	struct listnode *node;
	struct srv6_locator_chunk *chunk;
	struct srv6_locator *loc = NULL;

	loc = zebra_srv6_locator_lookup(locator_name);
	if (!loc)
		return -1;

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: Releasing srv6-locator on %s", __func__,
			   locator_name);

	for (ALL_LIST_ELEMENTS_RO((struct list *)loc->chunks, node, chunk)) {
		if (chunk->proto != proto ||
		    chunk->instance != instance ||
		    chunk->session_id != session_id)
			continue;
		chunk->proto = NO_PROTO;
		chunk->instance = 0;
		chunk->session_id = 0;
		chunk->keep = 0;
		ret = 0;
		break;
	}

	if (ret != 0)
		flog_err(EC_ZEBRA_SRV6M_UNRELEASED_LOCATOR_CHUNK,
			 "%s: SRv6 locator chunk not released", __func__);

	return ret;
}

static int zebra_srv6_manager_release_locator_chunk(struct zserv *client,
						    const char *locator_name,
						    vrf_id_t vrf_id)
{
	if (vrf_id != VRF_DEFAULT) {
		zlog_err("SRv6 locator doesn't support vrf");
		return -1;
	}

	return release_srv6_locator_chunk(client->proto, client->instance,
					  client->session_id, locator_name);
}

/**
 * Release srv6-locator chunks from a client.
 *
 * Called on client disconnection or reconnection. It only releases chunks
 * with empty keep value.
 *
 * @param proto Daemon protocol of client, to identify the owner
 * @param instance Instance, to identify the owner
 * @return Number of chunks released
 */
int release_daemon_srv6_locator_chunks(struct zserv *client)
{
	int ret;
	int count = 0;
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct listnode *loc_node;
	struct listnode *chunk_node;
	struct srv6_locator *loc;
	struct srv6_locator_chunk *chunk;

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: Releasing chunks for client proto %s, instance %d, session %u",
			   __func__, zebra_route_string(client->proto),
			   client->instance, client->session_id);

	for (ALL_LIST_ELEMENTS_RO(srv6->locators, loc_node, loc)) {
		for (ALL_LIST_ELEMENTS_RO(loc->chunks, chunk_node, chunk)) {
			if (chunk->proto == client->proto &&
			    chunk->instance == client->instance &&
			    chunk->session_id == client->session_id &&
			    chunk->keep == 0) {
				ret = release_srv6_locator_chunk(
						chunk->proto, chunk->instance,
						chunk->session_id, loc->name);
				if (ret == 0)
					count++;
			}
		}
	}

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: Released %d srv6-locator chunks",
			   __func__, count);

	return count;
}

void zebra_srv6_encap_src_addr_set(struct in6_addr *encap_src_addr)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	if (!encap_src_addr)
		return;

	memcpy(&srv6->encap_src_addr, encap_src_addr, sizeof(struct in6_addr));
}

void zebra_srv6_encap_src_addr_unset(void)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	memset(&srv6->encap_src_addr, 0, sizeof(struct in6_addr));
}

/* --- SRv6 SID Allocation/Release functions -------------------------------- */

/**
 * Return the SRv6 SID obtained composing the locator and function.
 *
 * @param sid_value SRv6 SID address returned
 * @param locator Parent locator of the SRv6 SID
 * @param sid_func Function part of the SID
 * @param sid_func_wide Wide function of the SID
 * @param is_localonly SID is local-only
 * @return True if success, False otherwise
 */
static bool zebra_srv6_sid_compose(struct in6_addr *sid_value, struct srv6_locator *locator,
				   uint32_t sid_func, uint32_t sid_func_wide, bool is_localonly)
{
	uint8_t offset, func_len;
	struct srv6_sid_format *format;
	struct zebra_srv6_sid_block *block;

	if (!sid_value || !locator)
		return false;

	block = locator->sid_block;

	format = locator->sid_format;
	if (format) {
		offset = is_localonly ? format->block_len : format->block_len + format->node_len;
		func_len = format->function_len;
	} else {
		offset = is_localonly ? locator->block_bits_length
				      : locator->block_bits_length + locator->node_bits_length;
		func_len = locator->function_bits_length;
	}

	*sid_value = is_localonly ? block->prefix.prefix : locator->prefix.prefix;
	for (uint8_t idx = 0; idx < func_len; idx++) {
		uint8_t tidx = offset + idx;

		sid_value->s6_addr[tidx / 8] &= ~(0x1 << (7 - tidx % 8));
		if (sid_func >> (func_len - 1 - idx) & 0x1)
			sid_value->s6_addr[tidx / 8] |= 0x1 << (7 - tidx % 8);
	}
	for (uint8_t idx = 0; idx < func_len; idx++) {
		uint8_t tidx = offset + func_len + idx;

		sid_value->s6_addr[tidx / 8] &= ~(0x1 << (7 - tidx % 8));
		if (sid_func_wide >> (func_len - 1 - idx) & 0x1)
			sid_value->s6_addr[tidx / 8] |= 0x1 << (7 - tidx % 8);
	}

	return true;
}

/**
 * Return the parent locator and function of an SRv6 SID.
 *
 * @param sid_value SRv6 SID address to be decomposed
 * @param sid_block Parent block of the SRv6 SID
 * @param locator Parent locator of the SRv6 SID
 * @param sid_func Function part of the SID
 * @param sid_wide_func Wide function of the SID
 * @return True if success, False otherwise
 */
static bool zebra_srv6_sid_decompose(struct in6_addr *sid_value,
				     struct zebra_srv6_sid_block **sid_block,
				     struct srv6_locator **locator,
				     uint32_t *sid_func, uint32_t *sid_wide_func)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct srv6_locator *l;
	struct zebra_srv6_sid_block *b;
	struct srv6_sid_format *format;
	struct listnode *node;
	struct prefix_ipv6 tmp_prefix;
	uint8_t offset, func_len;

	if (!sid_value || !sid_func)
		return false;

	*sid_func = 0;
	*sid_wide_func = 0;

	/*
	 * Build a temporary prefix_ipv6 object representing the SRv6 SID.
	 * This temporary prefix object is used below by the prefix_match
	 * function to check if the SID belongs to a specific locator.
	 */
	tmp_prefix.family = AF_INET6;
	tmp_prefix.prefixlen = IPV6_MAX_BITLEN;
	tmp_prefix.prefix = *sid_value;

	/*
	 * Lookup the parent locator of the SID and return the locator and
	 * the function of the SID.
	 */
	for (ALL_LIST_ELEMENTS_RO(srv6->locators, node, l)) {
		/*
		 * Check if the locator prefix includes the temporary prefix
		 * representing the SID.
		 */
		if (prefix_match((struct prefix *)&l->prefix,
				 (struct prefix *)&tmp_prefix)) {
			format = l->sid_format;

			if (format) {
				offset = format->block_len + format->node_len;
				func_len = format->function_len;
			} else {
				offset = l->block_bits_length +
					 l->node_bits_length;
				func_len = l->function_bits_length;
			}

			for (uint8_t idx = 0; idx < func_len; idx++) {
				uint8_t tidx = offset + idx;
				*sid_func |= (sid_value->s6_addr[tidx / 8] &
					      (0x1 << (7 - tidx % 8)))
					     << (((func_len - 1 - idx) / 8) * 8);
			}

			/*
			 * If function comes from the Wide LIB range, we also
			 * need to get the Wide function.
			 */
			if (format && format->type == SRV6_SID_FORMAT_TYPE_USID) {
				if (*sid_func >= format->config.usid.wlib_start &&
				    *sid_func <= format->config.usid.wlib_end) {
					format = l->sid_format;

					offset = format->block_len +
						 format->node_len +
						 format->function_len;

					for (uint8_t idx = 0; idx < 16; idx++) {
						uint8_t tidx = offset + idx;
						*sid_wide_func |=
							(sid_value->s6_addr[tidx /
									    8] &
							 (0x1 << (7 - tidx % 8)))
							<< (((16 - 1 - idx) / 8) *
							    8);
					}
				}
			}

			*locator = l;
			*sid_block = l->sid_block;

			return true;
		}
	}

	/*
	 * If we arrive here, the SID does not belong to any locator.
	 * Then, let's try to find the parent block from which the SID
	 * has been allocated.
	 */

	/*
	 * Lookup the parent block of the SID and return the block and
	 * the function of the SID.
	 */
	for (ALL_LIST_ELEMENTS_RO(srv6->sid_blocks, node, b)) {
		/*
		 * Check if the block prefix includes the temporary prefix
		 * representing the SID
		 */
		if (prefix_match((struct prefix *)&b->prefix,
				 (struct prefix *)&tmp_prefix)) {
			format = b->sid_format;

			if (format) {
				offset = format->block_len;
				func_len = format->function_len;
			} else {
				offset = b->prefix.prefixlen;
				func_len = SRV6_SID_FORMAT_USID_F3216_FUNCTION_LEN;
			}

			for (uint8_t idx = 0; idx < func_len; idx++) {
				uint8_t tidx = offset + idx;
				*sid_func |= (sid_value->s6_addr[tidx / 8] &
					      (0x1 << (7 - tidx % 8)))
					     << (((func_len - 1 - idx) / 8) * 8);
			}

			/*
			 * If function comes from the Wide LIB range, we also
			 * need to get the Wide function.
			 */
			if (format && format->type == SRV6_SID_FORMAT_TYPE_USID &&
			    *sid_func >= format->config.usid.wlib_start &&
			    *sid_func <= format->config.usid.wlib_end) {
				format = b->sid_format;

				offset = format->block_len + format->function_len;

				for (uint8_t idx = 0; idx < 16; idx++) {
					uint8_t tidx = offset + idx;
					*sid_wide_func |=
						(sid_value->s6_addr[tidx / 8] &
						 (0x1 << (7 - tidx % 8)))
						<< (((16 - 1 - idx) / 8) * 8);
				}
			}

			*sid_block = b;

			return true;
		}
	}

	return false;
}

/**
 * Allocate an explicit SID function (i.e. specific SID function value) from a given SID block.
 *
 * @param block SRv6 SID block from which the SID function has to be allocated
 * @param sid_func SID function to be allocated
 * @param sid_wide_func SID wide function to be allocated
 *
 * @return true on success, false otherwise
 */
static bool alloc_srv6_sid_func_explicit(struct zebra_srv6_sid_block *block,
					 uint32_t sid_func,
					 uint32_t sid_wide_func)
{
	struct srv6_sid_format *format;
	struct listnode *node;
	uint32_t *sid_func_ptr = NULL;

	if (!block)
		return false;

	format = block->sid_format;

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: trying to allocate explicit SID function %u from block %pFX",
			   __func__, sid_func, &block->prefix);

	/*
	 * Allocate SID function from the corresponding range depending on the SID format type
	 */
	if (format) {
		if (format->type == SRV6_SID_FORMAT_TYPE_USID) {
			uint32_t elib_start = format->config.usid.elib_start;
			uint32_t elib_end = format->config.usid.elib_end;
			uint32_t wlib_start = format->config.usid.wlib_start;
			uint32_t wlib_end = format->config.usid.wlib_end;
			uint32_t ewlib_start = format->config.usid.ewlib_start;
			uint32_t ewlib_end = wlib_end;
			uint32_t *sid_wide_func_ptr = NULL;

			/* Figure out the range from which the SID function has been allocated and release it */
			if ((sid_func >= elib_start) && (sid_func <= elib_end)) {
				/* The SID function has to be allocated from the ELIB range */

				/* Ensure that the requested SID function has not already been taken */
				for (ALL_LIST_ELEMENTS_RO(block->u.usid.lib
								  .func_allocated,
							  node, sid_func_ptr))
					if (*sid_func_ptr == sid_func)
						break;

				if (sid_func_ptr) {
					zlog_err("%s: invalid SM request arguments: SID function %u already taken",
						 __func__, sid_func);
					return false;
				}

				/*
				 * Mark the SID function as "taken" by adding it to the "func_allocated" list and
				 * increase the counter of function allocated
				 */
				sid_func_ptr =
					zebra_srv6_sid_func_alloc(sid_func);
				listnode_add(block->u.usid.lib.func_allocated,
					     sid_func_ptr);
				block->u.usid.lib.num_func_allocated++;
			} else if ((sid_func >= ewlib_start) &&
				   (sid_func <= ewlib_end)) {
				/* The SID function has to be allocated from the EWLIB range */

				/* Ensure that the requested SID function has not already been taken */
				for (ALL_LIST_ELEMENTS_RO(block->u.usid
								  .wide_lib[sid_func - wlib_start]
								  .func_allocated,
							  node, sid_wide_func_ptr))
					if (*sid_wide_func_ptr == sid_wide_func)
						break;

				if (sid_wide_func_ptr) {
					zlog_err("%s: invalid SM request arguments: SID function %u already taken",
						 __func__, sid_func);
					return false;
				}

				/*
				 * Mark the SID function as "taken" by adding it to the "func_allocated" list and
				 * increase the counter of function allocated
				 */
				sid_wide_func_ptr = zebra_srv6_sid_func_alloc(
					sid_wide_func);
				listnode_add(block->u.usid.wide_lib[sid_func - wlib_start]
						     .func_allocated,
					     sid_wide_func_ptr);
				block->u.usid.wide_lib[sid_func - wlib_start].num_func_allocated++;
			} else {
				zlog_warn("%s: function %u is outside ELIB [%u/%u] and EWLIB alloc ranges [%u/%u]",
					  __func__, sid_func, elib_start,
					  elib_end, ewlib_start, ewlib_end);
				return false;
			}
		} else if (format->type == SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
			uint32_t explicit_start =
				format->config.uncompressed.explicit_start;
			uint32_t explicit_end =
				(uint32_t)((1 << format->function_len) - 1);

			/* Ensure that the SID function comes from the Explicit range */
			if (!(sid_func >= explicit_start &&
			      sid_func <= explicit_end)) {
				zlog_err("%s: invalid SM request arguments: SID function %u out of explicit range (%u - %u)",
					 __func__, sid_func, explicit_start,
					 explicit_end);
				return false;
			}

			/* Ensure that the SID function has not already been taken */

			for (ALL_LIST_ELEMENTS_RO(block->u.uncompressed
							  .func_allocated,
						  node, sid_func_ptr))
				if (*sid_func_ptr == sid_func)
					break;

			/* SID function already taken */
			if (sid_func_ptr) {
				zlog_err("%s: invalid SM request arguments: SID function %u already taken",
					 __func__, sid_func);
				return false;
			}

			/*
			 * Mark the SID function as "taken" by adding it to the "func_allocated" list and
			 * increase the counter of function allocated
			 */
			sid_func_ptr = zebra_srv6_sid_func_alloc(sid_func);
			listnode_add(block->u.uncompressed.func_allocated,
				     sid_func_ptr);
			block->u.uncompressed.num_func_allocated++;
		} else {
			/* We should never arrive here */
			zlog_err("%s: unknown SID format type: %u", __func__,
				 format->type);
			assert(0);
		}
	} else {
		/* Ensure that the SID function has not already been taken */

		for (ALL_LIST_ELEMENTS_RO(block->u.uncompressed.func_allocated,
					  node, sid_func_ptr))
			if (*sid_func_ptr == sid_func)
				break;

		/* SID function already taken */
		if (sid_func_ptr) {
			zlog_err("%s: invalid SM request arguments: SID function %u already taken",
				 __func__, sid_func);
			return false;
		}

		/*
		 * Mark the SID function as "taken" by adding it to the "func_allocated" list and
		 * increase the counter of function allocated
		 */
		sid_func_ptr = zebra_srv6_sid_func_alloc(sid_func);
		listnode_add(block->u.uncompressed.func_allocated, sid_func_ptr);
		block->u.uncompressed.num_func_allocated++;
	}

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: allocated explicit SID function %u from block %pFX",
			   __func__, sid_func, &block->prefix);

	return true;
}

/**
 * Allocate a dynamic SID function (i.e. any available SID function value) from a given SID block.
 *
 * @param block SRv6 SID block from which the SID function has to be allocated
 * @param sid_func SID function allocated
 *
 * @return true on success, false otherwise
 */
static bool alloc_srv6_sid_func_dynamic(struct zebra_srv6_sid_block *block,
					uint32_t *sid_func)
{
	struct srv6_sid_format *format;
	uint32_t *sid_func_ptr = NULL;

	if (!block || !sid_func)
		return false;

	format = block->sid_format;

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: trying to allocate dynamic SID function from block %pFX",
			   __func__, &block->prefix);

	/*
	 * Allocate SID function from the corresponding range depending on the SID format type
	 */
	if (format) {
		if (format->type == SRV6_SID_FORMAT_TYPE_USID) {
			/* Format is uSID and behavior => allocate SID function from LIB range */

			/* The Dynamic LIB range ends where the Explicit LIB range begins */
			uint32_t dlib_end = format->config.usid.elib_start - 1;

			/* Check if we ran out of available SID functions */
			if (block->u.usid.lib.first_available_func > dlib_end) {
				zlog_warn("%s: SRv6: Warning, SRv6 Dynamic LIB is depleted",
					  __func__);
				return false;
			}

			/*
			 * First, let's check if there are any SID functions that were previously
			 * allocated and then released.
			 */
			if (listcount(block->u.usid.lib.func_released) != 0) {
				/*
				 * There are SID functions previously allocated and then released,
				 * let's pick the first one and reuse it now.
				 */
				sid_func_ptr = listnode_head(
					block->u.usid.lib.func_released);
				*sid_func = *sid_func_ptr;
				listnode_delete(block->u.usid.lib.func_released,
						sid_func_ptr);
				zebra_srv6_sid_func_free(sid_func_ptr);
			} else {
				/*
				 * There are no SID functions previously allocated and then released,
				 * let's allocate a new function from the pool of available functions.
				 */
				*sid_func =
					block->u.usid.lib.first_available_func;
				block->u.usid.lib.first_available_func++;
			}

			/* Increase the counter of SID functions allocated */
			block->u.usid.lib.num_func_allocated++;

			if (block->u.usid.lib.first_available_func > dlib_end)
				zlog_warn("%s: SRv6: Warning, SRv6 Dynamic LIB is depleted and next SID request will fail",
					  __func__);
		} else if (format->type == SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
			/* Format is uncompressed => allocate SID function from Dynamic range */

			uint32_t dynamic_end =
				format->config.uncompressed.explicit_start - 1;

			/* Check if we ran out of available SID functions */
			if (block->u.uncompressed.first_available_func >
			    dynamic_end) {
				zlog_warn("%s: SRv6: Warning, SRv6 SID Dynamic alloc space is depleted",
					  __func__);
				return false;
			}

			/*
			 * First, let's check if there are any SID functions that were previously
			 * allocated and then released.
			 */
			if (listcount(block->u.uncompressed.func_released) != 0) {
				/*
				 * There are SID functions previously allocated and then released,
				 * let's pick the first one and reuse it now.
				 */
				sid_func_ptr = listnode_head(
					block->u.uncompressed.func_released);
				*sid_func = *sid_func_ptr;
				listnode_delete(block->u.uncompressed
							.func_released,
						sid_func_ptr);
				zebra_srv6_sid_func_free(sid_func_ptr);
			} else {
				/*
				 * There are no SID functions previously allocated and then released,
				 * let's allocate a new function from the pool of available functions.
				 */
				*sid_func = block->u.uncompressed
						    .first_available_func;
				block->u.uncompressed.first_available_func++;
			}

			/* Increase the counter of SID functions allocated */
			block->u.uncompressed.num_func_allocated++;

			if (block->u.uncompressed.first_available_func >
			    dynamic_end)
				zlog_warn("%s: SRv6: Warning, SRv6 SID Dynamic alloc space is depleted and next SID request will fail",
					  __func__);
		} else {
			/* We should never arrive here */
			zlog_err("%s: unknown SID format type: %u", __func__,
				 format->type);
			assert(0);
		}
	} else {
		/*
		 * First, let's check if there are any SID functions that were previously
		 * allocated and then released.
		 */
		if (listcount(block->u.uncompressed.func_released) != 0) {
			/*
			 * There are SID functions previously allocated and then released,
			 * let's pick the first one and reuse it now.
			 */
			sid_func_ptr = listnode_head(
				block->u.uncompressed.func_released);
			*sid_func = *sid_func_ptr;
			listnode_delete(block->u.uncompressed.func_released,
					sid_func_ptr);
			zebra_srv6_sid_func_free(sid_func_ptr);
		} else {
			/*
			 * There are no SID functions previously allocated and then released,
			 * let's allocate a new function from the pool of available functions.
			 */
			*sid_func = block->u.uncompressed.first_available_func;
			block->u.uncompressed.first_available_func++;
		}

		/* Increase the counter of SID functions allocated */
		block->u.uncompressed.num_func_allocated++;
	}

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: allocated dynamic SID function %u from block %pFX",
			   __func__, *sid_func, &block->prefix);

	return true;
}

/**
 * Get an explicit SID (i.e., a specific SID value) for a given context.
 *
 * If a SID already exists associated with the context, it returns the existing SID.
 * Otherwise, it allocates a new SID.
 *
 * @param sid SID returned
 * @param ctx Context for which the SID has been requested
 * @param locator Parent locator of the SID
 * @param sid_value specific SRv6 SID value (i.e. IPv6 address) to be
 * allocated explicitly
 * @param is_localonly SID is local-only
 *
 * @return 0 if the function returned an existing SID and SID value has not changed,
 * 1 if a new SID has been allocated or the existing SID value has changed, -1 if an error occurred
 */
static int get_srv6_sid_explicit(struct zebra_srv6_sid **sid, struct srv6_sid_ctx *ctx,
				 struct srv6_locator *locator, struct in6_addr *sid_value,
				 bool is_localonly)
{
	struct zebra_srv6_sid_ctx *zctx = NULL;
	uint32_t sid_func = 0, sid_func_wide = 0;
	struct srv6_locator *loc = NULL;
	struct zebra_srv6_sid_block *block = NULL;
	char buf[256];

	if (!ctx || !sid_value)
		return -1;

	/* Get parent locator and function of the provided SID */
	if (!zebra_srv6_sid_decompose(sid_value, &block, &loc, &sid_func, &sid_func_wide)) {
		zlog_err("%s: invalid SM request arguments: parent block/locator not found for SID %pI6",
			 __func__, sid_value);
		return -1;
	}

	if (!locator)
		locator = loc;

	/* Check if we already have a SID associated with the provided context */
	zctx = zebra_srv6_sid_ctx_lookup(ctx, block);

	if (zctx) {
		/*
		 * If the context is already associated with a SID that has the same SID value, then
		 * return the existing SID
		 */
		if (zctx->sid->func == sid_func && zctx->sid->wide_func == sid_func_wide) {
			if (IS_ZEBRA_DEBUG_SRV6)
				zlog_debug("%s: returning existing SRv6 SID %pI6 ctx %s", __func__,
					   sid_value, srv6_sid_ctx2str(buf, sizeof(buf), ctx));
			*sid = zctx->sid;
			zebra_srv6_sid_entry_add(*sid, locator->name, sid_value, is_localonly);
			return 0;
		}

		/* Allocate an explicit SID function for the SID */
		if (ctx->behavior != ZEBRA_SEG6_LOCAL_ACTION_END)
			if (!alloc_srv6_sid_func_explicit(block, sid_func, sid_func_wide)) {
				zlog_err("%s: invalid SM request arguments: failed to allocate SID function %u from block %pFX",
					 __func__, sid_func, &block->prefix);
				return -1;
			}

		/*
		 * If we already have a SID associated with this context, we need to
		 * deallocate the current SID function before allocating the new one
		 */
		if (IS_ZEBRA_DEBUG_SRV6)
			zlog_debug("%s: ctx %s already associated with SID %u, releasing SID",
				   __func__, srv6_sid_ctx2str(buf, sizeof(buf), ctx),
				   zctx->sid->func);

		release_srv6_sid_func(zctx);

		zebra_srv6_sid_clients_release_notify_all(zctx->sid);
		zebra_srv6_sid_entry_delete_all(zctx->sid);

		zctx->sid->block = block;
		zctx->sid->func = sid_func;
		zctx->sid->wide_func = sid_func_wide;
		zctx->sid->alloc_mode = SRV6_SID_ALLOC_MODE_EXPLICIT;

		*sid = zctx->sid;
		(*sid)->ctx = zctx;
	} else {
		/* Allocate an explicit SID function for the SID */
		if (ctx->behavior != ZEBRA_SEG6_LOCAL_ACTION_END)
			if (!alloc_srv6_sid_func_explicit(block, sid_func, sid_func_wide)) {
				zlog_err("%s: invalid SM request arguments: failed to allocate SID function %u from block %pFX",
					 __func__, sid_func, &block->prefix);
				return -1;
			}

		/* If we don't have a zebra SID context for this context, allocate a new one */
		zctx = zebra_srv6_sid_ctx_alloc();
		zctx->ctx = *ctx;

		/* Allocate the SID to store SID information */
		*sid = zebra_srv6_sid_alloc(zctx, locator, block, sid_func,
					    SRV6_SID_ALLOC_MODE_EXPLICIT);
		if (!(*sid)) {
			flog_err(EC_ZEBRA_SM_CANNOT_ASSIGN_SID,
				 "%s: failed to create SRv6 SID %s (%pI6)", __func__,
				 srv6_sid_ctx2str(buf, sizeof(buf), ctx), sid_value);
			return -1;
		}
		(*sid)->wide_func = sid_func_wide;
		(*sid)->ctx = zctx;
		zctx->sid = *sid;
		zebra_srv6_sid_ctx_list_add_tail(&block->sids, zctx);
	}

	zebra_srv6_sid_entry_add(*sid, locator->name, sid_value, is_localonly);

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: allocated explicit SRv6 SID function %u for context %s", __func__,
			   (*sid)->func, srv6_sid_ctx2str(buf, sizeof(buf), ctx));

	return 1;
}

/**
 * Get a dynamic SID (i.e., any available SID value) for a given context.
 *
 * If a SID already exists associated with the context, it returns the existing SID.
 * Otherwise, it allocates a new SID.
 *
 * @param sid SID returned
 * @param ctx Context for which the SID has been requested
 * @param locator SRv6 locator from which the SID has to be allocated
 * @param is_localonly SID is local-only
 *
 * @return 0 if the function returned an existing SID and SID value has not changed,
 * 1 if a new SID has been allocated or the existing SID value has changed, -1 if an error occurred
 */
static int get_srv6_sid_dynamic(struct zebra_srv6_sid **sid, struct srv6_sid_ctx *ctx,
				struct srv6_locator *locator, bool is_localonly)
{
	struct zebra_srv6_sid_block *block;
	struct srv6_sid_format *format;
	struct zebra_srv6_sid_ctx *zctx;
	struct in6_addr sid_value;
	uint32_t sid_func = 0;
	char buf[256];

	if (!ctx || !locator)
		return -1;

	block = locator->sid_block;
	format = locator->sid_format;

	/*
	 * If we already have a SID for the provided context, we return the existing
	 * SID instead of allocating a new one.
	 */
	zctx = zebra_srv6_sid_ctx_lookup(ctx, block);
	if (zctx) {
		if (((format && format->type == SRV6_SID_FORMAT_TYPE_USID) ||
		     (!format && CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID))) &&
		    ctx->behavior == ZEBRA_SEG6_LOCAL_ACTION_END) {
			sid_value = locator->prefix.prefix;
		} else {
			zebra_srv6_sid_compose(&sid_value, locator, zctx->sid->func,
					       zctx->sid->wide_func, is_localonly);
		}
		zebra_srv6_sid_entry_add(zctx->sid, locator->name, &sid_value, is_localonly);

		*sid = zctx->sid;
		return 0;
	}

	if (format && format->type == SRV6_SID_FORMAT_TYPE_USID &&
	    ctx->behavior == ZEBRA_SEG6_LOCAL_ACTION_END) {
		/* uN SID is allocated from the GIB range */
		sid_value = locator->prefix.prefix;
	} else if (!format && ctx->behavior == ZEBRA_SEG6_LOCAL_ACTION_END) {
		/* uN SID is allocated from the GIB range */
		sid_value = locator->prefix.prefix;
	} else {
		/* Allocate a dynamic SID function for the SID */
		if (!alloc_srv6_sid_func_dynamic(block, &sid_func)) {
			zlog_err("%s: invalid SM request arguments: failed to allocate SID function %u from block %pFX",
				 __func__, sid_func, &block->prefix);
			return -1;
		}

		/* Compose the SID as the locator followed by the SID function */
		zebra_srv6_sid_compose(&sid_value, locator, sid_func, 0, is_localonly);
	}

	/* Allocate a zebra SID context to store SID context information */
	zctx = zebra_srv6_sid_ctx_alloc();
	zctx->ctx = *ctx;

	/* Allocate the SID to store SID information */
	*sid = zebra_srv6_sid_alloc(zctx, locator, block, sid_func, SRV6_SID_ALLOC_MODE_DYNAMIC);
	if (!(*sid)) {
		flog_err(EC_ZEBRA_SM_CANNOT_ASSIGN_SID,
			 "%s: failed to create SRv6 SID ctx %s (%pI6)", __func__,
			 srv6_sid_ctx2str(buf, sizeof(buf), ctx), &sid_value);
		return -1;
	}
	(*sid)->ctx = zctx;
	zctx->sid = *sid;
	zebra_srv6_sid_ctx_list_add_tail(&block->sids, zctx);

	zebra_srv6_sid_entry_add(*sid, locator->name, &sid_value, is_localonly);

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: allocated new dynamic SRv6 SID %u for context %s", __func__,
			   (*sid)->func, srv6_sid_ctx2str(buf, sizeof(buf), ctx));

	return 1;
}

/**
 * Get an SRv6 SID for a given context.
 *
 * If a SID already exists associated with the context, it returns the existing SID.
 * Otherwise, it allocates a new SID.
 *
 * If the sid_value parameter is non-NULL, it allocates the requested SID value
 * if it is available (explicit SID allocation).
 * If the sid_value parameter is NULL, it allocates any available SID value
 * (dynamic SID allocation).
 *
 * @param sid SID returned
 * @param ctx Context for which the SID has been requested
 * @param sid_value SRv6 SID value to be allocated (for explicit SID allocation)
 * @param locator_name Parent SRv6 locator from which the SID has to be allocated (for dynamic SID allocation)
 * @param is_localonly SID is local-only
 *
 * @return 0 if the function returned an existing SID and SID value has not changed,
 * 1 if a new SID has been allocated or the existing SID value has changed, -1 if an error occurred
 */
int get_srv6_sid(struct zebra_srv6_sid **sid, struct srv6_sid_ctx *ctx, struct in6_addr *sid_value,
		 const char *locator_name, bool is_localonly)
{
	int ret = -1;
	struct srv6_locator *locator = NULL;
	char buf[256];
	struct nhg_connected *rb_node_dep = NULL;
	struct listnode *node;
	struct nexthop *nexthop;
	struct nbr_connected *nc;
	bool found = false;
	struct interface *ifp;
	struct zebra_if *zebra_if;

	enum srv6_sid_alloc_mode alloc_mode =
		(sid_value) ? SRV6_SID_ALLOC_MODE_EXPLICIT
			    : SRV6_SID_ALLOC_MODE_DYNAMIC;

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: received SRv6 SID alloc request: SID ctx %s (%pI6), mode=%s",
			   __func__, srv6_sid_ctx2str(buf, sizeof(buf), ctx),
			   sid_value, srv6_sid_alloc_mode2str(alloc_mode));

	if (ctx->ifindex != 0 && IPV6_ADDR_SAME(&ctx->nh6, &in6addr_any)) {
		ifp = if_lookup_by_index(ctx->ifindex, VRF_DEFAULT);
		if (!ifp) {
			zlog_err("%s: interface %u does not exist", __func__, ctx->ifindex);
			return -1;
		}

		for (ALL_LIST_ELEMENTS_RO(ifp->nbr_connected, node, nc))
			if (nc->address && nc->address->family == AF_INET6 &&
			    IN6_IS_ADDR_LINKLOCAL(&nc->address->u.prefix6)) {
				ctx->nh6 = nc->address->u.prefix6;
				found = true;
				break;
			}

		if (!found) {
			zebra_if = ifp->info;

			frr_each (nhg_connected_tree, &zebra_if->nhg_dependents, rb_node_dep) {
				for (ALL_NEXTHOPS(rb_node_dep->nhe->nhg, nexthop)) {
					/* skip non link-local addresses */
					if (!IPV6_ADDR_SAME(&nexthop->gate.ipv6, &in6addr_any)) {
						ctx->nh6 = nexthop->gate.ipv6;
						found = true;
						break;
					}
				}
				if (found)
					break;
			}
			if (!found) {
				zlog_err("%s: cannot get SID, interface (ifindex %u) not found",
					 __func__, ctx->ifindex);
				return -1;
			}
		}
	}

	if (alloc_mode == SRV6_SID_ALLOC_MODE_EXPLICIT) {
		/*
		 * Explicit SID allocation: allocate a specific SID value
		 */

		if (locator_name) {
			locator = zebra_srv6_locator_lookup(locator_name);
			if (!locator) {
				zlog_err("%s: invalid SM request arguments: SRv6 locator '%s' does not exist",
					 __func__, locator_name);
				return -1;
			}
		}

		if (!sid_value) {
			zlog_err("%s: invalid SM request arguments: missing SRv6 SID value, necessary for explicit allocation",
				 __func__);
			return -1;
		}

		ret = get_srv6_sid_explicit(sid, ctx, locator, sid_value, is_localonly);
	} else {
		/*
		 * Dynamic SID allocation: allocate any available SID value
		 */

		if (!locator_name) {
			zlog_err("%s: invalid SM request arguments: missing SRv6 locator, necessary for dynamic allocation",
				 __func__);
			return -1;
		}

		locator = zebra_srv6_locator_lookup(locator_name);
		if (!locator) {
			zlog_err("%s: invalid SM request arguments: SRv6 locator '%s' does not exist",
				 __func__, locator_name);
			return -1;
		}

		ret = get_srv6_sid_dynamic(sid, ctx, locator, is_localonly);
	}

	return ret;
}

/**
 * Release an explicit SRv6 SID function.
 *
 * @param block Parent SRv6 SID block of the SID function that has to be released
 * @param sid_func SID function to be released
 * @return 0 on success, -1 otherwise
 */
static bool release_srv6_sid_func_explicit(struct zebra_srv6_sid_block *block,
					   uint32_t sid_func,
					   uint32_t sid_wide_func)
{
	struct srv6_sid_format *format;
	struct listnode *node;
	uint32_t *sid_func_ptr = NULL;

	if (!block)
		return -1;

	format = block->sid_format;

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: trying to release explicit SRv6 SID function %u from block %pFX",
			   __func__, sid_func, &block->prefix);

	/*
	 * Release SID function from the corresponding range depending on the SID format type
	 */
	if (format) {
		if (format->type == SRV6_SID_FORMAT_TYPE_USID) {
			uint32_t elib_start = format->config.usid.elib_start;
			uint32_t elib_end = format->config.usid.elib_end;
			uint32_t wlib_start = format->config.usid.wlib_start;
			uint32_t ewlib_start = format->config.usid.ewlib_start;
			uint32_t ewlib_end = format->config.usid.wlib_end;
			uint32_t *sid_wide_func_ptr = NULL;

			/* Figure out the range from which the SID function has been allocated and release it */
			if ((sid_func >= elib_start) && (sid_func <= elib_end)) {
				/* The SID function comes from the ELIB range */

				/* Lookup SID function in the functions allocated list of ELIB range */
				for (ALL_LIST_ELEMENTS_RO(block->u.usid.lib
								  .func_allocated,
							  node, sid_func_ptr))
					if (*sid_func_ptr == sid_func)
						break;

				/* Ensure that the SID function is allocated */
				if (!sid_func_ptr) {
					zlog_warn("%s: failed to release SID function %u, function is not allocated",
						  __func__, sid_func);
					return -1;
				}

				/* Release the SID function from the ELIB range */
				listnode_delete(block->u.usid.lib.func_allocated,
						sid_func_ptr);
				zebra_srv6_sid_func_free(sid_func_ptr);
			} else if ((sid_func >= ewlib_start) &&
				   (sid_func <= ewlib_end)) {
				/* The SID function comes from the EWLIB range */

				/* Lookup SID function in the functions allocated list of EWLIB range */
				for (ALL_LIST_ELEMENTS_RO(block->u.usid
								  .wide_lib[sid_func - wlib_start]
								  .func_allocated,
							  node, sid_wide_func_ptr))
					if (*sid_wide_func_ptr == sid_wide_func)
						break;

				/* Ensure that the SID function is allocated */
				if (!sid_wide_func_ptr) {
					zlog_warn("%s: failed to release wide SID function %u, function is not allocated",
						  __func__, sid_wide_func);
					return -1;
				}

				/* Release the SID function from the EWLIB range */
				listnode_delete(block->u.usid.wide_lib[sid_func - wlib_start]
							.func_allocated,
						sid_wide_func_ptr);
				zebra_srv6_sid_func_free(sid_wide_func_ptr);
			} else {
				zlog_warn("%s: function %u is outside ELIB [%u/%u] and EWLIB alloc ranges [%u/%u]",
					  __func__, sid_func, elib_start,
					  elib_end, ewlib_start, ewlib_end);
				return -1;
			}
		} else if (format->type == SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
			uint32_t explicit_start =
				format->config.uncompressed.explicit_start;
			uint32_t explicit_end =
				(uint32_t)((1 << format->function_len) - 1);

			/* Ensure that the SID function comes from the Explicit range */
			if (!(sid_func >= explicit_start &&
			      sid_func <= explicit_end)) {
				zlog_warn("%s: function %u is outside explicit alloc range [%u/%u]",
					  __func__, sid_func, explicit_start,
					  explicit_end);
				return -1;
			}

			/* Lookup SID function in the functions allocated list of Explicit range */
			for (ALL_LIST_ELEMENTS_RO(block->u.uncompressed
							  .func_allocated,
						  node, sid_func_ptr))
				if (*sid_func_ptr == sid_func)
					break;

			/* Ensure that the SID function is allocated */
			if (!sid_func_ptr) {
				zlog_warn("%s: failed to release SID function %u, function is not allocated",
					  __func__, sid_func);
				return -1;
			}

			/* Release the SID function from the Explicit range */
			listnode_delete(block->u.uncompressed.func_allocated,
					sid_func_ptr);
			zebra_srv6_sid_func_free(sid_func_ptr);
		} else {
			/* We should never arrive here */
			assert(0);
		}
	} else {
		/* Lookup SID function in the functions allocated list of Explicit range */
		for (ALL_LIST_ELEMENTS_RO(block->u.uncompressed.func_allocated,
					  node, sid_func_ptr))
			if (*sid_func_ptr == sid_func)
				break;

		/* Ensure that the SID function is allocated */
		if (!sid_func_ptr) {
			zlog_warn("%s: failed to release SID function %u, function is not allocated",
				  __func__, sid_func);
			return -1;
		}

		/* Release the SID function from the Explicit range */
		listnode_delete(block->u.uncompressed.func_allocated,
				sid_func_ptr);
		zebra_srv6_sid_func_free(sid_func_ptr);
	}

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: released explicit SRv6 SID function %u from block %pFX",
			   __func__, sid_func, &block->prefix);

	return 0;
}

/**
 *  Release a dynamic SRv6 SID function.
 *
 * @param block Parent SRv6 SID block of the SID function that has to be released
 * @param sid_func SID function to be released
 * @return 0 on success, -1 otherwise
 */
static int release_srv6_sid_func_dynamic(struct zebra_srv6_sid_block *block,
					 uint32_t sid_func)
{
	struct srv6_sid_format *format;
	struct listnode *node, *nnode;
	uint32_t *sid_func_ptr = NULL;

	if (!block)
		return -1;

	format = block->sid_format;

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: trying to release dynamic SRv6 SID function %u from block %pFX",
			   __func__, sid_func, &block->prefix);

	/*
	 * Release SID function from the corresponding range depending on the SID format type
	 */
	if (format && format->type == SRV6_SID_FORMAT_TYPE_USID) {
		uint32_t dlib_start = format->config.usid.lib_start;
		/* The Dynamic LIB range ends where the Explicit LIB range begins */
		uint32_t dlib_end = format->config.usid.elib_start - 1;

		/* Ensure that the SID function to be released comes from the Dynamic LIB (DLIB) range */
		if (!(sid_func >= dlib_start && sid_func <= dlib_end)) {
			zlog_warn("%s: function %u is outside Dynamic LIB range [%u/%u]",
				  __func__, sid_func, dlib_start, dlib_end);
			return -1;
		}

		if (sid_func == block->u.usid.lib.first_available_func - 1) {
			/*
			 * The SID function to be released precedes the `first_available_func`.
			 * Reset first_available_func to the first available position.
			 */

			block->u.usid.lib.first_available_func -= 1;

			bool found;

			do {
				found = false;
				for (ALL_LIST_ELEMENTS(block->u.usid.lib
							       .func_released,
						       node, nnode,
						       sid_func_ptr))
					if (*sid_func_ptr ==
					    block->u.usid.lib.first_available_func -
						    1) {
						listnode_delete(block->u.usid
									.lib
									.func_released,
								sid_func_ptr);
						zebra_srv6_sid_func_free(
							sid_func_ptr);
						block->u.usid.lib
							.first_available_func -=
							1;
						found = true;
						break;
					}
			} while (found);
		} else {
			/*
			 * The SID function to be released does not precede the `first_available_func`.
			 * Add the released function to the func_released array to indicate
			 * that it is available again for allocation.
			 */
			sid_func_ptr = zebra_srv6_sid_func_alloc(sid_func);
			listnode_add_head(block->u.usid.lib.func_released,
					  sid_func_ptr);
		}
	} else if (format && format->type == SRV6_SID_FORMAT_TYPE_UNCOMPRESSED) {
		uint32_t dynamic_start =
			SRV6_SID_FORMAT_UNCOMPRESSED_F4024_FUNC_UNRESERVED_MIN;
		/* The Dynamic range ends where the Explicit range begins */
		uint32_t dynamic_end =
			format->config.uncompressed.explicit_start - 1;

		/* Ensure that the SID function to be released comes from the Dynamic range */
		if (!(sid_func >= dynamic_start && sid_func <= dynamic_end)) {
			zlog_warn("%s: function %u is outside dynamic range [%u/%u]",
				  __func__, sid_func, dynamic_start,
				  dynamic_end);
			return -1;
		}

		if (sid_func == block->u.uncompressed.first_available_func - 1) {
			/*
			 * The released SID function precedes the `first_available_func`.
			 * Reset first_available_func to the first available position.
			 */

			block->u.uncompressed.first_available_func -= 1;

			bool found;

			do {
				found = false;
				for (ALL_LIST_ELEMENTS(block->u.uncompressed
							       .func_released,
						       node, nnode,
						       sid_func_ptr))
					if (*sid_func_ptr ==
					    block->u.uncompressed
							    .first_available_func -
						    1) {
						listnode_delete(block->u.uncompressed
									.func_released,
								sid_func_ptr);
						zebra_srv6_sid_func_free(
							sid_func_ptr);
						block->u.uncompressed
							.first_available_func -=
							1;
						found = true;
						break;
					}
			} while (found);
		} else {
			/*
			 * The released SID function does not precede the `first_available_func`.
			 * Add the released function to the func_released array to indicate
			 * that it is available again for allocation.
			 */
			sid_func_ptr = zebra_srv6_sid_func_alloc(sid_func);
			listnode_add_head(block->u.uncompressed.func_released,
					  sid_func_ptr);
		}
	} else if (!format) {
		if (sid_func == block->u.uncompressed.first_available_func - 1) {
			/*
			 * The released SID function precedes the `first_available_func`.
			 * Reset first_available_func to the first available position.
			 */

			block->u.uncompressed.first_available_func -= 1;

			bool found;

			do {
				found = false;
				for (ALL_LIST_ELEMENTS(block->u.uncompressed
							       .func_released,
						       node, nnode,
						       sid_func_ptr))
					if (*sid_func_ptr ==
					    block->u.uncompressed
							    .first_available_func -
						    1) {
						listnode_delete(block->u.uncompressed
									.func_released,
								sid_func_ptr);
						zebra_srv6_sid_func_free(
							sid_func_ptr);
						block->u.uncompressed
							.first_available_func -=
							1;
						found = true;
						break;
					}
			} while (found);
		} else {
			/*
			 * The released SID function does not precede the `first_available_func`.
			 * Add the released function to the func_released array to indicate
			 * that it is available again for allocation.
			 */
			sid_func_ptr = zebra_srv6_sid_func_alloc(sid_func);
			listnode_add_head(block->u.uncompressed.func_released,
					  sid_func_ptr);
		}
	}

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: released dynamic SRv6 SID function %u from block %pFX",
			   __func__, sid_func, &block->prefix);

	return 0;
}

static void release_srv6_sid_func(const struct zebra_srv6_sid_ctx *zctx)
{
	if (!(zctx->sid->block->sid_format &&
	      zctx->sid->block->sid_format->type == SRV6_SID_FORMAT_TYPE_USID &&
	      zctx->ctx.behavior == ZEBRA_SEG6_LOCAL_ACTION_END) &&
	    !(!zctx->sid->block->sid_format && zctx->ctx.behavior == ZEBRA_SEG6_LOCAL_ACTION_END)) {
		if (zctx->sid->alloc_mode == SRV6_SID_ALLOC_MODE_EXPLICIT)
			/* Release SRv6 SID function */
			release_srv6_sid_func_explicit(zctx->sid->block, zctx->sid->func,
						       zctx->sid->wide_func);
		else if (zctx->sid->alloc_mode == SRV6_SID_ALLOC_MODE_DYNAMIC)
			/* Release SRv6 SID function */
			release_srv6_sid_func_dynamic(zctx->sid->block, zctx->sid->func);
		else
			/* We should never arrive here */
			assert(0);
	}
}

struct zebra_srv6_sid_client *zebra_srv6_sid_client_lookup(struct zebra_srv6_sid *sid,
							   struct zebra_srv6_sid_entry *entry,
							   struct zserv *client)
{
	struct zebra_srv6_sid_client *zclient;

	frr_each (zebra_srv6_sid_client_list, &entry->clients_list, zclient)
		if (zclient->client == client)
			return zclient;

	return NULL;
}

/**
 * Core function, release the SRv6 SID associated with a given context.
 *
 * @param client The client for which the SID has to be released
 * @param ctx Context associated with the SRv6 SID to be released
 * @param locator Parent locator of the SID
 * @param is_localonly SID is local-only
 * @return 0 on success, -1 otherwise
 */
int release_srv6_sid(struct zserv *client, struct zebra_srv6_sid_ctx *zctx,
		     struct srv6_locator *locator, bool is_localonly)
{
	char buf[256];
	struct zebra_srv6_sid_entry *entry;
	struct zebra_srv6_sid_client *zclient;
	struct zebra_srv6_sid_block *block;

	if (!zctx || !zctx->sid)
		return -1;

	block = zctx->sid->block;

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: releasing SRv6 SID func %u associated with ctx %s (proto=%u, instance=%u)",
			   __func__, zctx->sid->func,
			   srv6_sid_ctx2str(buf, sizeof(buf), &zctx->ctx), client->proto,
			   client->instance);

	entry = zebra_srv6_sid_entry_lookup(zctx->sid, locator->name, is_localonly);
	if (!entry) {
		zlog_err("SRv6 SID func %u ctx %s is not allocated from the provided locator %s",
			 zctx->sid->func, srv6_sid_ctx2str(buf, sizeof(buf), &zctx->ctx),
			 locator->name);
		return -1;
	}

	zclient = zebra_srv6_sid_client_lookup(zctx->sid, entry, client);
	if (!zclient) {
		flog_err(EC_ZEBRA_SM_DAEMON_MISMATCH, "%s: Daemon mismatch!!", __func__);
		return -1;
	}

	/* Remove the client from the list of clients using the SID */
	zebra_srv6_sid_client_del(zctx->sid, entry, zclient);

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: released SRv6 SID %u associated with ctx %s (proto=%u, instance=%u)",
			   __func__, zctx->sid->func,
			   srv6_sid_ctx2str(buf, sizeof(buf), &zctx->ctx), client->proto,
			   client->instance);

	/*
	 * If the SID is not used by any other client, then deallocate it
	 * and remove it from the SRv6 database.
	 */
	if (zebra_srv6_sid_entry_list_count(&zctx->sid->entries) == 0) {
		if (IS_ZEBRA_DEBUG_SRV6)
			zlog_debug("%s: SRv6 SID %u associated with ctx %s is no longer in use, removing it from SRv6 database",
				   __func__, zctx->sid->func,
				   srv6_sid_ctx2str(buf, sizeof(buf), &zctx->ctx));

		release_srv6_sid_func(zctx);

		/* Free the SID */
		zebra_srv6_sid_free(zctx->sid);
		zctx->sid = NULL;

		/* Remove the SID context from the list and free memory */
		zebra_srv6_sid_ctx_list_del(&block->sids, zctx);
		zebra_srv6_sid_ctx_free(zctx);
	}

	return 0;
}

/**
 * Handle a get SRv6 Locator request received from a client.
 *
 * It looks up the requested locator and send it to the client.
 *
 * @param locator SRv6 locator returned by this function
 * @param client The client that sent the Get SRv6 Locator request
 * @param locator_name Name of the locator to look up
 *
 * @return 0 on success
 */
static int srv6_manager_get_srv6_locator_internal(struct srv6_locator **locator,
						  struct zserv *client,
						  const char *locator_name)
{
	*locator = zebra_srv6_locator_lookup(locator_name);
	if (!*locator)
		return -1;

	return zsend_zebra_srv6_locator_add(client, *locator);
}

/**
 * Handle a get SID request received from a client.
 *
 * It gets a SID for a given context. If there is no SID associated with the context yet,
 * we allocate one and return it to the client. Otherwise, we return the existing SID.
 *
 * - When the `sid_value` parameter is non-NULL, SRv6 Manager assigns the requested SID value
 *   if it is available (explicit SID allocation).
 * - When the `sid_value` parameter is NULL, SRv6 Manager assigns any available SID value
 *   (dynamic SID allocation).
 *
 * Finally, notify the client whether the SID allocation was successful or failed.
 *
 * @param sid SID returned by this function
 * @param client The client that requested the SID
 * @param ctx Context for which the SID was requested
 * @param sid_value SID value (i.e., IPv6 address) that has to be assigned to the SID
 *                  (for explicit SID allocation)
 * @param locator_name Locator from which the SID has to be allocated (for dynamic SID allocation)
 * @param is_localonly SID is local-only
 *
 * @return 0 on success, -1 otherwise
 */
static int srv6_manager_get_sid_internal(struct zebra_srv6_sid **sid, struct zserv *client,
					 struct srv6_sid_ctx *ctx, struct in6_addr *sid_value,
					 const char *locator_name, bool is_localonly)
{
	int ret = -1;
	char buf[256];
	struct srv6_locator *locator = NULL;

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: getting SRv6 SID for ctx %s, sid_value=%pI6, locator_name=%s",
			   __func__, srv6_sid_ctx2str(buf, sizeof(buf), ctx),
			   sid_value ? sid_value : &in6addr_any, locator_name);

	if (locator_name && locator_name[0] != '\0') {
		locator = zebra_srv6_locator_lookup(locator_name);
		if (!locator) {
			zlog_err("%s: invalid SM request arguments: SRv6 locator '%s' does not exist",
				 __func__, locator_name);
			return -1;
		}
	}

	ret = get_srv6_sid(sid, ctx, sid_value, locator_name, is_localonly);
	if (ret < 0) {
		zlog_warn("%s: not got SRv6 SID for ctx %s, sid_value=%pI6, locator_name=%s",
			  __func__, srv6_sid_ctx2str(buf, sizeof(buf), ctx),
			  sid_value ? sid_value : &in6addr_any, locator_name);

		/* Notify client about SID alloc failure */
		zebra_srv6_sid_clients_notify_single(*sid, NULL, client, is_localonly,
						     ZAPI_SRV6_SID_FAIL_ALLOC);
	} else if (ret == 0) {
		assert(*sid);
		if (IS_ZEBRA_DEBUG_SRV6)
			zlog_debug("%s: got existing SRv6 SID for ctx %s: sid_value=%pI6 (func=%u) (proto=%u, instance=%u, sessionId=%u), notify client",
				   __func__, srv6_sid_ctx2str(buf, sizeof(buf), ctx), sid_value,
				   (*sid)->func, client->proto, client->instance,
				   client->session_id);
		zebra_srv6_sid_client_add(*sid, is_localonly, locator, client);
		zebra_srv6_sid_clients_notify_single(*sid, locator, client, is_localonly,
						     ZAPI_SRV6_SID_ALLOCATED);
	} else {
		if (IS_ZEBRA_DEBUG_SRV6)
			zlog_debug("%s: got new SRv6 SID for ctx %s: sid_value=%pI6 (func=%u) (proto=%u, instance=%u, sessionId=%u), notifying all clients",
				   __func__, srv6_sid_ctx2str(buf, sizeof(buf), ctx), sid_value,
				   (*sid)->func, client->proto, client->instance,
				   client->session_id);
		zebra_srv6_sid_client_add(*sid, is_localonly, locator, client);
		zebra_srv6_sid_clients_notify_all(*sid, locator, is_localonly,
						  ZAPI_SRV6_SID_ALLOCATED);
	}

	return ret;
}

/**
 * Release SRv6 SIDs from a client.
 *
 * Called on client disconnection or reconnection.
 *
 * @param client The client to release SIDs from
 * @return Number of SIDs released
 */
int release_daemon_srv6_sids(struct zserv *client)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct listnode *node_block;
	struct zebra_srv6_sid_ctx *ctx;
	int count = 0;
	struct zebra_srv6_sid_block *block;

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: releasing SRv6 SIDs for client proto %s, instance %d, session %u",
			   __func__, zebra_route_string(client->proto),
			   client->instance, client->session_id);

	/* Iterate over the SIDs and release SIDs used by the client daemon */
	for (ALL_LIST_ELEMENTS_RO(srv6->sid_blocks, node_block, block))
		frr_each_safe (zebra_srv6_sid_ctx_list, &block->sids, ctx)
			zebra_srv6_sid_client_del_all(ctx->sid, client);

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: released %d SRv6 SIDs", __func__, count);

	return count;
}

/**
 * Release SRv6 SIDs from a client.
 *
 * @param client The client zapi session
 * @param ctx Context associated with the SRv6 SID
 * @param locator_name Locator from which the SID has to be allocated (for dynamic SID allocation)
 * @param is_localonly SID is local-only
 * @return 0 on success, -1 on failure
 */
static int srv6_manager_release_sid_internal(struct zserv *client, struct srv6_sid_ctx *ctx,
					     const char *locator_name, bool is_localonly)
{
	int ret = -1;
	struct zebra_srv6_sid_ctx *zctx;
	char buf[256];
	struct srv6_locator *locator = NULL;
	struct in6_addr sid_value = {};
	struct zebra_srv6_sid_block *block = NULL;
	struct zebra_srv6_sid_entry *entry = NULL;

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: releasing SRv6 SID associated with ctx %s",
			   __func__, srv6_sid_ctx2str(buf, sizeof(buf), ctx));

	if (!locator_name || locator_name[0] == '\0') {
		zlog_err("%s: invalid SM request arguments: SRv6 locator not provided", __func__);
		return -1;
	}

	locator = zebra_srv6_locator_lookup(locator_name);
	if (!locator) {
		if (IS_ZEBRA_DEBUG_SRV6)
			zlog_debug("%s: SRv6 locator '%s' does not exist", __func__, locator_name);
		return 0;
	}

	block = locator->sid_block;

	/* Lookup Zebra SID context and release it */
	frr_each_safe (zebra_srv6_sid_ctx_list, &block->sids, zctx)
		if (memcmp(&zctx->ctx, ctx, sizeof(struct srv6_sid_ctx)) == 0) {
			if (zctx->sid) {
				entry = zebra_srv6_sid_entry_lookup(zctx->sid, locator->name,
								    is_localonly);
				if (!entry)
					break;

				sid_value = entry->sid_value;
			}

			ret = release_srv6_sid(client, zctx, locator, is_localonly);
			break;
		}

	if (IS_ZEBRA_DEBUG_SRV6)
		zlog_debug("%s: no SID associated with ctx %s", __func__,
			   srv6_sid_ctx2str(buf, sizeof(buf), ctx));

	if (ret == 0)
		zsend_srv6_sid_notify(client, ctx, &sid_value, 0, 0, locator_name,
				      ZAPI_SRV6_SID_RELEASED);
	else
		zsend_srv6_sid_notify(client, ctx, &sid_value, 0, 0, locator_name,
				      ZAPI_SRV6_SID_FAIL_RELEASE);

	return ret;
}

void zebra_srv6_terminate(void)
{
	struct srv6_locator *locator;
	struct srv6_sid_format *format;
	struct zebra_srv6_sid_block *block;
	struct zebra_srv6_sid_ctx *sid_ctx;

	if (g_srv6.locators) {
		while (listcount(g_srv6.locators)) {
			locator = listnode_head(g_srv6.locators);

			listnode_delete(g_srv6.locators, locator);
			srv6_locator_free(locator);
		}

		list_delete(&g_srv6.locators);
	}

	/* Free SRv6 SID blocks */
	if (g_srv6.sid_blocks) {
		while (listcount(g_srv6.sid_blocks)) {
			block = listnode_head(g_srv6.sid_blocks);

			/* Free SRv6 SIDs */
			while (zebra_srv6_sid_ctx_list_count(&block->sids)) {
				sid_ctx = zebra_srv6_sid_ctx_list_first(&block->sids);

				zebra_srv6_sid_free(sid_ctx->sid);

				zebra_srv6_sid_ctx_list_del(&block->sids, sid_ctx);
				zebra_srv6_sid_ctx_free(sid_ctx);
			}

			zebra_srv6_sid_ctx_list_fini(&block->sids);

			listnode_delete(g_srv6.sid_blocks, block);
			zebra_srv6_sid_block_free(block);
		}

		list_delete(&g_srv6.sid_blocks);
	}

	/* Free SRv6 SID formats */
	if (g_srv6.sid_formats) {
		while (listcount(g_srv6.sid_formats)) {
			format = listnode_head(g_srv6.sid_formats);

			srv6_sid_format_unregister(format);
			srv6_sid_format_free(format);
		}

		list_delete(&g_srv6.sid_formats);
	}
}

void zebra_srv6_init(void)
{
	hook_register(zserv_client_close, zebra_srv6_cleanup);
	hook_register(srv6_manager_get_chunk,
		      zebra_srv6_manager_get_locator_chunk);
	hook_register(srv6_manager_release_chunk,
		      zebra_srv6_manager_release_locator_chunk);

	hook_register(srv6_manager_get_sid, srv6_manager_get_sid_internal);
	hook_register(srv6_manager_release_sid,
		      srv6_manager_release_sid_internal);
	hook_register(srv6_manager_get_locator,
		      srv6_manager_get_srv6_locator_internal);
}

bool zebra_srv6_is_enable(void)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();

	return listcount(srv6->locators);
}
