









/* clang-format off */


DEFPY(staticd_show_graceful_restart, staticd_show_graceful_restart_cmd,
      "show static graceful-restart [vrf]$vrf_name [json]",
      SHOW_STR
      STATICD_STR
      GRACEFUL_RESTART_STR
      VRF_STR
      JSON_STR)
{
	vrf_id_t vrf_id;

	if (vrf_name) {
		vrf_id_t = vrf_id_lookup_by_name(vrf_name);

		if (!!json)
			show_static_gr_vrf_json(vty, vrf_id);
		else
			show_static_gr_vrf(vty, vrf_id);
	} else {
		if (!!json)
        		show_static_gr_vrf_all_json(vty);
		else
        		show_static_gr_vrf_all(vty);
	}

        return CMD_SUCCESS;
}


/* EOF */
