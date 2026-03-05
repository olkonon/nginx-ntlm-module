



/* ---------- режимы ntlm_mode ---------- */

typedef enum {
    NGX_NTLM_MODE_UNSET   = NGX_CONF_UNSET_UINT,
    NGX_NTLM_MODE_STRICT  = 0,
    NGX_NTLM_MODE_LENIENT = 1,
    NGX_NTLM_MODE_AUTO    = 2
} ngx_ntlm_mode_e;

/* ---------- прото ---------- */
