
/* location/server/main conf for ntlm_mode */
typedef struct {
    ngx_uint_t mode; /* ngx_ntlm_mode_e */
} ngx_http_upstream_ntlm_loc_conf_t;


/* ---------- режимы ntlm_mode ---------- */

typedef enum {
    NGX_NTLM_MODE_UNSET   = NGX_CONF_UNSET_UINT,
    NGX_NTLM_MODE_STRICT  = 0,
    NGX_NTLM_MODE_LENIENT = 1,
    NGX_NTLM_MODE_AUTO    = 2
} ngx_ntlm_mode_e;


/* ---------- upstream srv conf / cache ---------- */

typedef struct {
    ngx_uint_t max_cached;
    ngx_msec_t timeout;
    ngx_queue_t free;
    ngx_queue_t cache;
    ngx_shmtx_t *cache_mutex;   /* mutex for NTLM cache */
    ngx_http_upstream_init_pt original_init_upstream;
    ngx_http_upstream_init_peer_pt original_init_peer;
} ngx_http_upstream_ntlm_srv_conf_t;

typedef struct {
    ngx_http_upstream_ntlm_srv_conf_t *conf;
    ngx_queue_t queue;
    ngx_connection_t *peer_connection;
    ngx_connection_t *client_connection;
    unsigned client_closed:1;   /* A3: client aborted */
    unsigned queued_in_cache:1; /* A3: in cache queue now */
} ngx_http_upstream_ntlm_cache_t;

typedef struct {
    ngx_http_upstream_ntlm_srv_conf_t *conf;
    ngx_http_upstream_t *upstream;
    void *data;
    ngx_connection_t *client_connection;
    unsigned cached : 1;
    unsigned ntlm_init : 1;
    unsigned lenient : 1;              /* режим послабления A4 для long-poll */
    ngx_http_request_t *request;
    ngx_event_get_peer_pt original_get_peer;
    ngx_event_free_peer_pt original_free_peer;
#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt original_set_session;
    ngx_event_save_peer_session_pt original_save_session;
#endif

} ngx_http_upstream_ntlm_peer_data_t;
