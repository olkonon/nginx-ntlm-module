#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* ---------- режимы ntlm_mode ---------- */

typedef enum {
    NGX_NTLM_MODE_UNSET   = NGX_CONF_UNSET_UINT,
    NGX_NTLM_MODE_STRICT  = 0,
    NGX_NTLM_MODE_LENIENT = 1,
    NGX_NTLM_MODE_AUTO    = 2
} ngx_ntlm_mode_e;


/* ---------- прото ---------- */

static ngx_int_t
ngx_http_upstream_init_ntlm_peer(ngx_http_request_t *r,
                                 ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_ntlm_peer(ngx_peer_connection_t *pc,
                                                 void *data);
static void ngx_http_upstream_free_ntlm_peer(ngx_peer_connection_t *pc,
                                             void *data, ngx_uint_t state);

static void ngx_http_upstream_ntlm_dummy_handler(ngx_event_t *ev);
static void ngx_http_upstream_ntlm_close_handler(ngx_event_t *ev);
static void ngx_http_upstream_ntlm_close(ngx_connection_t *c);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_upstream_ntlm_set_session(ngx_peer_connection_t *pc,
                                                    void *data);
static void ngx_http_upstream_ntlm_save_session(ngx_peer_connection_t *pc,
                                                void *data);
#endif

static void *ngx_http_upstream_ntlm_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_ntlm(ngx_conf_t *cf, ngx_command_t *cmd,
                                    void *conf);

/* location/server/main conf for ntlm_mode */
typedef struct {
    ngx_uint_t mode; /* ngx_ntlm_mode_e */
} ngx_http_upstream_ntlm_loc_conf_t;

static void *ngx_http_upstream_ntlm_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_ntlm_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_upstream_ntlm_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void ngx_http_upstream_client_conn_cleanup(void *data);


/* ---------- upstream srv conf / cache ---------- */

typedef struct {
    ngx_uint_t max_cached;
    ngx_msec_t timeout;
    ngx_queue_t free;
    ngx_queue_t cache;
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


/* ---------- директивы ---------- */

static ngx_command_t ngx_http_upstream_ntlm_commands[] = {

    /* upstream-level */
    { ngx_string("ntlm"),
      NGX_HTTP_UPS_CONF | NGX_CONF_NOARGS | NGX_CONF_TAKE1,
      ngx_http_upstream_ntlm,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ntlm_timeout"),
      NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_ntlm_srv_conf_t, timeout),
      NULL },

    /* per-request mode (http/server/location) */
    { ngx_string("ntlm_mode"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_upstream_ntlm_mode,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


/* ---------- модульный контекст ---------- */

static ngx_http_module_t ngx_http_upstream_ntlm_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    ngx_http_upstream_ntlm_create_conf, /* create server (upstream srv) configuration */
    NULL,                                /* merge server configuration */

    ngx_http_upstream_ntlm_create_loc_conf,  /* create location config for ntlm_mode */
    ngx_http_upstream_ntlm_merge_loc_conf    /* merge location config */
};


/* ---------- определение модуля ---------- */

ngx_module_t ngx_http_upstream_ntlm_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_ntlm_ctx,     /* module context */
    ngx_http_upstream_ntlm_commands, /* module directives */
    NGX_HTTP_MODULE,                 /* module type */
    NULL,                            /* init master */
    NULL,                            /* init module */
    NULL,                            /* init process */
    NULL,                            /* init thread */
    NULL,                            /* exit thread */
    NULL,                            /* exit process */
    NULL,                            /* exit master */
    NGX_MODULE_V1_PADDING
};


/* ---------- helpers: auto-detect lenient for Exchange ---------- */

static ngx_table_elt_t *
ngx_http_ntlm_find_header(ngx_http_request_t *r, const char *name)
{
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *h = part->elts;
    ngx_uint_t i;

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (h[i].key.len == ngx_strlen(name) &&
            ngx_strncasecmp(h[i].key.data, (u_char *)name, h[i].key.len) == 0)
        {
            return &h[i];
        }
    }
    return NULL;
}

static ngx_uint_t
ngx_http_ntlm_should_lenient_auto(ngx_http_request_t *r)
{
    /* ActiveSync Ping: /Microsoft-Server-ActiveSync?Cmd=Ping */
    if (r->uri.len >= sizeof("/Microsoft-Server-ActiveSync") - 1 &&
        ngx_strncasecmp(r->uri.data, (u_char*)"/Microsoft-Server-ActiveSync",
                        sizeof("/Microsoft-Server-ActiveSync") - 1) == 0)
    {
        if (r->args.len &&
            ngx_strcasestrn(r->args.data, (char *)"Cmd=Ping", sizeof("Cmd=Ping")-1) != NULL)
        {
            return 1;
        }
    }

    /* MAPI notifications: /mapi/notifications... */
    if (r->uri.len >= sizeof("/mapi/notifications") - 1 &&
        ngx_strncasecmp(r->uri.data, (u_char*)"/mapi/notifications",
                        sizeof("/mapi/notifications") - 1) == 0)
    {
        return 1;
    }

    /* EWS streaming/pull: /EWS/... with SOAPAction / action= */
    if (r->uri.len >= 5 &&
        ngx_strncasecmp(r->uri.data, (u_char*)"/EWS/", 5) == 0)
    {
        /* SOAP 1.1: SOAPAction header */
        ngx_table_elt_t *sa = ngx_http_ntlm_find_header(r, "SOAPAction");
        if (sa && sa->value.len) {
            if (ngx_strcasestrn(sa->value.data, (char *)"GetStreamingEvents", sizeof("GetStreamingEvents")-1) ||
                ngx_strcasestrn(sa->value.data, (char *)"Subscribe",            sizeof("Subscribe")-1) ||
                ngx_strcasestrn(sa->value.data, (char *)"Connect",              sizeof("Connect")-1) ||
                ngx_strcasestrn(sa->value.data, (char *)"GetEvents",            sizeof("GetEvents")-1) ||
                ngx_strcasestrn(sa->value.data, (char *)"CreateSubscription",   sizeof("CreateSubscription")-1))
            {
                return 1;
            }
        }

        /* SOAP 1.2: Content-Type: ...; action="..." */
        if (r->headers_in.content_type) {
            if (ngx_strcasestrn(r->headers_in.content_type->value.data,
                                (char *)"action=", sizeof("action=")-1))
            {
                u_char *p = r->headers_in.content_type->value.data;
                /* простая проверка на наличие известных слов */
                if (ngx_strcasestrn(p, (char *)"GetStreamingEvents", sizeof("GetStreamingEvents")-1) ||
                    ngx_strcasestrn(p, (char *)"Subscribe",            sizeof("Subscribe")-1) ||
                    ngx_strcasestrn(p, (char *)"Connect",              sizeof("Connect")-1) ||
                    ngx_strcasestrn(p, (char *)"GetEvents",            sizeof("GetEvents")-1) ||
                    ngx_strcasestrn(p, (char *)"CreateSubscription",   sizeof("CreateSubscription")-1))
                {
                    return 1;
                }
            }
        }
    }

    return 0;
}


/* ---------- upstream init (srv conf) ---------- */

static ngx_int_t
ngx_http_upstream_init_ntlm(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t i;
    ngx_http_upstream_ntlm_cache_t *cached;
    ngx_http_upstream_ntlm_srv_conf_t *hncf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "ntlm init");

    hncf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_ntlm_module);

    ngx_conf_init_uint_value(hncf->max_cached, 100);
    ngx_conf_init_msec_value(hncf->timeout, 60000);

    if (hncf->original_init_upstream(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    hncf->original_init_peer = us->peer.init;
    us->peer.init = ngx_http_upstream_init_ntlm_peer;

    cached = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_ntlm_cache_t) *
                                       hncf->max_cached);
    if (cached == NULL) {
        return NGX_ERROR;
    }

    ngx_queue_init(&hncf->cache);
    ngx_queue_init(&hncf->free);

    for (i = 0; i < hncf->max_cached; i++) {
        ngx_queue_insert_head(&hncf->free, &cached[i].queue);
        cached[i].conf = hncf;
        cached[i].client_closed   = 0;
        cached[i].queued_in_cache = 0;
    }

    return NGX_OK;
}


/* ---------- peer init per request ---------- */

static ngx_int_t
ngx_http_upstream_init_ntlm_peer(ngx_http_request_t *r,
                                 ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_ntlm_peer_data_t *hnpd;
    ngx_http_upstream_ntlm_srv_conf_t  *hncf;
    ngx_http_upstream_ntlm_loc_conf_t  *lcf;
    ngx_str_t auth_header_value;

    /* upstream srv conf */
    hncf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_ntlm_module);

    /* allocate peer data */
    hnpd = ngx_palloc(r->pool, sizeof(ngx_http_upstream_ntlm_peer_data_t));
    if (hnpd == NULL) {
        return NGX_ERROR;
    }

    if (hncf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    hnpd->ntlm_init = 0;
    hnpd->cached = 0;
    hnpd->lenient = 0;

    if (r->headers_in.authorization != NULL) {
        auth_header_value = r->headers_in.authorization->value;

        if ((auth_header_value.len >= sizeof("NTLM") - 1 &&
             ngx_strncasecmp(auth_header_value.data, (u_char *)"NTLM",
                             sizeof("NTLM") - 1) == 0) ||
            (auth_header_value.len >= sizeof("Negotiate") - 1 &&
             ngx_strncasecmp(auth_header_value.data, (u_char *)"Negotiate",
                             sizeof("Negotiate") - 1) == 0))
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "ntlm auth header found");
            hnpd->ntlm_init = 1;
        }
    }

    hnpd->conf = hncf;
    hnpd->upstream = r->upstream;
    hnpd->request  = r;
    hnpd->data = r->upstream->peer.data;
    hnpd->client_connection = r->connection;

    /* прочитаем ntlm_mode из loc/server/main conf */
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_upstream_ntlm_module);
    if (lcf && lcf->mode != NGX_NTLM_MODE_UNSET) {
        switch (lcf->mode) {
        case NGX_NTLM_MODE_LENIENT:
            hnpd->lenient = 1; break;
        case NGX_NTLM_MODE_STRICT:
            hnpd->lenient = 0; break;
        case NGX_NTLM_MODE_AUTO:
        default:
            hnpd->lenient = ngx_http_ntlm_should_lenient_auto(r) ? 1 : 0;
            break;
        }
    } else {
        /* дефолт: AUTO */
        hnpd->lenient = ngx_http_ntlm_should_lenient_auto(r) ? 1 : 0;
    }

    hnpd->original_get_peer  = r->upstream->peer.get;
    hnpd->original_free_peer = r->upstream->peer.free;

    r->upstream->peer.data = hnpd;
    r->upstream->peer.get  = ngx_http_upstream_get_ntlm_peer;
    r->upstream->peer.free = ngx_http_upstream_free_ntlm_peer;

#if (NGX_HTTP_SSL)
    hnpd->original_set_session  = r->upstream->peer.set_session;
    hnpd->original_save_session = r->upstream->peer.save_session;

    r->upstream->peer.set_session  = ngx_http_upstream_ntlm_set_session;
    r->upstream->peer.save_session = ngx_http_upstream_ntlm_save_session;
#endif

    return NGX_OK;
}


/* ---------- get peer (reuse from cache) ---------- */

static ngx_int_t
ngx_http_upstream_get_ntlm_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_ntlm_peer_data_t *hndp = data;
    ngx_http_upstream_ntlm_cache_t *item;

    ngx_int_t rc;
    ngx_queue_t *q, *cache;
    ngx_connection_t *c;

    /* ask balancer */
    rc = hndp->original_get_peer(pc, hndp->data);
    if (rc != NGX_OK) {
        return rc;
    }

    /* search cache for suitable connection */
    cache = &hndp->conf->cache;

    for (q = ngx_queue_head(cache); q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q)) {
        item = ngx_queue_data(q, ngx_http_upstream_ntlm_cache_t, queue);

        if (item->client_connection == hndp->client_connection) {
            c = item->peer_connection;

            ngx_queue_remove(q);
            item->queued_in_cache = 0; /* A3 */
            ngx_queue_insert_head(&hndp->conf->free, q);

            hndp->cached = 1;
            goto found;
        }
    }

    return NGX_OK;

found:

    /* liveness check: явные плохие флаги */
    if (c->fd == (ngx_socket_t) -1
        || c->close
        || c->read->eof || c->read->error || c->read->timedout
        || c->write->error || c->write->timedout)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "ntlm peer cached connection %p is dead, closing", c);

        ngx_http_upstream_ntlm_close(c);
        pc->cached = 0;
        pc->connection = NULL;
        item->peer_connection = NULL;
        return NGX_OK;
    }

    /* A4: строгая проверка «тишины» только если !lenient */
    if (!hndp->lenient && c->read->ready) {
        int  n;
        char b;
        n = recv(c->fd, &b, 1, MSG_PEEK);
        if (n == 0 || (n == -1 && ngx_socket_errno != NGX_EAGAIN)) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "ntlm peer cached connection %p failed peek (n=%d), closing", c, n);
            ngx_http_upstream_ntlm_close(c);
            pc->cached = 0;
            pc->connection = NULL;
            item->peer_connection = NULL;
            return NGX_OK;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "ntlm peer using cached connection %p", c);

    /* prepare socket for reuse */
    c->idle = 0;
    c->sent = 0;
    c->data = NULL;

    if (c->read->timer_set)  ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    c->read->delayed = 0;

    c->read->handler  = NULL;
    c->write->handler = NULL;

    c->log        = pc->log;
    c->read->log  = pc->log;
    c->write->log = pc->log;
    c->pool->log  = pc->log;

    pc->connection = c;
    pc->cached     = 1;

    return NGX_DONE;
}


/* ---------- free peer (put to cache) ---------- */

static void
ngx_http_upstream_free_ntlm_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state)
{
    ngx_http_upstream_ntlm_peer_data_t *hndp = data;
    ngx_http_upstream_ntlm_cache_t *item;

    ngx_queue_t *q;
    ngx_connection_t *c;
    ngx_http_upstream_t *u;
    ngx_pool_cleanup_t *cln;
    ngx_http_upstream_ntlm_cache_t *cleanup_item = NULL;

    /* cache valid connections */
    u = hndp->upstream;
    c = pc->connection;

    if (state & NGX_PEER_FAILED || c == NULL || c->read->eof ||
        c->read->error || c->read->timedout || c->write->error ||
        c->write->timedout) {
        goto invalid;
    }

    if (!u->keepalive) {
        goto invalid;
    }

    if (!u->request_body_sent) {
        goto invalid;
    }

    if (ngx_terminate || ngx_exiting) {
        goto invalid;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        goto invalid;
    }

    if (hndp->ntlm_init == 0 && hndp->cached == 0) {
        goto invalid;
    }

    /* не кэшируем если есть несбитый вывод nginx */
    if (c->buffered) {
        goto invalid;
    }

    /* A4: строгая проверка «тишины» только если !lenient */
    if (!hndp->lenient && c->read->ready) {
        int  n; char b;
        n = recv(c->fd, &b, 1, MSG_PEEK);
        if (n > 0)  { goto invalid; } /* есть данные — не «тихо» */
        if (n == 0) { goto invalid; } /* FIN */
        if (n == -1 && ngx_socket_errno != NGX_EAGAIN) { goto invalid; }
    }

    if (ngx_queue_empty(&hndp->conf->free)) {
        q = ngx_queue_last(&hndp->conf->cache);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_upstream_ntlm_cache_t, queue);

        ngx_http_upstream_ntlm_close(item->peer_connection);
        item->peer_connection = NULL;
        item->client_closed   = 0;
        item->queued_in_cache = 0;

    } else {
        q = ngx_queue_head(&hndp->conf->free);
        ngx_queue_remove(q);
        item = ngx_queue_data(q, ngx_http_upstream_ntlm_cache_t, queue);
    }

    ngx_queue_insert_head(&hndp->conf->cache, q);
    item->queued_in_cache = 1;   /* A3 */

    item->peer_connection   = c;
    item->client_connection = hndp->client_connection;
    item->client_closed     = 0; /* A3 */

    ngx_log_debug2(
        NGX_LOG_DEBUG_HTTP, pc->log, 0,
        "ntlm free peer saving item client_connection %p, peer connection %p",
        item->client_connection, c);

    /* client connection cleanup: create once */
    for (cln = item->client_connection->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_upstream_client_conn_cleanup) {
            cleanup_item = cln->data;
            break;
        }
    }
    if (cleanup_item == NULL) {
        cln = ngx_pool_cleanup_add(item->client_connection->pool, 0);
        if (cln == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "ntlm free peer ngx_pool_cleanup_add returned null");
        } else {
            cln->handler = ngx_http_upstream_client_conn_cleanup;
            cln->data = item;
        }
    }

    pc->connection = NULL;

    /* idle-режим + таймер */
    c->read->delayed = 0;

    if (c->write->timer_set) ngx_del_timer(c->write);
    if (c->read->timer_set)  ngx_del_timer(c->read);
    ngx_add_timer(c->read, hndp->conf->timeout);

    c->write->handler = ngx_http_upstream_ntlm_dummy_handler;
    c->read->handler  = ngx_http_upstream_ntlm_close_handler;

    c->data = item;
    c->idle = 1;

    c->log        = ngx_cycle->log;
    c->read->log  = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log  = ngx_cycle->log;

    if (c->read->ready) {
        ngx_http_upstream_ntlm_close_handler(c->read);
    }

invalid:
    hndp->original_free_peer(pc, hndp->data, state);
}


/* ---------- cleanup on client connection close ---------- */

static void
ngx_http_upstream_client_conn_cleanup(void *data)
{
    ngx_http_upstream_ntlm_cache_t *item = data;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "ntlm client closed %p, posting close for upstream %p",
                   item->client_connection, item->peer_connection);

    if (item->peer_connection != NULL) {
        item->client_closed = 1;                     /* A1/A3 mark */
        item->peer_connection->read->timedout = 1;   /* force close-handler path */
        ngx_post_event(item->peer_connection->read, &ngx_posted_events);
    }
}


/* ---------- handlers ---------- */

static void
ngx_http_upstream_ntlm_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "ntlm dummy handler");
}

static void
ngx_http_upstream_ntlm_close_handler(ngx_event_t *ev)
{
    ngx_http_upstream_ntlm_srv_conf_t  *conf;
    ngx_http_upstream_ntlm_cache_t     *item;
    ngx_connection_t                   *c;
    int                                  n;
    char                                 buf[1];

    c = ev->data;

    /* идемпотентный гард */
    if (c->fd == (ngx_socket_t) -1 || c->close) {
        return;
    }

    /* если таймаута нет, проверить «живость» */
    if (!c->read->timedout) {
        n = recv(c->fd, buf, 1, MSG_PEEK);

        if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
            ev->ready = 0;

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                goto close;
            }

            return;
        }
    }

close:

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "ntlm close peer connection %p, timeout %ui",
                   c, c->read->timedout);

    item = c->data;
    conf = item->conf;

    /* не позволяем cleanup постить повторно */
    item->peer_connection = NULL;

    /* очередями управляем только здесь */
    if (item->queued_in_cache) {
        ngx_queue_remove(&item->queue);
        item->queued_in_cache = 0;
        ngx_queue_insert_head(&conf->free, &item->queue);
    }

    ngx_http_upstream_ntlm_close(c);

    item->client_closed = 0;
}

static void
ngx_http_upstream_ntlm_close(ngx_connection_t *c)
{
#if (NGX_HTTP_SSL)
    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_upstream_ntlm_close;
            return;
        }
    }
#endif

    if (c->pool) {
        ngx_destroy_pool(c->pool);
        c->pool = NULL;
    }
    ngx_close_connection(c);
}


/* ---------- SSL session passthrough ---------- */

#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_upstream_ntlm_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_ntlm_peer_data_t *hndp = data;
    return hndp->original_set_session(pc, hndp->data);
}

static void
ngx_http_upstream_ntlm_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_ntlm_peer_data_t *hndp = data;
    hndp->original_save_session(pc, hndp->data);
    return;
}

#endif


/* ---------- create srv conf (upstream) ---------- */

static void *
ngx_http_upstream_ntlm_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_ntlm_srv_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_ntlm_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->max_cached = NGX_CONF_UNSET_UINT;
    conf->timeout    = NGX_CONF_UNSET_MSEC;

    return conf;
}


/* ---------- upstream directive "ntlm" ---------- */

static char *
ngx_http_upstream_ntlm(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t *uscf;
    ngx_http_upstream_ntlm_srv_conf_t *hncf = conf;

    ngx_int_t n;
    ngx_str_t *value;

    /* read options */
    if (cf->args->nelts == 2) {
        value = cf->args->elts;
        n = ngx_atoi(value[1].data, value[1].len);
        if (n == NGX_ERROR || n == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ntlm invalid value \"%V\" in \"%V\" directive",
                               &value[1], &cmd->name);
            return NGX_CONF_ERROR;
        }
        hncf->max_cached = (ngx_uint_t) n;
    }

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    hncf->original_init_upstream = uscf->peer.init_upstream
                                       ? uscf->peer.init_upstream
                                       : ngx_http_upstream_init_round_robin;

    uscf->peer.init_upstream = ngx_http_upstream_init_ntlm;

    return NGX_CONF_OK;
}


/* ---------- location/server/main conf for ntlm_mode ---------- */

static void *
ngx_http_upstream_ntlm_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_ntlm_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_ntlm_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->mode = NGX_NTLM_MODE_UNSET;
    return conf;
}

static char *
ngx_http_upstream_ntlm_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_upstream_ntlm_loc_conf_t *prev = parent;
    ngx_http_upstream_ntlm_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->mode, prev->mode, NGX_NTLM_MODE_AUTO);
    return NGX_CONF_OK;
}

static char *
ngx_http_upstream_ntlm_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_ntlm_loc_conf_t *lcf = conf;

    ngx_str_t       *value = cf->args->elts;
    ngx_str_t        m = value[1];

    if (ngx_strcasecmp(m.data, (u_char *)"strict") == 0) {
        lcf->mode = NGX_NTLM_MODE_STRICT;
        return NGX_CONF_OK;
    }
    if (ngx_strcasecmp(m.data, (u_char *)"lenient") == 0) {
        lcf->mode = NGX_NTLM_MODE_LENIENT;
        return NGX_CONF_OK;
    }
    if (ngx_strcasecmp(m.data, (u_char *)"auto") == 0) {
        lcf->mode = NGX_NTLM_MODE_AUTO;
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid value \"%V\" in \"ntlm_mode\"; "
                       "expected strict|lenient|auto", &m);
    return NGX_CONF_ERROR;
}