#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <pthread.h>

typedef struct {
    ngx_flag_t enable;
} ngx_http_isucon_loc_conf_t;

static char* ngx_http_isucon(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void* ngx_http_isucon_create_loc_conf(ngx_conf_t *cf);

typedef int bool;
typedef struct {
    uint32_t id;
    char login[32];
    int login_len;
    uint32_t passwd_hash;
    char salt[10];
    char pass[32];
} isucon_user_t;
typedef struct {
    uint32_t id;
    time_t created_at;
    uint32_t user;
    uint32_t ip;
    bool succeeded;
} isucon_log_t;
typedef struct {
    isucon_user_t *user;
    int cap;
    int len;
    isucon_log_t **items;
} isucon_log_id_idx_t;
typedef struct {
    uint32_t ip;
    int cap;
    int len;
    isucon_log_t **items;
} isucon_log_ip_idx_t;
typedef struct {
    isucon_user_t *user;
    uint32_t ip;
    const char *msg;
} isucon_session_t;

static time_t startup_time;
static ngx_str_t template_base_0;
static ngx_str_t template_base_1;
static ngx_str_t template_index_0;
static ngx_str_t template_index_1;
static ngx_str_t template_mypage_0;
static ngx_str_t template_mypage_1;
static ngx_str_t template_mypage_2;
static ngx_str_t template_mypage_3;

static ngx_str_t public_isucon_bank_png;
static ngx_str_t public_bootflat_min_css;
static ngx_str_t public_bootstrap_min_css;
static ngx_str_t public_isucon_bank_css;

#define ERROR_BANNED -1
#define ERROR_LOCKED -2
#define ERROR_WRONG_PASSWD -3
#define ERROR_WRONG_LOGIN  -4

#define SESSION_BANNED  1
#define SESSION_LOCKED  2
#define SESSION_WRONG   3
#define SESSION_NOLOGIN 4

#define False 0
#define True  1

static void isucon_login_log(time_t access_time, bool succeeded, uint32_t user_id, uint32_t ip);
static bool isucon_user_locked(uint32_t user_id);
static bool isucon_ip_banned(uint32_t ip);
static uint32_t isucon_compute_hash(const char *pass, int pass_len, const char *salt, int salt_len);
static const isucon_user_t* isucon_attempt_login(const char *login, const char *password, uint32_t ip, int *reason);
static const isucon_log_t* isucon_last_login(const isucon_user_t *user);
static uint32_t* isucon_banned_ips(int *length);
static uint32_t* isucon_locked_users(int *length);

static void _set_session(ngx_http_request_t*, int);
static int _get_session(ngx_http_request_t*);
static ngx_int_t index_(ngx_http_request_t*);
static ngx_int_t login(ngx_http_request_t*);
static ngx_int_t mypage(ngx_http_request_t*);
static ngx_int_t report(ngx_http_request_t*);

static isucon_user_t *db_users;
static int db_users_len, db_users_cap;
static isucon_log_t *db_log;
static volatile int db_log_len;
static int db_log_cap;
static isucon_log_id_idx_t *db_idx_id;
static isucon_log_ip_idx_t *db_idx_ip;
static const uint32_t idx_ip_base = (127 << 24) | (1 << 16) | 1;
static const uint32_t idx_ip_len  = 256 * 256 * 256; // 16Mi
static isucon_session_t *db_session;
static int db_session_len, db_session_cap;
static void db_init();

static pthread_mutex_t db_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t db_session_mutex = PTHREAD_MUTEX_INITIALIZER;

static int user_lock_threshold = 3;
static int ip_ban_threshold = 10;
static char *host_ip = NULL;

static ngx_command_t ngx_http_isucon_commands[] = {
    {
        ngx_string("isucon"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_isucon,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_isucon_module_ctx = {
    NULL,  /* preconfiguration */
    NULL,  /* postconfiguration */

    NULL,  /* create main configuration */
    NULL,  /* init main configuration */

    NULL,  /* create server configuration */
    NULL,  /* merge server configuration */

    ngx_http_isucon_create_loc_conf,  /* create location configuration */
    NULL
};

ngx_str_t _load_file(const char *path)
{
    FILE *f;
    ngx_str_t str;
    f = fopen(path, "rb");
    if (!f) abort();
    fseek(f, 0, SEEK_END);
    str.len = ftell(f);
    str.data = (u_char*)malloc(str.len);
    fseek(f, 0, SEEK_SET);
    fread(str.data, 1, str.len, f);
    fclose(f);
    return str;
}

void set_redirect_url(ngx_http_request_t *r, const char *url)
{
    char buf[64];
    ngx_str_t tmp;
    if (!host_ip) {
        if (r->headers_in.host) {
            char *ip = (char*)malloc(r->headers_in.host->value.len + 1);
            memcpy(ip, r->headers_in.host->value.data,
                   r->headers_in.host->value.len);
            ip[r->headers_in.host->value.len] = '\0';
            host_ip = ip;
        }
    }
    if (host_ip) {
        sprintf(buf, "http://%s%s", host_ip, url);
    } else {
        sprintf(buf, "%s", url);
    }
    //printf("redirect: %s\n", buf);
    tmp.len = strlen(buf);
    tmp.data = (u_char*)buf;
    r->headers_out.location->value.len = tmp.len;
    r->headers_out.location->value.data = ngx_pstrdup(r->pool, &tmp);
}

static ngx_int_t ngx_http_isucon_init_module(ngx_cycle_t *cycle)
{
    time(&startup_time);

    public_isucon_bank_png = _load_file("/home/isucon/webapp/public/images/isucon-bank.png");
    public_bootflat_min_css = _load_file("/home/isucon/webapp/public/stylesheets/bootflat.min.css");
    public_bootstrap_min_css = _load_file("/home/isucon/webapp/public/stylesheets/bootstrap.min.css");
    public_isucon_bank_css = _load_file("/home/isucon/webapp/public/stylesheets/isucon-bank.css");

    template_base_0 = _load_file("/home/isucon/webapp/ringo/base_0.html");
    template_base_1 = _load_file("/home/isucon/webapp/ringo/base_1.html");
    template_index_0 = _load_file("/home/isucon/webapp/ringo/index_0.html");
    template_index_1 = _load_file("/home/isucon/webapp/ringo/index_1.html");
    template_mypage_0 = _load_file("/home/isucon/webapp/ringo/mypage_0.html");
    template_mypage_1 = _load_file("/home/isucon/webapp/ringo/mypage_1.html");
    template_mypage_2 = _load_file("/home/isucon/webapp/ringo/mypage_2.html");
    template_mypage_3 = _load_file("/home/isucon/webapp/ringo/mypage_3.html");

    db_init();

    return NGX_OK;
}

ngx_module_t ngx_http_isucon_module = {
    NGX_MODULE_V1,
    &ngx_http_isucon_module_ctx, /* module context */
    ngx_http_isucon_commands,    /* module directives */
    NGX_HTTP_MODULE,             /* module type */
    NULL,                        /* init master */
    ngx_http_isucon_init_module, /* init module */
    NULL,                        /* init process */
    NULL,                        /* init thread */
    NULL,                        /* exit thread */
    NULL,                        /* exit process */
    NULL,                        /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_isucon_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_isucon_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_isucon_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    return conf;
}

static ngx_int_t
ngx_http_isucon_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_chain_t out;
    ngx_str_t *target = NULL;
    char *mime = "text/css";
    int mime_len = 8;

    if (ngx_strncmp(r->uri.data, "/", r->uri.len) == 0) {
        ngx_http_discard_request_body(r);
        if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)))
            return NGX_HTTP_NOT_ALLOWED;
        return index_(r);
    } else if (ngx_strncmp(r->uri.data, "/login", r->uri.len) == 0) {
        if (!(r->method & NGX_HTTP_POST)) {
            ngx_http_discard_request_body(r);
            return NGX_HTTP_NOT_ALLOWED;
        }
        return login(r);
    } else if (ngx_strncmp(r->uri.data, "/mypage", r->uri.len) == 0) {
        ngx_http_discard_request_body(r);
        if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)))
            return NGX_HTTP_NOT_ALLOWED;
        return mypage(r);
    } else if (ngx_strncmp(r->uri.data, "/report", r->uri.len) == 0) {
        ngx_http_discard_request_body(r);
        if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)))
            return NGX_HTTP_NOT_ALLOWED;
        return report(r);
    }

    ngx_http_discard_request_body(r);
    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)))
        return NGX_HTTP_NOT_ALLOWED;

    if (ngx_strncmp(r->uri.data, "/images/isucon-bank.png", r->uri.len) == 0) {
        mime = "image/png";
        mime_len = 9;
        target = &public_isucon_bank_png;
    } else if (ngx_strncmp(r->uri.data, "/stylesheets/bootflat.min.css", r->uri.len) == 0) {
        target = &public_bootflat_min_css;
    } else if (ngx_strncmp(r->uri.data, "/stylesheets/bootstrap.min.css", r->uri.len) == 0) {
        target = &public_bootstrap_min_css;
    } else if (ngx_strncmp(r->uri.data, "/stylesheets/isucon-bank.css", r->uri.len) == 0) {
        target = &public_isucon_bank_css;
    } else {
        return NGX_HTTP_NOT_FOUND;
    }

    // TODO: if-modified-since

    out.buf = ngx_pcalloc(r->pool, target->len);
    out.buf->pos = ngx_pstrdup(r->pool, target);
    out.buf->last = out.buf->pos + target->len;
    out.buf->memory = 1;
    out.buf->last_buf = 1;
    out.next = NULL;

    r->headers_out.content_type.len = mime_len;
    r->headers_out.content_type.data = (u_char *)mime;
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = target->len;
    r->headers_out.last_modified_time = startup_time;

    if (r->method == NGX_HTTP_HEAD) {
        ngx_pfree(r->pool, out.buf);
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    return ngx_http_output_filter(r, &out);
}

static char *
ngx_http_isucon(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_isucon_handler;

    return NGX_CONF_OK;
}

static void isucon_login_log(time_t access_time, bool succeeded, uint32_t user_id, uint32_t ip)
{
    int id;

    pthread_mutex_lock(&db_log_mutex);
    id = db_log_len;
    db_log[id].id = id;
    db_log[id].created_at = access_time;
    db_log[id].user = user_id;
    db_log[id].ip = ip;
    db_log[id].succeeded = succeeded;
    ++db_log_len;
    pthread_mutex_unlock(&db_log_mutex);

    if (db_log_len > db_log_cap) {
        printf("overflow db-log\n");
        fflush(stdout);
        abort();
    }
}

static bool isucon_user_locked(uint32_t user_id)
{
    int i;
    int cnt = 0;
    //pthread_mutex_lock(&db_log_mutex);
    i = db_log_len - 1;
    //pthread_mutex_unlock(&db_log_mutex);
    for (; i >= 0; --i) {
        if (db_log[i].user != user_id)
            continue;
        if (db_log[i].succeeded)
            break;
        ++cnt;
    }
    return user_lock_threshold <= cnt;
}

static bool isucon_ip_banned(uint32_t ip)
{
    int i;
    int cnt = 0;
    //pthread_mutex_lock(&db_log_mutex);
    i = db_log_len - 1;
    //pthread_mutex_unlock(&db_log_mutex);
    for (; i >= 0; --i) {
        if (db_log[i].ip != ip)
            continue;
        if (db_log[i].succeeded)
            break;
        ++cnt;
    }
    return ip_ban_threshold <= cnt;
}

static const isucon_user_t* isucon_attempt_login(const char *login, const char *password, uint32_t ip, int *reason)
{
    int i;
    int len = strlen(login);
    const isucon_user_t *found_user = NULL;
    time_t now;
    time(&now);
    *reason = ERROR_WRONG_LOGIN;

    for (i = 0; i < db_users_len; ++i) {
        if (len != db_users[i].login_len) continue;
        if (memcmp(login, db_users[i].login, len) == 0) {
            found_user = db_users + i;
            break;
        }
    }

    if (isucon_ip_banned(ip)) {
        if (found_user) {
            isucon_login_log(now, False, found_user->id, ip);
        } else {
            isucon_login_log(now, False, 0, ip);
        }
        *reason = ERROR_BANNED;
        return NULL;
    }

    if (found_user && isucon_user_locked(found_user->id)) {
        isucon_login_log(now, False, found_user->id, ip);
        *reason = ERROR_LOCKED;
        return NULL;
    }

    if (!found_user) {
        isucon_login_log(now, False, 0, ip);
        *reason = ERROR_WRONG_LOGIN;
        return NULL;
    } else if (found_user->passwd_hash == isucon_compute_hash(password, strlen(password),
                                                              found_user->salt, strlen(found_user->salt))) {
        if (strcmp(found_user->pass, password) != 0)
            printf("hash equal but password mismatch\n");
        isucon_login_log(now, True, found_user->id, ip);
        return found_user;
    } else {
        isucon_login_log(now, False, found_user->id, ip);
        *reason = ERROR_WRONG_PASSWD;
        return NULL;
    }
}

static const isucon_log_t* isucon_last_login(const isucon_user_t *user)
{
    int i;
    uint32_t user_id = user->id;
    int cnt = 0;
    int cur_id = -1;
    //pthread_mutex_lock(&db_log_mutex);
    i = db_log_len - 1;
    //pthread_mutex_unlock(&db_log_mutex);
    for (; i >= 0; --i) {
        if (db_log[i].user != user_id)
            continue;
        if (db_log[i].succeeded) {
            if (cnt == 1)
                return &(db_log[i]);
            cur_id = i;
            ++cnt;
        }
    }
    if (cur_id >= 0)
        return &(db_log[cur_id]);
    return NULL;
}

static uint32_t* isucon_banned_ips(int *length)
{
    int i;
    int len = 0, q = 0;
    uint8_t *lst = (uint8_t*)malloc(sizeof(uint8_t) * idx_ip_len);
    uint8_t *counts = (uint8_t*)malloc(sizeof(uint8_t) * idx_ip_len);
    uint32_t *ret;
    //pthread_mutex_lock(&db_log_mutex);
    i = db_log_len - 1;
    //pthread_mutex_unlock(&db_log_mutex);
    memset(lst, 0, sizeof(uint8_t) * idx_ip_len);
    memset(counts, 0, sizeof(uint8_t) * idx_ip_len);
    for (; i >= 0; --i) {
        if (db_log[i].ip - idx_ip_base >= idx_ip_len) {
            printf("    cnt_idx %d is out-of-range\n", db_log[i].ip - idx_ip_base);fflush(stdout);
            abort();
        }
        if (db_log[i].succeeded) {
            if (counts[db_log[i].ip - idx_ip_base] < ip_ban_threshold) {
                lst[db_log[i].ip - idx_ip_base] = 1;
            }
        } else {
            ++counts[db_log[i].ip - idx_ip_base];
        }
    }

    for (i = 0; i < idx_ip_len; ++i) {
        if (counts[i] < ip_ban_threshold) {
            lst[i] = 1;
            continue;
        }
        if (!lst[i]) ++len;
    }
    printf("found %d banned ips\n", len);fflush(stdout);

    *length = len;
    if (len == 0) {
        ret = NULL;
    } else {
        ret = (uint32_t*)malloc(sizeof(uint32_t) * len);
        for (i = 0; i < idx_ip_len; ++i) {
            if (lst[i]) continue;
            ret[q++] = idx_ip_base + i;
        }
    }
    free(lst);
    free(counts);
    return ret;
}

// TODO: banned_ipsと統合するか，user-idでインデックスを張る
// TODO: 登録されていないユーザの扱いを…
static uint32_t* isucon_locked_users(int *length)
{
    int i;
    int len = 0, q = 0;
    int lst_size = db_users_len + 1;
    uint8_t *lst = (uint8_t*)malloc(sizeof(uint8_t) * lst_size);
    uint8_t *counts = (uint8_t*)malloc(sizeof(uint8_t) * lst_size);
    uint32_t *ret;
    //pthread_mutex_lock(&db_log_mutex);
    i = db_log_len - 1;
    //pthread_mutex_unlock(&db_log_mutex);
    memset(lst, 0, sizeof(uint8_t) * lst_size);
    memset(counts, 0, sizeof(uint8_t) * lst_size);
    for (; i >= 0; --i) {
        if (db_log[i].succeeded) {
            if (counts[db_log[i].user] < user_lock_threshold) {
                lst[db_log[i].user] = 1;
            }
        } else {
            ++counts[db_log[i].user];
        }
    }

    // user_id == 0 は不明なユーザ名を示すのでスキップ
    for (i = 1; i < lst_size; ++i) {
        if (counts[i] < user_lock_threshold) {
            lst[i] = 1;
            continue;
        }
        if (!lst[i])
            ++len;
    }
    *length = len;
    printf("found %d locked users\n", *length);fflush(stdout);

    if (*length == 0) {
        ret = NULL;
    } else {
        q = 0;
        ret = (uint32_t*)malloc(sizeof(uint32_t) * (*length));
        for (i = 1; i < lst_size; ++i) {
            if (lst[i]) continue;
            ret[q++] = (uint32_t)i;
        }
    }
    free(lst);
    free(counts);
    return ret;
}

static int _get_session(ngx_http_request_t *r)
{
    if (r->headers_in.cookies.nelts > 0) {
        int i;
        char buf[32];
        int id;
        ngx_table_elt_t **h = r->headers_in.cookies.elts;
        for (i = 0; i < r->headers_in.cookies.nelts; ++i) {
            if (h[i]->value.len >= 32) continue;
            memcpy(buf, h[i]->value.data, h[i]->value.len);
            buf[h[i]->value.len] = '\0';
            if ( strstr(buf, "_session_id_=") != buf) continue;
            sscanf(buf + 14, "%x", &id);
            return id;
        }
    }
    return 0;
}

static void _set_session(ngx_http_request_t *r, int session_id)
{
    char buf[64];
    ngx_str_t tmp;
    sprintf(buf, "_session_id_=%x; HttpOnly; Path=/", session_id);
    tmp.data = (u_char*)buf;
    tmp.len = strlen(buf);

    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    h->hash = 1;
    h->key.len = sizeof("Set-Cookie") - 1;
    h->key.data = (u_char *)"Set-Cookie";
    h->value.len = tmp.len;
    h->value.data = ngx_pstrdup(r->pool, &tmp);
}

static int _copy_template(ngx_http_request_t *r,
                           ngx_chain_t *chain,
                           ngx_str_t *template)
{
    chain->next = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    chain = chain->next;
    chain->buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    chain->buf->pos = ngx_pstrdup(r->pool, template);
    chain->buf->last = chain->buf->pos + template->len;
    chain->buf->memory = 1;
    return template->len;
}

static int _copy_str(ngx_http_request_t *r,
                     ngx_chain_t *chain,
                     const char *str)
{
    ngx_str_t tmp;
    tmp.data = (u_char*)str;
    tmp.len = strlen(str);
    chain->next = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    chain = chain->next;
    chain->buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    chain->buf->pos = ngx_pstrdup(r->pool, &tmp);
    chain->buf->last = chain->buf->pos + tmp.len;
    chain->buf->memory = 1;
    return tmp.len;
}

static ngx_chain_t _build_base0(ngx_http_request_t *r)
{
    ngx_chain_t out;
    out.buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    out.buf->pos = ngx_pstrdup(r->pool, &template_base_0);
    out.buf->last = out.buf->pos + template_base_0.len;
    out.buf->memory = 1;
    return out;
}

static uint32_t _get_ip(ngx_http_request_t *r)
{
    uint32_t ip = (uint32_t)(((struct sockaddr_in*)r->connection->sockaddr)->sin_addr.s_addr);
    if (r->headers_in.x_forwarded_for.nelts > 0) {
        ngx_table_elt_t **elts = r->headers_in.x_forwarded_for.elts;
        char ip_buf[16];
        struct in_addr addr;
        memcpy(ip_buf, elts[0]->value.data, elts[0]->value.len);
        ip_buf[elts[0]->value.len] = '\0';
        inet_aton(ip_buf, &addr);
        ip = addr.s_addr;
    } else {
        abort();
    }
    ip = (ip >> 24)
        | (((ip >> 16) & 0xff) << 8)
        | (((ip >>  8) & 0xff) << 16)
        | (((ip >>  0) & 0xff) << 24);
    if (ip < idx_ip_base || ip >= idx_ip_base + idx_ip_len) {
        printf("ip out-of-range: %x (%s)\n", ip,
               (r->headers_in.x_forwarded_for.nelts > 0 ? "x-forwarded-for" : "conn"));
        fflush(stdout);
        abort();
    }
    return ip;
}

static ngx_int_t index_(ngx_http_request_t *r)
{
    ngx_chain_t out = _build_base0(r);
    ngx_chain_t *chain = &out;
    int len = template_base_0.len;
    ngx_int_t rc;
    int session = _get_session(r);
    //printf("index-page: session=%d\n", session);

    len += _copy_template(r, chain, &template_index_0); chain = chain->next;
    if (session == SESSION_LOCKED || session == SESSION_BANNED
        || session == SESSION_WRONG || session == SESSION_NOLOGIN) {
        len += _copy_str(r, chain, "    <div id=\"notice-message\" class=\"alert alert-danger\" role=\"alert\">");
        chain = chain->next;
        len += _copy_str(r, chain, db_session[session].msg);
        chain = chain->next;
        len += _copy_str(r, chain, "</div>");
        chain = chain->next;
    }
    _set_session(r, 0);
    len += _copy_template(r, chain, &template_index_1); chain = chain->next;
    len += _copy_template(r, chain, &template_base_1);  chain = chain->next;
    chain->buf->last_buf = 1;

    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *)"text/html";
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;
    if (r->method == NGX_HTTP_HEAD) {
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static int _read_request_buffer(ngx_http_request_t *r, char *body, int max_buf)
{
    if (r->request_body->temp_file) {
        return ngx_read_file(&r->request_body->temp_file->file, (u_char*)body, max_buf, 0);
    } else {
        ngx_buf_t *buf;
        ngx_chain_t  *cl;
        int off = 0;
        cl = r->request_body->bufs;
        for (;NULL != cl; cl = cl->next) {
            buf = cl->buf;
            memcpy(body + off, buf->pos, buf->last - buf->pos);
            off += buf->last - buf->pos;
        }
        return off;
    }
}

static void _login(ngx_http_request_t *r)
{
    char body[1024];
    int body_len = _read_request_buffer(r, body, 1024);
    char *login;
    char *passwd;
    char *strtmp;
    const isucon_user_t *user;
    int reason;
    uint32_t ip = _get_ip(r);

    body[body_len] = '\0';
    strtmp = strstr(body, "login=");
    if (!strtmp) {
        printf("login-form parse error#1\n");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    login = strtmp + 6;
    strtmp = strstr(body, "password=");
    if (!strtmp) {
        printf("login-form parse error#2\n");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    passwd = strtmp + 9;
    strtmp = strstr(body, "&");
    if (!strtmp) {
        printf("login-form parse error#3\n");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    *strtmp = '\0';

    user = isucon_attempt_login(login, passwd, ip, &reason);
    if (user) {
        int session_id;
        pthread_mutex_lock(&db_session_mutex);
        session_id = db_session_len++;
        db_session[session_id].user = user;
        db_session[session_id].ip = ip;
        pthread_mutex_unlock(&db_session_mutex);
        _set_session(r, session_id);
        if (db_session_len > db_session_cap) {
            printf("session overflow\n"); fflush(stdout);
            abort();
        }
        //printf("login %d %x\n", user->id, ip);
    } else {
        int session_id;
        switch (reason) {
        case ERROR_BANNED:
            session_id = SESSION_BANNED;
            break;
        case ERROR_LOCKED:
            session_id = SESSION_LOCKED;
            break;
        default:
            session_id = SESSION_WRONG;
            break;
        }
        _set_session(r, session_id);
        //printf("login failed: %s %x reason=%d\n", login, ip, session_id);
    }

    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *)"text/html";
    r->headers_out.status = NGX_HTTP_MOVED_TEMPORARILY;
    r->headers_out.content_length_n = 0;

    r->headers_out.location = ngx_list_push(&r->headers_out.headers);
    r->headers_out.location->hash = 1;
    r->headers_out.location->key.len = sizeof("Location") - 1;
    r->headers_out.location->key.data = (u_char *) "Location";
    if (user) {
        set_redirect_url(r, "/mypage");
    } else {
        set_redirect_url(r, "/");
    }
    ngx_http_finalize_request(r, NGX_HTTP_MOVED_TEMPORARILY);
}

static ngx_int_t login(ngx_http_request_t *r)
{
    ngx_int_t rc;
    rc = ngx_http_read_client_request_body(r, _login);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
        return rc;
    return NGX_DONE;
}

static ngx_int_t mypage(ngx_http_request_t *r)
{
    ngx_chain_t out = _build_base0(r);
    ngx_chain_t *chain = &out;
    int len = template_base_0.len;
    ngx_int_t rc;
    int session = _get_session(r);
    char buf[32];
    struct tm dt;
    isucon_user_t *user;
    isucon_log_t *last_login;
    uint32_t ip = _get_ip(r);

    if (session == 0 || !db_session[session].user || db_session[session].ip != ip) {
        if (db_session[session].ip != ip)
            printf("invalid session: wrong ip\n");
        r->headers_out.content_type.len = sizeof("text/html") - 1;
        r->headers_out.content_type.data = (u_char *)"text/html";
        r->headers_out.status = NGX_HTTP_MOVED_TEMPORARILY;
        r->headers_out.content_length_n = 0;

        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
        r->headers_out.location->hash = 1;
        r->headers_out.location->key.len = sizeof("Location") - 1;
        r->headers_out.location->key.data = (u_char *) "Location";
        set_redirect_url(r, "/");

        _set_session(r, SESSION_NOLOGIN);
        return NGX_HTTP_MOVED_TEMPORARILY;
    }

    user = db_session[session].user;
    last_login = isucon_last_login(user);
    //printf("last: %s %d %x %d\n", user->login, user->id, last_login->ip, last_login->succeeded);
    len += _copy_template(r, chain, &template_mypage_0); chain = chain->next;

    gmtime_r(&(last_login->created_at), &dt);
    strftime(buf, 32, "%Y-%m-%d %H:%M:%S", &dt);
    len += _copy_str(r, chain, buf); chain = chain->next;
    len += _copy_template(r, chain, &template_mypage_1); chain = chain->next;
    sprintf(buf, "%d.%d.%d.%d",
            (last_login->ip >> 24) & 0xff,
            (last_login->ip >> 16) & 0xff,
            (last_login->ip >>  8) & 0xff,
            (last_login->ip >>  0) & 0xff);
    len += _copy_str(r, chain, buf); chain = chain->next;
    len += _copy_template(r, chain, &template_mypage_2); chain = chain->next;
    len += _copy_str(r, chain, user->login); chain = chain->next;
    len += _copy_template(r, chain, &template_mypage_3); chain = chain->next;
    len += _copy_template(r, chain, &template_base_1);  chain = chain->next;
    chain->buf->last_buf = 1;

    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *)"text/html";
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;
    if (r->method == NGX_HTTP_HEAD) {
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t report(ngx_http_request_t *r)
{
    ngx_chain_t out;
    ngx_chain_t *chain = &out;
    int len;
    ngx_int_t rc;
    int i, ips_len, users_len;
    uint32_t *ips = isucon_banned_ips(&ips_len);
    uint32_t *users = isucon_locked_users(&users_len);

    char buf[32];
    static const char *lead_text = "{\"banned_ips\": [";

    {
        ngx_str_t tmp;
        tmp.len = strlen(lead_text);
        tmp.data = (u_char*)lead_text;
        out.buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        out.buf->pos = ngx_pstrdup(r->pool, &tmp);
        out.buf->last = out.buf->pos + tmp.len;
        out.buf->memory = 1;
        len = tmp.len;
    }
    for (i = 0; i < ips_len; ++i) {
        if (i != ips_len - 1) {
            sprintf(buf, "\"%d.%d.%d.%d\",",
                    (ips[i] >> 24) & 0xff,
                    (ips[i] >> 16) & 0xff,
                    (ips[i] >>  8) & 0xff,
                    (ips[i] >>  0) & 0xff);
        } else {
            sprintf(buf, "\"%d.%d.%d.%d\"",
                    (ips[i] >> 24) & 0xff,
                    (ips[i] >> 16) & 0xff,
                    (ips[i] >>  8) & 0xff,
                    (ips[i] >>  0) & 0xff);
        }
        len += _copy_str(r, chain, buf); chain = chain->next;
    }
    len += _copy_str(r, chain, "], \"locked_users\": ["); chain = chain->next;
    for (i = 0; i < users_len; ++i) {
        if (i != users_len - 1) {
            sprintf(buf, "\"%s\",", db_users[users[i]].login);
        } else {
            sprintf(buf, "\"%s\"", db_users[users[i]].login);
        }
        len += _copy_str(r, chain, buf); chain = chain->next;
    }
    len += _copy_str(r, chain, "]}"); chain = chain->next;
    chain->buf->last_buf = 1;

    if (ips) free(ips);
    if (users) free(users);

    r->headers_out.content_type.len = sizeof("application/json") - 1;
    r->headers_out.content_type.data = (u_char *)"application/json";
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;
    if (r->method == NGX_HTTP_HEAD) {
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static uint32_t isucon_compute_hash(const char *pass, int pass_len, const char *salt, int salt_len)
{
    char temp[64];
    memcpy(temp, pass, pass_len);
    temp[pass_len] = ':';
    memcpy(temp + pass_len + 1, salt, salt_len);
    return ngx_murmur_hash2(temp, pass_len + salt_len + 1);
}

static void db_init()
{
    static const int MAX_LINE = 256;
    char line[MAX_LINE];
    int id, succeeded;
    int64_t time;
    uint32_t user_id, ip;
    char login[32];
    char passwd[32];
    char salt[16];
    FILE *f;
    int count = 0;

    db_users_cap = 200000;
    db_users = (isucon_user_t*)malloc(sizeof(isucon_user_t) * db_users_cap);
    db_users_len = 0;

    db_log_cap = 1000000 + 70000;
    db_log = (isucon_log_t*)malloc(sizeof(isucon_log_t) * db_log_cap);
    db_log_len = 0;

    if (!(f = fopen("/home/isucon/sql/dummy_users.tsv", "r")))
        abort();
    while (fgets(line, MAX_LINE, f) != NULL) {
        if (sscanf(line, "%d\t%s\t%s\t%s\t", &id, login, passwd, salt) != 4)
            continue;
        db_users[db_users_len].id = (uint32_t)id;
        db_users[db_users_len].passwd_hash = isucon_compute_hash(passwd, strlen(passwd),
                                                                 salt, strlen(salt));
        strcpy(db_users[db_users_len].login, login);
        strcpy(db_users[db_users_len].pass, passwd);
        db_users[db_users_len].login_len = strlen(login);
        strcpy(db_users[db_users_len].salt, salt);
        ++db_users_len;
    }
    fclose(f);

    if (!(f = fopen("/home/isucon/sql/dummy_log.tsv", "r")))
        abort();
    while (fgets(line, MAX_LINE, f) != NULL) {
        if (sscanf(line, "%lld\t%u\t%u\t%d", &time, &user_id, &ip, &succeeded) != 4) {
            printf("failed\n");
            fflush(stdout);
            abort();
            continue;
        }
        isucon_login_log((time_t)time, (bool)succeeded, user_id, ip);
    }
    printf("load log: %d\n", db_log_len);
    fclose(f);

    db_idx_id = (isucon_log_id_idx_t*)malloc(sizeof(isucon_log_id_idx_t) * (db_users_len + 1));
    memset(db_idx_id, 0, sizeof(isucon_log_id_idx_t) * (db_users_len + 1));

    db_idx_ip = (isucon_log_ip_idx_t*)malloc(sizeof(isucon_log_ip_idx_t) * idx_ip_len);
    memset(db_idx_ip, 0, sizeof(isucon_log_ip_idx_t) * idx_ip_len);

    db_session_cap = 10000;
    db_session = (isucon_session_t*)malloc(sizeof(isucon_session_t) * db_session_cap);
    db_session_len = 0;

    db_session[SESSION_BANNED].user = NULL;
    db_session[SESSION_BANNED].msg  = "You're banned.";
    db_session[SESSION_LOCKED].user = NULL;
    db_session[SESSION_LOCKED].msg  = "This account is locked.";
    db_session[SESSION_WRONG].user = NULL;
    db_session[SESSION_WRONG].msg  = "Wrong username or password";
    db_session[SESSION_NOLOGIN].user = NULL;
    db_session[SESSION_NOLOGIN].msg  = "You must be logged in";
    db_session_len = SESSION_NOLOGIN + 1;
}
