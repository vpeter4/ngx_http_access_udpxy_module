
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Peter Vicman
 *  derived from http_access (C) Igor Sysoev & Nginx, Inc
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define UDPXY_LOG 01

/* todo later */
#undef NGX_HAVE_INET6

#define URL_UDP_START_STR     "/udp/"
#define URL_UDP_START_STR_LEN (sizeof(URL_UDP_START_STR) - 1)
#define AUTH_BASIC_STR        "Basic "
#define AUTH_BASIC_STR_LEN    (sizeof(AUTH_BASIC_STR) - 1)

#if UDPXY_LOG == 1
/*#define UDPXY_DEBUG(log, fmt, ...) \
          ngx_log_error(NGX_LOG_EMERG, log, 0, fmt1, __VA_ARGS__)

#define UDPXY_DEBUG0(log, fmt) \
          ngx_log_error(NGX_LOG_EMERG, log1, 0, fmt1)*/

#define UDPXY_DEBUG(log, fmt, ...) \
          ngx_log_stderr(0, fmt, __VA_ARGS__)

#define UDPXY_DEBUG0(log, fmt) \
          ngx_log_stderr(0, fmt)
#else
#define UDPXY_DEBUG(log1, fmt1, ...)

#define UDPXY_DEBUG0(log1, fmt1, ...)
#endif

typedef struct {
    ngx_str_t         user;
    in_addr_t         mask_src;
    in_addr_t         addr_src;
    in_addr_t         mask_dest;
    in_addr_t         addr_dest;
    ngx_uint_t        deny;      /* unsigned  deny:1; */
} ngx_http_access_udpxy_rule_t;

#if (NGX_HAVE_INET6)
typedef struct {
    ngx_str_t         user;
    in_addr_t         mask_src;
    in_addr_t         addr_src;
    struct in6_addr   addr_dest;
    struct in6_addr   mask_dest;
    ngx_uint_t        deny;      /* unsigned  deny:1; */
} ngx_http_access_udpxy_rule6_t;
#endif

typedef struct {
    ngx_array_t      *rules;     /* array of ngx_http_access_udpxy_rule_t */
#if (NGX_HAVE_INET6)
    ngx_array_t      *rules6;    /* array of ngx_http_access_udpxy_rule6_t */
#endif
} ngx_http_access_udpxy_loc_conf_t;

/* contents of the request's authorization header */
typedef struct {
  ngx_str_t username;
  ngx_str_t uri;
} ngx_http_access_udpxy_cred_t;

static ngx_int_t ngx_http_access_udpxy_authorization(ngx_http_request_t *r,
    ngx_http_access_udpxy_cred_t *ctx);
static ngx_int_t ngx_http_access_udpxy_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_access_udpxy_inet(ngx_http_request_t *r,
    ngx_http_access_udpxy_loc_conf_t *alcf, in_addr_t addr_src, in_addr_t addr_dest,
    ngx_str_t *user);
#if (NGX_HAVE_INET6)
static ngx_int_t ngx_http_access_udpxy_inet6(ngx_http_request_t *r,
    ngx_http_access_udpxy_loc_conf_t *alcf, u_char *p);
#endif
static ngx_int_t ngx_http_access_udpxy_found(ngx_http_request_t *r, ngx_uint_t deny);
static char *ngx_http_access_udpxy_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_http_access_udpxy_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_access_udpxy_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_access_udpxy_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_access_udpxy_commands[] = {
    { ngx_string("allow_udpxy"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_access_udpxy_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("deny_udpxy"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_access_udpxy_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_access_udpxy_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_access_udpxy_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_access_udpxy_create_loc_conf, /* create location configuration */
    ngx_http_access_udpxy_merge_loc_conf   /* merge location configuration */
};


ngx_module_t  ngx_http_access_udpxy_module = {
    NGX_MODULE_V1,
    &ngx_http_access_udpxy_module_ctx,     /* module context */
    ngx_http_access_udpxy_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/*
 * copied from ngx_http_auth_resource_module.c
 *
 * copyright (c) Erik Dubbelboer
 * fork from nginx-http-auth-digest (c) samizdat drafting co.
 * derived from http_auth_basic (c) igor sysoev
 */
static ngx_int_t ngx_http_access_udpxy_authorization(ngx_http_request_t *r,
    ngx_http_access_udpxy_cred_t *ctx) {

  if (r->headers_in.authorization == NULL)
    return NGX_DECLINED;

  /*
     token          = 1*<any CHAR except CTLs or separators>
     separators     = "(" | ")" | "<" | ">" | "@"
                    | "," | ";" | ":" | "\" | <">
                    | "/" | "[" | "]" | "?" | "="
                    | "{" | "}" | SP | HT
  */

  static uint32_t token_char[] = {
      0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

      /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
      0x03ff6cf8, /* 0000 0011 1111 1111  0110 1100 1111 1000 */

      /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
      0xc7fffffe, /* 1100 0111 1111 1111  1111 1111 1111 1110 */

      /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
      0x57ffffff, /* 0101 0111 1111 1111  1111 1111 1111 1111 */

      0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
      0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
      0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
      0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
  };

  u_char ch, *p, *last, *start = 0, *end;
  ngx_str_t name, value;
  ngx_int_t comma_count = 0, quoted_pair_count = 0;

  name.data = 0;
  name.len = 0;
  value.data = 0;
  value.len = 0;

  enum {
    sw_start = 0,
    sw_scheme,
    sw_scheme_end,
    sw_lws_start,
    sw_lws,
    sw_param_name_start,
    sw_param_name,
    sw_param_value_start,
    sw_param_value,
    sw_param_quoted_value,
    sw_param_end,
    sw_error,
  } state;

  ngx_str_t    encoded = r->headers_in.authorization->value;
  ngx_str_t    encoded_auth;
  ngx_int_t    rc;
  ngx_str_t    decoded;

  UDPXY_DEBUG(r->connection->log, "ngx_http_access_udpxy_authorization: '%V'", &encoded);
  UDPXY_DEBUG(r->connection->log, "r->uri: '%V'", &r->uri);

  /* Authorization: Digest username="user1", realm="myrealm", nonce="07dfe63f5953d9c8", uri="/udp/239.1.1.1:5000", ...
     Authorization: Basic dDJhZG1pbjpwYXNz */
  if (ngx_strncmp(encoded.data, AUTH_BASIC_STR, AUTH_BASIC_STR_LEN) == 0) {
    encoded_auth.data = encoded.data + AUTH_BASIC_STR_LEN;
    encoded_auth.len = encoded.len - AUTH_BASIC_STR_LEN;

    UDPXY_DEBUG(r->connection->log, "ngx_http_access_udpxy_authorization encoded_auth: '%V'", &encoded_auth);

    decoded.data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(encoded_auth.len));
    if (decoded.data == NULL)
      return NGX_ERROR;

    rc = ngx_decode_base64(&decoded, &encoded_auth);
    if (rc != NGX_OK)
      return NGX_ERROR;

    UDPXY_DEBUG(r->connection->log, "ngx_decode_base64: '%V'", &decoded);

    p = ngx_strlchr(decoded.data, decoded.data + decoded.len, ':');
    if (p == NULL)
      return NGX_ERROR;

    ctx->username.data = decoded.data;
    ctx->username.len = p - decoded.data;
    ctx->uri = r->uri;

    UDPXY_DEBUG(r->connection->log, "ctx->username: '%V'", &ctx->username);
    UDPXY_DEBUG(r->connection->log, "ctx->uri: '%V'", &ctx->uri);

    return NGX_OK;
  }

  state = sw_start;
  p = encoded.data;
  last = encoded.data + encoded.len;

  ch = *p++;

  while (p <= last) {
    switch (state) {
    default:
    case sw_error:
      return NGX_DECLINED;

    /* first char */
    case sw_start:
      if (ch == CR || ch == LF || ch == ' ' || ch == '\t') {
        ch = *p++;
      } else if (token_char[ch >> 5] & (1 << (ch & 0x1f))) {
        start = p - 1;
        state = sw_scheme;
      } else {
        state = sw_error;
      }
      break;

    case sw_scheme:
      if (token_char[ch >> 5] & (1 << (ch & 0x1f))) {
        ch = *p++;
      } else if (ch == ' ') {
        end = p - 1;
        state = sw_scheme_end;

        if (ngx_strncasecmp(start, (u_char *)"Digest", end - start) != 0)
          state = sw_error;
      } else {
        state = sw_error;
      }
      break;

    case sw_scheme_end:
      if (ch == ' ') {
        ch = *p++;
      } else {
        state = sw_param_name_start;
      }
      break;

    case sw_lws_start:
      comma_count = 0;
      state = sw_lws;

    /* fall through */
    case sw_lws:
      if (comma_count > 0 && (token_char[ch >> 5] & (1 << (ch & 0x1f)))) {
        state = sw_param_name_start;
      } else if (ch == ',') {
        comma_count++;
        ch = *p++;
      } else if (ch == CR || ch == LF || ch == ' ' || ch == '\t') {
        ch = *p++;
      } else {
        state = sw_error;
      }
      break;

    case sw_param_name_start:
      if (token_char[ch >> 5] & (1 << (ch & 0x1f))) {
        start = p - 1;
        state = sw_param_name;
        ch = *p++;
      } else {
        state = sw_error;
      }
      break;

    case sw_param_name:
      if (token_char[ch >> 5] & (1 << (ch & 0x1f))) {
        ch = *p++;
      } else if (ch == '=') {
        end = p - 1;
        state = sw_param_value_start;

        name.data = start;
        name.len = end - start;

        ch = *p++;
      } else {
        state = sw_error;
      }
      break;

    case sw_param_value_start:
      if (token_char[ch >> 5] & (1 << (ch & 0x1f))) {
        start = p - 1;
        state = sw_param_value;
        ch = *p++;
      } else if (ch == '\"') {
        start = p;
        quoted_pair_count = 0;
        state = sw_param_quoted_value;
        ch = *p++;
      } else {
        state = sw_error;
      }
      break;

    case sw_param_value:
      if (token_char[ch >> 5] & (1 << (ch & 0x1f))) {
        ch = *p++;
      } else {
        end = p - 1;
        value.data = start;
        value.len = end - start;
        state = sw_param_end;
      }
      break;

    case sw_param_quoted_value:
      if (ch < 0x20 || ch == 0x7f) {
        state = sw_error;
      } else if (ch == '\\' && *p <= 0x7f) {
        quoted_pair_count++;
        /* Skip the next char, even if it's a \ */
        ch = *(p += 2);
      } else if (ch == '\"') {
        end = p - 1;
        ch = *p++;
        value.data = start;
        value.len = end - start - quoted_pair_count;
        if (quoted_pair_count > 0) {
          value.data = ngx_palloc(r->pool, value.len);
          u_char *d = value.data;
          u_char *s = start;
          for (; s < end; s++) {
            ch = *s;
            if (ch == '\\') {
              /* Make sure to add the next character
               * even if it's a \
               */
              s++;
              if (s < end) {
                *d++ = ch;
              }
              continue;
            }
            *d++ = ch;
          }
        }
        state = sw_param_end;
        goto param_end;
      } else {
        ch = *p++;
      }
      break;

    param_end:
    case sw_param_end:
      if (ngx_strncasecmp(name.data, (u_char *)"username", name.len) == 0) {
        ctx->username = value;
        ctx->uri = r->uri;
        UDPXY_DEBUG(r->connection->log, "authorization username: '%V'", &ctx->username);
        UDPXY_DEBUG(r->connection->log, "authorization uri: '%V'", &ctx->uri);
      }

      state = sw_lws_start;
      break;
    }
  }

  if (state != sw_lws_start && state != sw_lws) {
    return NGX_DECLINED;
  }

  /* check values */
  if (!(ctx->username.len > 0 && ctx->uri.len > 0)) {
    return NGX_DECLINED;
  }

  return NGX_OK;
}


static ngx_int_t
ngx_http_access_udpxy_handler(ngx_http_request_t *r)
{
    ngx_http_access_udpxy_loc_conf_t  *alcf;
#if (NGX_HAVE_INET6)
    in_addr_t                     addr;
    struct sockaddr_in6          *sin6;
#endif
    u_char                       *p;
    char uri_ip[INET_ADDRSTRLEN] = {0};
    size_t                        uri_ip_len;
    struct sockaddr_in           *sin_src;
    struct in_addr                addr_dest;
    ngx_http_access_udpxy_cred_t *auth_fields;
    ngx_int_t                     rc;

    /* unpack the Authorization header */
    auth_fields = ngx_pcalloc(r->pool, sizeof(ngx_http_access_udpxy_cred_t));
    if (auth_fields == NULL)
      return NGX_HTTP_INTERNAL_SERVER_ERROR;

    rc = ngx_http_access_udpxy_authorization(r, auth_fields);
    if (rc == NGX_DECLINED)
      return NGX_OK;
    else if (rc == NGX_ERROR)
      return NGX_HTTP_INTERNAL_SERVER_ERROR;

    /* check if starts with /udp/ */
    if (ngx_strncmp(auth_fields->uri.data, URL_UDP_START_STR, URL_UDP_START_STR_LEN) != 0) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "URI '%V' doesn't start with '%s' (skip)", &auth_fields->uri, URL_UDP_START_STR);
      return NGX_DECLINED;
    }

    /* /udp/239.10.1.91:5000 */
    p = ngx_strlchr(auth_fields->uri.data, auth_fields->uri.data + auth_fields->uri.len, ':');
    if (p != NULL)
        uri_ip_len = (p - auth_fields->uri.data) - URL_UDP_START_STR_LEN;
    else
        uri_ip_len = auth_fields->uri.len - URL_UDP_START_STR_LEN;

    if (uri_ip_len >= sizeof(uri_ip))
      return NGX_DECLINED;

    memcpy(&uri_ip, auth_fields->uri.data + URL_UDP_START_STR_LEN, uri_ip_len);
    uri_ip[uri_ip_len] = '\0';

    UDPXY_DEBUG(r->connection->log, "uri_ip '%s'", uri_ip);

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_access_udpxy_module);

    sin_src = (struct sockaddr_in *) r->connection->sockaddr;
    inet_aton(uri_ip, &addr_dest);

    if (alcf->rules)
        return ngx_http_access_udpxy_inet(r, alcf, sin_src->sin_addr.s_addr, addr_dest.s_addr, &auth_fields->username);

/* todo */
#if 0
    switch (&addr->sa_family) {
    case AF_INET:
        if (alcf->rules) {
            return ngx_http_access_udpxy_inet(r, alcf, addr.s_addr, &auth_fields->username);
        }
        break;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        p = sin6->sin6_addr.s6_addr;

        if (alcf->rules && IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            addr = p[12] << 24;
            addr += p[13] << 16;
            addr += p[14] << 8;
            addr += p[15];
            return ngx_http_access_udpxy_inet(r, alcf, htonl(addr));
        }

        if (alcf->rules6) {
            return ngx_http_access_udpxy_inet6(r, alcf, p);
        }

        break;

#endif
    }
#endif

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_access_udpxy_inet(ngx_http_request_t *r, ngx_http_access_udpxy_loc_conf_t *alcf,
    in_addr_t addr_src, in_addr_t addr_dest, ngx_str_t *user)
{
    ngx_uint_t               i;
    ngx_http_access_udpxy_rule_t  *rule;

    rule = alcf->rules->elts;

    for (i = 0; i < alcf->rules->nelts; i++) {
        UDPXY_DEBUG0((r->connection->log), "******************************************************************");
        UDPXY_DEBUG(r->connection->log, "           checking rule user: '%V' '%V'",
            &rule[i].user, user);
        UDPXY_DEBUG(r->connection->log, "     checking rule permission:  %s",
            (rule[i].deny == 1) ? "deny" : "allow");
        UDPXY_DEBUG(r->connection->log, "            checking addr_src: '%s'",
            inet_ntoa(*(struct in_addr *)&addr_src));
        UDPXY_DEBUG(r->connection->log, "       checking rule addr_src: '%s'",
            inet_ntoa(*(struct in_addr *)&rule[i].addr_src));
        UDPXY_DEBUG(r->connection->log, "       checking rule mask_src: '%s'",
            inet_ntoa(*(struct in_addr *)&rule[i].mask_src));
        UDPXY_DEBUG(r->connection->log, "           checking addr_dest: '%s'",
            inet_ntoa(*(struct in_addr *)&addr_dest));
        UDPXY_DEBUG(r->connection->log, "      checking rule addr_dest: '%s'",
            inet_ntoa(*(struct in_addr *)&rule[i].addr_dest));
        UDPXY_DEBUG(r->connection->log, "      checking rule mask_dest: '%s'",
            inet_ntoa(*(struct in_addr *)&rule[i].mask_dest));
        UDPXY_DEBUG0(r->connection->log, "******************************************************************");

        if (rule[i].user.len == user->len &&
            ngx_strncmp(rule[i].user.data, user->data, user->len) == 0) {
          UDPXY_DEBUG0(r->connection->log, "for this user");

          if ((addr_src & rule[i].mask_src) == rule[i].addr_src &&
              (addr_dest & rule[i].mask_dest) == rule[i].addr_dest) {
            UDPXY_DEBUG0(r->connection->log, "all IP/mask check ok");
            return ngx_http_access_udpxy_found(r, rule[i].deny);
          }
        }
    }

    return NGX_DECLINED;
    /* return NGX_HTTP_FORBIDDEN;  default is forbidden */
}


#if (NGX_HAVE_INET6)
static ngx_int_t
ngx_http_access_udpxy_inet6(ngx_http_request_t *r, ngx_http_access_udpxy_loc_conf_t *alcf,
    u_char *p)
{
    ngx_uint_t                n;
    ngx_uint_t                i;
    ngx_http_access_udpxy_rule6_t  *rule6;

    rule6 = alcf->rules6->elts;
    for (i = 0; i < alcf->rules6->nelts; i++) {

#if (NGX_DEBUG)
        {
        size_t  cl, ml, al;
        u_char  ct[NGX_INET6_ADDRSTRLEN];
        u_char  mt[NGX_INET6_ADDRSTRLEN];
        u_char  at[NGX_INET6_ADDRSTRLEN];

        cl = ngx_inet6_ntop(p, ct, NGX_INET6_ADDRSTRLEN);
        ml = ngx_inet6_ntop(rule6[i].mask_dest.s6_addr, mt, NGX_INET6_ADDRSTRLEN);
        al = ngx_inet6_ntop(rule6[i].addr_dest.s6_addr, at, NGX_INET6_ADDRSTRLEN);

        ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "access: %*s %*s %*s", cl, ct, ml, mt, al, at);
        }
#endif

        for (n = 0; n < 16; n++) {
            if ((p[n] & rule6[i].mask_dest.s6_addr[n]) != rule6[i].addr_dest.s6_addr[n]) {
                goto next;
            }
        }

        return ngx_http_access_udpxy_found(r, rule6[i].deny);

    next:
        continue;
    }

    return NGX_DECLINED;
}
#endif


static ngx_int_t
ngx_http_access_udpxy_found(ngx_http_request_t *r, ngx_uint_t deny)
{
    ngx_http_core_loc_conf_t  *clcf;

    if (deny) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->satisfy == NGX_HTTP_SATISFY_ALL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "access to resource forbidden by udpxy rule");
        }

        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_OK;
}


static char *
ngx_http_access_udpxy_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_access_udpxy_loc_conf_t *alcf = conf;

    ngx_int_t                   rc;
    ngx_uint_t                  all;
    ngx_http_access_udpxy_rule_t     *rule;
#if (NGX_HAVE_INET6)
    ngx_http_access_udpxy_rule6_t    *rule6;
#endif
    ngx_cidr_t                  cidr_src;
    ngx_cidr_t                  cidr_dest;
    ngx_str_t                  *value_arg;
    ngx_str_t                   value_user = ngx_null_string;
    ngx_str_t                   value_src = ngx_null_string;
    ngx_str_t                   value_dest = ngx_null_string;
    u_char                     *p_comma1;
    u_char                     *p_comma2;
    ngx_str_t                   user_tmp = ngx_null_string;

    value_arg = cf->args->elts;

    UDPXY_DEBUG(cf->log, "value_arg[1].data '%V'", &value_arg[1]);
    UDPXY_DEBUG(cf->log, "value_arg[1].len %d", value_arg[1].len);

    /* admin,223.56.1.4,239.10.1.9 */
    p_comma1 = ngx_strlchr(value_arg[1].data, value_arg[1].data + value_arg[1].len, ',');
    if (p_comma1 == NULL)
        goto parameter_error;

    p_comma2 = ngx_strlchr(p_comma1 + 1, value_arg[1].data + value_arg[1].len, ',');
    if (p_comma2 == NULL) {
      parameter_error:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "invalid parameter: '%V' should be 'user,src_ip/mask,dest_ip/mask'",
                     &value_arg[1]);
        return NGX_CONF_ERROR;
    }

    value_user.data = value_arg[1].data;
    value_user.len = p_comma1 - value_arg[1].data;
    UDPXY_DEBUG(cf->log, "value_user.data '%V'", &value_user);
    UDPXY_DEBUG(cf->log, "value_user.len %d", value_user.len);

    value_src.data = p_comma1 + 1;
    value_src.len = (p_comma2 - 1) - p_comma1;
    UDPXY_DEBUG(cf->log, "value_src.data '%V'", &value_src);
    UDPXY_DEBUG(cf->log, "value_src.len %d", value_src.len);

    value_dest.data = p_comma2 + 1;
    value_dest.len = value_arg[1].data + value_arg[1].len - (p_comma2 + 1);
    UDPXY_DEBUG(cf->log, "value_dest.data '%V'", &value_dest);
    UDPXY_DEBUG(cf->log, "value_dest.len %d", value_dest.len);

    if (alcf->rules == NULL) {
        alcf->rules = ngx_array_create(cf->pool, 4,
                                       sizeof(ngx_http_access_udpxy_rule_t));
        if (alcf->rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(alcf->rules);
    if (rule == NULL)
        return NGX_CONF_ERROR;

    user_tmp.data = ngx_pnalloc(cf->pool, value_user.len + 1);
    if (user_tmp.data == NULL)
        return NGX_CONF_ERROR;

    ngx_memcpy(user_tmp.data, value_user.data, value_user.len);
    user_tmp.data[value_user.len] = '\0';
    user_tmp.len = value_user.len;

    memcpy(&rule->user, &user_tmp, sizeof(ngx_str_t));

    rule->deny = (value_arg[0].data[0] == 'd') ? 1 : 0;

    UDPXY_DEBUG0(cf->log, "**********************");
    UDPXY_DEBUG(cf->log, "     adding user '%V' '%s'",
        &rule->user, (rule->deny == 1) ? "deny" : "allow");

    all = 0;
    ngx_memzero(&cidr_src, sizeof(ngx_cidr_t));

    if (value_src.len == 3 && ngx_strncmp(value_src.data, "all", value_src.len) == 0) {
        all = 1;
    } else {
        rc = ngx_ptocidr(&value_src, &cidr_src);
        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "invalid parameter src '%V'", &value_src);
            return NGX_CONF_ERROR;
        }

        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                         "low address bits of %V are meaningless", &value_src);
        }
    }

    if (cidr_src.family == AF_INET || all) {
        rule->mask_src = cidr_src.u.in.mask;
        rule->addr_src = cidr_src.u.in.addr;

        UDPXY_DEBUG(cf->log, " adding addr_src '%s'",
            inet_ntoa(*(struct in_addr *)&rule->addr_src));
        UDPXY_DEBUG(cf->log, " adding mask_src '%s'",
            inet_ntoa(*(struct in_addr *)&rule->mask_src));
    }

    all = 0;
    ngx_memzero(&cidr_dest, sizeof(ngx_cidr_t));

    if (value_dest.len == 3 && ngx_strncmp(value_dest.data, "all", value_dest.len) == 0) {
        all = 1;
    } else {
        rc = ngx_ptocidr(&value_dest, &cidr_dest);

        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "invalid parameter dest '%V'", &value_dest);
            return NGX_CONF_ERROR;
        }

        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                         "low address bits of %V are meaningless", &value_dest);
        }
    }

    if (cidr_dest.family == AF_INET || all) {
        rule->mask_dest = cidr_dest.u.in.mask;
        rule->addr_dest = cidr_dest.u.in.addr;

        UDPXY_DEBUG(cf->log, "adding addr_dest '%s'",
            inet_ntoa(*(struct in_addr *)&rule->addr_dest));
        UDPXY_DEBUG(cf->log, "adding mask_dest '%s'",
            inet_ntoa(*(struct in_addr *)&rule->mask_dest));
    }

    UDPXY_DEBUG0(cf->log, "**********************");

/* todo */
#if (NGX_HAVE_INET6)
    if (cidr.family == AF_INET6 || all) {

        if (alcf->rules6 == NULL) {
            alcf->rules6 = ngx_array_create(cf->pool, 4,
                                            sizeof(ngx_http_access_udpxy_rule6_t));
            if (alcf->rules6 == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        rule6 = ngx_array_push(alcf->rules6);
        if (rule6 == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memcpy(&rule6->user, &value_arg[1], sizeof(ngx_str_t));
        rule6->mask_dest = cidr.u.in6.mask_dest;
        rule6->addr_dest = cidr.u.in6.addr_dest;
        rule6->deny = (value_dest[0].data[0] == 'd') ? 1 : 0;
    }
#endif

    return NGX_CONF_OK;
}


static void *
ngx_http_access_udpxy_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_access_udpxy_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_access_udpxy_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_access_udpxy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_access_udpxy_loc_conf_t  *prev = parent;
    ngx_http_access_udpxy_loc_conf_t  *conf = child;

    if (conf->rules == NULL
#if (NGX_HAVE_INET6)
        && conf->rules6 == NULL
#endif
    ) {
        conf->rules = prev->rules;
#if (NGX_HAVE_INET6)
        conf->rules6 = prev->rules6;
#endif
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_access_udpxy_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_access_udpxy_handler;

    return NGX_OK;
}
