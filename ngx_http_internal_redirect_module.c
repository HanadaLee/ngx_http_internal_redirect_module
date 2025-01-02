
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef enum {
    NGX_HTTP_INTERNAL_REDIRECT_PHASE_PREACCESS = 0,
    NGX_HTTP_INTERNAL_REDIRECT_PHASE_ACCESS,
    NGX_HTTP_INTERNAL_REDIRECT_PHASE_PRECONTENT,
    NGX_HTTP_INTERNAL_REDIRECT_PHASE_CONTENT,
    NGX_HTTP_INTERNAL_REDIRECT_PHASE_MAX
} ngx_http_internal_redirect_phase_t;


typedef enum {
    NGX_HTTP_INTERNAL_REDIRECT_FLAG_DEFAULT = 0,
    NGX_HTTP_INTERNAL_REDIRECT_FLAG_BREAK,
    NGX_HTTP_INTERNAL_REDIRECT_FLAG_STATUS_301,
    NGX_HTTP_INTERNAL_REDIRECT_FLAG_STATUS_302,
    NGX_HTTP_INTERNAL_REDIRECT_FLAG_STATUS_303,
    NGX_HTTP_INTERNAL_REDIRECT_FLAG_STATUS_307,
    NGX_HTTP_INTERNAL_REDIRECT_FLAG_STATUS_308,
} ngx_http_internal_redirect_flag_t;


typedef struct {
    ngx_regex_t               *regex;
    ngx_http_complex_value_t  *replacement;
    ngx_flag_t                 flag;
    ngx_http_complex_value_t  *filter;
    ngx_uint_t                 negative;
} ngx_http_internal_redirect_rule_t;


typedef struct {
    ngx_array_t               *rules[NGX_HTTP_INTERNAL_REDIRECT_PHASE_MAX];
} ngx_http_internal_redirect_loc_conf_t;



static ngx_int_t ngx_http_internal_redirect_init(ngx_conf_t *cf);

static void * ngx_http_internal_redirect_create_conf(ngx_conf_t *cf);
static char * ngx_http_internal_redirect_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char * ngx_http_internal_redirect_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_internal_redirect_handler_preaccess(ngx_http_request_t *r);
static ngx_int_t ngx_http_internal_redirect_handler_access(ngx_http_request_t *r);
static ngx_int_t ngx_http_internal_redirect_handler_precontent(ngx_http_request_t *r);
static ngx_int_t ngx_http_internal_redirect_handler_content(ngx_http_request_t *r);

static ngx_command_t  ngx_http_internal_redirect_commands[] = {

    {
      ngx_string("internal_redirect"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_internal_redirect_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL
    },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_internal_redirect_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_internal_redirect_init,        /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_internal_redirect_create_conf, /* create location configuration */
    ngx_http_internal_redirect_merge_conf   /* merge location configuration */
};


ngx_module_t  ngx_http_internal_redirect_module = {
    NGX_MODULE_V1,
    &ngx_http_internal_redirect_module_ctx, /* module context */
    ngx_http_internal_redirect_commands,    /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_internal_redirect_create_conf(ngx_conf_t *cf)
{
    ngx_http_internal_redirect_loc_conf_t  *ilcf;

    ilcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_internal_redirect_loc_conf_t));
    if (ilcf == NULL) {
        return NULL;
    }

    for (int i = 0; i < NGX_HTTP_INTERNAL_REDIRECT_PHASE_MAX; i++) {
        ilcf->rules[i] = NGX_CONF_UNSET_PTR;
    }

    return ilcf;
}


static char *
ngx_http_internal_redirect_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_internal_redirect_loc_conf_t *prev = parent;
    ngx_http_internal_redirect_loc_conf_t *conf = child;
    ngx_uint_t i;

    for (i = 0; i < NGX_HTTP_IR_PHASE_MAX; i++) {
        if (conf->rules[i] == NGX_CONF_UNSET_PTR) {
            conf->rules[i] = prev->rules[i];
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_internal_redirect_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_internal_redirect_loc_conf_t *ilcf = conf;

    ngx_str_t                          *value;
    ngx_uint_t                          cur, last;
    ngx_http_internal_redirect_rule_t  *rule;
    ngx_regex_compile_t                 rc;
    u_char                              errstr[NGX_MAX_CONF_ERRSTR];
    ngx_str_t                           pattern, replacement;
    ngx_http_complex_value_t           *filter;
    ngx_flag_t                          negative, ignore_case;
    ngx_uint_t                          flag;
    ngx_int_t                           phase;
    ngx_http_compile_complex_value_t    ccv;

    negative = 0;
    ignore_case = 0;
    filter = NULL;
    phase = NGX_HTTP_INTERNAL_REDIRECT_PHASE_PREACCESS;
    flag = NGX_HTTP_INTERNAL_REDIRECT_FLAG_DEFAULT;

    value = cf->args->elts;
    last = cf->args->nelts -1 ;

    if (cf->args->nelts < 3) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid number of parameters in \"internal_redirect\"");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&pattern, sizeof(pattern));
    ngx_memzero(&replacement, sizeof(replacement));
    ngx_memzero(&phase_str, sizeof(phase_str));
    ngx_memzero(&flag_str, sizeof(phase_str));

    cur = 1;

    if (cur <= last && ngx_strcmp(value[cur].data, "-i") == 0) {
        ignore_case = 1;
        cur++;
    }

    if (cur + 1 > last) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid usage of \"internal_redirect\" directive");
        return NGX_CONF_ERROR;
    }

    pattern = value[cur];
    cur++;

    replacement = value[cur];
    cur++;

    for (; cur <= last; cur++) {
        if (ngx_strncmp(value[cur].data, "phase=", 6) == 0) {
            s.data = value[cur].data + 6;
            s.len  = value[cur].len - 6;

            if (ngx_strcmp(s.data, "preaccess") == 0) {
                phase = NGX_HTTP_INTERNAL_REDIRECT_PHASE_PREACCESS;
            } else if (ngx_strcmp(s.data, "access") == 0) {
                phase = NGX_HTTP_INTERNAL_REDIRECT_PHASE_ACCESS;
            } else if (ngx_strcmp(s.data, "precontent") == 0) {
                phase = NGX_HTTP_INTERNAL_REDIRECT_PHASE_PRECONTENT;
            } else if (ngx_strcmp(s.data, "content") == 0) {
                phase = NGX_HTTP_INTERNAL_REDIRECT_PHASE_CONTENT;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid phase \"%V\"", &s);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[cur].data, "flag=", 5) == 0) {
            s.data = value[cur].data + 5;
            s.len = value[cur].len - 5;

            if (ngx_strcmp(s.data, "break") == 0) {
                flag = NGX_HTTP_INTERNAL_REDIRECT_FLAG_DEFAULT;
            } else if (ngx_strcmp(s.data, "status_301") == 0) {
                flag = NGX_HTTP_INTERNAL_REDIRECT_FLAG_STATUS_301;
            } else if (ngx_strcmp(s.data, "status_302") == 0) {
                flag = NGX_HTTP_INTERNAL_REDIRECT_FLAG_STATUS_302;
            } else if (ngx_strcmp(s.data, "status_303") == 0) {
                flag = NGX_HTTP_INTERNAL_REDIRECT_FLAG_STATUS_303;
            } else if (ngx_strcmp(s.data, "status_307") == 0) {
                flag = NGX_HTTP_INTERNAL_REDIRECT_FLAG_STATUS_307;
            } else if (ngx_strcmp(s.data, "status_308") == 0) {
                flag = NGX_HTTP_INTERNAL_REDIRECT_FLAG_STATUS_308;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid flag \"%V\"", &s);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[cur].data, "if=", 3) == 0
            || ngx_strncmp(value[cur].data, "if!=", 4) == 0)
        {
            if (ngx_strncmp(value[cur].data, "if=", 3) == 0) {
                s.len = value[cur].len - 3;
                s.data = value[cur].data + 3;
                negative = 0;
            } else {
                s.len = value[cur].len - 4;
                s.data = value[cur].data + 4;
                negative = 1;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &s;
            ccv.complex_value = ngx_palloc(cf->pool,
                                        sizeof(ngx_http_complex_value_t));
            if (ccv.complex_value == NULL) {
                return NGX_CONF_ERROR;
            }

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            filter = ccv.complex_value;
        }
    }

    if (ilcf->rules[phase] == NGX_CONF_UNSET_PTR) {
        ilcf->rules[phase] = ngx_array_create(cf->pool, 4,
            sizeof(ngx_http_internal_redirect_rule_t));
        if (ilcf->rules[phase] == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(ilcf->rules[phase]);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    rule->ignore_case = ignore_case;
    rule->flag = flag;
    rule->filter = filter;
    rule->negative = negative;

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
    rc.pool = cf->pool;
    rc.pattern = pattern;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (ignore_case == 1) {
        rc.options = NGX_REGEX_CASELESS;
    }

    rule->regex = ngx_http_regex_compile(cf, &rc);
    if (rule->regex == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "regex \"%V\" compile failed: %V",
                           &pattern, &rc.err);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &s;
    ccv.complex_value = ngx_palloc(cf->pool,
                                sizeof(ngx_http_complex_value_t));
    if (ccv.complex_value == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    rule->replacement = ccv.complex_value;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_internal_redirect_handler(ngx_http_request_t *r, ngx_array_t *rules)
{
    ngx_http_internal_redirect_rule_t *rule;
    ngx_uint_t i;
    ngx_str_t  current_uri;
    ngx_str_t  final_uri;
    ngx_int_t  matched = 0;  /* 是否有命中 */

    if (rules == NULL || rules == NGX_CONF_UNSET_PTR || rules->nelts == 0) {
        return NGX_DECLINED;
    }

    /* 拿当前请求的 URI */
    current_uri = r->uri;
    ngx_str_null(&final_uri);

    rule = rules->elts;
    for (i = 0; i < rules->nelts; i++) {

        /* 1. 判断 if=xxx 条件 */
        if (rule[i].var_index != NGX_CONF_UNSET) {
            ngx_http_variable_value_t *vv;
            vv = ngx_http_get_indexed_variable(r, rule[i].var_index);
            if (vv == NULL || vv->not_found) {
                /* 变量不存在则不匹配 */
                continue;
            }
            /* if=xxx: 值非空且不是"0" => 生效
             * if!=xxx: 值为空或"0" => 生效
             */
            if (rule[i].var_negate == 0) {
                /* if=xxx */
                if (vv->len == 0 || (vv->len == 1 && vv->data[0] == '0')) {
                    continue;
                }
            } else {
                /* if!=xxx */
                if (!(vv->len == 0 || (vv->len == 1 && vv->data[0] == '0'))) {
                    continue;
                }
            }
        }

        /* 2. 执行正则匹配
         *   简化写法：只要能匹配到就视为成功，不做捕获组替换的示例
         */
        if (ngx_regex_exec(rule[i].regex, &current_uri, NULL, 0) >= 0) {
            /* 命中 */
            matched = 1;
            final_uri = rule[i].replacement;

            /* 如果 flag=break，则立即重定向并退出循环 */
            if (rule[i].brk) {
                break;
            }
            /* 否则继续看下一条规则，可能有更后面的覆盖掉前面 */
        }
    }

    if (!matched) {
        return NGX_DECLINED;
    }

    /* 有匹配，则执行 internal redirect */
    if (final_uri.len == 0) {
        return NGX_DECLINED;
    }

    if (final_uri.data[0] == '@') {
        (void) ngx_http_named_location(r, &final_uri);
    } else if (final_uri.data[0] == '/') {
        ngx_str_t args;
        ngx_str_null(&args);
        ngx_http_split_args(r, &final_uri, &args);
        (void) ngx_http_internal_redirect(r, &final_uri, &args);
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid internal redirect URI: \"%V\"", &final_uri);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* 返回 NGX_DONE 表示此请求处理到此就结束，移交给新的 internal redirect */
    return NGX_DONE;
}


static ngx_int_t
ngx_http_internal_redirect_handler_preaccess(ngx_http_request_t *r)
{
    ngx_http_internal_redirect_loc_conf_t  *ilcf;
    ilcf = ngx_http_get_module_loc_conf(r, ngx_http_internal_redirect_module);
    if (ilcf == NULL) {
        return NGX_DECLINED;
    }
    return ngx_http_internal_redirect_handler(r, ilcf->rules[NGX_HTTP_INTERNAL_REDIRECT_PHASE_PREACCESS]);
}


static ngx_int_t
ngx_http_internal_redirect_handler_access(ngx_http_request_t *r)
{
    ngx_http_internal_redirect_loc_conf_t  *ilcf;
    ilcf = ngx_http_get_module_loc_conf(r, ngx_http_internal_redirect_module);
    if (ilcf == NULL) {
        return NGX_DECLINED;
    }
    return ngx_http_internal_redirect_handler(r, ilcf->rules[NGX_HTTP_INTERNAL_REDIRECT_PHASE_ACCESS]);
}


static ngx_int_t
ngx_http_internal_redirect_handler_precontent(ngx_http_request_t *r)
{
    ngx_http_internal_redirect_loc_conf_t  *ilcf;
    ilcf = ngx_http_get_module_loc_conf(r, ngx_http_internal_redirect_module);
    if (ilcf == NULL) {
        return NGX_DECLINED;
    }
    return ngx_http_internal_redirect_handler(r, ilcf->rules[NGX_HTTP_INTERNAL_REDIRECT_PHASE_PRECONTENT]);
}


static ngx_int_t
ngx_http_internal_redirect_handler_content(ngx_http_request_t *r)
{
    ngx_http_internal_redirect_loc_conf_t  *ilcf;
    ilcf = ngx_http_get_module_loc_conf(r, ngx_http_internal_redirect_module);
    if (ilcf == NULL) {
        return NGX_DECLINED;
    }
    return ngx_http_internal_redirect_handler(r, ilcf->rules[NGX_HTTP_INTERNAL_REDIRECT_PHASE_CONTENT]);
}


static ngx_int_t
ngx_http_internal_redirect_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_handler_pt        *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf == NULL) {
        return NGX_ERROR;
    }

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_internal_redirect_handler_preaccess;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_internal_redirect_handler_access;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_internal_redirect_handler_precontent;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_internal_redirect_handler_content;

    return NGX_OK;
}
