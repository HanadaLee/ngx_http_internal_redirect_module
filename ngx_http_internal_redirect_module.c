
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


typedef struct {
    ngx_regex_t               *regex;
    ngx_http_complex_value_t  *replacement;
    ngx_flag_t                 ignore_case;
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


static ngx_command_t  ngx_http_internal_redirect_commands[] = {

    {
      ngx_string("internal_redirect"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
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

    /* 将数组指针初始为 NGX_CONF_UNSET_PTR */
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

    for (int i = 0; i < NGX_HTTP_INTERNAL_REDIRECT_PHASE_MAX; i++) {
        if (conf->rules[i] == NGX_CONF_UNSET_PTR) {
            conf->rules[i] = (prev->rules[i] != NGX_CONF_UNSET_PTR)
                ? prev->rules[i]
                : ngx_array_create(cf->pool, 4, sizeof(ngx_http_internal_redirect_rule_t));
            if (conf->rules[i] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_internal_redirect_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_internal_redirect_loc_conf_t *ilcf = conf;

    ngx_str_t       *value;
    ngx_uint_t       n;
    ngx_http_internal_redirect_rule_t     *rule;
    ngx_regex_compile_t     rc;
    u_char           errstr[NGX_MAX_CONF_ERRSTR];
    ngx_str_t        pattern, replacement;
    ngx_str_t        phase_str;
    ngx_str_t        if_str;   /* 用于存储 if=xxx 或 if!=xxx 的部分 */
    ngx_flag_t       negate = 0;
    ngx_flag_t       insensitive = 0;
    ngx_flag_t       brk = 0;
    ngx_int_t        phase = NGX_HTTP_INTERNAL_REDIRECT_PHASE_PREACCESS; /* 默认 preaccess */

    value = cf->args->elts;
    n = cf->args->nelts;
    if (n < 3) {
        /*
         * 例如最少也要： internal_redirect regex replacement
         * 但由于可能含 -i，所以再稍微宽松点判断
         */
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of parameters in \"internal_redirect\"");
        return (char *)NGX_CONF_ERROR;
    }

    /* 先初始化需要用到的字符串 */
    ngx_memzero(&pattern, sizeof(pattern));
    ngx_memzero(&replacement, sizeof(replacement));
    ngx_memzero(&phase_str, sizeof(phase_str));
    ngx_memzero(&if_str, sizeof(if_str));

    /* 开始从第一个或第二个参数起做解析 */
    ngx_uint_t cur = 1;

    /* 如果第一个参数是 -i，则说明要大小写不敏感 */
    if (cur < n && ngx_strcmp(value[cur].data, "-i") == 0) {
        insensitive = 1;
        cur++;
    }

    if (cur + 1 >= n) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid usage of \"internal_redirect\" directive");
        return (char *)NGX_CONF_ERROR;
    }

    /* 此时 cur 指向 regex */
    pattern = value[cur];
    cur++;

    /* 下一个应该是 replacement */
    replacement = value[cur];
    cur++;

    /* 继续解析后面的可选参数 */
    for (; cur < n; cur++) {
        /* phase=preaccess|access|precontent */
        if (ngx_strncmp(value[cur].data, "phase=", 6) == 0) {
            phase_str.data = value[cur].data + 6;
            phase_str.len  = value[cur].len - 6;
            if (ngx_strcmp(phase_str.data, "preaccess") == 0) {
                phase = NGX_HTTP_INTERNAL_REDIRECT_PHASE_PREACCESS;
            } else if (ngx_strcmp(phase_str.data, "access") == 0) {
                phase = NGX_HTTP_INTERNAL_REDIRECT_PHASE_ACCESS;
            } else if (ngx_strcmp(phase_str.data, "precontent") == 0) {
                phase = NGX_HTTP_INTERNAL_REDIRECT_PHASE_PRECONTENT;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid phase \"%V\"", &phase_str);
                return (char *)NGX_CONF_ERROR;
            }
        }
        /* flag=break */
        else if (ngx_strncmp(value[cur].data, "flag=", 5) == 0) {
            ngx_str_t flg;
            flg.data = value[cur].data + 5;
            flg.len = value[cur].len - 5;
            if (ngx_strcmp(flg.data, "break") == 0) {
                brk = 1;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "only \"flag=break\" is supported");
                return (char *)NGX_CONF_ERROR;
            }
        }
        /* if=xxx 或 if!=xxx */
        else if (ngx_strncmp(value[cur].data, "if=", 3) == 0) {
            negate = 0;
            if_str.data = value[cur].data + 3;
            if_str.len = value[cur].len - 3;
        }
        else if (ngx_strncmp(value[cur].data, "if!=", 4) == 0) {
            negate = 1;
            if_str.data = value[cur].data + 4;
            if_str.len = value[cur].len - 4;
        }
        else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[cur]);
            return (char *)NGX_CONF_ERROR;
        }
    }

    /* 如果对应 phase 的 rules 数组还没创建，则创建 */
    if (ilcf->rules[phase] == NGX_CONF_UNSET_PTR) {
        ilcf->rules[phase] = ngx_array_create(cf->pool, 4, sizeof(ngx_http_internal_redirect_rule_t));
        if (ilcf->rules[phase] == NULL) {
            return (char *)NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(ilcf->rules[phase]);
    if (rule == NULL) {
        return (char *)NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(*rule));
    rule->phase       = phase;
    rule->insensitive = insensitive;
    rule->brk         = brk;
    ngx_str_set(&rule->var_name, "");

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
    rc.pattern = pattern;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;
    rc.pool = cf->pool;

    rc.options = (insensitive ? NGX_REGEX_CASELESS : 0);

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "regex \"%V\" compile failed: %V", &pattern, &rc.err);
        return (char *)NGX_CONF_ERROR;
    }

    rule->regex = rc.regex;

    /* 保存 replacement */
    rule->replacement = replacement;

    /* 处理 if= / if!= 参数 */
    if (if_str.len) {
        /* 去掉前面的 '$'（若有） */
        if (if_str.data[0] == '$') {
            if_str.data++;
            if_str.len--;
        }
        rule->var_name = if_str;
        rule->var_negate = negate;
        /* 通过 Nginx 提供的接口获取变量索引 */
        rule->var_index = ngx_http_get_variable_index(cf, &if_str);
        if (rule->var_index == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid variable name in if= or if!= argument: \"%V\"", &if_str);
            return (char *)NGX_CONF_ERROR;
        }
    } else {
        /* 未设置 if=xxx */
        rule->var_index = NGX_CONF_UNSET;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_internal_redirect_match_phase(ngx_http_request_t *r, ngx_array_t *rules)
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
    return ngx_http_internal_redirect_match_phase(r, ilcf->rules[NGX_HTTP_INTERNAL_REDIRECT_PHASE_PREACCESS]);
}


static ngx_int_t
ngx_http_internal_redirect_handler_access(ngx_http_request_t *r)
{
    ngx_http_internal_redirect_loc_conf_t  *ilcf;
    ilcf = ngx_http_get_module_loc_conf(r, ngx_http_internal_redirect_module);
    if (ilcf == NULL) {
        return NGX_DECLINED;
    }
    return ngx_http_internal_redirect_match_phase(r, ilcf->rules[NGX_HTTP_INTERNAL_REDIRECT_PHASE_ACCESS]);
}


static ngx_int_t
ngx_http_internal_redirect_handler_precontent(ngx_http_request_t *r)
{
    ngx_http_internal_redirect_loc_conf_t  *ilcf;
    ilcf = ngx_http_get_module_loc_conf(r, ngx_http_internal_redirect_module);
    if (ilcf == NULL) {
        return NGX_DECLINED;
    }
    return ngx_http_internal_redirect_match_phase(r, ilcf->rules[NGX_HTTP_INTERNAL_REDIRECT_PHASE_PRECONTENT]);
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

    return NGX_OK;
}
