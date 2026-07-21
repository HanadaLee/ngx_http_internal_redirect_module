# Name

`ngx_http_internal_redirect_module` allows making an internal redirect. In contrast to rewriting URIs, the redirection is made after rewrite phase. Currently supported request phases are preaccess, access, precontent and content, allowing it to be used with many nginx official or third-party modules.

> This module is inspired by the nginx official [ngx_http_internal_redirect_module]([ngx_http_internal_redirect_module](https://nginx.org/en/docs/http/ngx_http_internal_redirect_module.html)).

# Table of Content

- [Name](#name)
- [Table of Content](#table-of-content)
- [Status](#status)
- [Synopsis](#synopsis)
- [Installation](#installation)
- [Conditional syntax](#conditional-syntax)
- [Directives](#directives)
  - [internal\_redirect](#internal_redirect)
- [Author](#author)
- [License](#license)

# Status

This Nginx module is currently considered experimental. Issues and PRs are welcome if you encounter any problems.

# Synopsis

```nginx
server {
    listen 127.0.0.1:80;
    server_name localhost;

    location /old {
        condition old_uri str_regex_match $uri ^/old;
        when old_uri {
            internal_redirect -i ^/old(.+) /new$1 phase=preaccess;
        }
    }

    location /new {
        return 200 'current uri is: $uri';
    }
}
```

# Installation

To use theses modules, configure your nginx branch with `--add-module=/path/to/ngx_http_internal_redirect_module`.

To enable named conditions, build `ngx_condition_module` and this module statically in the same nginx configuration.

# Conditional syntax

Conditional syntax is selected at compile time. With `ngx_condition_module`, place `internal_redirect` inside a `server` or `location` `when` block; `if=` and `if!=` are rejected. Without it, `when` is unavailable and legacy `if=`/`if!=` remain supported. `if=` matches a non-empty value other than `"0"`; `if!=` matches an empty value or `"0"`.

# Directives

## internal_redirect 

**Syntax:** *internal_redirect [-i] pattern replacement [phase=phase] [flag=flag];*

**Default:** *-*

**Context:** *server, location, server when, location when*

Sets the new URI for internal redirection of the request. It is also possible to use a named location instead of the URI. The replacement value can contain variables. If the uri value is empty, then the redirect will not be made. After an internal redirect occurs, the request URI will be changed, and request will be returns to the NGX_HTTP_SERVER_REWRITE_PHASE (server_rewrite) phase. The request proceeds with a server default location. Later at NGX_HTTP_FIND_CONFIG_PHASE (find_config) a new location is chosen based on the new request URI.

> For more information about nginx request phases, please refer to [Development guide#http_phases](https://nginx.org/en/docs/dev/development_guide.html#http_phases)

The optional `-i` parameter specifies that a case-insensitive regular expression match should be performed.

The optional `phase=` parameter is used to indicate the phase in which this rule takes effect. The possible values ​​are preaccess, access, precontent and content. The rules of each phase will be executed completely before the internal redirection is performed. The default value is preaccess.

The optional `flag=` parameter is used for additional actions after evaluating the rule. The value of this parameter can be one of:
* `break`
stops processing the current set of rules at this phase, and immediately executes an internal redirection;
* `http_301`
stops processing the current set of rules at this phase, and immediately returns a redirection with the 301 code.
* `http_302`
stops processing the current set of rules at this phase, and immediately returns a redirection with the 302 code.
* `http_303`
stops processing the current set of rules at this phase, and immediately returns a redirection with the 303 code.
* `http_307`
stops processing the current set of rules at this phase, and immediately returns a redirection with the 307 code.
* `http_308`
stops processing the current set of rules at this phase, and immediately returns a redirection with the 308 code.

The legacy `if=` and `if!=` parameters are available only when `ngx_condition_module` is not built.

The rules of the previous level will be merged into the rules of the current level.

# Author

Hanada im@hanada.info

# License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
