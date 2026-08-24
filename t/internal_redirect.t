#!/usr/bin/perl

# Tests for ngx_http_internal_redirect_module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite ngx_condition_module
	ngx_http_internal_redirect_module/)->plan(13);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        condition enabled str_eq $arg_go yes;

        internal_redirect ^/server-old$ /target;

        location ~ ^/old/ {
            internal_redirect ^/old/(.*)$ /new/$1;
        }

        location = /with-args {
            internal_redirect ^/with-args\?.*$ /target?copied=$arg_x;
        }

        location = /case {
            internal_redirect -i ^/CASE$ /target;
        }

        location = /conditional {
            when enabled {
                internal_redirect ^/conditional(?:\?.*)?$
                    /target?selected=condition;
            }
            internal_redirect ^/conditional(?:\?.*)?$ /fallback;
        }

        location = /access-phase {
            internal_redirect ^/access-phase$ /target phase=access;
        }

        location = /precontent-phase {
            internal_redirect ^/precontent-phase$ /target phase=precontent;
        }

        location = /content-phase {
            internal_redirect ^/content-phase$ /target phase=content;
        }

        location = /named {
            internal_redirect ^/named$ @named;
        }

        location = /external {
            internal_redirect ^/external$ /target flag=http_302;
        }

        location = /invalid {
            internal_redirect ^/invalid$ relative;
        }

        location = /server-old {
            alias %%TESTDIR%%/original;
        }

        location /new/ {
            return 200 "$uri|$args";
        }

        location = /target {
            return 200 "$uri|$args";
        }

        location = /fallback {
            return 200 fallback;
        }

        location @named {
            return 200 "named:$uri";
        }
    }
}

EOF

$t->write_file('original', 'original');
$t->run();

###############################################################################

sub body_is {
	my ($uri, $body, $name) = @_;
	like(http_get($uri), qr/\x0d\x0a\x0d\x0a\Q$body\E$/, $name);
}

body_is('/old/item', '/new/item|', 'regex capture changes URI');
body_is('/with-args?x=one', '/target|copied=one',
	'replacement variables set new arguments');
body_is('/case', '/target|', 'case-insensitive pattern matches');
body_is('/conditional?go=yes', '/target|selected=condition',
	'matching condition wins before fallback');
body_is('/conditional?go=no', 'fallback',
	'condition miss uses unconditional fallback');
body_is('/access-phase', '/target|', 'access phase redirect');
body_is('/precontent-phase', '/target|', 'precontent phase redirect');
body_is('/content-phase', '/target|', 'content phase redirect');
body_is('/named', 'named:/named', 'named location redirect');
body_is('/server-old', '/target|', 'server rule is inherited by location');

my $response = http_get('/external');
like($response, qr/^HTTP\/1\.1 302 /, 'HTTP redirect flag sets status');
like($response, qr{^Location: (?:http://localhost:8080)?/target\x0d$}m,
	'HTTP redirect flag sets location');

like(http_get('/invalid'), qr/^HTTP\/1\.1 500 /,
	'invalid replacement is rejected at runtime');

###############################################################################
