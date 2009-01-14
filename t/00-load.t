#!perl -w
use warnings;
use strict;
use Test::More tests => 2;

BEGIN {
    use_ok('POE::Component::Server::Twirc');
    use_ok('App::Twirc');
}
