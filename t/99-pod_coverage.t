#!perl -wT
use warnings;
use strict;
use Test::More;

plan skip_all => 'set TEST_POD to enable this test'
    unless $ENV{TEST_POD} || -e 'MANIFEST.SKIP';

eval "use Pod::Coverage 0.19";
plan skip_all => 'Pod::Coverage 0.19 required' if $@;

eval "use Test::Pod::Coverage 1.04";
plan skip_all => 'Test::Pod::Coverage 1.04 required' if $@;

plan skip_all => 'set TEST_POD to enable this test'
  unless ($ENV{TEST_POD} || -e 'MANIFEST.SKIP');

plan tests => 2;

# TODO: I really should add documentation
pod_coverage_ok(
    'POE::Component::Server::Twirc',
    { trustme => [ map qr/^$_$/, qw/
            DEFAULT
            START
            add_user
            bot_notice
            bot_says
            delete_user
            get_friends_timeline
            get_replies
            get_statuses
            handle_favorite
            merge_replies
            nicks_alternation
            post_ircd
            set_topic
            sort_unique_statuses
            twitter
            twitter_error
        /],
    },
    'POE::Component::Server::Twirc coverage'
);

pod_coverage_ok(
    'App::Twirc',
    'App::Twirc coverage'
);
