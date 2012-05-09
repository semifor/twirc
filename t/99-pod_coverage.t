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
            add_follower_id
            add_user
            are_followers_stale
            bot_notice
            bot_says
            BUILD
            connect_twitter_stream
            DEFAULT
            delete_user
            followers_stale_after
            formatted_status_text
            friends_stale_after
            get_authenticated_user
            get_friends_timeline
            get_replies
            get_statuses
            handle_favorite
            is_follower_id
            is_user_stale
            max_reconnect_delay
            merge_replies
            nicks_alternation
            on_event_block
            on_event_favorite
            on_event_follow
            on_event_list_member_added
            on_event_list_member_removed
            on_event_retweet
            on_event_unblock
            on_event_unfavorite
            post_ircd
            remove_follower_id
            set_topic
            sort_unique_statuses
            START
            status_text_too_long
            twitter
            twitter_error
            twitter_id
            twitter_screen_name
            twitter_stream_timeout
        /],
    },
    'POE::Component::Server::Twirc coverage'
);

pod_coverage_ok(
    'App::Twirc',
    'App::Twirc coverage'
);
