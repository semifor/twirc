#!perl
use warnings;
use strict;
use Test::More tests => 6;

BEGIN { use_ok 'App::Twirc::Plugin::SquashWhiteSpace' }

BEGIN {
    my $plugin = App::Twirc::Plugin::SquashWhiteSpace->new;

    sub call {
        my $text = shift;

        $plugin->cmd_post((undef) x 3, \$text);
        return $text;
    }
}

is call('foo   bar'),     'foo bar',      'extra space';
is call('foo  bar  baz'), 'foo bar baz',  'multiple squash';
is call('foo bar baz '),  'foo bar baz ', 'unchanghed';
is call("foo\tbar"),      'foo bar',      'tab';
is call("foo\nbar"),      'foo bar',      'newline';

exit 0;
