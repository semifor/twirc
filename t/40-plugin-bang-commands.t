use warnings;
use strict;
use Test::More tests => 4;

BEGIN { use_ok 'App::Twirc::Plugin::BangCommands' }

BEGIN {
    my $plugin = App::Twirc::Plugin::BangCommands->new;

    sub call {
        my $text = shift;

        $plugin->preprocess((undef) x 3, \$text);
        return $text;
    }
}

is call('foo bar'),       'post foo bar', 'implicit post';
is call('!post foo bar'), 'post foo bar', 'explicit post';
is call('!cmd foo bar'),  'cmd foo bar',  'other command';

exit 0;
