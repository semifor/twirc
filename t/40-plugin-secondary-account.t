#!perl
use warnings;
use strict;
use Test::More tests => 9;

BEGIN {
    $INC{'Net/Twitter.pm'} = __FILE__;

    package # hide from PAUSE
        Net::Twitter;

    our $VERSION = '3.0';

    sub new {
        my $class = shift;
        bless { @_ }, $class;
    }

    sub update {
       my ($self, $text) = @_;
       ${$self->{status}} = $text;
    }
}

BEGIN {
    my $plugin;

    sub new_plugin {
        $plugin = App::Twirc::Plugin::SecondaryAccount->new(@_);
    }

    sub call {
        my $text = shift;

        return $plugin->cmd_post((undef) x 3, \$text);
    }
}

my $status = 'untouched';

use_ok 'App::Twirc::Plugin::SecondaryAccount';

new_plugin(
    username => 'user',
    password => 'secret',
    option => 'fb',
    net_twitter_options => { status => \$status },
);

ok !call('no-op'), 'continue processing chain';
is $status, 'untouched',  'no-op';

ok !call('-fb new status'), 'also continue';
is $status, 'new status', 'set with option';

ok call('-fbonly stat2'), 'end processing chain';
is $status, 'stat2',      'set with "only" option';


new_plugin(
    username => 'user',
    password => 'secret',
    net_twitter_options => { status => \$status },
);

ok !call('always'), 'always continue';
is $status, 'always', 'no option';

exit 0;
