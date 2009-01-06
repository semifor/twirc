package App::Twirc::LogAppender;
use warnings;
use strict;

use base qw/Log::Log4perl::Appender/;

sub new {
    my($class, @options) = @_;

    my $self = {
        name        => 'twirc-logger',
        irc_channel => '&twirc-log',
        @options,
    };

    for ( qw/ircd irc_botname irc_channel/ ) {
        die "$_ required" unless defined $self->{$_};
    }

    bless $self, $class;
}

sub log {
    my($self, %params) = @_;

    $self->{ircd}->yield(daemon_cmd_privmsg =>
        $self->{irc_botname}, $self->{irc_channel}, $params{message});
}

1;
