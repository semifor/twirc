package POE::Component::Server::Twirc::LogAppender;
use warnings;
use strict;

use base qw/Log::Log4perl::Appender/;

sub new {
    my($class, @options) = @_;

    my $self = {
        name         => 'twirc-logger',
        irc_channel  => '&twirc-log',
        history      => [],
        history_size => 50,
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

    push @{$self->{history}}, \%params;
    shift @{$self->{history}} while @{$self->{history}} > $self->{history_size};
}

sub dump_history {
    my $self = shift;

    $self->{ircd}->yield(daemon_cmd_privmsg =>
            $self->{irc_botname}, $self->{irc_channel}, $_->{message})
        for @{$self->{history}};
}

1;
