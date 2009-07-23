package App::Twirc::Plugin::BangCommands;
use warnings;
use strict;

sub new { bless {}, shift }

sub preprocess {
    my (undef,undef,undef,undef, $textref) = @_;

    unless ( $$textref =~ s/^!\s*// ) {
        $$textref = "post $$textref";
    }
    return;
}

1;

__END__

=head1 NAME

App::Twirc::Plugin::BangCommands - Commands prefixed with !

=head1 SYNOPSIS

  # in config (.yml in this example)
  plugins:
      -BangCommands

  # in your IRC clientt
  This is a status message (no "post" prefix necessary)
  !follow net_twitter
  !rate_limit_status

=head1 DESCRIPTION

In your IRC client, text entered without an exclamation point (!) prefix will
be posted as a status message.  Commands start with an exclamation mark (!)
prefix.

=head1 AUTHOR

Marc Mims <marc@questright.com>

=head1 LICENSE

Copyright (c) 2009 Marc Mims

You may distribute this code and/or modify it under the same terms as Perl itself.

=cut
