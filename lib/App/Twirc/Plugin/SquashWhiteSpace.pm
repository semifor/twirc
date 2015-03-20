package App::Twirc::Plugin::SquashWhiteSpace;

use warnings;
use strict;

sub new { bless {}, shift }

sub cmd_post {
    my (undef, undef, undef, undef, $textref) = @_;

    $$textref =~ s/\s+/ /g;
    return;
}

1;

__END__

=head1 NAME

App::Twirc::Plugin::SquashWhitSpace - Squash whitespace in status updates

=head1 SYNOPSIS

  # in config (.yml in this example)
  plugins:
      -SquashWhiteSpace

=head1 DESCRIPTION

Squashes each occurence of whitespace in a status update to a single space.
After all, we only have 140 characters to work with!

=head1 AUTHOR

Marc Mims <marc@questright.com>

=head1 LICENSE

Copyright (c) 2009 Marc Mims

You may distribute this code and/or modify it under the same terms as Perl itself.

=cut
