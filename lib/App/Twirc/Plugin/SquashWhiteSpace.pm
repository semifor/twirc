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
