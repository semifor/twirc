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
