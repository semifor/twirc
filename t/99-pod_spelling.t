#!perl -w
use strict;
use warnings;
use Test::More;

plan skip_all => 'set TEST_POD to enable this test'
    unless $ENV{TEST_POD} || -e 'MANIFEST.SKIP';

eval 'use Test::Spelling 0.11';
plan skip_all => 'Test::Spelling 0.11 not installed' if $@;

set_spell_cmd('aspell list');

add_stopwords(<DATA>);

all_pod_files_spelling_ok();

__DATA__
API
BangCommands
CPAN
Facebook
INI
IRC
Identi
JSON
LoudMouth
Marc
Mims
STDERR
SecondaryAccount
SquashWhiteSpace
Twitter's
YAML
bot's
ca's
configfile
favoriting
irc
irssi
OAuth
plugins
redisplaying
retweet
retweeting
spammers
timeline
timelines
Twirc
twirc
un
unfollow
username
verifier
whois
