#!perl -wT
use warnings;
use strict;
use Test::More;

plan skip_all => 'set TEST_AUTHOR to enable this test' unless $ENV{TEST_AUTHOR};

eval "use Pod::Coverage 0.19";
plan skip_all => 'Pod::Coverage 0.19 required' if $@;

eval "use Test::Pod::Coverage 1.04";
plan skip_all => 'Test::Pod::Coverage 1.04 required' if $@;

plan skip_all => 'set TEST_POD to enable this test'
  unless ($ENV{TEST_POD} || -e 'MANIFEST.SKIP');

my @modules = sort { $a cmp $b } (Test::Pod::Coverage::all_modules());
plan tests => scalar(@modules);

foreach my $module (@modules) {
    pod_coverage_ok($module, "$module POD coverage");
}
