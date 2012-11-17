#!perl -T

use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

if($ENV{PWSAFE_FULL_TEST}) {
    plan tests => 2;
} else {
    plan skip_all => "Skipped as runs fairly slowly. Set environment variable PWSAFE_FULL_TEST to execute this test.";
}

use Passwd::Keyring::PWSafe3;

my $DBFILE = File::Spec->catfile($FindBin::Bin, "sampledb", "test.psafe3");

my $ring = Passwd::Keyring::PWSafe3->new(
    file=>$DBFILE, master_password=>"10101010");

ok( defined($ring) && ref $ring eq 'Passwd::Keyring::PWSafe3',   'new() works' );

ok( $ring->is_persistent eq 1, "is_persistent knows we are persistent");

