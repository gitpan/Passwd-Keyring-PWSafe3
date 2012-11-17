#!perl

use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

if($ENV{PWSAFE_FULL_TEST}) {
    plan tests => 9;
} else {
    plan skip_all => "Skipped as runs fairly slowly. Set environment variable PWSAFE_FULL_TEST to execute this test.";
}

use Passwd::Keyring::PWSafe3;

my $DBFILE = File::Spec->catfile($FindBin::Bin, "sampledb", "test.psafe3");

# No lazy_save, on purpose, let's check also no lazy save mode
my $ring = Passwd::Keyring::PWSafe3->new(
    file=>$DBFILE, master_password=>"10101010");

ok( defined($ring) && ref $ring eq 'Passwd::Keyring::PWSafe3',  'new() works, database loaded' );

my $USER = 'John';
my $PASSWORD = 'verysecret';
my $REALM = 'some simple realm';

$ring->set_password($USER, $PASSWORD, $REALM);

ok( 1, "set_password works" );

is( $ring->get_password($USER, $REALM), $PASSWORD, "get recovers");

is( $ring->clear_password($USER, $REALM), 1, "clear_password removed one password" );

is( $ring->get_password($USER, $REALM), undef, "no password after clear");

is( $ring->clear_password($USER, $REALM), 0, "clear_password again has nothing to clear" );

is( $ring->clear_password("Non user", $REALM), 0, "clear_password for unknown user has nothing to clear" );
is( $ring->clear_password("$USER", 'non realm'), 0, "clear_password for unknown realm has nothing to clear" );

