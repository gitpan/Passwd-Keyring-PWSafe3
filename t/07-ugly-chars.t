#!perl

use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

if($ENV{PWSAFE_FULL_TEST}) {
    plan tests => 4;
} else {
    plan skip_all => "Skipped as runs fairly slowly. Set environment variable PWSAFE_FULL_TEST to execute this test.";
}

use Passwd::Keyring::PWSafe3;

my $DBFILE = File::Spec->catfile($FindBin::Bin, "sampledb", "test.psafe3");

my $UGLY_NAME = "Joh ## no ^^ »ąćęłóśż«";
my $UGLY_PWD =  "«tajne hasło»";
my $UGLY_REALM = '«do»–main';

# NO lazy_save on purpose
my $ring = Passwd::Keyring::PWSafe3->new(
    app=>"Passwd::PWSafe3::Keyring unit tests", group=>"Ugly chars",
    file=>$DBFILE, master_password=>"10101010");

ok( defined($ring) && ref $ring eq 'Passwd::Keyring::PWSafe3',   'new() works' );

$ring->set_password($UGLY_NAME, $UGLY_PWD, $UGLY_REALM);

ok( 1, "set_password with ugly chars works" );

ok( $ring->get_password($UGLY_NAME, $UGLY_REALM) eq $UGLY_PWD, "get works with ugly characters");

ok( $ring->clear_password($UGLY_NAME, $UGLY_REALM) eq 1, "clear clears");

