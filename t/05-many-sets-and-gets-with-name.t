#!perl

use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

if($ENV{PWSAFE_FULL_TEST}) {
    plan tests => 22;
} else {
    plan skip_all => "Skipped as runs fairly slowly. Set environment variable PWSAFE_FULL_TEST to execute this test.";
}

use Passwd::Keyring::PWSafe3;

my $DBFILE = File::Spec->catfile($FindBin::Bin, "sampledb", "test.psafe3");

my $REALM_A = 'my@@realm';
my $REALM_B = 'bum trala la';
my $REALM_C = 'other realm';

my $USER1 = "Paul Anton";
my $USER2 = "Gżegąź";
my $USER4 = "-la-san-ty-";

my $PWD1 = "secret-Paul";
my $PWD1_ALT = "secret-Paul2 ąąąą";
my $PWD2 = "secret-Greg";
my $PWD4 = "secret-Duke";

my $ring = Passwd::Keyring::PWSafe3->new(
    app=>"Passwd::Keyring::PWSafe3", group=>"Unit tests (secrets)",
    file=>$DBFILE, master_password=>"10101010",
    lazy_save=>1);

ok( defined($ring) && ref $ring eq 'Passwd::Keyring::PWSafe3',   'new() works' );

$ring->set_password($USER1, $PWD1, $REALM_B);
$ring->set_password($USER2, $PWD2, $REALM_B);#
$ring->set_password($USER1, $PWD1_ALT, $REALM_C);
$ring->set_password($USER4, $PWD4, $REALM_B);

ok( 1, "set_password works" );

$ring->save();
ok( 1, "Save succeeded");

ok( $ring->get_password($USER1, $REALM_B) eq $PWD1, "get works");

ok( $ring->get_password($USER2, $REALM_B) eq $PWD2, "get works");

ok( $ring->get_password($USER1, $REALM_C) eq $PWD1_ALT, "get works");

ok( $ring->get_password($USER4, $REALM_B) eq $PWD4, "get works");

$ring->clear_password($USER1, $REALM_B);
ok(1, "clear_password works");

ok( ! defined($ring->get_password($USER1, $REALM_A)), "get works");

ok( ! defined($ring->get_password($USER2, $REALM_A)), "get works");

ok( $ring->get_password($USER2, $REALM_B) eq $PWD2, "get works");

ok( $ring->get_password($USER1, $REALM_C) eq $PWD1_ALT, "get works");

ok( $ring->get_password($USER4, $REALM_B) eq $PWD4, "get works");

ok( $ring->clear_password($USER2, $REALM_B) eq 1, "clear clears");

ok( ! defined($ring->get_password($USER2, $REALM_A)), "clear cleared");

ok( $ring->get_password($USER1, $REALM_C) eq $PWD1_ALT, "get works");

ok( $ring->get_password($USER4, $REALM_B) eq $PWD4, "get works");

ok( $ring->clear_password($USER1, $REALM_C) eq 1, "clear clears");

ok( $ring->clear_password($USER4, $REALM_B) eq 1, "clear clears");

ok( ! defined($ring->get_password($USER1, $REALM_C)), "clear cleared");
ok( ! defined($ring->get_password($USER4, $REALM_B)), "clear cleared");

$ring->save();
ok( 1, "Save succeeded");




