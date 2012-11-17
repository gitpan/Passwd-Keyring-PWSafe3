#!perl

use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

if($ENV{PWSAFE_FULL_TEST}) {
    plan tests => 14;
} else {
    plan skip_all => "Skipped as runs fairly slowly. Set environment variable PWSAFE_FULL_TEST to execute this test.";
}

use Passwd::Keyring::PWSafe3;

my $DBFILE = File::Spec->catfile($FindBin::Bin, "sampledb", "test.psafe3");
my $SOME_REALM = 'my@@realm';
my $OTHER_REALM = 'other realm';

my $ring = Passwd::Keyring::PWSafe3->new(
    app=>"Passwd::Keyring::PWSafe3", group=>"Unit tests",
    file=>$DBFILE, master_password=>sub {"10101010"},
    lazy_save => 1);

ok( defined($ring) && ref $ring eq 'Passwd::Keyring::PWSafe3',   'new() works' );

ok( ! defined($ring->get_password("Paul", $SOME_REALM)), "get works");

ok( $ring->get_password("Gregory", $SOME_REALM) eq 'secret-Greg', "get works");

ok( $ring->get_password("Paul", $OTHER_REALM) eq 'secret-Paul2', "get works");

ok( $ring->get_password("Duke", $SOME_REALM) eq 'secret-Duke', "get works");

ok( $ring->clear_password("Gregory", $SOME_REALM) eq 1, "clear clears");

ok( ! defined($ring->get_password("Gregory", $SOME_REALM)), "clear cleared");

ok( $ring->get_password("Paul", $OTHER_REALM) eq 'secret-Paul2', "get works");

ok( $ring->get_password("Duke", $SOME_REALM) eq 'secret-Duke', "get works");

ok( $ring->clear_password("Paul", $OTHER_REALM) eq 1, "clear clears");

ok( $ring->clear_password("Duke", $SOME_REALM) eq 1, "clear clears");

ok( ! defined($ring->get_password("Paul", $SOME_REALM)), "clear cleared");
ok( ! defined($ring->get_password("Duke", $SOME_REALM)), "clear cleared");

$ring->save();
ok( 1, "Save succeeded");


