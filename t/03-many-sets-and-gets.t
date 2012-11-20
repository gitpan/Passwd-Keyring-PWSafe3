#!perl

use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

unless($ENV{PWSAFE_SKIP_TEST}) {
    plan tests => 11;
} else {
    plan skip_all => "Skipped as PWSAFE_SKIP_TEST is set.";
}

use Passwd::Keyring::PWSafe3;

my $DBFILE = File::Spec->catfile($FindBin::Bin, "test.psafe3");
my $SOME_REALM = 'my@@realm';
my $OTHER_REALM = 'other realm';

my $ring = Passwd::Keyring::PWSafe3->new(
    app=>"Passwd::Keyring::PWSafe3", group=>"Unit tests",
    file=>$DBFILE, master_password=>"10101010",
    lazy_save=>1);

ok( defined($ring) && ref $ring eq 'Passwd::Keyring::PWSafe3',   'new() works' );

$ring->set_password("Paul", "secret-Paul", $SOME_REALM);
$ring->set_password("Gregory", "secret-Greg", $SOME_REALM);#
$ring->set_password("Paul", "secret-Paul2", $OTHER_REALM);
$ring->set_password("Duke", "secret-Duke", $SOME_REALM);

ok( 1, "set_password works" );

ok( $ring->get_password("Paul", $SOME_REALM) eq 'secret-Paul', "get works");

ok( $ring->get_password("Gregory", $SOME_REALM) eq 'secret-Greg', "get works");

ok( $ring->get_password("Paul", $OTHER_REALM) eq 'secret-Paul2', "get works");

ok( $ring->get_password("Duke", $SOME_REALM) eq 'secret-Duke', "get works");

ok( $ring->clear_password("Paul", $SOME_REALM) eq 1, "clear_password removed 1");

ok( ! defined($ring->get_password("Paul", $SOME_REALM)), "get works");

ok( $ring->get_password("Gregory", $SOME_REALM) eq 'secret-Greg', "get works");

ok( $ring->get_password("Paul", $OTHER_REALM) eq 'secret-Paul2', "get works");

ok( $ring->get_password("Duke", $SOME_REALM) eq 'secret-Duke', "get works");

# No ring->save, on purpose, let's test destructor
#$ring->save();
#ok( 1, "Save succeeded");

# Note: cleanup is performed by test 04, we test passing data to
#       separate program.
