#!perl

use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

unless($ENV{PWSAFE_SKIP_TEST}) {
    plan tests => 16;
} else {
    plan skip_all => "Skipped as PWSAFE_SKIP_TEST is set.";
}

use Passwd::Keyring::PWSafe3;

my $DBFILE = File::Spec->catfile($FindBin::Bin, "test.psafe3");

my $USER = "Herakliusz";
my $REALM = "test realm";
my $PWD = "arcytajne haslo";
my $PWD2 = "inny sekret";

my $APP1 = "Passwd::Keyring::Unit tests (1)";
my $APP2 = "Passwd::Keyring::Unit tests (2)";
my $GROUP1 = "Passwd::Keyring::Unit tests - group 1";
my $GROUP2 = "Passwd::Keyring::Unit tests - group 2";
my $GROUP3 = "Passwd::Keyring::Unit tests - group 3";

{
    my $ring = Passwd::Keyring::PWSafe3->new(
        app=>$APP1, group=>$GROUP1,
        file=>$DBFILE, master_password=>"10101010",
        lazy_save=>1);

    ok( defined($ring) && ref $ring eq 'Passwd::Keyring::PWSafe3',   'new() works' );

    ok( ! defined($ring->get_password($USER, $REALM)), "initially unset");

    $ring->set_password($USER, $PWD, $REALM);
    ok(1, "set password");

    ok( $ring->get_password($USER, $REALM) eq $PWD, "normal get works");

    $ring->save();
}


# Another object with the same app and group

{
    my $ring = Passwd::Keyring::PWSafe3->new(
        app=>$APP1, group=>$GROUP1,
        file=>$DBFILE, master_password=>"10101010");

    ok( defined($ring) && ref $ring eq 'Passwd::Keyring::PWSafe3', 'second new() works' );

    ok( $ring->get_password($USER, $REALM) eq $PWD, "get from another ring with the same data works");
}

# Only app changes
{
    my $ring = Passwd::Keyring::PWSafe3->new(
        app=>$APP2, group=>$GROUP1,
        file=>$DBFILE, master_password=>"10101010");

    ok( defined($ring) && ref $ring eq 'Passwd::Keyring::PWSafe3', 'third new() works' );

    ok( $ring->get_password($USER, $REALM) eq $PWD, "get from another ring with changed app but same group works");
}

# Only group changes
my $sec_ring;
{
    my $ring = Passwd::Keyring::PWSafe3->new(
        app=>$APP1, group=>$GROUP2,
        file=>$DBFILE, master_password=>"10101010");

    ok( defined($ring) && ref $ring eq 'Passwd::Keyring::PWSafe3', 'third new() works' );

    ok( ! defined($ring->get_password($USER, $REALM)), "changing group forces another password");

    # To test whether original won't be spoiled
    $ring->set_password($USER, $PWD2, $REALM);
}

# App and group change
{
    my $ring = Passwd::Keyring::PWSafe3->new(
        app=>$APP2, group=>$GROUP3,
        file=>$DBFILE, master_password=>"10101010");

    ok( defined($ring) && ref $ring eq 'Passwd::Keyring::PWSafe3', 'third new() works' );

    ok( ! defined($ring->get_password($USER, $REALM)), "changing group and app forces another password");

}

# Re-reading original to check whether it was properly kept, and
# finally clearing it
{
    my $ring = Passwd::Keyring::PWSafe3->new(
        app=>$APP1, group=>$GROUP1,
        file=>$DBFILE, master_password=>"10101010");

    ok( defined($ring) && ref $ring eq 'Passwd::Keyring::PWSafe3', 'second new() works' );

    ok( $ring->get_password($USER, $REALM) eq $PWD, "get original after changes in other group works");

    ok( $ring->clear_password($USER, $REALM) eq 1, "clearing");
}

# Clearing the remaining 
{
    my $ring = Passwd::Keyring::PWSafe3->new(
        app=>$APP1, group=>$GROUP2,
        file=>$DBFILE, master_password=>"10101010");

    ok( $ring->clear_password($USER, $REALM) eq 1, "clearing");
}


