#!/usr/bin/perl -s
##
## Crypt::Random -- Interface to /dev/random and /dev/urandom.
##
## Copyright (c) 1998, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: Random.pm,v 0.33 2001/02/18 20:56:07 vipul Exp vipul $

package Crypt::Random; 
require Exporter;
use vars qw($VERSION @EXPORT_OK); 
use Math::Pari qw(PARI floor Mod pari2pv pari2num lift); 
use Carp; 
use Data::Dumper;
*import      = \&Exporter::import;

@EXPORT_OK   = qw( makerandom makerandom_itv );
( $VERSION ) = '$Revision: 0.33 $' =~ /\s+(\d+\.\d+)\s+/; 
$DEV{ 0 }    = "/dev/urandom";   
$DEV{ 1 }    = "/dev/random";   

sub makerandom { 

	my ( %params ) = @_;

    my $size     = $params{ Size }; 
    my $strength = $params{ Strength };
    my $dev      = $params{ Device }; 
    my $down     = $size - 1;
    $params{Verbosity} = 0 unless $params{Verbosity};

	$dev = $DEV{ 0 } unless $strength || $dev; 
	$dev = $DEV{ 1 }     if $strength && !($dev); 

	croak "$dev doesn't exist.  aborting." unless -e $dev;

    $| = 1;
    my $r = $rt = "";
    my $bytes = int ( pari2num($size) / 8 ) + 1;
	open  RANDOM, $dev;
    for ( 0 .. $bytes ) {
        read  RANDOM, $rt, 1;
        print "." if $params{Verbosity} == 1 && (!($_ % 2));
        $r .= $rt;
    }
    print "\n" if $params{Verbosity} == 1;
    close RANDOM;

    $y = unpack "H*",     pack "B*", '0' x ( $size%8 ? 8-$size % 8 : 0 ). '1'.
         unpack "b$down", $r;

	return Math::Pari::_hex_cvt ( "0x$y" );

}


sub makerandom_itv { 

	my ( %params ) = @_; 

    my $a  = $params{ Lower }; $a = PARI ( $a ); 
    my $b  = $params{ Upper }; $b = PARI ( $b );

	my $itv    = Mod ( 0, $b - $a );
	my $size   = length ( $itv ) * 5;
	my $random = makerandom Size      => $size, 
                            Strength  => $params{ Strength }, 
                            Device    => $params{ Device }, 
                            Verbosity => $params{ Verbosity };

	$itv += $random; 
    my $r = PARI ( lift ( $itv ) + $a );

    undef $itv; undef $a; undef $b; 
    return "$r";

}

'True Value';

=head1 NAME

Crypt::Random - Cryptographically Secure, True Random Number Generator. 

=head1 VERSION

 $Revision: 0.33 $
 $Date: 2001/02/18 20:56:07 $

=head1 SYNOPSIS

 use Crypt::Random qw( makerandom ); 
 my $r = makerandom ( Size => 512, Strength => 1 ); 

=head1 DESCRIPTION

Crypt::Random is an interface module to the /dev/random device found on
most modern Unix systems. The /dev/random driver gathers environmental
noise from various non-deterministic sources including inter-keyboard
timings and inter-interrupt timings that occur within the operating system
environment.

The /dev/random driver maintains an estimate of true randomness in the
pool and decreases it every time random strings are requested for use.
When the estimate goes down to zero, the routine blocks and waits for the
occurrence of non-deterministic events to refresh the pool.

The /dev/random kernel module also provides another interface,
/dev/urandom, that does not wait for the entropy-pool to recharge and
returns as many bytes as requested. /dev/urandom is considerably faster at
generation compared to /dev/random, which should be used only when very
high quality randomness is desired.

=head1 METHODS 

=over 4

=item B<makerandom()>

Generates a random number of requested bitsize in base 10. Following
arguments can be specified.

=over 4

=item B<Size> 

Bitsize of the random number. 

=item B<Strength> 0 || 1 

Value of 1 implies that /dev/random should be used
for requesting random bits while 0 implies /dev/urandom.

=item B<Device> 

Alternate device to request random bits from. 

=back 

=item B<makerandom_itv()> 

Generates a random number in the specified interval.  In addition 
to the arguments to makerandom() following attributes can be 
specified. 

=over 4

=item B<Lower> 

Inclusive Lower limit.  

=item B<Upper> 

Exclusive Upper limit. 

=back 

=back

=head1 DEPENDENCIES

Crypt::Random needs Math::Pari 2.001802 or higher. As of this writing, the
latest version of Math::Pari isn't available from CPAN. Fetch it from
ftp://ftp.math.ohio-state.edu/pub/users/ilya/perl/modules/

=head1 BIBLIOGRAPHY 

=over 4

=item 1 random.c by Theodore Ts'o.  Found in drivers/char directory of 
the Linux kernel sources.

=item 2 Handbook of Applied Cryptography by Menezes, Paul C. van Oorschot
and Scott Vanstone.

=back

=head1 AUTHOR

Vipul Ved Prakash, <mail@vipul.net>

=cut


