#!/usr/bin/perl -s
##
## Crypt::Random -- Interface to /dev/random and /dev/urandom.
##
## Copyright (c) 1998, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: Random.pm,v 1.11 2001/07/12 15:59:47 vipul Exp $

package Crypt::Random; 
require Exporter;
use vars qw($VERSION @EXPORT_OK); 
use Math::Pari qw(PARI floor Mod pari2pv pari2num lift); 
use Carp; 
use Data::Dumper;
use Class::Loader;
use Crypt::Random::Generator;
*import      = \&Exporter::import;

@EXPORT_OK   = qw( makerandom makerandom_itv makerandom_octet );
($VERSION) = do { my @r = (q$Revision: 1.13 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };


sub _pickprovider { 

    my (%params) = @_;

    return $params{Provider} if $params{Provider};
    $params{Strength} ||= 0;
    my $gen = new Crypt::Random::Generator Strength => $params{Strength};
    return $gen->{Provider};

}

sub makerandom { 

    my ( %params ) = @_;

    $params{Verbosity} = 0 unless $params{Verbosity};

    local $| = 1;

    my $provider = _pickprovider(%params);
    my $loader = new Class::Loader;
    my $po = $loader->_load ( Module => "Crypt::Random::Provider::$provider", 
                              Args => [ %params ] ) 
        or die "Unable to load module Crypt::Random::Provider::$provider - $!";
    my $r = $po->get_data( %params );

    my $size     = $params{Size};
    my $down     = $size - 1;
    $y = unpack "H*",     pack "B*", '0' x ( $size%8 ? 8-$size % 8 : 0 ). '1'.
         unpack "b$down", $r;

    return Math::Pari::_hex_cvt ( "0x$y" );

}


sub makerandom_itv { 

    my ( %params ) = @_; 

    my $a  = $params{ Lower } || 0; $a = PARI ( $a ); 
    my $b  = $params{ Upper }; $b = PARI ( $b );

    my $itv    = Mod ( 0, $b - $a );
    my $size   = length ( $itv ) * 5;
    my $random = makerandom %params, Size => $size;

    $itv += $random; 
    my $r = PARI ( lift ( $itv ) + $a );

    undef $itv; undef $a; undef $b; 
    return "$r";

}


sub makerandom_octet  {

    my ( %params ) = @_; 

    $params{Verbosity} = 0 unless $params{Verbosity};

    my $provider = _pickprovider(%params); 
    my $loader = new Class::Loader;
    my $po = $loader->_load ( Module => "Crypt::Random::Provider::$provider", 
                              Args => [ %params ] );
    return $po->get_data( %params );


}


'True Value';

=head1 NAME

Crypt::Random - Cryptographically Secure, True Random Number Generator. 

=head1 VERSION

 $Revision: 1.11 $
 $Date: 2001/07/12 15:59:47 $

=head1 SYNOPSIS

 use Crypt::Random qw( makerandom ); 
 my $r = makerandom ( Size => 512, Strength => 1 ); 

=head1 DESCRIPTION

Crypt::Random is an interface module to the /dev/random device found on
most modern unix systems. It also interfaces with egd, a user space
entropy gathering daemon, available for systems where /dev/random (or
similar) devices are not available. When Math::Pari is installed,
Crypt::Random can generate random integers of arbritary size of a given
bitsize or in a specified interval.

=head1 BLOCKING BEHAVIOUR

The /dev/random driver maintains an estimate of true randomness in the
pool and decreases it every time random strings are requested for use.
When the estimate goes down to zero, the routine blocks and waits for the
occurrence of non-deterministic events to refresh the pool.

When the routine is blocked, Crypt::Random's read() will be blocked till
desired amount of random bytes have been read off of the device. The
/dev/random kernel module also provides another interface, /dev/urandom,
that does not wait for the entropy-pool to recharge and returns as many
bytes as requested. For applications that must not block (for a
potentially long time) should use /dev/urandom. /dev/random should be
reserved for instances where very high quality randomness is desired.

=head1 HARDWARE RNG

If there's a hardware random number generator available, for instance the
Intel i8x0 random number generator, please use it instead of /dev/random!.
It'll be high quality, a lot faster and it won't block! Usually your OS
will provide access to the RNG as a device, eg (/dev/intel_rng).

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

=item B<makerandom_octet()>

Generates a random octet string of specified length. In addition to
B<Strength>, B<Device> and B<Verbosity>, following arguments can be
specified.

=over 4

=item B<Length>

Length of the desired octet string. 

=item B<Skip>

An octet string consisting of characters to be skipped while reading from
the random device.

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

