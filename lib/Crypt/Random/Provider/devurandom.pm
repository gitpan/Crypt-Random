#!/usr/bin/perl -sw
##
##
##
## Copyright (c) 2001, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: devurandom.pm,v 1.1 2001/06/22 03:21:41 vipul Exp $

package Crypt::Random::Provider::devurandom; 
use lib qw(/home/vipul/PERL/crypto/random/lib);
use Crypt::Random::Provider::File;
use vars qw(@ISA);
@ISA = qw(Crypt::Random::Provider::File);

sub _defaultsource { return "/dev/urandom" } 


