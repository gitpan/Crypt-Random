package Crypt::Random::Provider::File; 


sub _defaultsource { 
    return;
}


sub new { 

    my ($class, %args) = @_;
    my $self = { Source => $args{File} || $args{Device} || $args{Filename} || $class->_defaultsource() };
    return bless $self, $class;

}


sub get_data { 

    my ($self, %params) = @_;
    $self = {} unless ref $self;

    my $size = $params{Size}; 
    my $skip = $params{Skip} || $$self{Skip};

    if ($size && ref $size eq "Math::Pari") { 
        $size = pari2num($size);
    }

    my $bytes = $params{Length} || (int($size / 8) + 1);

    open RANDOM, $$self{Source};

    my($r, $read, $rt) = ('', 0);
    while ($read < $bytes) {
        read  RANDOM, $rt, 1;
        unless ($skip && $skip =~ /\Q$rt\E/) {
            $r .= $rt; $read++;
        }
    }

    $r;

}


sub available { 
    my ($class) = @_;
    return -e $class->_defaultsource();
}


1;
