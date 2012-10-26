require 5.003000;

use strict;
use ExtUtils::MakeMaker;

my $PM = 'lib/Digest/SHA3.pm';

my %att = (
	'NAME'		=> 'Digest::SHA3',
	'VERSION_FROM'	=> $PM,
	'LIBS'		=> [''],
	'INC'		=> '-I.',
	'EXE_FILES'	=> [ 'sha3sum' ],
);

my $MMversion = $ExtUtils::MakeMaker::VERSION || 0;
$att{NO_META} = 1 unless $MMversion < 6.10_03;

WriteMakefile(%att);
