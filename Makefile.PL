require 5.003000;

use strict;
use ExtUtils::MakeMaker;
use Getopt::Std;
use Config qw(%Config);

my $PM = 'lib/Digest/SHA3.pm';

my %opts;
getopts('w', \%opts);

my @extra = ();

	# Workaround for DEC compiler bug, adapted from Digest::MD5

if ($^O eq 'VMS') {
	if (defined($Config{ccname})) {
		if (grep(/VMS_VAX/, @INC) && ($Config{ccname} eq 'DEC')) {
			# VAX compiler optimizer even up to v6.4 gets stuck
			push(@extra, OPTIMIZE => "/Optimize=(NODISJOINT)");
		}
	}
}

	# Enhance performance on Intel when using gcc

if ($Config{archname} =~ /^i[3456]86/ && $Config{ccname} eq 'gcc') {
	push(@extra, OPTIMIZE => '-O1 -fomit-frame-pointer');
}

push(@extra, CCFLAGS => '-W -Wall ' . $Config{ccflags}) if $opts{'w'};

my @srcs = map { "src/$_" } qw(sha3.c);
my @hdrs = map { "src/$_" } qw(sha3.h);
my $deps = join(' ', @srcs, @hdrs);

my %att = (
	'NAME'		=> 'Digest::SHA3',
	'VERSION_FROM'	=> $PM,
	'LIBS'		=> [''],
	'INC'		=> '-I.',
	'EXE_FILES'	=> [ 'sha3sum' ],
	'depend'	=> { 'SHA3.c' => $deps },
	@extra,
);

my $MMversion = $ExtUtils::MakeMaker::VERSION || 0;
$att{NO_META} = 1 unless $MMversion < 6.10_03;

WriteMakefile(%att);
