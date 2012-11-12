package Digest::SHA3;

require 5.003000;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
use Fcntl;
use integer;

$VERSION = '0.04';

require Exporter;
require DynaLoader;
@ISA = qw(Exporter DynaLoader);
@EXPORT_OK = qw(
	sha3_0		sha3_0_base64		sha3_0_hex
	sha3_224	sha3_224_base64		sha3_224_hex
	sha3_256	sha3_256_base64		sha3_256_hex
	sha3_384	sha3_384_base64		sha3_384_hex
	sha3_512	sha3_512_base64		sha3_512_hex);

# If possible, inherit from Digest::base

eval {
	require Digest::base;
	push(@ISA, 'Digest::base');
};

*addfile   = \&Addfile;
*hexdigest = \&Hexdigest;
*b64digest = \&B64digest;

# The following routines aren't time-critical, so they can be left in Perl

sub new {
	my($class, $alg) = @_;
	$alg =~ s/\D+//g if defined $alg;
	$alg =~ s/^3?(0|224|256|384|512)$/$1/ if defined $alg;
	if (ref($class)) {	# instance method
		unless (defined($alg) && ($alg != $class->algorithm)) {
			sharewind($$class);
			return($class);
		}
		shaclose($$class) if $$class;
		$$class = shaopen($alg) || return;
		return($class);
	}
	$alg = 224 unless defined $alg;
	my $state = shaopen($alg) || return;
	my $self = \$state;
	bless($self, $class);
	return($self);
}

sub DESTROY {
	my $self = shift;
	shaclose($$self) if $$self;
}

sub clone {
	my $self = shift;
	my $state = shadup($$self) || return;
	my $copy = \$state;
	bless($copy, ref($self));
	return($copy);
}

*reset = \&new;

sub add_bits {
	my($self, $data, $nbits) = @_;
	unless (defined $nbits) {
		$nbits = length($data);
		$data = pack("B*", $data);
	}
	$nbits = length($data) * 8 if $nbits > length($data) * 8;
	shawrite($data, $nbits, $$self);
	return($self);
}

sub _bail {
	my $msg = shift;

	$msg .= ": $!";
        require Carp;
        Carp::croak($msg);
}

sub _addfile {  # this is "addfile" from Digest::base 1.00
    my ($self, $handle) = @_;

    my $n;
    my $buf = "";

    while (($n = read($handle, $buf, 4096))) {
        $self->add($buf);
    }
    _bail("Read failed") unless defined $n;

    $self;
}

sub Addfile {
	my ($self, $file, $mode) = @_;

	return(_addfile($self, $file)) unless ref(\$file) eq 'SCALAR';

	$mode = defined($mode) ? $mode : "";
	my ($binary, $portable, $BITS) = map { $_ eq $mode } ("b", "p", "0");

		## Always interpret "-" to mean STDIN; otherwise use
		## sysopen to handle full range of POSIX file names
	local *FH;
	$file eq '-' and open(FH, '< -')
		or sysopen(FH, $file, O_RDONLY)
			or _bail('Open failed');

	if ($BITS) {
		my ($n, $buf) = (0, "");
		while (($n = read(FH, $buf, 4096))) {
			$buf =~ s/[^01]//g;
			$self->add_bits($buf);
		}
		_bail("Read failed") unless defined $n;
		close(FH);
		return($self);
	}

	binmode(FH) if $binary || $portable;
	unless ($portable && -T $file) {
		$self->_addfile(*FH);
		close(FH);
		return($self);
	}

	my ($n1, $n2);
	my ($buf1, $buf2) = ("", "");

	while (($n1 = read(FH, $buf1, 4096))) {
		while (substr($buf1, -1) eq "\015") {
			$n2 = read(FH, $buf2, 4096);
			_bail("Read failed") unless defined $n2;
			last unless $n2;
			$buf1 .= $buf2;
		}
		$buf1 =~ s/\015?\015\012/\012/g;	# DOS/Windows
		$buf1 =~ s/\015/\012/g;			# early MacOS
		$self->add($buf1);
	}
	_bail("Read failed") unless defined $n1;
	close(FH);

	$self;
}

Digest::SHA3->bootstrap($VERSION);

1;
__END__

=head1 NAME

Digest::SHA3 - Perl extension for SHA-3

=head1 SYNOPSIS

In programs:

		# Functional interface

	use Digest::SHA3 qw(sha3_224 sha3_256_hex sha3_512_base64 ...);

	$digest = sha3_224($data);
	$digest = sha3_256_hex($data);
	$digest = sha3_384_base64($data);
	$digest = sha3_512($data);

	$digest = sha3_0_hex($data);

		# Object-oriented

	use Digest::SHA3;

	$sha3 = Digest::SHA3->new($alg);

	$sha3->add($data);		# feed data into stream

	$sha3->addfile(*F);
	$sha3->addfile($filename);

	$sha3->add_bits($bits);
	$sha3->add_bits($data, $nbits);

	$digest = $sha3->digest;	# compute digest
	$digest = $sha3->hexdigest;
	$digest = $sha3->b64digest;

=head1 ABSTRACT

Digest::SHA3 is a complete implementation of the NIST SHA-3
cryptographic hash function, known originally as Keccak.  It gives
Perl programmers a convenient way to calculate SHA3-224, SHA3-256,
SHA3-384, and SHA3-512 message digests, as well as variable-length
hashes using the SHA3-0 variant.  The module can handle all types of
input, including partial-byte data.

=head1 DESCRIPTION

Digest::SHA3 is written in C for speed.  If your platform lacks a C
compiler, perhaps you can find the module in a binary form compatible
with your particular processor and operating system.

The programming interface is easy to use: it's the same one found
in CPAN's L<Digest> module.  So, if your applications currently use
L<Digest::SHA> and you'd prefer the newer flavor of the NIST standard,
it's a simple matter to convert them.

The interface provides two ways to calculate digests:  all-at-once,
or in stages.  To illustrate, the following short program computes
the SHA3-256 digest of "hello world" using each approach:

	use Digest::SHA3 qw(sha3_256_hex);

	$data = "hello world";
	@frags = split(//, $data);

	# all-at-once (Functional style)
	$digest1 = sha3_256_hex($data);

	# in-stages (OOP style)
	$state = Digest::SHA3->new(256);
	for (@frags) { $state->add($_) }
	$digest2 = $state->hexdigest;

	print $digest1 eq $digest2 ?
		"that's the ticket!\n" : "oops!\n";

To calculate the digest of an n-bit message where I<n> is not a
multiple of 8, use the I<add_bits()> method.  For example, consider
the 446-bit message consisting of the bit-string "110" repeated
148 times, followed by "11".  Here's how to display its SHA3-512
digest:

	use Digest::SHA3;
	$bits = "110" x 148 . "11";
	$sha3 = Digest::SHA3->new(512)->add_bits($bits);
	print $sha3->hexdigest, "\n";

Note that for larger bit-strings, it's more efficient to use the
two-argument version I<add_bits($data, $nbits)>, where I<$data> is
in the customary packed binary format used for Perl strings.

=head1 PADDING OF BASE64 DIGESTS

By convention, CPAN Digest modules do B<not> pad their Base64 output.
Problems can occur when feeding such digests to other software that
expects properly padded Base64 encodings.

For the time being, any necessary padding must be done by the user.
Fortunately, this is a simple operation: if the length of a Base64-encoded
digest isn't a multiple of 4, simply append "=" characters to the end
of the digest until it is:

	while (length($b64_digest) % 4) {
		$b64_digest .= '=';
	}

To illustrate, I<sha3_256_base64("abc")> is computed to be

	TgNleupFqU/H1HuoJsjWZ8DR5uM6ZKA27ET1j6EtbEU

which has a length of 43.  So, the properly padded version is

	TgNleupFqU/H1HuoJsjWZ8DR5uM6ZKA27ET1j6EtbEU=

=head1 EXPORT

None by default.

=head1 EXPORTABLE FUNCTIONS

Provided your C compiler supports a 64-bit type (e.g. the I<long long> of
C99, or I<__int64> used by Microsoft C/C++), all of these functions will
be available for use.  Otherwise you won't be able to perform any of them.

In the interest of simplicity, maintainability, and small code size,
it's unlikely that future versions of this module will support a 32-bit
implementation.  Older platforms using 32-bit-only compilers should
continue to favor 32-bit hash implementations such as SHA-1, SHA-224,
or SHA-256.  The desire to use the SHA-3 hash standard, dating from 2012,
should reasonably require that one's compiler adhere to programming
language standards dating from at least 1999.

I<Functional style>

=over 4

=item B<sha3_0($data, ...)>

=item B<sha3_224($data, ...)>

=item B<sha3_256($data, ...)>

=item B<sha3_384($data, ...)>

=item B<sha3_512($data, ...)>

Logically joins the arguments into a single string, and returns its
SHA3-0/224/256/384/512 digest encoded as a binary string.

The digest size for SHA3-0 is 4096 bits (512 bytes), which can be
truncated to any desired length.  The ability to generate even larger
digest sizes might be supported in future versions of this module,
pending interest from the user community.

=item B<sha3_0_hex($data, ...)>

=item B<sha3_224_hex($data, ...)>

=item B<sha3_256_hex($data, ...)>

=item B<sha3_384_hex($data, ...)>

=item B<sha3_512_hex($data, ...)>

Logically joins the arguments into a single string, and returns
its SHA3-0/224/256/384/512 digest encoded as a hexadecimal string.

=item B<sha3_0_base64($data, ...)>

=item B<sha3_224_base64($data, ...)>

=item B<sha3_256_base64($data, ...)>

=item B<sha3_384_base64($data, ...)>

=item B<sha3_512_base64($data, ...)>

Logically joins the arguments into a single string, and returns
its SHA3-0/224/256/384/512 digest encoded as a Base64 string.

It's important to note that the resulting string does B<not> contain
the padding characters typical of Base64 encodings.  This omission is
deliberate, and is done to maintain compatibility with the family of
CPAN Digest modules.  See L</"PADDING OF BASE64 DIGESTS"> for details.

=back

I<OOP style>

=over 4

=item B<new($alg)>

Returns a new Digest::SHA3 object.  Allowed values for I<$alg> are 0, 224,
256, 384, or 512.  It's also possible to use common string representations
of the algorithm (e.g. "sha3-256", "SHA-3-384").  If the argument is
missing, SHA3-224 will be used by default.

Invoking I<new> as an instance method will not create a new object;
instead, it will simply reset the object to the initial state associated
with I<$alg>.  If the argument is missing, the object will continue
using the same algorithm that was selected at creation.

=item B<reset($alg)>

This method has exactly the same effect as I<new($alg)>.  In fact,
I<reset> is just an alias for I<new>.

=item B<hashsize>

Returns the number of digest bits for this object.  The values are 4096,
224, 256, 384, and 512 for SHA3-0, SHA3-224, SHA3-256, SHA3-384, and
SHA3-512, respectively.

The associated digest size for SHA3-0 is 4096 bits (512 bytes), which
can be truncated to any desired length.  The ability to generate even
larger digest sizes might be supported in future versions of this module,
pending interest from the user community.

=item B<algorithm>

Returns the digest algorithm for this object.  The values are 0, 224,
256, 384, and 512 for SHA3-0, SHA3-224, SHA3-256, SHA3-384, and SHA3-512,
respectively.

=item B<clone>

Returns a duplicate copy of the object.

=item B<add($data, ...)>

Logically joins the arguments into a single string, and uses it to
update the current digest state.  In other words, the following
statements have the same effect:

	$sha3->add("a"); $sha3->add("b"); $sha3->add("c");
	$sha3->add("a")->add("b")->add("c");
	$sha3->add("a", "b", "c");
	$sha3->add("abc");

The return value is the updated object itself.

=item B<add_bits($data, $nbits)>

=item B<add_bits($bits)>

Updates the current digest state by appending bits to it.  The
return value is the updated object itself.

The first form causes the most-significant I<$nbits> of I<$data>
to be appended to the stream.  The I<$data> argument is in the
customary binary format used for Perl strings.

The second form takes an ASCII string of "0" and "1" characters as
its argument.  It's equivalent to

	$sha3->add_bits(pack("B*", $bits), length($bits));

So, the following two statements do the same thing:

	$sha3->add_bits("111100001010");
	$sha3->add_bits("\xF0\xA0", 12);

=item B<addfile(*FILE)>

Reads from I<FILE> until EOF, and appends that data to the current
state.  The return value is the updated object itself.

=item B<addfile($filename [, $mode])>

Reads the contents of I<$filename>, and appends that data to the current
state.  The return value is the updated object itself.

By default, I<$filename> is simply opened and read; no special modes
or I/O disciplines are used.  To change this, set the optional I<$mode>
argument to one of the following values:

	"b"	read file in binary mode

	"p"	use portable mode

	"0"	use BITS mode

The "p" mode ensures that the digest value of I<$filename> will be the
same when computed on different operating systems.  It accomplishes
this by internally translating all newlines in text files to UNIX format
before calculating the digest.  Binary files are read in raw mode with
no translation whatsoever.

The BITS mode ("0") interprets the contents of I<$filename> as a logical
stream of bits, where each ASCII '0' or '1' character represents a 0 or
1 bit, respectively.  All other characters are ignored.  This provides
a convenient way to calculate the digest values of partial-byte data by
using files, rather than having to write programs using the I<add_bits>
method.

=item B<digest>

Returns the digest encoded as a binary string.

Note that the I<digest> method is a read-once operation. Once it
has been performed, the Digest::SHA3 object is automatically reset
in preparation for calculating another digest value.  Call
I<$sha-E<gt>clone-E<gt>digest> if it's necessary to preserve the
original digest state.

=item B<hexdigest>

Returns the digest encoded as a hexadecimal string.

Like I<digest>, this method is a read-once operation.  Call
I<$sha-E<gt>clone-E<gt>hexdigest> if it's necessary to preserve the
original digest state.

This method is inherited if L<Digest::base> is installed on your system.
Otherwise, a functionally equivalent substitute is used.

=item B<b64digest>

Returns the digest encoded as a Base64 string.

Like I<digest>, this method is a read-once operation.  Call
I<$sha-E<gt>clone-E<gt>b64digest> if it's necessary to preserve the
original digest state.

This method is inherited if L<Digest::base> is installed on your system.
Otherwise, a functionally equivalent substitute is used.

It's important to note that the resulting string does B<not> contain
the padding characters typical of Base64 encodings.  This omission is
deliberate, and is done to maintain compatibility with the family of
CPAN Digest modules.  See L</"PADDING OF BASE64 DIGESTS"> for details.

=back

=head1 SEE ALSO

L<Digest>, L<Digest::SHA>, L<Digest::Keccak>

The Keccak/SHA-3 specifications can be found at:

L<http://keccak.noekeon.org/Keccak-reference-3.0.pdf>
L<http://keccak.noekeon.org/Keccak-submission-3.pdf>

=head1 AUTHOR

	Mark Shelor	<mshelor@cpan.org>

=head1 ACKNOWLEDGMENTS

The author is particularly grateful to

	Chris Skiscim

for being on the ball, as usual.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 Mark Shelor

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

L<perlartistic>

=cut
