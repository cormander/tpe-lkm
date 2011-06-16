#!/usr/bin/perl -w

use strict;
use warnings;

my @files = (
	'execve.c',
	'mmap.c',
);

my @funcs;

print "#include \"tpe.h\"\n";
print "extern void hijack_syscall(struct code_store *cs, const unsigned long code, const unsigned long addr);\n";

foreach my $file (@files) {

	open FILE, $file;
	my @file = <FILE>;
	close FILE;

	# print structs

	foreach my $line (@file) {

		if ($line =~ /^struct code_store /) {
			print "extern " . $line;

			my $func = $line;
			chomp $func;
			$func =~ s/.* cs_//;
			$func =~ s/;.*//;

			push @funcs, $func;
		}

	}

	# print functions

	my $ok = 0;

	foreach my $line (@file) {

		$line =~ s/\) *\{/);/;

		if ($line =~ /^int tpe_/) {
			$ok = 1;
			print "extern ";
		}

		print $line if $ok == 1;

		if ($line =~ /;/) {
			$ok = 0;
		}

	}

}

print "void hijack_syscalls(void) {\n";

foreach my $func (@funcs) {

	if ($func =~ /compat/) {
		print "#ifndef CONFIG_X86_32\n";
	}

	print "\thijack_syscall(&cs_$func, (unsigned long)tpe_$func, |addr_$func|);\n";

	if ($func =~ /compat/) {
		print "#endif\n";
	}

}

print "\n}\n";

print "void undo_hijack_syscalls(void) {\n";

foreach my $func (@funcs) {

	if ($func =~ /compat/) {
		print "#ifndef CONFIG_X86_32\n";
	}

	print "\tstop_my_code(&cs_$func);\n";

	if ($func =~ /compat/) {
		print "#endif\n";
	}

}

print "\n}\n";

