#!/usr/bin/perl

# Generate error.c
#
# Usage: ./generate_errors.pl or scripts/generate_errors.pl without arguments,
# or generate_errors.pl include_dir data_dir error_c [error_h]

use warnings;
use strict;

my ($include_dir, $data_dir, $error_c, $error_h) =
  qw(include/mbedtls scripts/data_files library/error.c include/mbedtls/error.h);

if( @ARGV ) {
    die "Invalid number of arguments" if @ARGV < 3 || @ARGV > 4;
    ($include_dir, $data_dir, $error_c) = @ARGV[1,3];
    $error_h = @ARGV == 4 ? $ARGV[3] : "$include_dir/error.h";

    -d $include_dir or die "No such directory: $include_dir\n";
    -d $data_dir or die "No such directory: $data_dir\n";
} else {
    unless( -d $include_dir && -d $data_dir ) {
        chdir '..' or die;
        -d $include_dir && -d $data_dir
            or die "Without arguments, must be run from root or scripts\n"
    }
}

my $error_format_file = $data_dir.'/error.fmt';

my @low_level_modules = ( "AES", "ASN1", "BLOWFISH", "CAMELLIA", "BIGNUM",
                          "BASE64", "XTEA", "PBKDF2", "OID",
                          "PADLOCK", "DES", "NET", "CTR_DRBG", "ENTROPY",
                          "HMAC_DRBG", "MD2", "MD4", "MD5", "RIPEMD160",
                          "SHA1", "SHA256", "SHA512", "GCM", "THREADING", "CCM" );
my @high_level_modules = ( "PEM", "X509", "DHM", "RSA", "ECP", "MD", "CIPHER", "SSL",
                           "PK", "PKCS12", "PKCS5" );

my $line_separator = $/;
undef $/;

open(FORMAT_FILE, "$error_format_file") or die "Opening error format file '$error_format_file': $!";
my $error_format = <FORMAT_FILE>;
close(FORMAT_FILE);

$/ = $line_separator;

=comment
open(ERROR_H, "<", $error_h) or die "Opening error.h";
my %sets;
my $section == 0;
while (my $line = <ERROR_H>)
{
    if ($line =~ /^[ *]+Module\s+Nr\s+Codes/)
    {
        $section = 1;
        next;
    }
    elsif ($line =~ /^[ *]+High-level module/../^[ *]*$/)
    {
        $section = 2;
        next;
    }
    elsif ($line =~ /^[ *]*$/)
    {
        $section = 0;
        next;
    }
    if ($section == 1 &&
        $line =~ /^[ *]+(\w+)
                   \s+([0-9]+)
                   ((?:\s+0x[[:xdigit:]]{4}-0x[[:xdigit:]]{4})+)/ix)
    {
        my ($module, $nr, $codes) = ($1, $2, $3);
    }
    if ($section == 2 &&
        $line =~ /^[ *]+(\w+)\s+([0-9]+)\s+([0-9]+)\s*(.*top)?/)
    {
        my ($module, $id, $nr) = ($1, $2, $3);
    }
}
close(ERROR_H);

=cut

open(GREP, "grep \"define MBEDTLS_ERR_\" $include_dir/* |") || die("Failure when calling grep: $!");

my $ll_old_define = "";
my $hl_old_define = "";

my $ll_code_check = "";
my $hl_code_check = "";

my $headers = "";

my %error_codes_seen;

while (my $line = <GREP>)
{
    next if ($line =~ /compat-1.2.h/);
    my ($error_name, $error_code) = $line =~ /(MBEDTLS_ERR_\w+)\s+\-(0x\w+)/;
    my $error_number = hex($error_code);
    my ($description) = $line =~ /\/\*\*< (.*?)\.? \*\//;

    die "Duplicated error code: $error_code ($error_name)\n"
        if exists $error_codes_seen{$error_number};

    $description =~ s/\\/\\\\/g;
    if ($description eq "") {
        $description = "DESCRIPTION MISSING";
        warn "Missing description for $error_name\n";
    }

    my ($module_name) = $error_name =~ /^MBEDTLS_ERR_([^_]+)/;

    # Fix faulty ones
    $module_name = "BIGNUM" if ($module_name eq "MPI");
    $module_name = "CTR_DRBG" if ($module_name eq "CTR");
    $module_name = "HMAC_DRBG" if ($module_name eq "HMAC");

    $error_codes_seen{$error_number} = $module_name;

    my $define_name = $module_name;
    $define_name = "X509_USE,X509_CREATE" if ($define_name eq "X509");
    $define_name = "ASN1_PARSE" if ($define_name eq "ASN1");
    $define_name = "SSL_TLS" if ($define_name eq "SSL");
    $define_name = "PEM_PARSE,PEM_WRITE" if ($define_name eq "PEM");

    my $include_name = $module_name;
    $include_name =~ tr/A-Z/a-z/;
    $include_name = "" if ($include_name eq "asn1");

    # Fix faulty ones
    $include_name = "net_sockets" if ($module_name eq "NET");

    my $found_ll = grep $_ eq $module_name, @low_level_modules;
    my $found_hl = grep $_ eq $module_name, @high_level_modules;
    if (!$found_ll && !$found_hl)
    {
        printf STDERR ("Error: unknown module name: $module_name\n");
        exit 1;
    }

    my $code_check;
    my $old_define;
    my $white_space;
    my $first;

    if ($found_ll)
    {
        if ($error_number < 1 || $error_number > 0x7f)
        {
            printf STDERR ("Error: invalid low-level error code $error_code ($error_name)\n");
            exit 1;
        }
        $code_check = \$ll_code_check;
        $old_define = \$ll_old_define;
        $white_space = '    ';
    }
    else
    {
        if ($error_number == 0 || $error_number > 0x7fff ||
            ($error_number & 0x7f) != 0)
        {
            printf STDERR ("Error: invalid high-level error code $error_code ($error_name)\n");
            exit 1;
        }
        $code_check = \$hl_code_check;
        $old_define = \$hl_old_define;
        $white_space = '        ';
    }

    if ($define_name ne ${$old_define})
    {
        if (${$old_define} ne "")
        {
            ${$code_check} .= "#endif /* ";
            $first = 0;
            foreach my $dep (split(/,/, ${$old_define}))
            {
                ${$code_check} .= " || " if ($first++);
                ${$code_check} .= "MBEDTLS_${dep}_C";
            }
            ${$code_check} .= " */\n\n";
        }

        ${$code_check} .= "#if ";
        $headers .= "#if " if ($include_name ne "");
        $first = 0;
        foreach my $dep (split(/,/, ${define_name}))
        {
            ${$code_check} .= " || " if ($first);
            $headers       .= " || " if ($first++);

            ${$code_check} .= "defined(MBEDTLS_${dep}_C)";
            $headers       .= "defined(MBEDTLS_${dep}_C)" if
                                                    ($include_name ne "");
        }
        ${$code_check} .= "\n";
        $headers .= "\n#include \"mbedtls/${include_name}.h\"\n".
                    "#endif\n\n" if ($include_name ne "");
        ${$old_define} = $define_name;
    }

    if ($error_name eq "MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE")
    {
        ${$code_check} .= "${white_space}if( use_ret == -($error_name) )\n".
                          "${white_space}\{\n".
                          "${white_space}    mbedtls_snprintf( buf, buflen, \"$module_name - $description\" );\n".
                          "${white_space}    return;\n".
                          "${white_space}}\n"
    }
    else
    {
        ${$code_check} .= "${white_space}if( use_ret == -($error_name) )\n".
                          "${white_space}    mbedtls_snprintf( buf, buflen, \"$module_name - $description\" );\n"
    }
}
close GREP or die "Error reading include files: $!";

if ($ll_old_define ne "")
{
    $ll_code_check .= "#endif /* ";
    my $first = 0;
    foreach my $dep (split(/,/, $ll_old_define))
    {
        $ll_code_check .= " || " if ($first++);
        $ll_code_check .= "MBEDTLS_${dep}_C";
    }
    $ll_code_check .= " */\n";
}
if ($hl_old_define ne "")
{
    $hl_code_check .= "#endif /* ";
    my $first = 0;
    foreach my $dep (split(/,/, $hl_old_define))
    {
        $hl_code_check .= " || " if ($first++);
        $hl_code_check .= "MBEDTLS_${dep}_C";
    }
    $hl_code_check .= " */\n";
}

$error_format =~ s/HEADER_INCLUDED\n/$headers/g;
$error_format =~ s/LOW_LEVEL_CODE_CHECKS\n/$ll_code_check/g;
$error_format =~ s/HIGH_LEVEL_CODE_CHECKS\n/$hl_code_check/g;

open(ERROR_FILE, ">$error_c") or die "Opening destination file '$error_c': $!";
print ERROR_FILE $error_format or die "Writing '$error_c': $!";
close(ERROR_FILE) or die "Closing '$error_c': $!";

sub check_range
{
    return if @_ <= 3;
    my $name = shift @_;
    my $min = shift @_;
    my $max = pop @_;
    foreach my $x (@_)
    {
        if ($x < $min || $x > $max)
        {
            printf STDERR ("%s (0x%04x) out of range 0x%04x-0x%04x\n",
                           $name, $x, $min, $max);
            exit 1;
        }
    }
}

my %h_low_entries;
my %h_high_entries;
foreach my $value (keys %error_codes_seen)
{
    my $name = $error_codes_seen{$value};
    if ($value <= 0x7f)
    {
        $h_low_entries{$name} = {nr=>0, even=>[], odd=>[]}
            unless exists $h_low_entries{$name};
        ++$h_low_entries{$name}{nr};
        push @{$h_low_entries{$name}{($value & 1 ? 'odd' : 'even')}}, $value;
    }
    else
    {
        if ($name eq 'SSL' && $value >= 0x7000)
        {
            # Hack because SSL occupies two high-level module IDs
            $name = 'SSL ';
        }
        $h_high_entries{$name} = {nr=>0, codes=>[]}
            unless exists $h_high_entries{$name};
        ++$h_high_entries{$name}{nr};
        push @{$h_high_entries{$name}{codes}}, $value;
    }
}
foreach my $name (keys %h_low_entries)
{
    my $entry = $h_low_entries{$name};
    my @even = sort {$a <=> $b} @{$entry->{even}};
    my @odd = sort {$a <=> $b} @{$entry->{odd}};
    check_range($name, @even);
    check_range($name, @odd);
    $entry->{ranges} = (@even ?
                        sprintf("0x%04X-0x%04X", $even[0], $even[@even-1]) :
                        "             ");
    $entry->{ranges} .= sprintf("   0x%04X-0x%04X", $odd[0], $odd[@odd-1])
        if @odd;
    $entry->{sort_key} = $entry->{ranges};
    $entry->{sort_key} =~ s/\A /~/;
}
foreach my $name (keys %h_high_entries)
{
    my $entry = $h_high_entries{$name};
    my @codes = sort {$a <=> $b} @{$entry->{codes}};
    check_range($name, @codes);
    $entry->{id} = $codes[@codes-1] >> 12;
    $entry->{comment} = (($codes[0] & 0xf80) == 0x080 ? '' :
                         ($codes[@codes-1] & 0xf80) == 0xf80 ?
                         ' (Started from top)' :
                         ' (Started from middle)');
    $entry->{sort_key} = sprintf("%04x", $codes[0]);
}
my $h_low_text =
    join('',
         map {sprintf(" * %-9s %2d  %s\n", $_,
                      $h_low_entries{$_}{nr},
                      $h_low_entries{$_}{ranges})}
         sort {$h_low_entries{$a}{sort_key} cmp $h_low_entries{$b}{sort_key}}
         keys %h_low_entries);
my $h_high_text =
    join('',
         map {sprintf(" * %-9s %2d  %d%s\n", $_,
                      $h_high_entries{$_}{id},
                      $h_high_entries{$_}{nr},
                      $h_high_entries{$_}{comment})}
         sort {$h_high_entries{$a}{sort_key} cmp $h_high_entries{$b}{sort_key}}
         keys %h_high_entries);

open(ERROR_FILE, "+<$error_h") or die "Opening destination file '$error_h': $!";
my $h_content = do { local $/ = undef; <ERROR_FILE> };
unless ($h_content =~ s{(\n \*\s+Module\s+Nr\s+Codes.*\n)(?: \* .*\n)*( \*\n)}
                       {$1$h_low_text$2})
{
    printf STDERR ("Error: comment with low-level ranges not found in '$error_h'\n");
    exit 1;
}
unless ($h_content =~ s{(\n \*\s+Name\s+ID\s+N.*\n)(?: \* .*\n)*( \*\n)}
                       {$1$h_high_text$2})
{
    printf STDERR ("Error: comment with high-level ranges not found in '$error_h'\n");
    exit 1;
}
seek ERROR_FILE, 0, 0 or die "Seeking in '$error_h': #$!";
truncate ERROR_FILE, 0 or die "Truncating '$error_h': $!";
print ERROR_FILE $h_content or die "Writing '$error_h': $!";
close(ERROR_FILE) or die "Closing '$error_h': $!";
