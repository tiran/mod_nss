#!/usr/bin/perl
#
# Migrate configuration from OpenSSL to NSS

use Cwd;
use Getopt::Std;

BEGIN {
   $NSSDir = cwd();

   $SSLCACertificatePath = "";
   $SSLCACertificateFile = "";
   $SSLCertificateFile = "";
   $SSLCARevocationPath = "";
   $SSLCARevocationFile = "";
   $SSLCertificateKeyFile = "";
   $passphrase = 0;
}

# these directives are common for mod_ssl 2.4.18 and mod_nss 1.0.13
%keep = ( "SSLCipherSuite" => "",
          "SSLEngine" => "",
          "SSLOptions" => "",
          "SSLPassPhraseDialog" => "",
          "SSLProtocol" => "",
          "SSLProxyCipherSuite" => "",
          "SSLProxyEngine" => "",
          "SSLProxyCheckPeerCN" => "",
          "SSLProxyProtocol" => "",
          "SSLRandomSeed" => "",
          "SSLRenegBufferSize" => "",
          "SSLRequire" => "",
          "SSLRequireSSL" => "",
          "SSLSessionCacheTimeout" => "",
          "SSLSessionTickets" => "",
          "SSLStrictSNIVHostCheck" => "",
          "SSLUserName" => "",
          "SSLVerifyClient" => "",
);

%insert =  ( "SSLSessionCacheTimeout", "NSSSessionCacheSize 10000\nNSSSession3CacheTimeout 86400\n",);

getopts('chr:w:' , \%opt );

sub usage() {
    print STDERR "Usage: migrate.pl [-c] -r <mod_ssl input file> -w <mod_nss output file>\n";
    print STDERR "\t-c converts the certificates\n";
    print STDERR "This conversion script is not aware of apache's configuration blocks\n";
    print STDERR "and nestable conditional directives. Please check the output of the\n";
    print STDERR "conversion and adjust manually if necessary!\n";
    exit();
}

usage() if ($opt{h} || !$opt{r} || !$opt{w});

print STDERR "input: $opt{r} output: $opt{w}\n";

open (SSL, "<", $opt{r} ) or die "Unable to open $opt{r}: $!.\n";
open (NSS, ">", $opt{w} ) or die "Unable to open $opt{w}: $!.\n";

print NSS "## This is a conversion of mod_ssl specific options by migrate.pl\n";
print NSS "## \n";
print NSS "## Please read through this configuration and verify the individual options!\n\n";

while (<SSL>) {
    my $comment = 0;

    # write through even if in comment before comments are stripped below.
    if(/(ServerName|ServerAlias)/) {
	print NSS $_;
	next;
    }

    # skip blank lines and comments
    if (/^\s*#/ || /^\s*$/) {
        print NSS $_;
        next;
    }

    s/mod_ssl\.c/mod_nss.c/;

    # write through nestable apache configuration block directives:
    if (/^</ || /^\s</) {
        print NSS $_;
        next;
    }

    m/(\w+)\s+(.+)/;
    $stmt = $1;
    $value = $2;

    # Handle the special cases
    if ($stmt eq "SSLVerifyClient" && $value eq "optional_no_ca") {
        print NSS "# Replaced optional_no_ca with optional\n";
        print NSS "SSLVerifyClient optional\n";
        next;
    }

    # we support OpenSSL cipher strings now, keeping the string as is
    #if ($stmt eq "SSLCipherSuite") {
       #print NSS "NSSCipherSuite ", get_ciphers($val), "\n";
       #print NSS "NSSProtocol SSLv3,TLSv1\n";
       #$comment = 1;
    if ($stmt eq "SSLProtocol" ) {
       print NSS "## we ignore the arguments to SSLProtocol. The original value was:\n";
       print NSS "##$_";
       print NSS "## The following is a _range_ from TLSv1.0 to TLSv1.2.\n";
       print NSS "NSSProtocol TLSv1.0,TLSv1.2\n\n";
       next;
    } elsif ($stmt eq "SSLProxyProtocol" ) {
       print NSS "## we ignore the arguments to SSLProxyProtocol. The original value was:\n";
       print NSS "##$_";
       print NSS "## The following is a _range_ from TLSv1.0 to TLSv1.2.\n";
       print NSS "NSSProxyProtocol TLSv1.0,TLSv1.2\n\n";
       next;
    } elsif ($stmt eq "SSLCACertificatePath") {
       $SSLCACertificatePath = $value;
       $comment = 1;
    } elsif ($stmt eq "SSLCACertificateFile") {
       $SSLCACertificateFile = $value;
       $comment = 1;
    } elsif ($stmt eq "SSLCertificateFile") {
       print NSS "NSSCertificateDatabase $NSSDir\n";
       print NSS "NSSNickName Server-Cert\n";
       $SSLCertificateFile = $value;
       $comment = 1;
    } elsif ($stmt eq "SSLCertificateKeyFile") {
       $SSLCertificateKeyFile = $value;
       $comment = 1;
    } elsif ($stmt eq "SSLCARevocationPath") {
       $SSLCARevocationPath = $value;
       $comment = 1;
    } elsif ($stmt eq "SSLCARevocationFile") {
       $SSLCARevocationFile = $value;
       $comment = 1;
    } elsif ($stmt eq "SSLPassPhraseDialog") {
       print NSS "NSSPassPhraseHelper /usr/libexec/nss_pcache\n";
       $passphrase = 1;
       $comment = 1;
    }

    if (exists($insert{$stmt})) {
        #print NSS "$_";
        print NSS $insert{$stmt};
        next;
    }

    if (m/^\s*SSL/) {
        if (!exists($keep{$stmt})) {
            print NSS "# Skipping, not applicable in mod_nss\n";
            print NSS "##$_";
            next;
        } else {
            # Fix up any remaining directive names
            s/^(\s*)SSL/\1NSS/;
        }
    }

    # Fall-through to print whatever is left
    if ($comment) {
        print NSS "##$_";
        $comment = 0;
    } else {
        print NSS $_;
    }
}

if ($passphrase == 0) {
    # NOTE:  Located at '/usr/sbin/nss_pcache' prior to 'mod_nss-1.0.9'.
    print NSS "NSSPassPhraseHelper /usr/libexec/nss_pcache\n";
}

close(NSS);
close(SSL);

#
# Create NSS certificate database and import any existing certificates
#

if ($opt{c}) {
    print STDERR "Creating NSS certificate database.\n";
    run_command("certutil -N -d $NSSDir");

    # Convert the certificate into pkcs12 format
    if ($SSLCertificateFile ne "" && $SSLCertificateKeyFile ne "") {
        my $subject = get_cert_subject($SSLCertificateFile);
        print STDERR "Importing certificate $subject as \"Server-Cert\".\n";
        run_command("openssl pkcs12 -export -in $SSLCertificateFile -inkey $SSLCertificateKeyFile -out server.p12 -name \"Server-Cert\" -passout pass:foo");
        run_command("pk12util -i server.p12 -d $NSSDir -W foo");
    }

    if ($SSLCACertificateFile ne "") {
        my $subject = get_cert_subject($SSLCACertificateFile);
        if ($subject ne "") {
            print STDERR "Importing CA certificate $subject\n";
            run_command("certutil -A -n \"$subject\" -t \"CT,,\" -d $NSSDir -a -i $SSLCACertificateFile");
        }
    }

    if ($SSLCACertificatePath ne "") {
        opendir(DIR, $SSLCACertificatePath) or die "can't opendir $SSLCACertificatePath: $!";
        while (defined($file = readdir(DIR))) {
            next if -d $file;

            # we can operate directly on the hash files so don't have to worry
            # about any SKIPME's.
            if ($file =~ /hash.*/) {
                my $subject = get_cert_subject("$SSLCACertificatePath/$file");
                if ($subject ne "") {
                    print STDERR "Importing CA certificate $subject\n";
                    run_command("certutil -A -n \"$subject\" -t \"CT,,\" -d $NSSDir -a -i $SSLCACertificatePath/$file");
                }
            }
        }
        closedir(DIR);
    }

    if ($SSLCARevocationFile ne "") {
        print STDERR "Importing CRL file $CARevocationFile\n";
            # Convert to DER format
            run_command("openssl crl -in $SSLCARevocationFile -out /root/crl.tmp -inform PEM -outform DER");
            run_command("crlutil -I -t 1 -d $NSSDir -i /root/crl.tmp");
            unlink("/root/crl.tmp");
    }

    if ($SSLCARevocationPath ne "") {
        opendir(DIR, $SSLCARevocationPath) or die "can't opendir $SSLCARevocationPath: $!";
        while (defined($file = readdir(DIR))) {
            next if -d $file;

            # we can operate directly on the hash files so don't have to worry
            # about any SKIPME's.
            if ($file =~ /hash.*/) {
                my $subject = get_cert_subject("$SSLCARevocationPath/$file");
                if ($subject ne "") {
                    print STDERR "Importing CRL file $file\n";
                    # Convert to DER format
                    run_command("openssl crl -in $SSLCARevocationPath/$file -out /root/crl.tmp -inform PEM -outform DER");
                    run_command("crlutil -I -t 1 -d $NSSDir -i /root/crl.tmp");
                    unlink("/root/crl.tmp");
                }
            }
        }
        closedir(DIR);
    }
}

print STDERR "\n\nConversion complete.\n";
print STDERR "The output file should contain a valid mod_nss configuration based on\n";
print STDERR "the mod_ssl directives from the input file.\n";
print STDERR "Recommended directory: /etc/apache2/mod_nss.d , suffix .conf!\n";
print STDERR "Also make sure to edit /etc/apache2/conf.d/mod_nss.conf and to remove the\n";
print STDERR "<VirtualHost> section if you do not need it.\n\n";
print STDERR "Also, do not forget to rename the ssl based apache config file";
print STDERR "(our example: myhost-ssl.conf) to a file that does not end in .conf\n";
print STDERR "(our example: myhost-ssl.conf-disabled-for-nss)\n\n";
print STDERR "Then, restart apache (rcapache2 restart) and have a look into the error logs.\n";

exit(0);


# Migrate configuration from OpenSSL to NSS
sub get_ciphers {
    my $str = shift;

    %cipher_list = (
        "rc4" => ":ALL:SSLv2:RSA:MD5:MEDIUM:RC4:",
        "rc4export" => ":ALL:SSLv2:RSA:EXP:EXPORT40:MD5:RC4:",
        "rc2" => ":ALL:SSLv2:RSA:MD5:MEDIUM:RC2:",
        "rc2export" => ":ALL:SSLv2:RSA:EXP:EXPORT40:MD5:RC2:",
        "des" => ":ALL:SSLv2:RSA:EXP:EXPORT56:MD5:DES:LOW:",
        "desede3" => ":ALL:SSLv2:RSA:MD5:3DES:HIGH:",
        "rsa_rc4_128_md5" => ":ALL:SSLv3:TLSv1:RSA:MD5:RC4:MEDIUM:",
        "rsa_rc4_128_sha" => ":ALL:SSLv3:TLSv1:RSA:SHA:RC4:MEDIUM:",
        "rsa_3des_sha" => ":ALL:SSLv3:TLSv1:RSA:SHA:3DES:HIGH:",
        "rsa_des_sha" => ":ALL:SSLv3:TLSv1:RSA:SHA:DES:LOW:",
        "rsa_rc4_40_md5" => ":ALL:SSLv3:TLSv1:RSA:EXP:EXPORT40:RC4:",
        "rsa_rc2_40_md5" => ":ALL:SSLv3:TLSv1:RSA:EXP:EXPORT40:RC2:",
        "rsa_null_md5" => ":SSLv3:TLSv1:RSA:MD5:NULL:",
        "rsa_null_sha" => ":SSLv3:TLSv1:RSA:SHA:NULL:",
        "rsa_des_56_sha" => ":ALL:SSLv3:TLSv1:RSA:DES:SHA:EXP:EXPORT56:",
        "rsa_rc4_56_sha" => ":ALL:SSLv3:TLSv1:RSA:RC4:SHA:EXP:EXPORT56:",
    );

    $NUM_CIPHERS = 16;

    for ($i = 0; $i < $NUM_CIPHERS; $i++) {
        $selected[$i] = 0;
    }

    # Don't need to worry about the ordering properties of "+" because
    # NSS always chooses the "best" cipher anyway. You can't specify
    # preferred order.

    # -1: this cipher is completely out
    #  0: this cipher is currently unselected, but maybe added later
    #  1: this cipher is selected

    @s = split(/:/, $str);

    for ($i = 0; $i <= $#s; $i++) {
        $j = 0;
        $val = 1;

        # ! means this cipher is disabled forever
        if ($s[$i] =~ /^!/) {
            $val = -1;
            ($s[$i] =~ s/^!//);
        } elsif ($s[$i] =~ /^-/) {
            $val = 0;
            ($s[$i] =~ s/^-//);
        } elsif ($s[$i] =~ /^+/) {
            ($s[$i] =~ s/^+//);
        }

        for $cipher (sort keys %cipher_list) {
            $match = 0;

            # For embedded + we do an AND for all options
            if ($s[$i] =~ m/(\w+\+)+/) {
                @sub = split(/^\+/, $s[$i]);
                $match = 1;
                for ($k = 0; $k <=$#sub; $k++) {
                    if ($cipher_list{$cipher} !=~ m/:$sub[$k]:/) {
                        $match = 0;
                    }
                }
            } else { # straightforward match
                if ($cipher_list{$cipher} =~ m/:$s[$i]:/) {
                    $match = 1;
                }
            }

            if ($match && $selected[$j] != -1) {
                $selected[$j] = $val;
            }
            $j++;
        }
    }

    # NSS doesn't honor the order of a cipher list, it uses the "strongest"
    # cipher available. So we'll print out the ciphers as SSLv2, SSLv3 and
    # the NSS ciphers not available in OpenSSL.
    $str = "SSLv2:SSLv3";
    @s = split(/:/, $str);

    $ciphersuite = "";

    for ($i = 0; $i <= $#s; $i++) {
        $j = 0;
        for $cipher (sort keys %cipher_list) {
            if ($cipher_list{$cipher} =~ m/:$s[$i]:/) {
                if ($selected[$j]) {
                    $ciphersuite .= "+";
                } else {
                    $ciphersuite .= "-";
                }
                $ciphersuite .= $cipher . ",";
            }
            $j++;
        }
    }

    $ciphersuite .= "-fortezza,-fortezza_rc4_128_sha,-fortezza_null,-fips_des_sha,+fips_3des_sha,-rsa_aes_128_sha,-rsa_aes_256_sha";

    return $ciphersuite;
}

# Given the filename of a PEM file, use openssl to fetch the certificate
# subject
sub get_cert_subject {
    my $file = shift;
    my $subject = "";

    return "" if ! -T $file;

    $subject = `openssl x509 -subject < $file | head -1`;
    $subject =~ s/subject= \///; # Remove leading subject= \
    $subject =~ s/\//,/g; # Replace / with , as separator
    $subject =~ s/Email=.*(,){0,1}//; # Remove Email attribute
    $subject =~ s/,$//; # Remove any trailing commas

    chomp($subject);

    return $subject;
}

#
# Wrapper around the system() command

sub run_command {
    my @args = shift;
    my $status = 0;

    $status = 0xffff & system(@args);

    return if ($status == 0);

    print STDERR "Command '@args' failed: $!\n";

    exit;
}
