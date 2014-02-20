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

%skip = ( "SSLRandomSeed" => "",
          "SSLSessionCache" => "",
          "SSLMutex" => "",
          "SSLCertificateChainFile" => "",
          "SSLVerifyDepth" => "" ,
          "SSLCryptoDevice" => "" ,
          "LoadModule" => "" ,
         );

%insert =  ( "NSSSessionCacheTimeout", "NSSSessionCacheSize 10000\nNSSSession3CacheTimeout 86400\n",);

getopts('ch');

if ($opt_h) {
    print "Usage: migrate.pl -c\n";
    print "\t-c convert the certificates\n";
    exit();
}

open (NSS, "> nss.conf") or die "Unable to open nss.conf: $!.\n";
open (SSL, "< ssl.conf") or die "Unable to open ssl.conf: $!.\n";

while (<SSL>) {
    my $comment = 0;

    # skip blank lines and comments
    if (/^#/ || /^\s*$/) {
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

    if ($stmt eq "SSLCipherSuite") {
       print NSS "NSSCipherSuite ", get_ciphers($val), "\n";
       print NSS "NSSProtocol SSLv3,TLSv1\n";
       $comment = 1;
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
       print NSS "NSSPassPhraseHelper /usr/local/bin/nss_pcache\n";
       $passphrase = 1;
       $comment = 1;
    }

    if (exists($skip{$stmt})) {
        print NSS "# Skipping, not applicable in mod_nss\n";
        print NSS "##$_";
        next;
    }

    # Fix up any remaining directive names
    s/^SSL/NSS/;

    if (exists($insert{$stmt})) {
        print NSS "$_";
        print NSS $insert{$stmt};
        next;
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

if ($opt_c) {
    print "Creating NSS certificate database.\n";
    run_command("certutil -N -d $NSSDir");

    # Convert the certificate into pkcs12 format
    if ($SSLCertificateFile ne "" && $SSLCertificateKeyFile ne "") {
        my $subject = get_cert_subject($SSLCertificateFile);
        print "Importing certificate $subject as \"Server-Cert\".\n";
        run_command("openssl pkcs12 -export -in $SSLCertificateFile -inkey $SSLCertificateKeyFile -out server.p12 -name \"Server-Cert\" -passout pass:foo");
        run_command("pk12util -i server.p12 -d $NSSDir -W foo");
    }

    if ($SSLCACertificateFile ne "") {
        my $subject = get_cert_subject($SSLCACertificateFile);
        if ($subject ne "") {
            print "Importing CA certificate $subject\n";
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
                    print "Importing CA certificate $subject\n";
                    run_command("certutil -A -n \"$subject\" -t \"CT,,\" -d $NSSDir -a -i $SSLCACertificatePath/$file");
                }
            }
        }
        closedir(DIR);
    }

    if ($SSLCARevocationFile ne "") {
        print "Importing CRL file $CARevocationFile\n";
            # Convert to DER format
            run_command("openssl crl -in $SSLCARevocationFile -out /tmp/crl.tmp -inform PEM -outform DER");
            run_command("crlutil -I -t 1 -d $NSSDir -i /tmp/crl.tmp");
            unlink("/tmp/crl.tmp");
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
                    print "Importing CRL file $file\n";
                    # Convert to DER format
                    run_command("openssl crl -in $SSLCARevocationPath/$file -out /tmp/crl.tmp -inform PEM -outform DER");
                    run_command("crlutil -I -t 1 -d $NSSDir -i /tmp/crl.tmp");
                    unlink("/tmp/crl.tmp");
                }
            }
        }
        closedir(DIR);
    }
}

print "Conversion complete.\n";
print "You will need to:\n";
print "  - rename/remove ssl.conf or Apache will not start.\n";
print "  - verify the location of nss_pcache. It is set as /usr/local/bin/nss_pcache\n";

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

    print "Command '@args' failed: $!\n";

    exit;
}
