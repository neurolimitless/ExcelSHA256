#!/usr/bin/perl -w
# All rights reserved Micro Survivor, Inc.
# Jorg Huser, 760-613-2728, jorg.huser@gmail.com
# sha256_v02.pl
#
#Comments
#

use strict;
use Digest::SHA qw(hmac_sha256_hex);
use Data::Dumper;
use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::AES;

use Crypt::CBC;
use MIME::Base64;
use Crypt::OpenSSL::RSA;
use Digest::SHA qw(sha1 sha1_hex sha1_base64 sha384 sha512 sha512_hex sha512_base64 sha256 sha256_hex sha256_base64 hmac_sha256 hmac_sha256_base64 hmac_sha256_hex hmac_sha512 hmac_sha512_base64);
use Bytes::Random::Secure qw(
         random_bytes random_bytes_base64 random_bytes_hex
);
use Cwd qw(abs_path);

my %CF = ();
$CF{FOLDER} = &GetCallDir(); $CF{FOLDER} .= "\\\\DATA\\\\";         #print "$CF{FOLDER}\n"; exit 0;
$CF{CONT} = "";                                                     #Content
$CF{FILE} = "$CF{FOLDER}";                                          #Filename
$CF{FILE} .= "cp1.csv";                                             #Filename

$CF{CONT} = &PrintDGI0701();
$CF{CONT} .= &PrintDGI0702();
#$CF{CONT} .= &PrintDGI0703();

#write to CSV
&SaveDataNew($CF{FILE}, $CF{CONT});

#write to xlsx


exit 0;


##########################
sub PrintDGI0701 {
##########################

    #INPUT Data Calculation
    #HMAC_INFO - Bundling of Data
            #my $a_salt = "sha256geheimersc"; #16 Byte only, padd w/ Hex ff
            #my $a_salt = "sha256geheimersc-blablablaasdf"; #16 Byte only, padd w/ Hex ff 
    my $a_salt = "sha256geheim"; #16 Byte only, padd w/ Hex ff
    my $h_salt = &ASCII2HEX($a_salt);
    $h_salt = &TruncateOrPadding($h_salt, 16);
    my $a_len_salt = 16;
    my $h_len_salt = &DEC2HEXwo0x($a_len_salt);
    
    my @HI_T = ("HMAC_Key_ID","HMAC_ITERATIONS","HMAC_Salt");                                   #T=Type
    my @HI_P = (1,10000,$a_salt);                                                               #P=Plain
    my @HI_L = (2,4,16);                                                                        #L=Fixed Length in Bytes
    my @HI_H = (&DEC2HEXwo0xL($HI_P[0],$HI_L[0]),&DEC2HEXwo0xL($HI_P[1],$HI_L[1]),$h_salt);     #H=Hex

    my ($a_hmacinfo, $h_hmacinfo) = "";
    my $i = 0;
    foreach my $type (@HI_T){
        $a_hmacinfo .= "$type ($HI_L[$i]) $HI_P[$i]; ";
        $h_hmacinfo .= "$HI_H[$i]"; 
        $i++;
    }
    my $h_len_hmacinfo = length ($h_hmacinfo)/2;
    $h_hmacinfo = &UC_BlankSep($h_hmacinfo);
    
    my $a_payload = "555446666"; #SSN 555-44-6666, Passport No., Drivers License #, DoD ID
    my $h_payload = &ASCII2HEX($a_payload); $h_payload = &UC_BlankSep($h_payload);
    my $a_len_payload = length ($a_payload);
    my $h_len_payload = &DEC2HEXwo0x($a_len_payload);


    #INPUT - Structured Data Prep
    my %ival = (); #{tag}{t}; {tag}{l}; {tag}{v}
    $ival{e}{0} = "PII Hash & Identifier";
    $ival{d}{0} = "07 01";
    $ival{m}{0} = "70";
    $ival{v0}{0} = "N/A";       #value before data prep calc
    
    $ival{i}{0} = "HMAC Info";
    $ival{t}{0} = "10";
    $ival{l}{0} = "$h_len_hmacinfo";
    $ival{v}{0} = "$h_hmacinfo";
    $ival{v0}{0} = "$a_hmacinfo";       #value before data prep calc
    
    $ival{i}{1} = "ID Type";
    $ival{t}{1} = "11";
    $ival{l}{1} = "01";
    $ival{v}{1} = "04";
    $ival{v0}{1} = "04";       #value before data prep calc
    
    $ival{i}{2} = "Cardholder ID Hash";
    $ival{t}{2} = "12";
    $ival{l}{2} = $h_len_payload;
    $ival{v}{2} = "$h_payload";
    $ival{v0}{2} = "$a_payload"; #value before data prep calc
     
    #CALCULATION    
    my $res = &Calc_HMAC_SHA256HEX ($h_payload, $h_salt, $HI_P[1]); #(payload, salt, iterations)
    #my ($val_hmac, $len_hmac) = &PrintLALH("HMAC_SHA256HEX", $res, 1);
    my $len_hmac = length ($res)/2;
    my $val_hmac = &UC_BlankSep($res);
    
    #OUTPUT
    my %tlv = ();
    $tlv{e}{0} = "$ival{e}{0}";             # Element
    $tlv{d}{0} = "$ival{d}{0}";             # DGI
    $tlv{m}{0} = "$ival{m}{0}";             # Template=Muster
    $tlv{i}{0} = "$ival{i}{0}";             # Identifier/description
    $tlv{t}{0} = "$ival{t}{0}";             # Tag
    $tlv{l}{0} = "$ival{l}{0}";             # Length
    $tlv{v}{0} = "$ival{v}{0}";             # Value
    $tlv{i}{1} = "$ival{i}{1}";             # Identifier/description
    $tlv{t}{1} = "$ival{t}{1}";             # Tag
    $tlv{l}{1} = "$ival{l}{1}";             # Length
    $tlv{v}{1} = "$ival{v}{1}";             # Value
    $tlv{i}{2} = "$ival{i}{2}";             # Identifier/description
    $tlv{t}{2} = "$ival{t}{2}";             # Tag
    $tlv{l}{2} = "$len_hmac";               # Length
    $tlv{v}{2} = "$val_hmac";               # Value
    
    my $ret = &PrintTLV(\%tlv, \%ival, 2);
    return $ret;

}

##########################
sub PrintDGI0702 {
##########################

    #INPUT Data Calculation
    #Payload - OKI    
    my @OKI_T = ("FORMAT_ID","ABA_NUMBER","BANK_ACCOUNT_NUMBER","BANK_ACCOUNT_TYPE","ISSUING_DEVICE","RFU");    #T=Type
    my @OKI_P = (1,123456789012,123456789012345678,4,"abc","abcdefghijkl");                                     #P=Plain
    my @OKI_L = (1,6,9,1,3,12);                                                                                 #L=Fixed Length in Bytes
    
    my $h_issdev = &ASCII2HEX($OKI_P[4]); $h_issdev = &TruncateOrPadding($h_issdev, $OKI_L[4]);
    my $h_rfu = &ASCII2HEX($OKI_P[5]); $h_rfu = &TruncateOrPadding($h_rfu, $OKI_L[5]);
    my $h_len_issdev = length ($h_issdev)/2;
    my $h_len_rfu = length ($h_rfu)/2;    
      
    my @OKI_H = (&DEC2HEXwo0xL($OKI_P[0],$OKI_L[0]),$OKI_P[1],$OKI_P[2],                                        #H=Hex
                 &DEC2HEXwo0xL($OKI_P[3],$OKI_L[3]),
                 $h_issdev, $h_rfu);

    my ($a_payload, $h_payload) = "";
    my $i = 0;
    foreach my $type (@OKI_T){
        $a_payload .= "$type ($OKI_L[$i]) $OKI_P[$i]; ";
        $h_payload .= "$OKI_H[$i]"; 
        $i++;
    }
    my $h_len_payload = length ($h_payload)/2;
    $h_payload = &UC_BlankSep($h_payload);

    # AES256 Encryption
    my $h_key = &AESKeyGen(256);
    my $h_len_key = length ($h_key)/2;
    my $a_len_key = &HEX2DEC($h_len_key);
    
    my $a_iv = "16bytepwd"; # AES ID = IV - 16 Byte only, padd w/ Hex ff
    my $h_iv = &ASCII2HEX($a_iv);
    $h_iv = &TruncateOrPadding($h_iv, 16);
    my $h_len_iv = length ($h_iv)/2;
    my $a_len_iv = &HEX2DEC($h_len_iv);
    #$a_iv = &HEX2ASCII($h_iv);
    
    #SHA256 SALT
    my $a_salt = "sha256geheim"; #16 Byte only, padd w/ Hex ff
    my $h_salt = &ASCII2HEX($a_salt);
    $h_salt = &TruncateOrPadding($h_salt, 16);
    my $h_len_salt = length ($h_salt)/2;
    my $a_len_salt = &HEX2DEC($h_len_salt); 
    
    #INPUT - Structured Data Prep
    my %ival = (); #{tag}{t}; {tag}{l}; {tag}{v}
    $ival{e}{0} = "Offline Kiosk";
    $ival{d}{0} = "07 02";
    $ival{m}{0} = "70";
    
    $ival{i}{0} = "RSA Key ID";
    $ival{t}{0} = "13";
    $ival{l}{0} = "01";
    $ival{v}{0} = "01";
    $ival{v0}{0} = "01";       #value before data prep calc
    
    $ival{i}{1} = "AES Key IV";
    $ival{t}{1} = "14";
    $ival{l}{1} = "$h_len_iv";
    $ival{v}{1} = "$h_iv";
    $ival{v0}{1} = "$a_iv";       #value before data prep calc
    
    $ival{i}{2} = "Offline Kiosk Info (OKI)";
    $ival{t}{2} = "15";
    $ival{l}{2} = "$h_len_payload";
    $ival{v}{2} = "$h_payload";
    $ival{v0}{2} = "$a_payload";   #value before data prep calc
    
    $ival{i}{3} = "OKI MAC";
    $ival{t}{3} = "16";
    $ival{l}{3} = "$h_len_salt";
    $ival{v}{3} = "$h_salt";
    $ival{v0}{3} = "$a_salt";       #value before data prep calc

     
    #CALCULATION    
    my ($h_encr, $h_len_encr) = &AESEncr($h_key, $a_payload, $h_iv);
    my $a_len_encr = &HEX2DEC($h_len_encr);
    my $h_res = &Calc_HMAC_SHA256HEX ($h_payload, $h_salt, 1);
    my $h_len_res = length($h_res)/2; 
    my $a_len_res = &HEX2DEC($h_len_res);
    
    #OUTPUT
    my %tlv = ();
    $tlv{e}{0} = "$ival{e}{0}";             # Element
    $tlv{d}{0} = "$ival{d}{0}";             # DGI
    $tlv{m}{0} = "$ival{m}{0}";             # Template=Muster
    $tlv{i}{0} = "$ival{i}{0}";             # Identifier/description
    $tlv{t}{0} = "$ival{t}{0}";             # Tag
    $tlv{l}{0} = "$ival{l}{0}";             # Length
    $tlv{v}{0} = "$ival{v}{0}";             # Value
    $tlv{i}{1} = "$ival{i}{1}";             # Identifier/description
    $tlv{t}{1} = "$ival{t}{1}";             # Tag
    $tlv{l}{1} = "$ival{l}{1}";             # Length
    $tlv{v}{1} = "$ival{v}{1}";             # Value
    $tlv{i}{2} = "$ival{i}{2}";             # Identifier/description
    $tlv{t}{2} = "$ival{t}{2}";             # Tag
    $tlv{l}{2} = "$h_len_encr";             # Length
    $tlv{v}{2} = "$h_encr";                 # Value
    $tlv{i}{3} = "$ival{i}{3}";             # Identifier/description
    $tlv{t}{3} = "$ival{t}{3}";             # Tag
    $tlv{l}{3} = "$h_len_res";              # Length
    $tlv{v}{3} = "$h_res";             # Value
    
    my $ret = &PrintTLV(\%tlv, \%ival, 3);
    return $ret;

}

##########################
sub PrintDGI0703 {
##########################
    my $rsa = &GenRSAKey(1024); # for encryting AES key
    
    my $rsa_pub = Crypt::OpenSSL::RSA->new_public_key($rsa->get_public_key_string());
    my $rsa_priv = Crypt::OpenSSL::RSA->new_private_key($rsa->get_private_key_string());

    my $plaintext = "Time is money!";
    my $ciphertext = $rsa_pub->encrypt($plaintext);

    print "\nplaintext:\n", $plaintext;
    print "\nciphertext:\n", $ciphertext;
    my $decrypttext = $rsa_priv->decrypt($ciphertext);
    print "\ndecrypttext:\n", $decrypttext;
}

##########################
sub TruncateOrPadding {
    #http://stackoverflow.com/questions/14441521/how-to-truncate-a-string-to-a-specific-length-in-perl
    #targetlen is byte length (2 digits) in dec
##########################
    my ($text, $targetlen) = @_;
    my $exactlenstring = "";
    $targetlen = $targetlen * 2;

    my $len = length ($text);
    if ($len > $targetlen){         # truncate string
        $exactlenstring = substr( $text, 0, $targetlen );        
    } elsif ($len < $targetlen) {   # padding of fixed length string
        $exactlenstring = "$text";
        $exactlenstring .= 'F'x($targetlen - $len);
    } else {
        print "String has the target length of $targetlen\n";
        $exactlenstring = "$text";  # remains the same
    }
    
    return ($exactlenstring);
}

##########################
sub Calc_HMAC_SHA256HEX {
    #Returns SHA encoded as hex, input can be anything
##########################
    my ($text, $secret, $iterations) = @_;
    my $digest = hmac_sha256_hex($text, $secret);
    for (my $i = 1; $i < $iterations; $i++){
       $digest = hmac_sha256_hex($digest, $secret); 
    }
    $digest = uc($digest);
    return $digest;
}

##########################
sub PrintTLV {
##########################
    my ($tlv, $tlvi, $n) = @_;
    my %cci = %$tlvi;   #input
    my %cc = %$tlv;     #output
    my $all_val = "";
    my $all_len = "";
    my $i = 0;
    my $ret = "";

    #print "----------------------------------------\n";
    #print "TLV\n";
    #print "----------------------------------------\n";
    
    $ret .= "ELEMENT,DESCRIPTION,DGI,TEMPLATE,TAG,LENGTH,RAWVALUE,PROCESSEDVALUE\n";
    $ret .= "INPUT,,$cci{d}{0}\n";
    for ($i=0; $i <= $n; $i++){
        $ret .= ",$cci{i}{$i},,,0x $cci{t}{$i},0x $cci{l}{$i},%s $cci{v0}{$i},0x $cci{v}{$i}\n";  
    }
    $ret .= "\n";
    $ret .= "OUTPUT\n";
    $ret .= "ELEMENT,DESCRIPTION,DGI,TEMPLATE,TAG,LENGTH,VALUE\n";
    #print "ELEMENT,DESCRIPTION,DGI,TEMPLATE,TAG,LENGTH,VALUE\n";
    #print "$cc{e}{0}\n";
    $ret .= "$cc{e}{0}\n";
    for ($i=0; $i <= $n; $i++){
        #print ",$cc{i}{$i},,,$cc{t}{$i},$cc{l}{$i},$cc{v}{$i}\n";
        $ret .= ",$cc{i}{$i},,,0x $cc{t}{$i},0x $cc{l}{$i},0x $cc{v}{$i}\n";
        $all_val .= "$cc{t}{$i} $cc{l}{$i} $cc{v}{$i} ";
    }

    ($all_len, $all_val) = &CalcHexLenX($all_val);
    $all_len /= 2;
    #my $all_len_hex = &DEC2HEX($all_len);
    my $all_len_hex = &DEC2HEXwo0x($all_len);
    $all_len_hex = uc($all_len_hex);
    #print ",,,$cc{d}{0},$cc{m}{0},,$all_len_hex,$all_val";
    $ret .= ",,$cc{d}{0},$cc{m}{0},,$all_len_hex,$all_val\n";
    $ret .= "\n";
    
    return $ret;
}

##########################
sub PrintLALH {
    #Prints ascii and hex with length in dec and hex
##########################
    my ($text, $ding, $two) = @_;
    my $ret = "";
    my $ding2 = "$ding";
    
    my $lc = length($ding)/2;
    my $lch = sprintf("%02x", $lc);
    $lch = uc($lch);
    
    if ($two){
        $ding2 =~ s#(\w{2})#$1 #g;
        $ret = printf "(%2d,0x%s) %20s:\t%s\n", $lc, $lch, $text, $ding2;
    } else {
        $ret = printf "(%2d,0x%s) %20s:\t%s\n", $lc, $lch, $text, $ding;
    }
    return ($ding2, $lch);
}

#########################
sub CalcHexLenX {
#########################
    my ($zeichen) = @_;

    $zeichen =~ s#\s*##sgi;
    my $ret = length($zeichen);
    $zeichen =~ s#(\w{2})#$1 #g;
    #print "$zeichen\n\n";
    return ($ret, $zeichen);
}

#########################
sub UC_BlankSep {
#########################
    my ($zeichen) = @_;
    $zeichen = uc $zeichen;
    $zeichen =~ s#(\w{2})#$1 #g;
    #print "$zeichen\n\n";
    return ($zeichen);
}

##########################
sub DEC2HEX  {
    #http://stackoverflow.com/questions/10481001/how-to-convert-decimal-to-hexadecimal-in-perl
##########################
    my ($d) = @_;
    my $hex = sprintf("%x", $d);
    my $lh = length($hex);
    
    if ($lh < 2) { $hex = sprintf("0%x", $d);}
    $hex = uc $hex;
    $hex = "0x$hex";
    
    return $hex;
}

##########################
sub DEC2HEXwo0x  {
    #http://stackoverflow.com/questions/10481001/how-to-convert-decimal-to-hexadecimal-in-perl
##########################
    my ($d) = @_;
    my $hex = sprintf("%x", $d);
    my $lh = length($hex);

    if ($lh < 2) { $hex = sprintf("0%x", $d);}
    $hex = uc $hex;
    
    #print "Hex laenge: $lh $d $hex\n";
    
    return $hex;
}

##########################
sub DEC2HEXwo0xL  {
    #http://stackoverflow.com/questions/10481001/how-to-convert-decimal-to-hexadecimal-in-perl
##########################
    my ($d, $lent) = @_;
    my $lent2 = $lent;
    $lent2 *= 2; #lent is in bytes => 2x for digits
    my $hex = sprintf("%x", $d);
    my $lh = length($hex);
    my $n = 0;
    my $insert = "";
    if ($lh < $lent2) {
        $n = $lent2 - $lh;
        $insert =~ s/^(.*)/'0' x $n . $1/mge; # leading zerors
        $hex = sprintf("$insert%x", $d);
        
    }
    $hex = uc $hex;
    
    #print "Hex laenge: $lh $d $hex TARGET: $lent\n";
    
    return $hex;
}

##########################
sub ASCII2HEX  {
    #http://www.perlmonks.org/bare/?node_id=476675
##########################
    my ($text) = @_;

    # split into array of individual characters
    my @characters = split(//,$text);

    # transform each one individually into uppercase hex
    foreach my $char (@characters) {
        $char = uc(unpack "H*", $char);
    }

    # print in quotes to demonstrate separation between array elements
    # print "@characters";
    #my $ret = join(' ', @characters);
    my $ret = join('',@characters);
    
    
    return $ret;
}


##########################
sub HEX2DEC {
    #http://www.perlmonks.org/?node_id=75607
##########################
    my ($hextext) = @_;
    my $dec_num = sprintf("%d", hex($hextext));  
    return $dec_num;
}

##########################
sub HEX2ASCII  {
    #http://www.perlmonks.org/bare/?node_id=149278
    #http://icfun.blogspot.com/2009/05/perl-convert-hex-string-into-character.html
##########################
    my ($hextext) = @_;
    
    # remove spaces
    $hextext =~ s#\s*##sgi;
    my $ret = $hextext;
      
    #convert to ascii   
    $ret =~ s/([a-fA-F0-9][a-fA-F0-9])/chr(hex($1))/eg;
     
    return $ret;
}


##########################
sub AESKeyGen{
     my ($keylen) = @_;
##########################
    
    $keylen /= 8; #convert from bit to byte
    my $random_generator = Bytes::Random::Secure->new(
        Bits        => 64,
        NonBlocking => 1,
    ); # Seed with 64 bits, and use /dev/urandom (or other non-blocking).

    my $key = $random_generator->bytes($keylen); # A string of 32/$keylen random bytes which we'll use as the AES key
 
    $key = &ASCII2HEX($key);   #HEX
    $key = &UC_BlankSep($key); #Blanks between HEX Bytes
    return $key;
}

##########################
sub AESEncr{
     my ($key, $plaintext, $id) = @_;
     #id = 16 char long encryption password
     #IN: plaintext - ascii; key, id - HEX;
     #OUT: HEX
##########################

    my $iv = &HEX2ASCII($id);
    $key = &HEX2ASCII($key);

    my $cipher = Crypt::CBC->new(
        -key => pack('H32',$key),
        -iv  => pack('H32',$iv),
        -cipher      => 'OpenSSL::AES',
        -literal_key => 1,
        -header      => "none",
        -padding     => "standard",
        -keysize     => 16
                             );
    
    my $encrypted = $cipher->encrypt_hex($plaintext);
    my $encrypted_bl = &UC_BlankSep($encrypted);
    my $len_encr = length($encrypted)/2;
    
    return ($encrypted_bl, $len_encr);
}

##########################
sub AESDecr{
     my ($key, $encrypted, $id) = @_;
     #IN: HEX; OUT: ascii/dec
##########################
    
    my $iv = &HEX2ASCII($id);
    $key = &HEX2ASCII($key);

    my $cipher = Crypt::CBC->new(
        -key => pack('H32',$key),
        -iv  => pack('H32',$iv),
        -cipher      => 'OpenSSL::AES',
        -literal_key => 1,
        -header      => "none",
        -padding     => "standard",
        -keysize     => 16
                             );
    
    $encrypted =~ s#\s*##sgi; #remove blanks from hex

    my $decrypted = $cipher->decrypt_hex($encrypted);
    my $len_decr = length($decrypted)/2;
    
    return ($decrypted, $len_decr);
}

##########################
sub GenRSAKey{
##########################
    my ($keylen) = @_;
    
    my $rsa = Crypt::OpenSSL::RSA->generate_key(1024);
    print "\nprivate key is:\n", $rsa->get_private_key_string();
    print "\npublic key is:\n", $rsa->get_public_key_string();
    
    return $rsa;
}

############################
sub GetCallDir{
    #http://stackoverflow.com/questions/84932/how-do-i-get-the-full-path-to-a-perl-script-that-is-executing
############################
    my $path = abs_path($0);
    my $calldir = $path;
    $calldir =~ s/(.*)\\([^\\]+)/$1/;
    $calldir =~ s#\\#\\\\#sgi;
    #print "-> $path\n";
    #print "-> $calldir\n";
    return $calldir;
}

############################
sub SaveDataNew{
############################
    my ($outfile, $what) = @_;
    open(FILE, ">", $outfile) or print "Failed to open $outfile: $!";
    print FILE "$what";
    close(FILE);
}

############################
sub SaveData{
############################
    my ($outfile, $what) = @_;
    open(FILE, ">>", $outfile) or print "Failed to open $outfile: $!";
    print FILE "$what";
    close(FILE);
}
