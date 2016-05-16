#!/usr/bin/perl -w
# All rights reserved Micro Survivor, Inc.
# Jorg Huser, +1-760-613-2728, jorg.huser@gmail.com
# sha256.pl
#
#Comments
#

use Digest::SHA qw(hmac_sha256_hex); 

my %CF = ();
$CF{FOLDER} = "C:\\Users\\Jorg\\Documents\\perl\\Encrypt\\DATA\\";  #Folder
$CF{CONT} = "";                                                     #Content
$CF{FILE} = "$CF{FOLDER}";                                          #Filename
$CF{FILE} .= "cp1.csv";                                             #Filename

#input: salt identifier, salt, id type, payload
my $saltid = ""; my $salt = ""; my $idtype = "04"; my $payload = "";
#output: HMAC_SHA256HEX, data set
$CF{CONT} = &PrintDGI0701();

#write to CSV
&SaveDataNew($CF{FILE}, $CF{CONT});

#write to xlsx



exit 0;

##########################
sub PrintDGI0701 {
##########################

    #INPUT Data Calculation
    #my $a_salt = "sha256geheimersc"; #16 Byte only, padd w/ Hex ff
    #my $a_salt = "sha256geheimersc-blablablaasdf"; #16 Byte only, padd w/ Hex ff 
    my $a_salt = "sha256geheim"; #16 Byte only, padd w/ Hex ff
    my $h_salt = &ASCII2HEX($a_salt);
    print "Before Pad & Trunc:\t $h_salt\n";
    $h_salt = &TruncateOrPadding($h_salt, 16);
    print "After Pad & Trunc:\t $h_salt\n";
    &PrintLALH("Salt ASCII", $a_salt, 0);
    my ($val_salt, $len_salt) = &PrintLALH("Salt HEX", $h_salt, 1);

    my $a_payload = "555446666"; #SSN 555-44-6666, Passport No., Drivers License #, DoD ID
    my $h_payload = &ASCII2HEX($a_payload);
    &PrintLALH("Payload ASCII", $a_payload, 0);
    &PrintLALH("Payload HEX", $h_payload, 1);

    
    #INPUT - Structured Data Prep
    my %ival = (); #{tag}{t}; {tag}{l}; {tag}{v}
    $ival{e}{0} = "PII Hash & Identifier";
    $ival{d}{0} = "07 01";
    $ival{m}{0} = "70";
    $ival{v0}{2} = "N/A";       #value before data prep calc
    
    $ival{i}{0} = "HMAC Salt Identifier";
    $ival{t}{0} = "10";
    $ival{l}{0} = "02";
    $ival{v}{0} = "00 01";
    $ival{v0}{0} = "01";       #value before data prep calc
    
    $ival{i}{1} = "HMAC Salt";
    $ival{t}{1} = "11";
    $ival{l}{1} = "$len_salt";
    $ival{v}{1} = "$val_salt";
    $ival{v0}{1} = "$a_salt";   #value before data prep calc
    
    $ival{i}{2} = "ID Type";
    $ival{t}{2} = "12";
    $ival{l}{2} = "01";
    $ival{v}{2} = "04";
    $ival{v0}{2} = "04";       #value before data prep calc
    
    $ival{i}{3} = "Cardholder ID Hash";
    $ival{t}{3} = "13";
    $ival{l}{3} = sprintf("%s", &CalcHexLenX($h_payload));
    $ival{v}{3} = "$h_payload";
    $ival{v0}{3} = "$a_payload"; #value before data prep calc
     
    #CALCULATION    
    my $res = &Calc_HMAC_SHA256HEX ($h_payload, $h_salt);
    my ($val_hmac, $len_hmac) = &PrintLALH("HMAC_SHA256HEX", $res, 1);
    
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
    $tlv{l}{2} = "$ival{l}{2}";             # Length
    $tlv{v}{2} = "$ival{v}{2}";             # Value
    $tlv{i}{3} = "Cardholder ID Hash";      # Identifier/description
    $tlv{t}{3} = "13";                      # Tag
    $tlv{l}{3} = "$len_hmac";               # Length
    $tlv{v}{3} = "$val_hmac";               # Value
    
    my $ret = &PrintTLV(\%tlv, \%ival, 3);
    return $ret;

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
    my ($text, $secret) = @_;
    my $digest = hmac_sha256_hex($text, $secret);
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

    print "----------------------------------------\n";
    print "TLV\n";
    print "----------------------------------------\n";
    
    $ret .= "ELEMENT,DESCRIPTION,DGI,TEMPLATE,TAG,LENGTH,RAWVALUE,PROCESSEDVALUE\n";
    $ret .= "INPUT,,$cci{d}{0}\n";
    for ($i=0; $i <= $n; $i++){
        $ret .= ",$cci{i}{$i},,,0x $cci{t}{$i},0x $cci{l}{$i},%d $cci{v0}{$i},0x $cci{v}{$i}\n";  
    }
    $ret .= "\n";
    $ret .= "OUTPUT\n";
    $ret .= "ELEMENT,DESCRIPTION,DGI,TEMPLATE,TAG,LENGTH,VALUE\n";
    print "ELEMENT,DESCRIPTION,DGI,TEMPLATE,TAG,LENGTH,VALUE\n";
    print "$cc{e}{0}\n";
    $ret .= "$cc{e}{0}\n";
    for ($i=0; $i <= $n; $i++){
        print ",$cc{i}{$i},,,$cc{t}{$i},$cc{l}{$i},$cc{v}{$i}\n";
        $ret .= ",$cc{i}{$i},,,0x $cc{t}{$i},0x $cc{l}{$i},0x $cc{v}{$i}\n";
        $all_val .= "$cc{t}{$i} $cc{l}{$i} $cc{v}{$i} ";
    }

    ($all_len, $all_val) = &CalcHexLenX($all_val);
    $all_len /= 2;
    #my $all_len_hex = &DEC2HEX($all_len);
    my $all_len_hex = &DEC2HEXwo0x($all_len);
    $all_len_hex = uc($all_len_hex);
    print ",,,$cc{d}{0},$cc{m}{0},,$all_len_hex,$all_val";
    $ret .= ",,$cc{d}{0},$cc{m}{0},,$all_len_hex,$all_val";
    
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

##########################
sub DEC2HEX  {
    #http://stackoverflow.com/questions/10481001/how-to-convert-decimal-to-hexadecimal-in-perl
##########################
    my ($d) = @_;
    my $hex = sprintf("0x%x", $d);
    return $hex;
}

##########################
sub DEC2HEXwo0x  {
    #http://stackoverflow.com/questions/10481001/how-to-convert-decimal-to-hexadecimal-in-perl
##########################
    my ($d) = @_;
    my $hex = sprintf("%x", $d);
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
