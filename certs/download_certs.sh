#!/bin/sh

# XXX: if you wish to rerun it, please run it from the script directory,
# or else you may end in deleting or creating files in places you did not want.
# But anyway none should have to run this. That's just for me.

# I support right now only:
# - StartSSSL (previously used for making the XSF an intermediate CA, so widely used) https://www.startssl.com/?app=26;
# - CAcert: the community-driven CA https://www.cacert.org/index.php?id=3
# - Verisign
# - Thawte
# - Geotrust

# XXX: on https://www.verisign.com/support/roots.html the have a root package with all verisign, thawte and geotrust. Use?
# I used the following guide to install these certs: http://gagravarr.org/writing/openssl-certs/others.shtml#ca-openssl
rm -f ./*.pem
rm -f ./*.cer
rm -f ./*.0
#wget https://www.thawte.com/roots/thawte_Primary_Root_CA.pem #thawte.com
#wget https://www.verisign.com/repository/roots/root-certificates/PCA-3G4.pem # verisign
#wget https://www.geotrust.com/resources/root_certificates/certificates/Equifax_Secure_Certificate_Authority.cer -o Equifax_Secure_Certificate_Authority.pem
wget https://www.startssl.com/certs/ca.pem -O startssl.pem # startSLL
wget https://www.cacert.org/certs/root.crt -O cacert.pem --no-check-certificate # CAcert
wget https://letsencrypt.org/certs/isrgrootx1.pem -O letsencrypt.pem # Let's Encrypt
wget https://www.symantec.com/content/en/us/enterprise/verisign/roots/roots.zip
unzip -j roots.zip
rm -f roots.zip
rm -f *.txt
rm -f *.cer

for cert in ./*.pem
do
	echo $cert
	openssl x509 -noout -fingerprint -in "$cert" # For manual verification. TODO: automatic verification
	echo "-----"
done;

