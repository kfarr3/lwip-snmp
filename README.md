# lwip-snmp
SNMP V1/2C/3 Library for LWIP

This is my implemention of SNMP for LWIP that includes all 3 popular varients, V1, V2C, and V3.  For V3, both MD5 and SHA authentication are supported and AES and DES encryption.  External hash and encryption libraries are required.  For my uses, the ones provided in axtls worked great.

the snmp_params structure is passed into the snmp_init() function, as such, it is up to the user/implementer to store and provide this structure.
