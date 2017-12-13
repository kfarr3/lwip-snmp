#ifndef ASN_1_H
#define ASN_1_H

#define TRAP_COLDSTART        0x00
#define TRAP_WARMSTART        0x01
#define TRAP_LINKDOWN         0x02
#define TRAP_LINKUP           0x03
#define TRAP_AUTH_FAILURE     0x04
#define TRAP_EGPNEIGHBORLOSS  0x05
#define TRAP_ENTERPRISE_SPEC  0x06

#define ASN_UNKNOWN           -1
#define ASN_INT               0x02
#define ASN_BIT_STRING        0x03
#define ASN_OCTET_STRING      0x04
#define ASN_NULL              0x05
#define ASN_OID               0x06
#define ASN_SEQUENCE          0x30

#define ASN_SNMP_IPADDRESS    0x40
#define ASN_SNMP_COUNTER      0x41
#define ASN_SNMP_GAUGE        0x42
#define ASN_SNMP_TIMETICKS    0x43

#define GET_REQUEST_PDU       0xA0
#define GET_NEXT_REQUEST_PDU  0xA1
#define GET_RESPONSE_PDU      0xA2
#define SET_REQUEST_PDU       0xA3
#define TRAP_PDU              0xA4
#define GET_BULK_PDU          0xA5
#define TRAPv2C_PDU			  0xA7
#define REPORT_PDU            0xA8

#define NO_SUCH_OBJECT        0x80
#define NO_SUCH_INSTANCE      0x81
#define END_OF_MIB_VIEW       0x82
#define MAX_OIDS 30
#define MAX_OID_ENC_LEN 40
typedef struct
{
    unsigned int len;
    unsigned int val[MAX_OIDS];
//    unsigned char enc_len;
 //   unsigned char enc_val[MAX_OID_ENC_LEN];
}_oid;

void print_oid(_oid *oid);
int str_to_oid(_oid *oid, char *str);
char* oid_to_str(char *str, _oid *oid);

// Calculates the number of bytes required to encode the length
int asn_bytes_length(unsigned int length);
// Calculates the number of bytes required to encode this type with data
int asn_bytes_to_encode(void *data, int type, int data_len);
int asn_bytes_to_encode_oid(_oid *oid);
// Calculates the number of bytes required to encode an OID
int asn_bytes_to_encode_oid(_oid *oid);

// All of these encode and decode functions return the number
// of bytes required to encode or decode the object

int asn_encode_snmp_ipaddress(unsigned char *data, unsigned char *ip_addr);
int asn_decode_snmp_ipaddress(unsigned char *data, unsigned char *ip_address);

int asn_encode_int(unsigned char *data, int type, int  value);
int asn_decode_int(unsigned char *data, unsigned int type, unsigned int *value);
int asn_decode_int_type(unsigned char *data,  unsigned int *type, unsigned int *value);

int asn_encode_length(unsigned char *data, unsigned int  len);
int asn_decode_length(unsigned char *data, unsigned int *len);

// Encode sequence header, doesn't encode actual data
int asn_encode_sequence(unsigned char *data, unsigned int  length);
int asn_decode_sequence(unsigned char *data, unsigned int *length);

int asn_encode_null(unsigned char *data);
int asn_decode_null(unsigned char *data);

// Encode octet string header, uses strlen to determine length
// Decode does not account for actual data bytes
int asn_encode_octet_string(unsigned char *data, unsigned char *value, int data_len);
int asn_decode_octet_string(unsigned char *data, unsigned int *len);

int asn_decode_request_type(unsigned char *data, unsigned int *type, unsigned int *length);

int asn_encode_oid(unsigned char *data, _oid *oid);
int asn_decode_oid(unsigned char *data, _oid *oid);

int asn_encode_pdu(unsigned char *data, unsigned int type, int data_len);

#endif
/***   End Of File   ***/
