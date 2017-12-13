#ifndef MIB_H
#define MIB_H

#include "asn.1.h"


#define snmp_NO_ERROR       		0x00
#define snmp_TOO_BIG        		0x01
#define snmp_NO_SUCH_NAME   		0x02
#define snmp_BAD_VALUE      		0x03
#define snmp_READ_ONLY      		0x04
#define snmp_GEN_ERROR      		0x05
#define snmp_NO_ACCESS				0x06
#define snmp_WRONG_TYPE				0x07
#define snmp_WRONG_LENGTH			0x08
#define snmp_WRONG_ENCODING			0x09
#define snmp_WRONG_VALUE			0x0A
#define snmp_NO_CREATION			0x0B
#define snmp_INCONSISTENT_VALUE		0x0C
#define snmp_RESOURCE_UNAVAILABLE	0x0D
#define snmp_COMMIT_FAILED			0x0E
#define snmp_UNDO_FAILED			0x0F
#define snmp_AUTHORIZATION_ERROR	0x10
#define snmp_NOT_WRITABLE			0x11
#define snmp_INCONSISTENT_NAME		0x12

typedef  int(*snmp_request)(void **data, int *data_len, _oid *oid, int request_type, int data_type, void *data_in, int data_in_len, int *error);

typedef struct
{
    snmp_request snmp_fn;
    _oid         oid;
    void *       next;
}_mib_handler;


// add an OID handler
int mib_register(_mib_handler *handler);

int mib_process_oid(unsigned char *data, _oid *oid, int request,int data_type, void *data_in, int data_in_len, int *error);
int mib_add_null_oid(unsigned char *data, _oid *oid);
int mib_add_var_binding(unsigned char *data, int data_len, _oid *oid, void *snmp_data, int type);

#endif
/***   End Of File   ***/
