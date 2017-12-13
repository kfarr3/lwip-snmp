// asn.1.c

// Standard Includes
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "misc/asn.1.h"
#include "system.h"

void print_oid(_oid *oid)
{
	if (oid->len > 128)
	{
		debug_printf("asn1: WARNING: Attempted to display an OID that was more than 128 fields long!\r\n");
		return;
	}
    int i;
    debug_printf("OID: ");
    for(i=0; i<oid->len; i++)
    {
        debug_printf(".%d", oid->val[i]);
    }
    debug_printf("\n");
}

int str_to_oid(_oid *oid, char *str)
{
	char *p1;
	p1=strtok(str, ".");
	for( oid->len=0; p1!=NULL; oid->len++, p1=strtok(NULL, "."))
	{
		oid->val[oid->len]=atoi(p1);
	}
	return oid->len;
}

char* oid_to_str(char *str, _oid *oid)
{
	int i;
	str[0]='\0';
	if (oid->len>30) oid->len=30;
	for(i=0; i<oid->len; i++)
	{
		if (i==0) sprintf(str, "%d", oid->val[i]);
		else sprintf(str+strlen(str), ".%d", oid->val[i]);
	}
	return str;
}

int asn_bytes_length(unsigned int length)
{
    // calculate the number of bytes required to encode a length
    if      (length<=127     ) return 1;
    else if (length< 255     ) return 2;
    else if (length< 65535   ) return 3;
    else if (length< 16777215) return 4;
    else                       return 5;
}

int asn_bytes_to_encode(void *data, int type, int data_len)
{
    switch(type)
    {
        case ASN_SNMP_IPADDRESS: return 6;
        case ASN_INT:
        case ASN_SNMP_GAUGE:
        case ASN_SNMP_TIMETICKS:
        case ASN_SNMP_COUNTER:
	        if (*(int*)data<0)
	        {
					 if (*(int*)data>=-127)     return 2+1;
				else if (*(int*)data>=-32768)   return 2+2;
				else if (*(int*)data>=-8388608) return 2+3;
				else                            return 2+4;
	        }
	        else
	        {
	            if      (*(int*)data<=0x000000FF) return (*(int*)data&0x00000080)? 2+2: 2+1;
	            else if (*(int*)data<=0x0000FFFF) return (*(int*)data&0x00008000)? 2+3: 2+2;
	            else if (*(int*)data<=0x00FFFFFF) return (*(int*)data&0x00800000)? 2+4: 2+3;
	            else                              return (*(int*)data&0x80000000)? 2+5: 2+4;
	        }

        case ASN_OCTET_STRING:
            return 1+data_len+asn_bytes_length(data_len);
        case ASN_NULL: 
            return 2;
        case ASN_OID:
            return asn_bytes_to_encode_oid((_oid*)data);
        case ASN_SEQUENCE:
            return 1+asn_bytes_length(data_len)+data_len;
      case REPORT_PDU:
      case GET_RESPONSE_PDU:
      case GET_REQUEST_PDU:
            return 1+asn_bytes_length(data_len)+data_len;

        default: return 0;
    }
}

int asn_encode_snmp_ipaddress(unsigned char *data, unsigned char *ip_addr)
{
    data[0]=ASN_SNMP_IPADDRESS;
    data[1]=4;
    memcpy(data+2,ip_addr,4);
    return 6;  
}


int asn_encode_int(unsigned char *data, int type, int value)
{
    int i;
    int bytes_required;
    
    *data=type;

	if (value<0)
	{
		// -1       : -128     - 1 byte
		// -129     : -32768   - 2 byte
		// -32769   : -8388608 - 3 byte
		// -8388609 :          - 4 byte
		
		     if (value>=-127)     bytes_required=1;
		else if (value>=-32768)   bytes_required=2;
		else if (value>=-8388608) bytes_required=3;
		else                      bytes_required=4;
	}
	else
	{
	    if      (value<=0x000000FF) bytes_required = (value&0x00000080)?2:1;
	    else if (value<=0x0000FFFF) bytes_required = (value&0x00008000)?3:2;
	    else if (value<=0x00FFFFFF) bytes_required = (value&0x00800000)?4:3;
	    else                        bytes_required = (value&0x80000000)?5:4;
	}

    
    data[1]=bytes_required;
    data+=2;
    for(i=bytes_required; i>0; i--)
    {
        *data++= ((value& (0xFF<<((8*(i-1))))) >> ((8*(i-1))));
    }
    return 2+bytes_required;
}

// returns the number of bytes used to encode the length into data
int asn_encode_length(unsigned char *data, unsigned int len)
{
    int num_octets = asn_bytes_length(len);
    int i;
    
    if (num_octets==1)
    {
        data[0]=len&0xFF;
        return 1;
    }
    else
    {
        *data++=(num_octets-1)|0x80;
        for(i=num_octets-1; i>0; i--)
        {
            *data++=(len&(0xFF<<((i-1)*8)))>>((i-1)*8);
        }
    }
    return num_octets;
      
}

int asn_encode_sequence(unsigned char *data, unsigned int length)
{
    *data=ASN_SEQUENCE;
    return asn_encode_length(data+1, length)+1;
}

int asn_encode_null(unsigned char *data)
{
    data[0]=ASN_NULL;
    data[1]=0;
    return 2;
}

int asn_encode_octet_string(unsigned char *data, unsigned char *value, int data_len)
{
    int bytes_used;
    data[0]=ASN_OCTET_STRING;
    bytes_used=asn_encode_length(data+1, data_len);
    memcpy(data+1+bytes_used, value, data_len);
    return 1+bytes_used+data_len;
}


// returns the number of bytes used to decode the length
// and sets the *len
int asn_decode_length(unsigned char *data, unsigned int *len)
{
    int num_octets;
    int i;
    if (data[0]<0x80)
    {
        // short form
        *len=data[0];
        return 1;
    }
    else if (data[0]==0x80)
    {
        // indefinite form, unsupported at the moment
        return 0;
    }
    else if (data[0]&0x80)
    {
        // definite form
        num_octets=data[0]&0x7F;
        if (num_octets>4) return 0; // cannot support more than a 4 byte length
        *len=0;
        for(i=0; i<num_octets; i++)
        {
            *len<<=8;
            *len|=data[1+i];
        }
        return num_octets+1;
    }
     
    return 0;
}

int asn_decode_snmp_ipaddress(unsigned char *data, unsigned char *ip_address)
{
    if (data[0]!=ASN_SNMP_IPADDRESS) return 0;
    if (data[1]!=4) return 0;
    memcpy(ip_address, data+2, 4);
    return 6;
}

int asn_decode_int_type(unsigned char *data,  unsigned int *type, unsigned int *value)
{
    *type=data[0];
    switch(*type) // ensure it's an INT type that we know about
    {
        case ASN_INT:
        case ASN_SNMP_GAUGE:
        case ASN_SNMP_TIMETICKS:
        case ASN_SNMP_COUNTER:
            return asn_decode_int(data, *type, value);
    }
    return 0;
}

// returns the number of bytes used to decode the integer
int asn_decode_int(unsigned char *data,  unsigned int type, unsigned int *value)
{
    unsigned char *p1;
    unsigned int len;
    int i;
    int bytes_used;
    
    if (data[0]!=type) return 0;
    
    if ((bytes_used=asn_decode_length(data+1, &len))==0) return 0;
    p1=data+1+bytes_used;

    if (len>4) return 0; // only supporting 4 byte integers or we overfill 32-bit
    *value=0;
    for(i=0; i<len; i++)
    {
        *value<<=8;
        *value|=p1[i];
    }
    return bytes_used+len+1;
}

// returns the number of bytes used to decode the null
int asn_decode_null(unsigned char *data)
{
    int bytes_used;
    unsigned int len;
    if (*data!=ASN_NULL) return 0;
    if ((bytes_used=asn_decode_length(data+1, &len))==0) return 0;
    return bytes_used+1;
}

int asn_decode_request_type(unsigned char *data, unsigned int *type, unsigned int *length)
{
    int bytes_used;
    *type=*data;
    if ((bytes_used=asn_decode_length(data+1,length))==0) return 0;
    return bytes_used+1;
}

int asn_decode_octet_string(unsigned char *data, unsigned int *len)
{
    int bytes_used;
    if (*data!=ASN_OCTET_STRING) return 0;
    if ((bytes_used=asn_decode_length(data+1, len))==0) return 0;
    return 1+bytes_used;
}

int asn_bytes_to_encode_oid_val(unsigned int val)
{
    // we're only dealing with 32-bit numbers here
    // each OID octet has only 7-bits worth of data
    if      (val <=  0x7F)      return 1;
    else if (val <= 0x3FFF)     return 2;
    else if (val <= 0x1FFFFF)   return 3;
    else if (val <= 0xFFFFFFF)  return 4;
    else                        return 5;  
}

int asn_bytes_to_encode_oid(_oid *oid)
{
    int i;
    int bytes_to_encode;
    
    // we need to calculate how many bytes are required to encode this OID
    bytes_to_encode=0;
    for(i=0; i<oid->len; i++)
    {
        if (i==0)
        {
            // the first 2 bytes are compressed and then encoded
            bytes_to_encode=asn_bytes_to_encode_oid_val((oid->val[0]*40)+oid->val[1]);
            i++; // since we're handling 2 bytes here
        }
        else
        {
            bytes_to_encode+=asn_bytes_to_encode_oid_val(oid->val[i]);
        }
    }
    
    return bytes_to_encode+1+asn_bytes_length(bytes_to_encode);
}

int asn_encode_oid(unsigned char *data, _oid *oid)
{
    unsigned char *p1;
    int i;
    int bytes_to_encode;
    int val;
    
    p1=data;
    *p1++=ASN_OID;
    
    // we need to calculate how many bytes are required to encode this OID
    bytes_to_encode=0;
    for(i=0; i<oid->len; i++)
    {
        if (i==0)
        {
            // the first 2 bytes are compressed and then encoded
            bytes_to_encode=asn_bytes_to_encode_oid_val((oid->val[0]*40)+oid->val[1]);
            i++; // since we're handling 2 bytes here
        }
        else
        {
            bytes_to_encode+=asn_bytes_to_encode_oid_val(oid->val[i]);
        }
    }
    
    // add length
    p1+=asn_encode_length(p1, bytes_to_encode);

    for(i=0; i<oid->len; i++)
    {
        if (i==0)
        {
            val=(oid->val[0]*40)+oid->val[1];
            i++;
        }
        else
        {
            val=oid->val[i];
        }
        switch(asn_bytes_to_encode_oid_val(val))
        {
            case 5: *p1++= ((val&0xF0000000)>>28)|0x80;
            case 4: *p1++= ((val&0x0FE00000)>>21)|0x80;
            case 3: *p1++= ((val&0x001FC000)>>14)|0x80;
            case 2: *p1++= ((val&0x00003F80)>> 7)|0x80;
            case 1: *p1++= ((val&0x0000007F)>> 0);
        }
    }
    return p1-data;
}

int asn_decode_oid(unsigned char *data, _oid *oid)
{
    unsigned int bytes_left=0;
    unsigned int bytes_used=0;
    unsigned int value;
    
    if (*data!=ASN_OID) return 0;

    // get the number of bytes describing this OID
    if ((bytes_used=asn_decode_length(data+1, &bytes_left))==0) return 0;
    bytes_used++; // for the ASN_OID

    data+=bytes_used;
    oid->len=0;
    while(bytes_left>0)
    {
        // step one, extract value
        // each OID value is encoded in multiple bytes
        // the 8th bit indicates that this isn't the the last octet in the value
        // while bits 7-1 are the actual data bits
        value=0;
        while((*data&0x80)&&(bytes_left>0)) // while there are more bytes left
        {
            value<<=7; // shift it 7 bits
            value|=(*data&0x7F);
            data++;
            bytes_left--;
            bytes_used++;
        }
        // we're on the last octet
        value<<=7; // shift it over 7 bits
        value|=*data;
        data++;
        bytes_left--;
        bytes_used++;
        
        // Now add the value to the OID structure
        // the first two OID values are compressed into one value
        if (oid->len==0) // doing the first
        {
            // first 2 octets are encoded X*40 + Y
            // 0 <= X <= 2
            // When X==0 or X==1 then Y<39
            // These rules are defined in X.690
            
            // try X=0
            if (value<=39)
            {
                oid->val[0]=0;
                oid->val[1]=value;
                oid->len=2;
            }
            else if (value<76)
            {
                oid->val[0]=1;
                oid->val[1]=value-40;
                oid->len=2;
            }
            else // assume 2
            {
                oid->val[0]=2;
                oid->val[1]=value-80;
                oid->len=2;
            }
        }
        else
        {
            oid->val[oid->len]=value;
            oid->len++;
        }
    }
    
    return bytes_used;    
}

// sets length to the length of the sequence
// returns the number of bytes used.
// the return_val + data = start of sequence
int asn_decode_sequence(unsigned char *data, unsigned int *length)
{
    int bytes_used;
    if (*data!=ASN_SEQUENCE) return 0;
    if ((bytes_used=asn_decode_length(data+1, length))==0) return 0;
    return bytes_used+1;
}

int asn_encode_pdu(unsigned char *data, unsigned int type, int data_len)
{
    unsigned char *p1=data;
    *p1++=type;
    p1+=asn_encode_length(p1, data_len);
    return p1-data;
}

/***   End Of File   **/
