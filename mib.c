// mib.c

// Standard Includes
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "mib.h"
#include "system.h"
#include "config_params.h"

_mib_handler *mib_head=NULL;

int oid_greater_than(_oid *oid_a, _oid *oid_b)
{
	int i;
	int length = (oid_a->len>oid_b->len)?oid_b->len:oid_a->len;
	
	for(i=0; i<length; i++)
	{
		if (oid_b->val[i]>oid_a->val[i]) return 1;
		if (oid_b->val[i]<oid_a->val[i]) return 0;
	}
	
	if (oid_b->len>oid_a->len) return 1;
	return 0;
}

void mib_sort(void)
{
	_mib_handler **pp = &mib_head;
    // p always points to the head of the list
    _mib_handler *p = *pp;
    _mib_handler *holder;
    *pp = NULL;

    while (p)
    {
        _mib_handler **lhs = &p;
        _mib_handler **rhs = (_mib_handler**)&p->next;
        unsigned char swapped = false;

        // keep going until qq holds the address of a null pointer
        while (*rhs)
        {
            // if the left side is greater than the right side
            if (oid_greater_than(&(*rhs)->oid, &(*lhs)->oid))
            {
                // swap linked node ptrs, then swap *back* their next ptrs
                holder=*lhs;
                *lhs=*rhs;
                *rhs=holder;
                
                holder=(*lhs)->next;
                (*lhs)->next = (*rhs)->next;
                (*rhs)->next = holder;
                
                lhs = (_mib_handler**)&(*lhs)->next;
                swapped = true;
            }
            else
            {   // no swap. advance both pointer-pointers
                lhs = rhs;
                rhs = (_mib_handler**)&(*rhs)->next;
            }
        }

        // link last node to the sorted segment
        *rhs = *pp;

        // if we swapped, detach the final node, terminate the list, and continue.
        if (swapped)
        {
            // take the last node off the list and push it into the result.
            *pp = *lhs;
            *lhs = NULL;
        }

        // otherwise we're done. since no swaps happened the list is sorted.
        // set the output parameter and terminate the loop.
        else
        { 
            *pp = p;
            break;
        }
    }
}

int mib_register(_mib_handler *handler)
{
    _mib_handler *mh;

    if (mib_head==NULL)
    {
        mib_head=handler;
        mib_head->next=NULL;
    }
    else
    {
        for(mh=mib_head; mh->next!=NULL; mh=mh->next);
        mh->next=handler;
        handler->next=NULL;
    }
    
    mib_sort();
    return 0;
}
 
int mib_add_var_binding(unsigned char *data, int data_len, _oid *oid, void *snmp_data, int type)
{
    unsigned char *p1;
    unsigned int sequence_length;

    // build var-binding reply
    p1=data;
    
    // we need to calculate the sequence length based on the type of data we're adding
    sequence_length   = asn_bytes_to_encode(snmp_data, type, data_len); // the data+type+length
    sequence_length  += asn_bytes_to_encode(oid, ASN_OID, 0);           // bytes to encode the oid
    
    // start encoding
    
    // add the var-binding sequence
    p1+=asn_encode_sequence(p1, sequence_length);
    
    // add the oid
    p1+=asn_encode_oid(p1, oid);

    // add the data
    switch(type)
    {
        case ASN_SNMP_IPADDRESS:
            p1+=asn_encode_snmp_ipaddress(p1, (unsigned char*)snmp_data);
            break;
        case ASN_INT:
        case ASN_SNMP_TIMETICKS:
        case ASN_SNMP_GAUGE:
        case ASN_SNMP_COUNTER:
            p1+=asn_encode_int(p1, type, *(int*)snmp_data);
            break;
        case ASN_OCTET_STRING:
            p1+=asn_encode_octet_string(p1, (unsigned char*)snmp_data, data_len);
            break;
        case ASN_NULL: 
            p1+=asn_encode_null(p1);
            break;
      case ASN_OID:
            p1+=asn_encode_oid(p1, (_oid*)snmp_data);
            break;
    }

    return p1-data;
}


// called when an error happened processing a previous OID, this will add the OID with a NULL
int mib_add_null_oid(unsigned char *data, _oid *oid)
{
    return mib_add_var_binding(data, 0, oid, NULL, ASN_NULL);  
}

#include "system.h"
#include "time_management.h"
int mib_process_oid(unsigned char *data, _oid *oid, int request, int data_type, void *data_in, int data_in_len, int *error)
{
    _mib_handler *mh=mib_head;
    int ret=ASN_UNKNOWN;
    void *snmp_data;
    int  data_len;
    
    if (uptime_sec>SEC_TO_WAIT_DEBUG_FLASH)
    {
		memcpy(&flash_debug.last_mib_requests[flash_debug.last_mib_index], oid, sizeof(_oid));
		flash_debug.last_mib_timestamp[flash_debug.last_mib_index] = utc_get_sec();
		flash_debug.last_mib_index++;
		if (flash_debug.last_mib_index>=NUM_DEBUG_MIB) flash_debug.last_mib_index=0;
    }


    // find registered MIB's for this item
    for(mh=mib_head; mh!=NULL; mh=mh->next)
    {
        if ((oid->len>=mh->oid.len) && (memcmp(mh->oid.val, oid->val, mh->oid.len*4)==0))
        {
            // found it
            ret=mh->snmp_fn(&snmp_data, &data_len, oid, request,data_type,data_in,data_in_len,error);
            break;
        }
    }
    if (*error==snmp_NO_SUCH_NAME)
    {
    	snmp_stats->out.noSuchNames++;
    }

    if ((request==GET_NEXT_REQUEST_PDU)&&((ret==ASN_UNKNOWN)||(*error==snmp_NO_SUCH_NAME)))
    {
    	debug_printf("End of OID: ");
    	print_oid(oid);
    	
    	debug_printf("Available OIDs\r\n");
        // we have to start over
        for(mh=mib_head; mh!=NULL; mh=mh->next)
        {
        	print_oid(&mh->oid);
        	
        	debug_printf("GT: %d\r\n", oid_greater_than(oid, &mh->oid));
        	
        	if (oid_greater_than(oid, &mh->oid))
        	{
        		debug_printf("sending to this handler\r\n");
        		memcpy(oid, &mh->oid, sizeof(_oid));
        	
        		ret=mh->snmp_fn(&snmp_data, &data_len, oid, request,data_type,data_in,data_in_len,error);
                break;
        	}
        }
    }

    
    if (ret==ASN_UNKNOWN)
    {
        ret=ASN_NULL;
        *error=snmp_NO_SUCH_NAME;
        
        if (mh==NULL)
        {
            debug_printf("Unknown OID: ");
            print_oid(oid);
        }
    }
    
    return mib_add_var_binding(data, data_len, oid, snmp_data, ret);
}

/***   End Of File   ***/
