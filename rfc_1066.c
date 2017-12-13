// rfc_1066.c

// Standard Includes
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "asn.1.h"
#include "mib.h"
#include "system.h"

#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/netif.h"
#include "netif/etharp.h"
#include "lwip/stats.h"
#include "config_params.h"

int rfc_1066_handler(void **data, int *data_len, _oid *oid, int request_type, int data_type, void *data_in, int data_in_len, int *error);

// set oid to 1.3.6.1.2.1
_mib_handler rfc_1066_mib={rfc_1066_handler,6,{1,3,6,1,2,1}};

// Data that should be elsewhere
const char sys_des[]={"nrgSmart"};
const _oid sys_oid={7,{1,3,6,1,4,1,532058}};
static int temp_int;
static int temp_str[7];

/*****************************
 * Dynamic Config
 * ***************************/

static int set_string(void **data_out, int *data_out_len, char *to,  char *from, unsigned int max_length, unsigned int length, int data_type, int *error)
{
	if (data_type!=ASN_OCTET_STRING)
	{
		*error=snmp_WRONG_TYPE;
		return ASN_NULL;
	}

	if (length>=max_length)
	{
		*error=snmp_WRONG_TYPE;
		return ASN_NULL;
	}

	strncpy((char*)to, (char*)from, length);
	to[length]='\0';

	*data_out=to;
	*data_out_len=strlen((char*)*data_out);
	return ASN_OCTET_STRING;
}

int snmp_system(void **data, int *data_len, _oid *oid, int request_type, int data_type, void *data_in, int data_in_len, int *error)
{
    *error = snmp_NO_ERROR;
    int ret;

    if (request_type==SET_REQUEST_PDU)
    {
        switch(oid->val[7])
        {
            case 4: // Contact
	        	ret = set_string(data, data_len, site_info->sys_contact, data_in, 255, data_in_len, data_type, error);
	        	if (*error==snmp_NO_ERROR) save_site_info();
	        	return ret;
            case 5: // OID
	        	ret = set_string(data, data_len, site_info->sys_name, data_in, 255, data_in_len, data_type, error);
	        	if (*error==snmp_NO_ERROR) save_site_info();
	        	return ret;
            case 6: // sUptime
	        	ret = set_string(data, data_len, site_info->sys_location, data_in, 255, data_in_len, data_type, error);
	        	if (*error==snmp_NO_ERROR) save_site_info();
	        	return ret;
            default:
                *error = snmp_NO_SUCH_NAME;
                return ASN_NULL;
        }
    }
    else if (request_type==GET_NEXT_REQUEST_PDU)
    {
        // this function owns every item from
        // 1.3.6.1.2.1.1
      
        // handle incrementing the oid
        // 0 1 2 3 4 5 6 7 8
        // 1 2 3 4 5 6 7 8 9
        // 1.3.6.1.2.1.1
        // 1.3.6.1.2.1.1.1.0  description
        // 1.3.6.1.2.1.1.2.0
        if (oid->len<8)
        {
            oid->val[7]=1;
            oid->val[8]=0;
            oid->len=9;
        }
        else
        {
            oid->val[7]++;
            oid->val[8]=0;
            oid->len=9;
        }
    }
    
    if ((oid->len!=9)&&(oid->val[8]!=0))
    {
        *error=snmp_NO_SUCH_NAME;
        return ASN_NULL;
    }
    
    switch(oid->val[7])
    {
        case 1: // description
            *data=(void*)sys_des;
            *data_len=strlen(sys_des);
            return ASN_OCTET_STRING;
        case 2: // OID
            *data=(void*)&sys_oid;
            return ASN_OID;
        case 3: // sUptime
        	temp_int = uptime_sec * 100;
            *data=(void*)&temp_int;
            return ASN_SNMP_TIMETICKS;
        case 4:
        	*data=(void*)site_info->sys_contact;
        	*data_len=strlen(site_info->sys_contact);
        	return ASN_OCTET_STRING;
        case 5:
        	*data=(void*)site_info->sys_name;
        	*data_len=strlen(site_info->sys_name);
        	return ASN_OCTET_STRING;
        case 6:
        	*data=(void*)site_info->sys_location;
        	*data_len=strlen(site_info->sys_location);
        	return ASN_OCTET_STRING;
        case 7:
            temp_int=0;
            *data=&temp_int;
            return ASN_INT;
        case 8:
        	temp_int=0;
        	*data=&temp_int;
        	return ASN_INT;
        default:
            *error = snmp_NO_SUCH_NAME;
            return ASN_NULL;
    }  
}

// index 0-x
struct netif * get_netif(int index)
{
    struct netif *netif;
    int i;

    for(i=0,netif=netif_list; (i<index)&&(netif!=NULL); i++,netif=netif->next);
    return netif;
}

int snmp_interface(void **data, int *data_len, _oid *oid, int request_type, int data_type, void *data_in, int data_in_len, int *error)
{
    struct netif *netif;
    int i;
    *error = snmp_NO_ERROR;

    if (request_type==SET_REQUEST_PDU)
    {
        *error=snmp_READ_ONLY;
        return ASN_NULL;
    }
    else if (request_type==GET_NEXT_REQUEST_PDU)
    {
        // handle incrementing the oid
        // 0 1 2 3 4 5 6 7 8 9
        // 1 2 3 4 5 6 7 8 9 A
        // 1.3.6.1.2.1.2
        // 1.3.6.1.2.1.2.1.0      num_interfaces
        // 1.3.6.1.2.1.2.2        ifEntry
        // 1.3.6.1.2.1.2.2.x      item
        // 1.3.6.1.2.1.2.2.x.y    item.index
        // 1.3.6.1.2.1.2.2        table
        // 1.3.6.1.2.1.2.2.1      table_entry
        // 1.3.6.1.2.1.2.2.1.1    table_index
        // 1.3.6.1.2.1.2.2.1.x.y  x=column, y=index
        // 0 1 2 3 4 5 6 7 8 9 A
        if (oid->len<8) // setup for the first leaf element
        {
            oid->val[7]=1;
            oid->val[8]=0;
            oid->len=9;
        }
        else if (oid->val[7]==1) // entering table
        {
            oid->val[7]=2;  // table
            oid->val[8]=1;  // table_entry
            oid->val[9]=1;  // column
            oid->val[10]=1; // row
            oid->len=11;
        }
        else if (oid->val[7]==2) // in table
        {
            if (get_netif(oid->val[10])==NULL) // no more rows
            {
                oid->val[9]++;
                oid->val[10]=1;
                oid->len=11;
            }
            else
            {
                oid->val[10]++;
                oid->len=11;
            }
        }
        else
        {
            *error=snmp_NO_SUCH_NAME;
            return ASN_NULL;
        }
    }

    if (oid->len<8)
    {
        *error=snmp_NO_SUCH_NAME;
        return ASN_NULL;
    }
    
    switch(oid->val[7])
    {
        case 1: // num_interfaces
            if (oid->val[8]!=0) break;
            for(i=0,netif=netif_list; netif!=NULL; i++,netif=netif->next);
            temp_int=i;
            *data=&temp_int;
            return ASN_INT;

        case 2: // ifEntry
           //0 1 2 3 4 5 6 7 8 9 A
          // 1.3.6.1.2.1.2.2        table
          // 1.3.6.1.2.1.2.2.1      table_entry
          // 1.3.6.1.2.1.2.2.1.1    table_index
          // 1.3.6.1.2.1.2.2.1.x.y  x=column, y=index

          if (oid->len!=11) break;
          netif=get_netif(oid->val[10]-1);
          if (netif==NULL) break; // no interface on that index
          
          switch(oid->val[9])
          {
              case 1: // ifIndex
                  temp_int=oid->val[10];
                  *data=&temp_int;
                  return ASN_INT;
              case 2: // ifDesc
                  *data=netif->name;
                  *data_len=strlen(netif->name);
                  return ASN_OCTET_STRING;
              case 3: // ifType
                  temp_int=netif->link_type;
                  *data=&temp_int;
                  return ASN_INT;
              case 4: // ifMtu
                  temp_int=netif->mtu;
                  *data=&temp_int;
                  return ASN_INT;
              case 5: // ifSpeed
                  temp_int=netif->link_speed;
                  *data=&temp_int;
                  return ASN_SNMP_GAUGE;
              case 6: // ifPhysAddress
                  *data=netif->hwaddr;
                  *data_len=6;
                  return ASN_OCTET_STRING;
              case 7: // ifAdminStatus
              case 8: // ifOperStatus
                  if ((netif_is_up(netif))&&(netif_is_link_up(netif))) temp_int=1;
                  else                                                 temp_int=2;
                  *data=&temp_int;
                  return ASN_INT;
              case 9: // ifLastChange
                  temp_int=netif->ts;
                  *data=&temp_int;
                  return ASN_SNMP_TIMETICKS;
              case 10: // ifInOctets
                  temp_int=netif->mib2_counters.ifinoctets;
                  *data=&temp_int;
                  return ASN_SNMP_COUNTER;
              case 11: // ifInUcastPkts
                  temp_int=netif->mib2_counters.ifinucastpkts;
                  *data=&temp_int;
                  return ASN_SNMP_COUNTER;
              case 12: // ifInNUcastPkts
                  temp_int=netif->mib2_counters.ifinnucastpkts;
                  *data=&temp_int;
                  return ASN_SNMP_COUNTER;
              case 13: // ifInDiscards
                  temp_int=netif->mib2_counters.ifindiscards;
                  *data=&temp_int;
                  return ASN_SNMP_COUNTER;
              case 14: // ifInErrors
                  temp_int=netif->mib2_counters.ifinerrors;
                  *data=&temp_int;
                  return ASN_SNMP_COUNTER;
              case 15: // ifInUnknownProtos
                  temp_int=netif->mib2_counters.ifinunknownprotos;
                  *data=&temp_int;
                  return ASN_SNMP_COUNTER;
              case 16: // ifOutOctets
                  temp_int=netif->mib2_counters.ifoutoctets;
                  *data=&temp_int;
                  return ASN_SNMP_COUNTER;
              case 17: // ifOutUcastPkts
                  temp_int=netif->mib2_counters.ifoutucastpkts;
                  *data=&temp_int;
                  return ASN_SNMP_COUNTER;
              case 18: // ifOutNUcastPkts
                  temp_int=netif->mib2_counters.ifoutnucastpkts;
                  *data=&temp_int;
                  return ASN_SNMP_COUNTER;
              case 19: // ifOutDiscards
                  temp_int=netif->mib2_counters.ifoutdiscards;
                  *data=&temp_int;
                  return ASN_SNMP_COUNTER;
              case 20: // ifOutErrors
                  temp_int=netif->mib2_counters.ifouterrors;
                  *data=&temp_int;
                  return ASN_SNMP_COUNTER;
              case 21: // ifOutQLen
                  temp_int=netif->mib2_counters.ifoutqlen;
                  *data=&temp_int;
                  return ASN_SNMP_GAUGE;
          }                  
          break;

    }  
            
    *error = snmp_NO_SUCH_NAME;
    return ASN_NULL;
}

struct etharp_entry *get_arp_entry(int index)
{
    int i;
    int j;
    struct etharp_entry * arp=arp_table;

    for(j=-1,i=0; i<ARP_TABLE_SIZE; i++)
    {
        if (arp[i].state==ETHARP_STATE_STABLE)
        {
            j++;
            if (j==index) return &arp[i];
        }
    }
    return NULL;
}

int snmp_at(void **data, int *data_len, _oid *oid, int request_type, int data_type, void *data_in, int data_in_len, int *error)
{
    struct etharp_entry *arp;
    
    *error = snmp_NO_ERROR;

    // 1 2 3 4 5 6 7 8 9 A
    // 0 1 2 3 4 5 6 7 8 9
    // 1.3.6.1.2.1.3.1.1   atEntry
    // 1.3.6.1.2.1.3.1.1.1 atIfIndex
    // 1.3.6.1.2.1.3.1.1.2 atPhysAddress
    // 1.3.6.1.2.1.3.1.1.3 atNetAddress
    
    // 1.3.6.1.2.1.3                          .at
    // 1.3.6.1.2.1.3.1                        .at.atTable
    // 1.3.6.1.2.1.3.1.1                      .at.atTable.atEntry
    // 1.3.6.1.2.1.3.1.1.1                    .at.atTable.atEntry.atIfIndex
    // 1.3.6.1.2.1.3.1.1.2                    .at.atTable.atEntry.atPhysAddr
    // 1.3.6.1.2.1.3.1.1.3                    .at.atTable.atEntry.atNetAddress
    // 1.3.6.1.2.1.3.1.1.x.y                  x=1-3 y=index
    // 0 1 2 3 4 5 6 7 8 9 A
    
    if (request_type==SET_REQUEST_PDU)
    {
        *error=snmp_READ_ONLY;
        return ASN_NULL;
    }
    else if (request_type==GET_NEXT_REQUEST_PDU)
    {
        // 0 1 2 3 4 5 6  7       8       9 A
        // 1.3.6.1.2.1.3 .1      .1      .x.y
        //             at.atTable.atEntry.X.Y
        if (oid->len<11)
        {
            oid->val[7]=1;    // at.atTable
            oid->val[8]=1;    // at.atTable.atEntry
            oid->val[9]=1;    // at.atTable.atEntry.atIfIndex
            oid->val[10]=1;   // at.atTable.atEntry.atIfIndex.1
            oid->len=11;
        }
        else if (oid->len>11) // asking for something greater
        {
            // check if the next index is available
            if (get_arp_entry(oid->val[10])==NULL) // nope
            {
                oid->val[9]++; // get next table column
                oid->val[10]=1; // set to first row
                oid->len=11;
            }
            else // yep
            {
                oid->val[10]++;
                oid->len=11;
            }
        }
        else if (get_arp_entry(oid->val[10])==NULL) // check if next row is invalid
        {
            oid->val[9]++;
            oid->val[10]=1;
            oid->len=11;
        }
        else
        {
            oid->val[10]++;
            oid->len=11;
        }
    }

    if (oid->len!=11)
    {
        *error=snmp_NO_SUCH_NAME;
        return ASN_NULL;
    }

    
    arp=get_arp_entry(oid->val[10]-1);
    if (arp==NULL)
    {
        *error=snmp_NO_SUCH_NAME;
        return ASN_NULL;
    }
    
    switch(oid->val[9])
    {
        case 1: // atEntry
            temp_int=oid->val[10];
            *data=&temp_int;
            return ASN_INT;
        case 2: // atPhysAddress
            memcpy(temp_str, arp->ethaddr.addr, 6);
            *data=temp_str;
            *data_len=6;
            return ASN_OCTET_STRING;
        case 3: // atNetAddress
            memcpy(temp_str,&arp->ipaddr.addr, 4);
            *data=temp_str;
            *data_len=4;
            return ASN_SNMP_IPADDRESS;
        default:
            *error = snmp_NO_SUCH_NAME;
            return ASN_NULL;
    }  
}

int snmp_ip(void **data, int *data_len, _oid *oid, int request_type, int data_type, void *data_in, int data_in_len, int *error)
{
    struct netif *netif;
    *error = snmp_NO_ERROR;

    if (request_type==SET_REQUEST_PDU)
    {
        switch(oid->val[7])
        {
            case 1: // Contact
                temp_int=2;
                *data=&temp_int;
                return ASN_INT;
            case 2: // OID
                temp_int=255;
                *data=&temp_int;
                return ASN_INT;
            default:
                *error = snmp_NO_SUCH_NAME;
                return ASN_NULL;
        }
    }
    else if (request_type==GET_NEXT_REQUEST_PDU)
    {
        // 0 1 2 3 4 5 6 7  8 9
        // 1.3.6.1.2.1.4         .ip
        // 1.3.6.1.2.1.4.1 .0    .ip.ipForwarding
        // ...
        // 1.3.6.1.2.1.4.19.0    .ip.ipFragCreat
        // then table
        // 1.3.6.1.2.1.4.20      .ip.AddrTable
        // 1.3.6.1.2.1.4.20.1    .ip.AddrTable.ipAddrEntry
        // 1.3.6.1.2.1.4.20.1.x   .ip.AddrTable.ipAddrEntry.X
      
        // 0 1 2 3 4 5  6   7        8           9 A
        // 1.3.6.1.2.1 .4 .20       .1          .x.y
        //             .ip.AddrTable.ipAddrEntry.X.Y
      
        if (oid->len<8) // setup for the first leaf elements
        {
            oid->val[7]=1;
            oid->val[8]=0;
            oid->len=9;
        }
        else if (oid->val[7]<19)
        {
            oid->val[7]++;
            oid->val[8]=0;
            oid->len=9;
        }
        else if (oid->val[7]==19) // entering table
        {
            oid->val[7]=20; // table
            oid->val[8]=1;  // table_entry
            oid->val[9]=1;  // column
            oid->val[10]=1;  // row
            oid->len=11;
        }
        else if (oid->val[7]==20) // in table
        {
            if (get_netif(oid->val[10])==NULL) // no more rows
            {
                oid->val[9]++;
                oid->val[10]=1;
                oid->len=11;
            }
            else
            {
                oid->val[10]++;
                oid->len=11;
            }
        }
        else
        {
            *error=snmp_NO_SUCH_NAME;
            return ASN_NULL;
        }
    }

    if (oid->len<9)
    {
        *error=snmp_NO_SUCH_NAME;
        return ASN_NULL;
    }
    
    temp_int=0;
    switch(oid->val[7])
    {
        case 1: // ipForwarding
#if IP_FORWARD
          temp_int=1;
#else
          temp_int=2;
#endif
            *data=&temp_int;
            return ASN_INT;
        case 2: // ipDefaultTTL
            temp_int=(unsigned int)IP_DEFAULT_TTL;
            *data=&temp_int;
            return ASN_INT;
        case 3: // ipInReceives
            *data=&lwip_stats.ip.recv;
            return ASN_SNMP_COUNTER;
        case 4: // ipInHdrErrors
            temp_int=lwip_stats.ip.chkerr+
                     lwip_stats.ip.lenerr+
                     lwip_stats.ip.proterr+
                     lwip_stats.ip.opterr+
                     lwip_stats.ip.err;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 5: // ipInAddrErrors
            *data=&temp_int;//lwip_stats.ip.addrerr;
            return ASN_SNMP_COUNTER;
        case 6: // ipForwDatagrams
            *data=&lwip_stats.ip.fw;
            return ASN_SNMP_COUNTER;
        case 7: // ipInUnknownProtos
            *data=&lwip_stats.ip.proterr;
            return ASN_SNMP_COUNTER;
        case 8: // ipInDiscards
            *data=&lwip_stats.ip.memerr;
            return ASN_SNMP_COUNTER;
        case 9: // ipInDelivers
            *data=&temp_int;//lwip_stats.ip.delivered;
            return ASN_SNMP_COUNTER;
        case 10: // ipOutRequests
            *data=&temp_int;//lwip_stats.ip.outreq;
            return ASN_SNMP_COUNTER;
        case 11: // ipOutDiscards
            *data=&temp_int;//lwip_stats.ip.outmemerr;
            return ASN_SNMP_COUNTER;
        case 12: // ipOutNoRoutes
            *data=&temp_int;//lwip_stats.ip.outnoroute;
            return ASN_SNMP_COUNTER;
        case 13: // ipReasmTimeout
            temp_int=0;
#if IP_REASSEMBLY
            temp_int = IP_REASS_MAXAGE;
#endif
            *data=&temp_int;
            return ASN_INT;
        case 14: //ipReasmReqds
            temp_int=0;
#if (IP_REASSEMBLY || IP_FRAG)
            temp_int=lwip_stats.ip_frag.recv;
#endif
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
            
        case 15: // ipReasmOKs
            temp_int=0;
#if (IP_REASSEMBLY || IP_FRAG)
            temp_int=lwip_stats.ip_frag.fragasm;
#endif
            *data=&temp_int;
            return ASN_SNMP_COUNTER;

        case 16: // ipReasmFails
            temp_int=0;
#if (IP_REASSEMBLY || IP_FRAG)
            temp_int=lwip_stats.ip_frag.err;
#endif
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
            
        case 17: // ipFragsOKs
            temp_int=0;
#if (IP_FRAG)
            temp_int=lwip_stats.ip_frag.xmit;
#endif
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
            
        case 18: // ipFragFails
            // current LWIP implementation doesn't support not fragmenting
            // outgoing packets if IP_FRAG is enabled, so none fail
            temp_int=0;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;

        case 19: // ipFragCreates
            temp_int=0;
#if (IP_FRAG)
            temp_int=lwip_stats.ip_frag.xmit;
#endif
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
            
      case 20: // ipAddrTable
        // 0 1 2 3 4 5 6  7 8 9 
        // 1.3.6.1.2.1.4.20.1       ipAddrEntry      : SEQUENCE
        // 1.3.6.1.2.1.4.20.1.1     ipAdEntAddr      : IPAddress
        // 1.3.6.1.2.1.4.20.1.2     ipAdEntIfIndex   : INTEGER
        // 1.3.6.1.2.1.4.20.1.3     ipAdEntNetMask   : IpAddress
        // 1.3.6.1.2.1.4.20.1.4     ipAdEntBcastAddr : INTEGER
        if (oid->len!=11)
        {
            *error=snmp_NO_SUCH_NAME;
            return ASN_NULL;
        }
        netif=get_netif(oid->val[10]-1);
        if (netif==NULL)
        {
            *error=snmp_NO_SUCH_NAME;
            return ASN_NULL;
        }
        switch (oid->val[9])
        {
            case 1: // ipAddrEntry
                memcpy(temp_str, &netif->ip_addr.u_addr.ip4.addr,4);
                *data=temp_str;
                *data_len=4;
                return ASN_SNMP_IPADDRESS;

            case 2:
                temp_int=oid->val[8];
                *data=&temp_int;
                return ASN_INT;
            
            case 3:
                memcpy(temp_str, &netif->netmask.u_addr.ip4.addr,4);
                *data=temp_str;
                *data_len=4;
                return ASN_SNMP_IPADDRESS;
            
            case 4:
                temp_int=1;
                *data=&temp_int;
                return ASN_INT;              
            
            default:
                *error = snmp_NO_SUCH_NAME;
                return ASN_NULL;
        }
        case 23: // ipRoutingDiscards
            // current LWIP implementation doesn't support not fragmenting
            // outgoing packets if IP_FRAG is enabled, so none fail
            temp_int=0;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        default:
            *error = snmp_NO_SUCH_NAME;
            return ASN_NULL;
    }  
}

int snmp_icmp(void **data, int *data_len, _oid *oid, int request_type, int data_type, void *data_in, int data_in_len, int *error)
{
    *error = snmp_NO_ERROR;

    if (request_type==SET_REQUEST_PDU)
    {
        *error=snmp_READ_ONLY;
        return ASN_NULL;
    }
    else if (request_type==GET_NEXT_REQUEST_PDU)
    {
        // this function owns every item from
        // 1.3.6.1.2.1.5
      
        // handle incrementing the oid
        // 0 1 2 3 4 5 6 7 8
        // 1 2 3 4 5 6 7 8 9
        // 1.3.6.1.2.1.5
        // 1.3.6.1.2.1.5.1.0  
        // 1.3.6.1.2.1.5.2.0
        if (oid->len<8)
        {
            oid->val[7]=1;
            oid->val[8]=0;
            oid->len=9;
        }
        else
        {
            oid->val[7]++;
            oid->val[8]=0;
            oid->len=9;
        }
    }
    
    if ((oid->len!=9)&&(oid->val[8]!=0))
    {
        *error=snmp_NO_SUCH_NAME;
        return ASN_NULL;
    }
    
    switch(oid->val[7])
    {
        case 1: // icmpInMsgs
            temp_int=lwip_stats.icmp.recv;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 2: // icmpInErrors
            temp_int=lwip_stats.icmp.err+lwip_stats.icmp.lenerr;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 3: // icmpInDestUnreachs
            temp_int=0;//lwip_stats.icmp.indestunreach;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 4: // icmpInTimeExcds
            temp_int=0;//lwip_stats.icmp.intimeexcds;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 5: // icmpInParmProbs
            temp_int=0;//lwip_stats.icmp.inparamprob;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 6: // icmpInSrcQuenchs
            temp_int=0;//lwip_stats.icmp.insrcquench;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 7: // icmpInRedirects
            temp_int=0;//lwip_stats.icmp.inredirects;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 8: // icmpInEchos
            temp_int=0;//lwip_stats.icmp.inecho;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 9: // icmpInEchoReply
            temp_int=0;//lwip_stats.icmp.inechoreply;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 10: // icmpInTimestamps
            temp_int=0;//lwip_stats.icmp.intimestamps;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 11: // icmpInTimestampsReps
            temp_int=0;//lwip_stats.icmp.intimestampreply;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 12: // icmpInAddrMasks
            temp_int=0;//lwip_stats.icmp.inaddrmasks;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 13: // icmpInAddrMasksReps
            temp_int=0;//lwip_stats.icmp.inaddrmaskreply;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 14: // icmpOutMsgs
            temp_int=lwip_stats.icmp.xmit;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 15: // icmpOutErrors
            temp_int=lwip_stats.icmp.err;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 16: // icmpOutDestUnreachs
            temp_int=0;//lwip_stats.icmp.outunreach;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 17: // icmpOutTimeExcds
            temp_int=0;//lwip_stats.icmp.outtimeexcds;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 18: // icmpOutParamProbs
            temp_int=0;//lwip_stats.icmp.outparamprobs;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 19: // icmpOutSrcQuenchs
            temp_int=0;//lwip_stats.icmp.outsrcquench;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 20: // icmpOutRedirects
            temp_int=0;//lwip_stats.icmp.outredirects;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 21: // icmpOutEchos
            temp_int=0;//lwip_stats.icmp.outecho;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 22: // icmpOutEchoReps
            temp_int=lwip_stats.icmp.xmit;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 23: // icmpOutTimestamps
            temp_int=0;//lwip_stats.icmp.outtimestamps;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 24: // icmpOutTimestampReps
            temp_int=0;//lwip_stats.icmp.outtimestampreply;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 25: // icmpOutAddrMasks
            temp_int=0;//lwip_stats.icmp.outaddrmasks;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 26: // icmpOutAddrMaskReps
            temp_int=0;//lwip_stats.icmp.outaddrmaskreply;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
            
            
        default:
            *error = snmp_NO_SUCH_NAME;
            return ASN_NULL;
    }  
}

struct tcp_pcb * get_tcp(int index)
{
    struct tcp_pcb *pcb;
    int i=0;
    
    // check listening tcb's first
    for(pcb=tcp_listen_pcbs.pcbs; (i<index)&&(pcb!=NULL); i++,pcb=pcb->next);
    if (pcb!=NULL) return pcb;
    // check active pcb's
    for(pcb=tcp_active_pcbs; (i<index)&&(pcb!=NULL); i++,pcb=pcb->next);
    if (pcb!=NULL) return pcb;
    // check time-wait pcb's
    for(pcb=tcp_tw_pcbs; (i<index)&&(pcb!=NULL); i++,pcb=pcb->next);
    
    return pcb;
}


int snmp_tcp(void **data, int *data_len, _oid *oid, int request_type, int data_type, void *data_in, int data_in_len, int *error)
{
    struct tcp_pcb *pcb;
    
    *error = snmp_NO_ERROR;

    if (request_type==SET_REQUEST_PDU)
    {
        *error=snmp_READ_ONLY;
        return ASN_NULL;
    }
    else if (request_type==GET_NEXT_REQUEST_PDU)
    {
        // this function owns every item from
        // 1.3.6.1.2.1.6
        
        if (oid->len<8) // setup for the first leaf elements
        {
            oid->val[7]=1;
            oid->val[8]=0;
            oid->len=9;
        }
        else if (oid->val[7]<12 || oid->val[7] == 14 || oid->val[7] == 15)
        {
            oid->val[7]++;
            oid->val[8]=0;
            oid->len=9;
        }
        else if (oid->val[7]==12) // entering table
        {
            oid->val[7]=13; // table
            oid->val[8]=1;  // table_entry
            oid->val[9]=1;  // column
            oid->val[10]=1;  // row
            oid->len=11;
        }
        else if (oid->val[7]==13) // in table
        {
            if (oid->len<11)
            {
                oid->val[8]=1;
                oid->val[9]=1;
                oid->val[10]=1;
                oid->len=11;
            }
            else if (get_tcp(oid->val[10])==NULL) // no more rows
            {
            	if (oid->val[9] < 5)
            	{
                   oid->val[9]++;
                   oid->val[10]=1;
                   oid->len=11;
            	}
            	else //Exit the table
            	{
                    oid->val[7]++;
                    oid->val[8]=0;
                    oid->len=9;
            	}
            }
            else
            {
                oid->val[10]++;
                oid->len=11;
            }
        }
        else
        {
            *error=snmp_NO_SUCH_NAME;
            return ASN_NULL;
        }
    }
    
    switch(oid->val[7])
    {
        case 1: // tcpRtoAlgorithm
            temp_int=4; // van jacobson's algorithm
            *data=&temp_int;
            return ASN_INT;
        case 2: // tcpRtoMin
            temp_int=1000; // not sure just yet
            *data=&temp_int;
            return ASN_INT;
        case 3: // tcpRtoMax
            temp_int=6000; // not sure just yet
            *data=&temp_int;
            return ASN_INT;
        case 4: // tcpMaxConn
            temp_int=MEMP_NUM_TCP_PCB;
            *data=&temp_int;
            return ASN_INT;
        case 5: // tcpActiveOpens
            temp_int=0;//lwip_stats.tcp.activeopens;
            *data=&temp_int;
            return ASN_INT;
        case 6: // tcpPassiveOpens
            temp_int=0;//lwip_stats.tcp.passiveopens;
            *data=&temp_int;
            return ASN_INT;
        case 7: // tcpAttemptFails
            temp_int=0;//lwip_stats.tcp.attemptfails;
            *data=&temp_int;
            return ASN_INT;
        case 8: // tcpEstabResets
            temp_int=0;//lwip_stats.tcp.estabresets;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 9: // tcpCurrEstab
            temp_int=0;
            for(pcb=tcp_active_pcbs; pcb!=NULL; pcb=pcb->next)
            {
                if ((pcb->state==ESTABLISHED)||(pcb->state==CLOSE_WAIT)) temp_int++;
            }
            *data=&temp_int;
            return ASN_SNMP_GAUGE;
        case 10: // tcpInSegs
            temp_int=lwip_stats.tcp.recv;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 11: // tcpOutSegs
            temp_int=lwip_stats.tcp.xmit;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 12: // tcpRetransSegs
            temp_int=0;//lwip_stats.tcp.retransmit;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 13: // tcpConnTable
            // 0 1 2 3 4 5 6  7 8 9 
            // 1.3.6.1.2.1.6.13.1       tcpConnEntry
            // 1.3.6.1.2.1.6.13.1.1     tcpConnState
            // 1.3.6.1.2.1.6.13.1.2     tcpConnLocalAddress
            // 1.3.6.1.2.1.6.13.1.3     tcpConnLocalPort
            // 1.3.6.1.2.1.6.13.1.4     tcpConnRemoteAddress
            // 1.3.6.1.2.1.6.13.1.5     tcpConnRemotePort
            if (oid->len!=11)
            {
                *error=snmp_NO_SUCH_NAME;
                return ASN_NULL;
            }
            pcb=get_tcp(oid->val[10]-1);
            if (pcb==NULL)
            {
                *error=snmp_NO_SUCH_NAME;
                return ASN_NULL;
            }
            switch (oid->val[9])
            {
                case 1: // tcpConnState
                    temp_int=pcb->state;
                    *data=&temp_int;
                    return ASN_INT;
                case 2: // tcpConnLocalAddress
                    memcpy(temp_str,&pcb->local_ip.u_addr.ip4.addr,4);
                    *data=temp_str;
                    return ASN_SNMP_IPADDRESS;
                case 3: // tcpConnLocalPort
                    temp_int=pcb->local_port;
                    *data=&temp_int;
                    return ASN_INT;
                case 4: // tcpConnRemoteAddress
                    memcpy(temp_str,&pcb->remote_ip.u_addr.ip4.addr,4);
                    *data=temp_str;
                    return ASN_SNMP_IPADDRESS;
                case 5: // tcpConnRemotePort
                    temp_int=pcb->remote_port;
                    *data=&temp_int;
                    return ASN_INT;
            }
       case 14: // tcpInErrors
          temp_int=0;
          *data=&temp_int;
          return ASN_SNMP_COUNTER;
       case 15: // tcpOutRst
          temp_int=0;
          *data=&temp_int;
          return ASN_SNMP_COUNTER;
        default:
            *error = snmp_NO_SUCH_NAME;
            return ASN_NULL;
    }  
}

int snmp_udp(void **data, int *data_len, _oid *oid, int request_type, int data_type, void *data_in, int data_in_len, int *error)
{
    *error = snmp_NO_ERROR;

    if (request_type==SET_REQUEST_PDU)
    {
        *error=snmp_READ_ONLY;
        return ASN_NULL;
    }
    else if (request_type==GET_NEXT_REQUEST_PDU)
    {
        // this function owns every item from
        // 1.3.6.1.2.1.7
      
        // handle incrementing the oid
        // 0 1 2 3 4 5 6 7 8
        // 1 2 3 4 5 6 7 8 9
        // 1.3.6.1.2.1.7
        // 1.3.6.1.2.1.7.1.0  
        // 1.3.6.1.2.1.7.2.0
        if (oid->len<8)
        {
            oid->val[7]=1;
            oid->val[8]=0;
            oid->len=9;
        }
        else
        {
            oid->val[7]++;
            oid->val[8]=0;
            oid->len=9;
        }
    }
    
    if ((oid->len!=9)&&(oid->val[8]!=0))
    {
        *error=snmp_NO_SUCH_NAME;
        return ASN_NULL;
    }
    
    switch(oid->val[7])
    {
        case 1: // udpInDatagrams
            temp_int=lwip_stats.udp.recv;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 2: // udpNoPorts
            temp_int=0;//lwip_stats.udp.noport;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 3: // udpInErrors
            temp_int=lwip_stats.udp.err;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 4: // udpOutDatagrams
            temp_int=lwip_stats.udp.xmit;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        default:
            *error = snmp_NO_SUCH_NAME;
            return ASN_NULL;
    }  
}

int snmp_egp(void **data, int *data_len, _oid *oid, int request_type, int data_type, void *data_in, int data_in_len, int *error)
{
    *error = snmp_NO_ERROR;

    if (request_type==SET_REQUEST_PDU)
    {
        *error=snmp_READ_ONLY;
        return ASN_NULL;
    }
    else if (request_type==GET_NEXT_REQUEST_PDU)
    {
        // this function owns every item from
        // 1.3.6.1.2.1.1

        // handle incrementing the oid
        // 0 1 2 3 4 5 6 7 8
        // 1 2 3 4 5 6 7 8 9
        // 1.3.6.1.2.1.1
        // 1.3.6.1.2.1.1.1.0  description
        // 1.3.6.1.2.1.1.2.0
        if (oid->len<8)
        {
            oid->val[7]=1;
            oid->val[8]=0;
            oid->len=9;
        }
        else
        {
            oid->val[7]++;
            oid->val[8]=0;
            oid->len=9;
        }
    }

    if ((oid->len!=9)&&(oid->val[8]!=0))
    {
        *error=snmp_NO_SUCH_NAME;
        return ASN_NULL;
    }

    switch(oid->val[7])
    {
    /*
    	case 1:
            temp_int=0;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
    	case 2:
            temp_int=0;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
    	case 3:
            temp_int=0;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
    	case 4:
            temp_int=0;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
    	case 6:
            temp_int=0;
            *data=&temp_int;
            return ASN_INT;
            */
        default:
            *error = snmp_NO_SUCH_NAME;
            return ASN_NULL;
    }
}

int snmp_null(void **data, int *data_len, _oid *oid, int request_type, int data_type, void *data_in, int data_in_len, int *error)
{
    *error = snmp_NO_ERROR;

    if (request_type==SET_REQUEST_PDU)
    {
        *error=snmp_READ_ONLY;
        return ASN_NULL;
    }
    else if (request_type==GET_NEXT_REQUEST_PDU)
    {
        // this function owns every item from
        // 1.3.6.1.2.1.1

        // handle incrementing the oid
        // 0 1 2 3 4 5 6 7 8
        // 1 2 3 4 5 6 7 8 9
        // 1.3.6.1.2.1.1
        // 1.3.6.1.2.1.1.1.0  description
        // 1.3.6.1.2.1.1.2.0
        if (oid->len<8)
        {
            oid->val[7]=1;
            oid->val[8]=0;
            oid->len=9;
        }
        else
        {
            oid->val[7]++;
            oid->val[8]=0;
            oid->len=9;
        }
    }

    if ((oid->len!=9)&&(oid->val[8]!=0))
    {
        *error=snmp_NO_SUCH_NAME;
        return ASN_NULL;
    }

    switch(oid->val[7])
    {
        default:
            *error = snmp_NO_SUCH_NAME;
            return ASN_NULL;
    }
}

int snmp_transmission(void **data, int *data_len, _oid *oid, int request_type, int data_type, void *data_in, int data_in_len, int *error)
{
    *error = snmp_NO_ERROR;

    if (request_type==SET_REQUEST_PDU)
    {
        *error=snmp_READ_ONLY;
        return ASN_NULL;
    }
    else if (request_type==GET_NEXT_REQUEST_PDU)
    {
        // this function owns every item from
        // 1.3.6.1.2.1.1

        // handle incrementing the oid
        // 0 1 2 3 4 5 6 7 8
        // 1 2 3 4 5 6 7 8 9
        // 1.3.6.1.2.1.1
        // 1.3.6.1.2.1.1.1.0  description
        // 1.3.6.1.2.1.1.2.0
        if (oid->len<8)
        {
            oid->val[7]=1;
            oid->val[8]=0;
            oid->len=9;
        }
        else
        {
            oid->val[7]++;
            oid->val[8]=0;
            oid->len=9;
        }
    }

    if ((oid->len!=9)&&(oid->val[8]!=0))
    {
        *error=snmp_NO_SUCH_NAME;
        return ASN_NULL;
    }

    switch(oid->val[7])
    {
        default:
            *error = snmp_NO_SUCH_NAME;
            return ASN_NULL;
    }
}

int snmp_snmp(void **data, int *data_len, _oid *oid, int request_type, int data_type, void *data_in, int data_in_len, int *error)
{
    *error = snmp_NO_ERROR;

    if (request_type==SET_REQUEST_PDU)
    {
        switch(oid->val[7])
        {
            case 30: // Contact
                temp_int=0;
                *data=&temp_int;
                return ASN_INT;
            default:
                *error = snmp_NO_SUCH_NAME;
                return ASN_NULL;
        }
    }
    else if (request_type==GET_NEXT_REQUEST_PDU)
    {
        // this function owns every item from
        // 1.3.6.1.2.1.1

        // handle incrementing the oid
        // 0 1 2 3 4 5 6 7 8
        // 1 2 3 4 5 6 7 8 9
        // 1.3.6.1.2.1.1
        // 1.3.6.1.2.1.1.1.0  description
        // 1.3.6.1.2.1.1.2.0
        if (oid->len<8)
        {
            oid->val[7]=1;
            oid->val[8]=0;
            oid->len=9;
        }
        else
        {
            oid->val[7]++;
            if (oid->val[7]==7 || oid->val[7] == 23) //Skip these OIDs as they are unused
            {
            	oid->val[7]++;
            }
            oid->val[8]=0;
            oid->len=9;
        }
    }

    if ((oid->len!=9)&&(oid->val[8]!=0))
    {
        *error=snmp_NO_SUCH_NAME;
        return ASN_NULL;
    }

    switch(oid->val[7])
    {
        case 1: // In Pkts (current)
            temp_int=snmp_stats->in.packets;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 2: // Out Pkts (obsolete)
            temp_int=snmp_stats->out.packets;;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 3: // In Bad Versions
            temp_int=snmp_stats->badVersions;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 4: //In bad community names
            temp_int=snmp_stats->badCommunityNames;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 5: //In bad community uses
            temp_int=snmp_stats->badCommunityUses;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 6: //In ASN Parse errors
            temp_int=snmp_stats->asnParseErrs;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 7: //Not defined in RFC
            temp_int=0;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 8: //In Too bigs
            temp_int=snmp_stats->in.tooBigs;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 9: //In no such names
            temp_int=snmp_stats->in.noSuchNames;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 10: //In bad values
            temp_int=snmp_stats->in.badValues;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 11: //In Read Onlys
            temp_int=snmp_stats->in.readOnlys;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 12: //In Gen Errs
            temp_int=snmp_stats->in.generalErrors;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 13: //In total Req Vars
            temp_int=snmp_stats->totalReqVars;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 14: //In total Set vars
            temp_int=snmp_stats->totalSetVars;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 15: //InGetRequests
            temp_int=snmp_stats->in.getRequests;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 16: //In GetNexts
            temp_int=snmp_stats->in.getNexts;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 17: //In Set requests
            temp_int=snmp_stats->in.setRequests;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 18: //In Get Responses
            temp_int=snmp_stats->in.getResponses;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 19: //SNMP traps in
            temp_int=snmp_stats->in.traps;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 20: //Out too bigs
            temp_int=snmp_stats->out.tooBigs;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 21: //Out No Such Names
            temp_int=snmp_stats->out.noSuchNames;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 22: //Out bad values
            temp_int=snmp_stats->out.badValues;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 23: //Not defined
            temp_int=0;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 24: //Out General Errors
            temp_int=snmp_stats->out.generalErrors;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 25: //Out Get Requests
            temp_int=snmp_stats->out.getRequests;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 26: //Out Get Nexts
            temp_int=snmp_stats->out.getNexts;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 27: //Out Set Requests
            temp_int=snmp_stats->out.setRequests;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 28: //Out Get Responses
            temp_int=snmp_stats->out.getResponses;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 29: //Out SNMP traps
            temp_int=snmp_stats->out.traps;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 30: //SNMP Enabled Authen Traps
            temp_int=0;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 31: //SNMP silent drops
            temp_int=snmp_stats->silentDrops;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        case 32: //SNMP Proxy Drops
            temp_int=snmp_stats->proxyDrops;
            *data=&temp_int;
            return ASN_SNMP_COUNTER;
        default:
            *error = snmp_NO_SUCH_NAME;
            return ASN_NULL;
    }
}


snmp_request rfc_1066_handlers[]={snmp_system,snmp_interface,snmp_at,snmp_ip,snmp_icmp,snmp_tcp,snmp_udp,snmp_egp,snmp_null,snmp_transmission,snmp_snmp};

int rfc_1066_handler(void **data, int *data_len, _oid *oid, int request_type, int data_type, void *data_in, int data_in_len, int *error)
{
    int reply;
    //debug_printf("rfc_1066_handler called with :");
    //print_oid(oid);
    
    // 1 2 3 4 5 6 7   Length
    // 0 1 2 3 4 5 6   val[x]
    // 1.3.6.1.2.1     RFC 1066
    // 1.3.6.1.2.1.1   system
    // 1.3.6.1.2.1.2   interface
    // 1.3.6.1.2.1.3   at
    //  ...
    
    if (request_type==GET_NEXT_REQUEST_PDU) // find next
    {
        if (oid->len==6)  // start of this tree, add element for next branch
        {
            oid->val[6]=1; // set to first element in the tree
            oid->len=7;
        }
      
        while( (oid->val[6]-1) < (sizeof(rfc_1066_handlers)/sizeof(snmp_request)) )
        {
            // request this handler for it's get_next, it might not be in this branch
            reply=rfc_1066_handlers[oid->val[6]-1](data,data_len,oid,request_type,data_type,data_in,data_in_len,error);

            // if this current branch doesn't have it, go up one
            if (*error==snmp_NO_SUCH_NAME)
            {
                oid->val[6]++;
                oid->len=7;
            }
            else
            {
                return reply;
            }
        }
        
        *error=snmp_NO_SUCH_NAME;
        return ASN_NULL;
    }
    
    if (oid->val[6]>(sizeof(rfc_1066_handlers)/sizeof(snmp_request)))
    {
        *error=snmp_NO_SUCH_NAME;
        return ASN_NULL;
    }
    return rfc_1066_handlers[oid->val[6]-1](data,data_len,oid,request_type,data_type,data_in,data_in_len,error);
}

void rfc_1066_init(void)
{
    mib_register((void*)&rfc_1066_mib);
}

/***   End Of File   ***/
