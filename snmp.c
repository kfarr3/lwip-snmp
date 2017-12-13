// snmpv1.c

#include "lwip/opt.h"

// Standard Includes
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// File Includes
#include "system.h"
#include "lwip/udp.h"
#include "snmp.h"
#include "tools.h"
#include "Crypto/des3.h"
#include "Crypto/aes.h"
#include "Crypto/hmac.h"
#include "asn.1.h"
#include "mib.h"
#include "rfc_1066.h"
#include "epiram_layout.h"
#include "logger.h"
#include "config_params.h"
#include "webconf.h"


static _snmp_params *snmp_params;

//                       AUTH_NONE  AUTH_MD5  AUTH_SHA -- both 96 bits
unsigned int auth_len[]={0,         12,        12};
//                       PRIV_NONE  PRIV_DES   PRIV_AES -- both 64 bits
unsigned int priv_len[]={0,         8,         8};


//NOTE: v1 and v2c are so similar that they are handled the same except when it
//      comes to getbulk, so when you see v1 you should also assume v2c

static _snmp_data in_data;                             // used to construct and hold inbound snmp values
static _snmp_data out_data;                            // used to construct and hold outbound snmp values
static _cb_struct cb_struct;                           // used to contain callback for CLIENT SNMP requests
static _varbinding_data vb_data;                       // used to contain var-binding data for inbound processing
static unsigned char snmp_buffer[SNMP_MAX_LEN];        // used to hold complete snmp messages
static unsigned char snmp_varbindings[SNMP_MAX_LEN];   // used to hold complete constructed outbound varbinding messages
static _auth_priv_str ap;

// SNMP v3 Security defines
#define MSG_SEC_AUTH 0x01
#define MSG_SEC_PRIV 0x02
#define MSG_SEC_REP  0x04





// function prototypes

static void encrypt_pdu(int priv_type, unsigned char *priv_key, unsigned char *data, unsigned int data_len, unsigned char *salt, unsigned int engine_boots, unsigned int engine_time);
static void decrypt_pdu(int priv_type, unsigned char *priv_key, unsigned char *data, unsigned int data_len, unsigned char *salt, unsigned int engine_boots, unsigned int engine_time);
static void calculate_hmac(int auth_type, unsigned char *auth_key, unsigned char *data, unsigned int data_len, unsigned char *to);
static void password_to_key(char *password, unsigned char *key, unsigned int auth_type);
static void localize_key(unsigned int auth_type, unsigned char *key, unsigned char *lkey, unsigned char *engine_id, unsigned int engine_id_len);

static int snmp_process_v3(unsigned char *packet_in, unsigned int in_length, unsigned char *packet_out);
static int snmp_process_v1(unsigned char *packet_in, unsigned int in_length, unsigned char *packet_out);

static int build_snmp_v1(unsigned char *out_buf, _snmp_data *data);
static int build_snmp_v2c(unsigned char *out_buf, _snmp_data *data);
static int build_snmp_v3(unsigned char *out_buf, _snmp_data *data);

static int process_varbindings(unsigned char *in_varbindings, int in_varbindings_len, unsigned char *out_varbindings, int msg_version, int request_type, int non_repeaters, int max_repetitions, int *error_status, int *error_index);
static int snmp_v3_error_oid_handler(void **data, int *data_len, _oid *oid, int request_type, int data_type, void *data_in, int data_in_len, int *error);


// snmp trap
static int snmp_build_trap_v1(unsigned char *buffer, void *auth, _trap_varbinding *var_bindings, unsigned int num_bindings);
static int snmp_build_trap_v2c(unsigned char *buffer, void *auth, _trap_varbinding *var_bindings, unsigned int num_bindings);
static int snmp_build_trap_v3(unsigned char *buffer, void *auth, _trap_varbinding *var_bindings, unsigned int num_bindings);

// v3 error OID stuff
// ERROR OID values for snmp v3
#define RPT_ERR_NONE      0
#define RPT_ERR_SEC_LVL   1
#define RPT_ERR_TIME_WIN  2
#define RPT_ERR_SEC_NAME  3
#define RPT_ERR_ENG_ID    4
#define RPT_ERR_AUTH_FAIL 5
#define RPT_ERR_DEC_ERR   6
#define RPT_ERR_LAST_ONE  7

#define RPT_ERR_INDEX 9

static const unsigned int rpt_err_oid[]={1,3,6,1,6,3,15,1,1,0,0};
static unsigned int snmp_v3_oid_errors[RPT_ERR_LAST_ONE];
static _mib_handler snmp_v3_error_oid_mib={snmp_v3_error_oid_handler,9,{1,3,6,1,6,3,15,1,1}};


// function definitions

int snmp_process(unsigned char *packet_in, unsigned int length_in, unsigned char *packet_out)
{
	int bytes_used;
	unsigned int len;
	unsigned int version_number;
	unsigned char *p1;
	
	// The header consists of an ASN.1 sequence containing:
    // INTEGER: Version
    // OCTET STRING: Community
    // ANY: Data

	p1=packet_in;

    if ((bytes_used=asn_decode_sequence(p1, &len))==0)
    {
    	snmp_stats->asnParseErrs++;
    	return 0;
    }
    p1+=bytes_used;

    if (len!=length_in-bytes_used)
    {
        debug_printf("snmp: length not equal to packet length\n");
        snmp_stats->asnParseErrs++;
        return 0;
    }
    
    // the next 2 bytes should be a type2 with a length of 1 and a value of 0
    // to indicate a primitive integer of length 1 and value 0 for the SNMP
    // version.  Anything else is wrong
    if ((bytes_used=asn_decode_int(p1, ASN_INT, &version_number))==0)
    {
    	snmp_stats->asnParseErrs++;
    	return 0;
    }
    
    if ((version_number==0)||(version_number==1))
    {
    	return snmp_process_v1(packet_in, length_in, packet_out);
    }
    else if (version_number==3)
    {
    	if (snmp_params->use_v3)
    	{
    		return snmp_process_v3(packet_in, length_in, packet_out);
    	}
    	else
    	{
    		debug_printf("Received V3 SNMP, but V3 is disabled\r\n");
    		return 0;
    	}
    }
    else
    {
    	snmp_stats->badVersions++;
    	return 0;
    }
}

// called by lwip stack when a packet is received
// checks version and hands off to correct processing function, snmp_process_v1 or snmp_process_v3
static void snmp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
    unsigned int out_length;
    snmp_stats->in.packets++;
   
    if (p==NULL)
    {
        debug_printf("snmp_recv with no data\n");
        return;
    }
    if (!(app_params.snmp.enabled & SNMP_LAN_ENABLED))
    {
    	pbuf_free(p);
    	debug_printf("Received SNMP request, but SNMP is disabled\r\n");
    	return;
    }
    if (GetFirmwareUploadStatus() == 1)
    {
    	pbuf_free(p);
    	debug_printf("Unable to process SNMP request, firmware update in progress\n");
    	return;
    }

    // RFC1157 states that we do not have to accept messages who's length exceeds 484 bytes, so we won't,
    // or at least make it configurable, at the time of this writing SNMP_MAX_LEN was set to 484
    if (p->tot_len>SNMP_MAX_LEN)
    {
        pbuf_free(p);
        return;
    }
#if USE_NRGSHARK==1
    add_request(addr->addr, 3);
#endif
    // copy pbuf into an array for easier processing
    pbuf_to_array(snmp_buffer,p);
    pbuf_free(p);
    out_length = snmp_process(snmp_buffer, p->tot_len, snmp_buffer);
    
    p=pbuf_alloc(PBUF_RAW, out_length, PBUF_POOL);
    if (p!=NULL)
    {
        array_to_pbuf(p, snmp_buffer, out_length);
        snmp_stats->out.packets++;
        udp_sendto(pcb, p, addr, port);
        pbuf_free(p);
    }
    else
    {
    	debug_printf("snmp: error allocating pbuf\r\n");
    }
}

int snmp_send_trap(int version, ip_addr_t *ipaddr, u16_t port, void *auth, _trap_varbinding *var_bindings, unsigned int num_bindings)
{
	int ret=0;
	int length;
	struct pbuf *p;
	struct udp_pcb *pcb;
	
	     if (version==0)	length = snmp_build_trap_v1(snmp_buffer, auth, var_bindings, num_bindings);
	else if (version==1)	length = snmp_build_trap_v2c(snmp_buffer,auth, var_bindings, num_bindings);
	else if (version==3)    length = snmp_build_trap_v3(snmp_buffer, auth, var_bindings, num_bindings);
	else                    length = 0;	
	
	pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
	if (pcb==NULL)
	{
		debug_printf("snmp trap, failed to get udp pcb\n");
		return 0;
	}
	
	p=pbuf_alloc(PBUF_RAW, length, PBUF_POOL);
    if (p!=NULL)
    {
        array_to_pbuf(p, snmp_buffer, length);
        udp_sendto(pcb, p, ipaddr, port);
        ret=1;
        pbuf_free(p);
        vTaskDelay(1);
    }
    else
    {
    	debug_printf("snmp: error allocating pbuf\r\n");
    }
    
    udp_remove(pcb);
    return ret;
}

int snmp_build_trap(unsigned char *buffer, int version, void *auth, _trap_varbinding *var_bindings, unsigned int num_bindings)
{
		 if (version==0)	return snmp_build_trap_v1(buffer, auth, var_bindings, num_bindings);
	else if (version==1)	return snmp_build_trap_v2c(buffer,auth, var_bindings, num_bindings);
	else if (version==3)    return snmp_build_trap_v3(buffer, auth, var_bindings, num_bindings);
	else                    return 0;
}

// Process a v3 message
static int snmp_process_v3(unsigned char *packet_in, unsigned int in_length, unsigned char *packet_out)
{
    unsigned char *p1;
    int bytes_used;
    unsigned int len;
    unsigned int user_index;
    unsigned int report_error = RPT_ERR_NONE;
    
    p1=packet_in;
    
    if ((bytes_used=asn_decode_sequence(p1, &len))==0) return 0;
    p1+=bytes_used;
    
    if (len!=in_length-bytes_used)
    {
        debug_printf("snmp3: length not equal to packet length\n");
        return 0;
    }
    
    // the next 2 bytes should be a type2 with a length of 1 and a value of 0
    // to indicate a primitive integer of length 1 and value 0 for the SNMP
    // version.  Anything else is wrong
    if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v3.msg_version))==0) return 0;
    
    if (in_data.v3.msg_version!=3)
    {
        debug_printf("snmp3: bad version number: %d\n", in_data.v3.msg_version);
        snmp_stats->badVersions++;
        return 0;
    }
    p1+=bytes_used;
    
    // next we get the header sequence which contains the msg_id, msg_max_size, msg_flags and msg_security_model
    if ((bytes_used=asn_decode_sequence(p1, &len))==0) return 0;
    p1+=bytes_used;
    
    // get msg_id
    if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v3.msg_id))==0) return 0;
    p1+=bytes_used;
    
    // get msg_max_size
    if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v3.msg_max_size))==0) return 0;
    p1+=bytes_used;
    
    // get msg_flags
    if ((bytes_used=asn_decode_octet_string(p1, &len))==0) return 0;
    p1+=bytes_used;
    
    if (len!=1) return 0;
    in_data.v3.msg_flags=*p1++;
    
    // get msg_security_model
    if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v3.msg_security_model))==0) return 0;
    p1+=bytes_used;
    
    if (in_data.v3.msg_security_model!=0x03) return 0;   // User Security Model
    
    // So far so good, now check the security settings
    // Security settings are contained within an octet_string which contains sequence
    // remove the octet_string and sequence
    if ((bytes_used=asn_decode_octet_string(p1, &len))==0) return 0;
    p1+=bytes_used; // don't remove the octet_string data, we'll parse that below
    if ((bytes_used=asn_decode_sequence(p1, &len))==0) return 0;
    p1+=bytes_used; // don't remove the sequence, we'll parse that below
    
    // now parse the items in the sequence: msg_authoritative_engine_id
    //                                      msg_authoritative_engine_boots
    //                                      msg_authoritative_engine_time
    //                                      msg_user_name
    //                                      msg_authentication_parameters
    //                                      msg_authentication_privacy_parameters
    
    // get msgAuthoritativeEngineId
    if ((bytes_used=asn_decode_octet_string(p1, &in_data.v3.msg_authoritative_engine_id_len))==0) return 0;
    if (in_data.v3.msg_authoritative_engine_id_len>MAX_ENGINE_ID)
    {
        debug_printf("snmp: Engine_ID greater than allowed, MAX=%d, LEN=%d\n", MAX_ENGINE_ID, in_data.v3.msg_authoritative_engine_id_len);
        return 0;
    }
    memcpy(in_data.v3.msg_authoritative_engine_id, p1+bytes_used, in_data.v3.msg_authoritative_engine_id_len);
    p1+=bytes_used+in_data.v3.msg_authoritative_engine_id_len;
    
    // get msgAuthoritativeEngineBoots
    if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v3.msg_authoritative_engine_boots))==0) return 0;
    p1+=bytes_used;
    
    // get msgAuthoritativeEngineTime
    if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v3.msg_authoritative_engine_time))==0) return 0;
    p1+=bytes_used;

    // get msgUserName
    if ((bytes_used=asn_decode_octet_string(p1, &len))==0) return 0;
    p1+=bytes_used;
    
    if (len>=MAX_USERNAME_LEN)
    {
        debug_printf("snmpv3: username too long MAX=%d, len=%d\n", MAX_USERNAME_LEN, len);
        return 0;
    }
    
    memcpy(in_data.v3.msg_username, p1, len);
    in_data.v3.msg_username[len]='\0';
    p1+=len;
    
    if (len==0)
    {
        user_index=0;
    }
    else // check for a valid user
    {
        for(user_index=0; user_index<MAX_SNMPV3_USERS; user_index++)
        {
            if (memcmp(snmp_params->users[user_index].username, in_data.v3.msg_username, len)==0) break;
        }
        if (user_index>=MAX_SNMPV3_USERS)
        {
            user_index=0;
        }
    }

    // now that we have a user check that the msg_flags are set properly for that user
    if (((snmp_params->users[user_index].auth_type!=AUTH_NONE)&&((in_data.v3.msg_flags&MSG_SEC_AUTH)==0))||
        ((snmp_params->users[user_index].auth_type==AUTH_NONE)&&((in_data.v3.msg_flags&MSG_SEC_AUTH)!=0))) report_error=RPT_ERR_AUTH_FAIL;
    if (((snmp_params->users[user_index].priv_type!=PRIV_NONE)&&((in_data.v3.msg_flags&MSG_SEC_PRIV)==0))||
        ((snmp_params->users[user_index].priv_type==PRIV_NONE)&&((in_data.v3.msg_flags&MSG_SEC_PRIV)!=0))) report_error=RPT_ERR_AUTH_FAIL;
    
    // get msgAuthenticationParameters
    if ((bytes_used=asn_decode_octet_string(p1, &len))==0) return 0;
    p1+=bytes_used;
    memcpy(in_data.v3.msg_authentication_parameters, p1, len>MAX_MSG_AUTH_PARAM?MAX_MSG_AUTH_PARAM:len);
    p1+=len;
    
    // get msgPrivacyParameters
    if ((bytes_used=asn_decode_octet_string(p1, &len))==0) return 0;
    p1+=bytes_used;
    memcpy(in_data.v3.msg_privacy_parameters, p1, len>MAX_MSG_PRIV_PARAM?MAX_MSG_PRIV_PARAM:len);
    p1+=len;    
    
    // The header is processed, now process the PDU data which is a sequence of : contextEngineID
    //                                                                          : contextName
    //                                                                          : PDU REQUEST
    
    // if the packet is encrypted we'll have an octet string next that contains the encrypted PDU
    if (in_data.v3.msg_flags&MSG_SEC_PRIV) // encrypted
    {
        if ((bytes_used=asn_decode_octet_string(p1, &len))==0) return 0;
        p1+=bytes_used;
        // decrypt it
        localize_key(snmp_params->users[user_index].auth_type, snmp_params->users[user_index].priv_key, in_data.v3.lkey, in_data.v3.msg_authoritative_engine_id, in_data.v3.msg_authoritative_engine_id_len);
        decrypt_pdu(snmp_params->users[user_index].priv_type, in_data.v3.lkey, p1, len, in_data.v3.msg_privacy_parameters, in_data.v3.msg_authoritative_engine_boots, in_data.v3.msg_authoritative_engine_time);
    }
    
    // get sequence
    if ((bytes_used=asn_decode_sequence(p1, &len))==0) return 0;
    p1+=bytes_used;
    
    // get contextEngineID and discard
    if ((bytes_used=asn_decode_octet_string(p1, &len))==0) return 0;
    p1+=bytes_used+len;
    
    // get contextName and discard
    if ((bytes_used=asn_decode_octet_string(p1, &len))==0) return 0;
    p1+=bytes_used+len;
    
    // get PDU packet type request type
    if ((bytes_used=asn_decode_request_type(p1,&in_data.v3.request_type,&len))==0) return 0;
    p1+=bytes_used;
    
    // get request id
    if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v3.request_id))==0) return 0;
    p1+=bytes_used;

    if (in_data.v3.request_type==GET_BULK_PDU) // get other vals
    {
        // get non-repeaters
        if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v3.non_repeaters))==0) return 0;
        p1+=bytes_used;
        
        // get max-repetitions
        if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v3.max_repetitions))==0) return 0;
        p1+=bytes_used;
        
        in_data.v3.error_index=0;
        in_data.v3.error_status=0;
    }
    else // error number and index not in version 2c getBulkPDU
    {
        // get error number
        if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v3.error_status))==0) return 0;
        p1+=bytes_used;
                
        // get error index
        if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v3.error_index))==0) return 0;
        p1+=bytes_used;
        
        in_data.v3.non_repeaters=0;
        in_data.v3.max_repetitions=0;
    }
     
    // based on the type of packet we check for errors
    if ((in_data.v3.request_type!=REPORT_PDU)&&(in_data.v3.request_type!=GET_RESPONSE_PDU))
    {
        // if the packet isn't a reply packet we check to make sure
        // the parameters match ours
      
        // the order we check errors is important, the least significant errors are
        // checked first in order to avoid overwriting a more important error
      
        // check time-window
        if ((abs((uptime_ms)-in_data.v3.msg_authoritative_engine_time)>=150)||
            ((in_data.v3.msg_authoritative_engine_boots!=snmp_params->boots)))
        {
            report_error=RPT_ERR_TIME_WIN; // bogus engine boots, send a report packet back
        }
      
        // check user
        if (user_index==0) report_error=RPT_ERR_AUTH_FAIL;
        
        // check engine_id LAST, we do this so we send a report packet back
        if ((in_data.v3.msg_authoritative_engine_id_len!=snmp_params->engine_id_len)||(memcmp(in_data.v3.msg_authoritative_engine_id, snmp_params->engine_id, snmp_params->engine_id_len)!=0))
        {
            report_error=RPT_ERR_ENG_ID; // bogus engine_id, send a report packet back
        }
        
        // Verify user has proper permissions
        if (report_error==RPT_ERR_NONE)
        {
        	switch(in_data.v3.request_type)
		    {
		    	case GET_RESPONSE_PDU:
		    		snmp_stats->in.getResponses++;
		    	case GET_REQUEST_PDU:
		    		snmp_stats->in.getRequests++;
		    	case GET_NEXT_REQUEST_PDU:
		    		snmp_stats->in.getNexts++;
		    		if (snmp_params->users[user_index].user_level==USER_LEVEL_NONE)
		    		{
		    			debug_printf("snmp: V3 GET Request for user with User Level None\r\n");
		    			report_error=RPT_ERR_AUTH_FAIL;
		    		}
		    		break;
		    		
		    	case SET_REQUEST_PDU:
		    		snmp_stats->in.setRequests++;
		    		if (snmp_params->users[user_index].user_level!=USER_LEVEL_READ_WRITE)
		    		{
		    			debug_printf("snmp: V3 SET Request for user without Read/Write access\r\n");
		    			report_error=RPT_ERR_AUTH_FAIL;
		    		}
		    		break;
		    }
        }
        
        // a request should never have an error
        if (in_data.v3.error_status!=0) return 0;
        if (in_data.v3.error_index!=0) return 0;
    }
    else
    {
        // do nothing since this is a reply packet and only the caller can verify this data
        report_error=RPT_ERR_NONE; // set to no report_error
    }
        
   	
        
    // keep track of errors
    out_data.v3.error_status=snmp_NO_ERROR;
    out_data.v3.error_index=0;
    
    // at this point we need to check for errors and determine if we should continue processing
    if (report_error!=RPT_ERR_NONE)
    {
        // send a report PDU
        out_data.v3.msg_version=3;
        out_data.v3.msg_id=in_data.v3.msg_id;
        out_data.v3.msg_max_size=SNMP_MAX_LEN;
        out_data.v3.msg_flags=0;
        out_data.v3.msg_security_model=3;
        memcpy(out_data.v3.msg_authoritative_engine_id, snmp_params->engine_id, snmp_params->engine_id_len);
        out_data.v3.msg_authoritative_engine_id_len=snmp_params->engine_id_len;
        out_data.v3.msg_authoritative_engine_boots=snmp_params->boots;
        out_data.v3.msg_authoritative_engine_time=uptime_ms;
        out_data.v3.msg_username[0]='\0';
        out_data.v3.request_type=REPORT_PDU;
        out_data.v3.request_id=in_data.v3.request_id;
        out_data.v3.error_status=0;
        out_data.v3.error_index=0;
        out_data.v3.user=&snmp_params->users[0];
        // no repeaters
        
        // oid to the error OID and then build the reply
        memcpy(vb_data.oid.val, rpt_err_oid, sizeof(rpt_err_oid));
        vb_data.oid.len=sizeof(rpt_err_oid)/sizeof(unsigned int);
        vb_data.oid.val[RPT_ERR_INDEX]=report_error;
        
        // add the report var-binding
        out_data.v3.var_bindings=snmp_varbindings;
        if ((out_data.v3.var_bindings_len=mib_process_oid(out_data.v3.var_bindings, &vb_data.oid, REPORT_PDU, 0, 0, 0, (int*)&out_data.v3.error_status))==0) return 0;
        
        return build_snmp_v3(packet_out, &out_data);
	}
    else if (in_data.v3.request_type==REPORT_PDU)
    {
        // set report values and make request
        if (cb_struct.wait_report)
        {
            // send a request PDU now that we have the report
            out_data.v3.msg_version=3;
            out_data.v3.msg_id=in_data.v3.msg_id;
            out_data.v3.msg_max_size=SNMP_MAX_LEN;
            out_data.v3.msg_flags=4; // reportable
            if (snmp_params->users[cb_struct.user_index].auth_type!=AUTH_NONE)  out_data.v3.msg_flags|=0x01;
            if (snmp_params->users[cb_struct.user_index].priv_type!=PRIV_NONE)  out_data.v3.msg_flags|=0x02;
            out_data.v3.msg_security_model=3;
            memcpy(out_data.v3.msg_authoritative_engine_id, in_data.v3.msg_authoritative_engine_id, in_data.v3.msg_authoritative_engine_id_len);
            out_data.v3.msg_authoritative_engine_id_len=in_data.v3.msg_authoritative_engine_id_len;
            out_data.v3.msg_authoritative_engine_boots=in_data.v3.msg_authoritative_engine_boots;
            out_data.v3.msg_authoritative_engine_time=in_data.v3.msg_authoritative_engine_time;
            strcpy((char*)out_data.v3.msg_username, (const char*)snmp_params->users[cb_struct.user_index].username);
            out_data.v3.request_type=GET_REQUEST_PDU;
            out_data.v3.request_id=in_data.v3.request_id;
            out_data.v3.error_status=0;
            out_data.v3.error_index=0;
            out_data.v3.user=&snmp_params->users[cb_struct.user_index];
            out_data.v3.var_bindings=snmp_varbindings;
            out_data.v3.non_repeaters=0;
            out_data.v3.max_repetitions=0;
          
            // add NULL varbinding for request OID
            out_data.v3.var_bindings_len=mib_add_var_binding(snmp_varbindings, 0, &cb_struct.oid, 0, ASN_NULL);            
            
            cb_struct.wait_report=0;
            cb_struct.wait_reply=1;
            
            return build_snmp_v3(packet_out, &out_data);
        }
    }
    else
    {
        out_data.v3.var_bindings_len=process_varbindings(p1, in_length-(p1-packet_in), snmp_varbindings, in_data.v3.msg_version, in_data.v3.request_type, in_data.v3.non_repeaters, in_data.v3.max_repetitions, (int*)&out_data.v3.error_status, (int*)&out_data.v3.error_index);
        
        if (out_data.v3.var_bindings_len>0) // build reply packet
        {
            // send a report PDU
            out_data.v3.msg_version=3;
            out_data.v3.msg_id=in_data.v3.msg_id;
            out_data.v3.msg_max_size=SNMP_MAX_LEN;
            out_data.v3.msg_flags=0;
            if (snmp_params->users[user_index].auth_type!=AUTH_NONE) out_data.v3.msg_flags|=0x01;
            if (snmp_params->users[user_index].priv_type!=PRIV_NONE) out_data.v3.msg_flags|=0x02;
            out_data.v3.msg_security_model=3;
            memcpy(out_data.v3.msg_authoritative_engine_id, snmp_params->engine_id, snmp_params->engine_id_len);
            out_data.v3.msg_authoritative_engine_id_len=snmp_params->engine_id_len;
            out_data.v3.msg_authoritative_engine_boots=in_data.v3.msg_authoritative_engine_boots;
            out_data.v3.msg_authoritative_engine_time=in_data.v3.msg_authoritative_engine_time;
            strcpy((char*)out_data.v3.msg_username, (const char*)snmp_params->users[user_index].username);
            out_data.v3.request_type=GET_RESPONSE_PDU;
            out_data.v3.request_id=in_data.v3.request_id;
            out_data.v3.error_status=0;
            out_data.v3.error_index=0;
            out_data.v3.user=&snmp_params->users[user_index];
            out_data.v3.var_bindings=snmp_varbindings;
            out_data.v3.non_repeaters=in_data.v3.non_repeaters;
            out_data.v3.max_repetitions=in_data.v3.max_repetitions;
          
            return build_snmp_v3(packet_out, &out_data);
        }
    }
      
    return 0;
}

// build a v3 message
static int build_snmp_v3(unsigned char *out_buf, _snmp_data *data)
{
    unsigned char *p1;
    unsigned char *pdu_ptr;
    unsigned char *auth_param_ptr;
    unsigned char *priv_param_ptr;
    int bytes_used;
    
    // At this point we have the var-bindings and we need to construct a reply packet  
    // we need to calculate how large the entire sequence is
    // VERSION
    // HEADER
    // SEC PARAMS
    // PDU
    int version_len;
    version_len = asn_bytes_to_encode(&data->v3.msg_version, ASN_INT, 0);
    
    int header_len;
    header_len =asn_bytes_to_encode(&data->v3.msg_id, ASN_INT, 0);                 // msgID
    header_len+=asn_bytes_to_encode(&data->v3.msg_max_size, ASN_INT, 0);           // msgMaxSize
    header_len+=asn_bytes_to_encode(&data->v3.msg_flags, ASN_OCTET_STRING, 1);     // msg_flags
    header_len+=asn_bytes_to_encode(&data->v3.msg_security_model, ASN_INT, 0);     // msg_security_model
    
    int security_param_len;
    security_param_len =asn_bytes_to_encode(data->v3.msg_authoritative_engine_id, ASN_OCTET_STRING, data->v3.msg_authoritative_engine_id_len);
    security_param_len+=asn_bytes_to_encode(&data->v3.msg_authoritative_engine_boots, ASN_INT, 0);
    security_param_len+=asn_bytes_to_encode(&data->v3.msg_authoritative_engine_time, ASN_INT, 0);    
    security_param_len+=asn_bytes_to_encode(0, ASN_OCTET_STRING, strlen((const char*)data->v3.user->username));    
    security_param_len+=asn_bytes_to_encode(0, ASN_OCTET_STRING, auth_len[data->v3.user->auth_type]);
    security_param_len+=asn_bytes_to_encode(0, ASN_OCTET_STRING, priv_len[data->v3.user->priv_type]);
    
        
    int pdu_len;
    pdu_len = asn_bytes_to_encode(&data->v3.request_id, ASN_INT, 0);
    pdu_len+= asn_bytes_to_encode(&data->v3.error_status, ASN_INT, 0);
    pdu_len+= asn_bytes_to_encode(&data->v3.error_index, ASN_INT, 0);
    pdu_len+= asn_bytes_to_encode(0, ASN_SEQUENCE, data->v3.var_bindings_len);

    int pdu_seq_len;
    pdu_seq_len = asn_bytes_to_encode(data->v3.msg_authoritative_engine_id, ASN_OCTET_STRING, data->v3.msg_authoritative_engine_id_len);
    pdu_seq_len+= asn_bytes_to_encode(0, ASN_OCTET_STRING, 0);
    pdu_seq_len+= asn_bytes_to_encode(0, data->v3.request_type, pdu_len);
    
    int pdu_encryption_len=0;
    int pad_bytes=0;
    // check to see if we're encrypting, we'll have an octet_string containing the encrypted data 
    // and the PDU packet needs to be padded to a multiple of 8 bytes
    if (data->v3.msg_flags&MSG_SEC_PRIV) // doing encryption
    {
        pdu_encryption_len=asn_bytes_to_encode(0, ASN_SEQUENCE, pdu_seq_len);
        if ((data->v3.user->priv_type==PRIV_DES)&&(pdu_encryption_len%8))
        {
            pad_bytes=(8-(pdu_encryption_len%8));
            pdu_encryption_len+=pad_bytes;
        }
    }
    
    // we know how big everything is, now we start constructing the packet
    // the Sequence is first, that contains everything
    p1=out_buf;
    p1+=asn_encode_sequence(p1, version_len+
                                asn_bytes_to_encode(0, ASN_SEQUENCE, header_len) +
                                asn_bytes_to_encode(0, ASN_OCTET_STRING, asn_bytes_to_encode(0, ASN_SEQUENCE, security_param_len)) +
                                ((data->v3.msg_flags&MSG_SEC_PRIV)?asn_bytes_to_encode(0, ASN_OCTET_STRING, pdu_encryption_len) : asn_bytes_to_encode(0, ASN_SEQUENCE,  pdu_seq_len))
                                );
    
    // add the version
    p1+=asn_encode_int(p1, ASN_INT, data->v3.msg_version);
    
    // add the header
    p1+=asn_encode_sequence(p1, header_len);
    p1+=asn_encode_int(p1, ASN_INT, data->v3.msg_id);
    p1+=asn_encode_int(p1, ASN_INT, data->v3.msg_max_size);
    p1+=asn_encode_octet_string(p1, (unsigned char*)&data->v3.msg_flags, 1);
    p1+=asn_encode_int(p1, ASN_INT, data->v3.msg_security_model); // USM
    
    // add the security parameters, this is tricky since the parameters are stored in an octet_string instead of a sequence
    // the first part is the octet_string token and length, then a sequence, this is a semi-hack job to do but it works
    // the first step is just to get the token and length then we'll manually copy the data in
    asn_encode_octet_string(p1, 0, asn_bytes_to_encode(0, ASN_SEQUENCE, security_param_len));
    bytes_used=1+asn_bytes_length(asn_bytes_to_encode(0, ASN_SEQUENCE, security_param_len));
    p1+=bytes_used;
    
    // now the octet_string token and length are encoded and we add the sequence
    p1+=asn_encode_sequence(p1, security_param_len);
    p1+=asn_encode_octet_string(p1, data->v3.msg_authoritative_engine_id, data->v3.msg_authoritative_engine_id_len);
    p1+=asn_encode_int(p1, ASN_INT, data->v3.msg_authoritative_engine_boots);
    p1+=asn_encode_int(p1, ASN_INT, data->v3.msg_authoritative_engine_time);
    p1+=asn_encode_octet_string(p1, (unsigned char*)data->v3.user->username, strlen(data->v3.user->username));
    
    // clear the auth_param and priv_parm structures, set them and then set the pointers, we'll fill this data in
    // later after it's calculated, it's fixed size so we can do this
    memset(data->v3.msg_authentication_parameters, 0, MAX_MSG_AUTH_PARAM);
    memset(data->v3.msg_privacy_parameters, 0, MAX_MSG_PRIV_PARAM);
    p1+=asn_encode_octet_string(p1, data->v3.msg_authentication_parameters, auth_len[data->v3.user->auth_type]);
    auth_param_ptr=p1-auth_len[data->v3.user->auth_type];
    p1+=asn_encode_octet_string(p1, data->v3.msg_privacy_parameters, priv_len[data->v3.user->priv_type]);
    priv_param_ptr=p1-priv_len[data->v3.user->priv_type];
    
    // if we're encrypting the packet we need to add an OCTET_STRING, pad the data and we'll encrypt at the end
    if (data->v3.msg_flags&MSG_SEC_PRIV) // encryption
    {
        // we fake it here since the encrypted data is stored as an octet_string and the asn_encode_octet_string tries to actually encode it
        asn_encode_octet_string(p1, 0, pdu_encryption_len);
        p1+=(1+asn_bytes_length(pdu_encryption_len));
    }
    
    pdu_ptr=p1;
    
    // add the PDU sequence stuffs
    p1+=asn_encode_sequence(p1, pdu_seq_len);
    p1+=asn_encode_octet_string(p1, data->v3.msg_authoritative_engine_id, data->v3.msg_authoritative_engine_id_len);
    p1+=asn_encode_octet_string(p1, 0, 0); // context name, which is not supported/used in this implementation
    
    // now the pdu
    p1+=asn_encode_pdu(p1, data->v3.request_type, pdu_len); // this just adds the token and length
    p1+=asn_encode_int(p1, ASN_INT, data->v3.request_id);
    p1+=asn_encode_int(p1, ASN_INT, data->v3.error_status);
    p1+=asn_encode_int(p1, ASN_INT, data->v3.error_status!=snmp_NO_ERROR?data->v3.error_index:0);
    p1+=asn_encode_sequence(p1, data->v3.var_bindings_len);
    memcpy(p1, data->v3.var_bindings, data->v3.var_bindings_len);
    p1+=data->v3.var_bindings_len;
    
    // now we encrypt and/or calculate HMAC
    if (data->v3.user->priv_type!=PRIV_NONE)
    {
        localize_key(data->v3.user->auth_type, data->v3.user->priv_key, data->v3.lkey, data->v3.msg_authoritative_engine_id, data->v3.msg_authoritative_engine_id_len);
        encrypt_pdu(data->v3.user->priv_type, data->v3.lkey, pdu_ptr, pdu_encryption_len, priv_param_ptr, data->v3.msg_authoritative_engine_boots, data->v3.msg_authoritative_engine_time);
        p1+=pad_bytes;
    }

    if (data->v3.user->auth_type!=AUTH_NONE)
    {
        localize_key(data->v3.user->auth_type, data->v3.user->auth_key, data->v3.lkey, data->v3.msg_authoritative_engine_id, data->v3.msg_authoritative_engine_id_len);
        calculate_hmac(data->v3.user->auth_type, data->v3.lkey, out_buf, p1-out_buf, auth_param_ptr);
    }
    
    return p1-out_buf;
}


// process a v1/v2c message
static int snmp_process_v1(unsigned char *packet_in, unsigned int in_length, unsigned char *packet_out)
{
    unsigned char *p1;
    unsigned int len;
    int bytes_used;
    
    // The header consists of an ASN.1 sequence containing:
    // INTEGER: Version
    // OCTET STRING: Community
    // ANY: Data
    
    p1=packet_in;

    if ((bytes_used=asn_decode_sequence(p1, &len))==0) return 0;
    p1+=bytes_used;

    if (len!=in_length-bytes_used)
    {
        debug_printf("snmp: length not equal to packet length\n");
        snmp_stats->asnParseErrs++;
        return 0;
    }
    
    // the next 2 bytes should be a type2 with a length of 1 and a value of 0
    // to indicate a primitive integer of length 1 and value 0 for the SNMP
    // version.  Anything else is wrong
    if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v1.msg_version))==0)
    {
    	snmp_stats->asnParseErrs++;
    	return 0;
    }
    
    if ((in_data.v1.msg_version!=0) && (in_data.v1.msg_version!=1))
    {
        debug_printf("snmp: bad version number: %d\n", in_data.v1.msg_version);
        snmp_stats->badVersions++;
        return 0;
    }
    p1+=bytes_used;
    
    // the next value should be a type 0x04 for the OCTET STRING
    // followed by our community name
    if ((bytes_used=asn_decode_octet_string(p1, &len))==0)
    {
    	snmp_stats->asnParseErrs++;
    	return 0;
    }
    p1+=bytes_used;

    // set community name
    memcpy(in_data.v1.community, p1, len>MAX_COMMUNITY_NAME?MAX_COMMUNITY_NAME:len);
    in_data.v1.community[len>=MAX_COMMUNITY_NAME?MAX_COMMUNITY_NAME-1:len]='\0';
    p1+=len; // take up slack from community name
    
    // get PDU packet type
    if ((bytes_used=asn_decode_request_type(p1,&in_data.v1.request_type,&len))==0)
    {
    	snmp_stats->asnParseErrs++;
    	return 0;
    }
    p1+=bytes_used;
    
    if ((in_data.v1.request_type!=GET_RESPONSE_PDU)&&(in_data.v1.request_type!=GET_REQUEST_PDU)&&(in_data.v1.request_type!=SET_REQUEST_PDU)&&(in_data.v1.request_type!=GET_NEXT_REQUEST_PDU))
    {
        if ((in_data.v1.msg_version==1)&&(in_data.v1.request_type!=GET_BULK_PDU))
        {
            debug_printf("snmp: Unsupported or unknown RequestPDU %x\n", in_data.v1.request_type);
            return 0;
        }
    }
    
    // Verify Community
    switch(in_data.v1.request_type)
    {
    	case GET_RESPONSE_PDU:
    		snmp_stats->in.getResponses++;
    	case GET_REQUEST_PDU:
    		snmp_stats->in.getRequests++;
    	case GET_NEXT_REQUEST_PDU:
    		snmp_stats->in.getNexts++;
    		if (strcmp((char*)in_data.v1.community, (char*)snmp_params->read_community)!=0)
    		{
    			debug_printf("snmp: Invalid Read Community: Got '%s' need '%s'\r\n", in_data.v1.community, snmp_params->read_community);
    			snmp_stats->badCommunityNames++;
    			return 0;
    		}
    		break;
    		
    	case SET_REQUEST_PDU:
    		snmp_stats->in.setRequests++;
    		if (strcmp((char*)in_data.v1.community, (char*)snmp_params->write_community)!=0)
    		{
    			debug_printf("snmp: Invalid Write Community: Got '%s' need '%s'\r\n", in_data.v1.community, snmp_params->write_community);
    			return 0;
    		}
    		break;
    		
    	default:
    		debug_printf("snmp: Unchecked request type %d\r\n", in_data.v1.request_type);
    		break;
    	
    }
    	
    
    
    // check the PDU length against the bytes left in the packet
    if ((in_length-(p1-packet_in))!=len)
    {
        debug_printf("snmp: invalid byte count, bytes_left=%d, pdu_bytes=%d\n", (in_length-(p1-packet_in)), len);
        snmp_stats->asnParseErrs++;
        return 0;
    }
    
    // get request id
    if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v1.request_id))==0)
    {
    	snmp_stats->asnParseErrs++;
    	return 0;
    }
    p1+=bytes_used;

    if ((in_data.v1.msg_version==1)&&(in_data.v1.request_type==GET_BULK_PDU)) // get other vals
    {
        // get non-repeaters
        if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v1.non_repeaters))==0)
        {
        	snmp_stats->asnParseErrs++;
        	return 0;
        }
        p1+=bytes_used;
        
        // get max-repetitions
        if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v1.max_repetitions))==0)
        {
        	snmp_stats->asnParseErrs++;
        	return 0;
        }
        p1+=bytes_used;
    }
    else // error number and index not in version 2c getBulkPDU
    {
        // get error number
        if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v1.error_status))==0)
        {
        	snmp_stats->asnParseErrs++;
        	return 0;
        }
        p1+=bytes_used;
                
        // get error index
        if ((bytes_used=asn_decode_int(p1, ASN_INT, &in_data.v1.error_index))==0)
        {
        	snmp_stats->asnParseErrs++;
        	return 0;
        }
        p1+=bytes_used;
    }
            
    out_data.v1.var_bindings=snmp_varbindings;
    out_data.v1.var_bindings_len=process_varbindings(p1, in_length-(p1-packet_in), out_data.v1.var_bindings, in_data.v1.msg_version, in_data.v1.request_type, in_data.v1.non_repeaters, in_data.v1.max_repetitions, (int*)&out_data.v1.error_status, (int*)&out_data.v1.error_index);
    // we've process all the varbindings, now to build the reply packet and send it
    if (out_data.v1.var_bindings_len>0)
    {
        // build reply packet
        out_data.v1.msg_version=in_data.v1.msg_version;
        strcpy((char*)out_data.v1.community, (const char*)in_data.v1.community);
        out_data.v1.request_type=GET_RESPONSE_PDU;
        out_data.v1.request_id=in_data.v1.request_id;
        out_data.v1.non_repeaters=0;
        out_data.v1.max_repetitions=0;
      
        return build_snmp_v2c(packet_out, &out_data);
    }
    
    return 0;
}

// build a v1/v2c message
int build_snmp_v2c(unsigned char *out_buf, _snmp_data *data)
{
    unsigned char *p1;
    unsigned int bytes_used;

    p1=out_buf;

    *p1++=ASN_SEQUENCE;
    // packet length consists of
    // 3 byte for version
    // 1 + asn_bytes_length(strlen(community_name)) + strlen(community_name)
    // 1 + asn_bytes_length(6+3+3+1+asn_bytes_length(var_binding_bytes_used)+var_binding_bytes_used)
    // 6 for REQUEST_ID
    // 3 for ERROR_STATUS
    // 3 for ERROR_INDEX
    // 1 + asn_bytes_length(var_binding_bytes_used) + var_binding_bytes_used
    bytes_used=asn_encode_length(p1, 3 + 1 + asn_bytes_length(strlen((const char*)data->v1.community)) + strlen((const char*)data->v1.community) +
                                         1 + asn_bytes_length(asn_bytes_to_encode(&data->v1.request_id, ASN_INT, 0)+3+3+1+asn_bytes_length(data->v1.var_bindings_len)+data->v1.var_bindings_len) +
                                         asn_bytes_to_encode(&data->v1.request_id, ASN_INT, 0) + 3 + 3 +
                                         1 + asn_bytes_length(data->v1.var_bindings_len) + data->v1.var_bindings_len);
    if (bytes_used==0) return 0;
    p1+=bytes_used;

    // Add version
    p1+=asn_encode_int(p1,ASN_INT, data->v1.msg_version);

    // add community
    *p1++=ASN_OCTET_STRING;
    if ((bytes_used=asn_encode_length(p1, strlen((const char*)data->v1.community)))==0) return 0;
    p1+=bytes_used;
    memcpy(p1, data->v1.community, strlen((const char*)data->v1.community));
    p1+=strlen((const char*)data->v1.community);

    // add packet_type
    *p1++=data->v1.request_type;
    if ((bytes_used=asn_encode_length(p1, asn_bytes_to_encode(&data->v1.request_id, ASN_INT, 0)+3+3+1+asn_bytes_length(data->v1.var_bindings_len)+data->v1.var_bindings_len))==0) return 0;
    p1+=bytes_used;

    // Add request ID
    p1+=asn_encode_int(p1, ASN_INT, data->v1.request_id);

    // Add ERROR STATUS
    p1+=asn_encode_int(p1, ASN_INT, data->v1.error_status);

    // Add ERROR INDEX
    p1+=asn_encode_int(p1, ASN_INT, data->v1.error_status!=snmp_NO_ERROR?data->v1.error_index:0);

    // Add VAR_BINDING SEQUENCE
    *p1++=ASN_SEQUENCE;
    if ((bytes_used=asn_encode_length(p1, data->v1.var_bindings_len))==0) return 0;
    p1+=bytes_used;
    memcpy(p1, data->v1.var_bindings, data->v1.var_bindings_len);
    p1+=data->v1.var_bindings_len;

    return p1-out_buf;
}

// build a v1
int build_snmp_v1(unsigned char *out_buf, _snmp_data *data)
{
    unsigned char *p1;
    unsigned int bytes_used;
  
    p1=out_buf;
    data->v1.generic_trap = TRAP_ENTERPRISE_SPEC;
    data->v1.specific_trap = 0;
    data->v1.enterprise.val[0] = 1;
    data->v1.enterprise.val[1] = 3;
    data->v1.enterprise.val[2] = 4;
    data->v1.enterprise.val[3] = 6;
    data->v1.enterprise.val[4] = 1234;
    data->v1.enterprise.len = 5;
    
    //*p1++=ASN_SEQUENCE;
    //*p1++=0x23;

    // packet length consists of
    // 1 + asn_bytes_length(strlen(community_name)) + strlen(community_name)
    // 1 + asn_bytes_length(6+3+3+1+asn_bytes_length(var_binding_bytes_used)+var_binding_bytes_used)
    // 1 + asn_bytes_length(&data->v1.specific_trap, ASN_INT, 0)
    // 1 + asn_bytes_length(&uptime_sec, ASN_INT, 0)
    // 1 + asn_bytes_length(&data->v1.enterprise)
    // 6 for agent-addr (IP)
    // 1 for request type (0xa4)
    // 1 for data length
    // 1 for end of sequence indicator
    // 1 for ending value of 0x00
    unsigned char length = asn_bytes_to_encode(&data->v1.community, ASN_OCTET_STRING, 0) + strlen((const char*)data->v1.community);
    length += 6 + 3 + 1 + 1 + 1 + asn_bytes_to_encode(&data->v1.specific_trap, ASN_INT, 0) + asn_bytes_to_encode(&uptime_sec, ASN_INT, 0);
    length += asn_bytes_to_encode(&data->v1.generic_trap, ASN_INT, 0);
    length += asn_bytes_to_encode_oid(&data->v1.enterprise) + data->v1.var_bindings_len + asn_bytes_length(data->v1.var_bindings_len);

    debug_printf("Var length: %d\n", length);

    *p1++=ASN_SEQUENCE;
    *p1++=length;
    
    // Add version
    p1+=asn_encode_int(p1,ASN_INT, data->v1.msg_version);
    
    // add community
    *p1++=ASN_OCTET_STRING;
    if ((bytes_used=asn_encode_length(p1, strlen((const char*)data->v1.community)))==0) return 0;
    p1+=bytes_used;
    memcpy(p1, data->v1.community, strlen((const char*)data->v1.community));
    p1+=strlen((const char*)data->v1.community);
    
    // add packet_type
    *p1++=data->v1.request_type;

    unsigned int data_length = 6 + 1 + asn_bytes_to_encode(&data->v1.specific_trap, ASN_INT, 0);
    data_length += asn_bytes_to_encode(&data->v1.generic_trap, ASN_INT, 0) + asn_bytes_to_encode(&uptime_sec, ASN_INT, 0);
    data_length += asn_bytes_to_encode_oid(&data->v1.enterprise) + data->v1.var_bindings_len + asn_bytes_length(data->v1.var_bindings_len);

    *p1++=data_length;

    //Encode the enterprise OID
     p1+=asn_encode_oid(p1, &data->v1.enterprise);

    //Encode the agent address
    p1+=asn_encode_snmp_ipaddress(p1, net_params.net.ip); //TODO: Need this to be specific to each interface

    //Encode Generic Trap
    p1+=asn_encode_int(p1, ASN_INT, data->v1.generic_trap);

    //Encode Specific Trap
    p1+=asn_encode_int(p1, ASN_INT, data->v1.specific_trap);

    //Encode time Stamp
    p1+=asn_encode_int(p1, ASN_SNMP_TIMETICKS, uptime_sec);

    //*p1++=0x30;
    //*p1++=0x00;


    // Add VAR_BINDING SEQUENCE
    *p1++=ASN_SEQUENCE;
    if ((bytes_used=asn_encode_length(p1, data->v1.var_bindings_len))==0) return 0;
    p1+=bytes_used;
    memcpy(p1, data->v1.var_bindings, data->v1.var_bindings_len);
    p1+=data->v1.var_bindings_len;
    
    return p1-out_buf;
}

int snmp_build_trap_v1(unsigned char *buffer, void *auth, _trap_varbinding *var_bindings, unsigned int num_bindings)
{
	int i;

    out_data.v1.var_bindings_len=0;

    for(i=0; i<num_bindings; i++)
    {
    	out_data.v1.var_bindings_len+=mib_add_var_binding(snmp_varbindings+out_data.v1.var_bindings_len, var_bindings[i].data_length, &var_bindings[i].oid, var_bindings[i].data, var_bindings[i].type);
    }

    // configure packet
    out_data.v1.msg_version=0;
    strcpy((char *)out_data.v1.community, (const char*)auth);
    out_data.v1.request_type=TRAP_PDU;
    out_data.v1.request_id=rand();
    out_data.v1.error_status=0;
    out_data.v1.error_index=0;
    out_data.v1.non_repeaters=0;
    out_data.v1.max_repetitions=0;
    out_data.v1.var_bindings=snmp_varbindings;

	// build packet
    return build_snmp_v1(buffer, &out_data);
}

int snmp_build_trap_v2c(unsigned char *buffer, void *auth, _trap_varbinding *var_bindings, unsigned int num_bindings)
{
	int i;
	
    out_data.v1.var_bindings_len=0;

    for(i=0; i<num_bindings; i++)
    {
    	out_data.v1.var_bindings_len+=mib_add_var_binding(snmp_varbindings+out_data.v1.var_bindings_len, var_bindings[i].data_length, &var_bindings[i].oid, var_bindings[i].data, var_bindings[i].type);
    }

    // configure packet
    out_data.v1.msg_version=1;
    strcpy((char *)out_data.v1.community, (const char*)auth);
    out_data.v1.request_type=TRAPv2C_PDU;
    out_data.v1.request_id=rand();
    out_data.v1.error_status=0;
    out_data.v1.error_index=0;
    out_data.v1.non_repeaters=0;
    out_data.v1.max_repetitions=0;
    out_data.v1.var_bindings=snmp_varbindings;

	// build packet
    return build_snmp_v2c(buffer, &out_data);
}

int snmp_build_trap_v3(unsigned char *buffer, void *auth, _trap_varbinding *var_bindings, unsigned int num_bindings)
{
	return 0;
}

// varbindings between v1, v2c and v3 are the same so we can process them all in the same function
int process_varbindings(unsigned char *in_varbindings, int in_varbindings_len, unsigned char *out_varbindings, int msg_version, int request_type, int non_repeaters, int max_repetitions, int *error_status, int *error_index)
{
    unsigned char *p1;
    unsigned int bytes_used;
    unsigned int len;
    int i;
    int temp;
    int set_type;
    void *set_value;
    int out_varbindings_len=0;
    
    p1=in_varbindings;
    *error_status=0;
    *error_index=0;
    
    // varbindings are encapsulated in a sequence, remove it first
    if ((bytes_used=asn_decode_sequence(p1, &len))==0) return 0;
    p1+=bytes_used;
        
    // now we process each var-binding
    while((in_varbindings_len-(p1-in_varbindings))>0)
    {
        // each var-binding is encapsulated in a sequence
        // and are comprised of an OID and a value
        if ((bytes_used=asn_decode_sequence(p1, &len))==0) break;
        p1+=bytes_used;              

        // get oid
        if ((bytes_used=asn_decode_oid(p1, &vb_data.oid))==0) break;
        p1+=bytes_used;
          
        // get value
        if ((bytes_used=asn_decode_null(p1))!=0)
        {
            set_type=ASN_NULL;
            set_value=NULL;
            p1+=bytes_used;
        }
        else if ((bytes_used=asn_decode_octet_string(p1, &len))!=0)
        {
            set_type=ASN_OCTET_STRING;
            memcpy(vb_data.val.octet_string, p1+bytes_used, len==OCTET_STRING_VB_LEN?OCTET_STRING_VB_LEN:len);
            vb_data.val.octet_string[len>=OCTET_STRING_VB_LEN?OCTET_STRING_VB_LEN-1:len]='\0';
            set_value=vb_data.val.octet_string;
            p1+=bytes_used+len;
        }
        else if ((bytes_used=asn_decode_int_type(p1, (unsigned int*)&set_type, &len))!=0)
        {
            memcpy(&vb_data.val.intv, &len, 4);
            set_value=&vb_data.val.intv;
            p1+=bytes_used;
        }
        else if ((bytes_used=asn_decode_oid(p1, &vb_data.val.oid))!=0)
        {
            set_value=&vb_data.val.oid;
            set_type=ASN_OID;
            p1+=bytes_used;
        }
        else
        {
            debug_printf("snmp: Can't decode var binding type 0x%x\n", *p1);
            return 0;
        }
          
        if (*error_status==snmp_NO_ERROR)
        {
            if ((msg_version==1)&&(request_type==GET_BULK_PDU))
            {
                if (non_repeaters>0)
                {
                    if ((temp=mib_process_oid(out_varbindings+out_varbindings_len, &vb_data.oid, GET_NEXT_REQUEST_PDU, set_type, set_value, len, error_status))==0) return 0;
                    out_varbindings_len+=temp;
                    (*error_index)++;
                    non_repeaters--;
                }
                else
                {
                    for(i=0; (i<max_repetitions) && (*error_status==snmp_NO_ERROR); i++)
                    {
                        if ((temp=mib_process_oid(out_varbindings+out_varbindings_len, &vb_data.oid, GET_NEXT_REQUEST_PDU, set_type, set_value, len, error_status))==0) return 0;
                        out_varbindings_len+=temp;
                        (*error_index)++;
                        non_repeaters--;
                    }
                }
            }
            else if (request_type==GET_RESPONSE_PDU)
            {
                // call call back function
                if ((cb_struct.wait_reply)&&(cb_struct.request_cb!=NULL))
                {
                    if ((in_data.msg_version==0)||(in_data.msg_version==1))
                    {
                        // check community
                        if (strcmp((const char*)cb_struct.community, (const char*)in_data.v1.community)!=0)
                        {
                        	snmp_stats->badCommunityNames++;
                        	return 0;
                        }
                    }
                    cb_struct.request_cb(&vb_data.oid, set_type, set_value, len);
                }
                return 0; // no reply to a GET_REQUEST_PDU
            }
            else
            {          
                if ((temp=mib_process_oid(out_varbindings+out_varbindings_len, &vb_data.oid, request_type, set_type, set_value, len, error_status))==0) return 0;
                out_varbindings_len+=temp;
                (*error_index)++;
            }
        }
        else // had an error, just add NULL's for each additional var-binding
        {
        	debug_printf("Error: SNMP.c process_varbindings, one varbinding had a null value.\r\n");
            if ((temp=mib_add_null_oid(out_varbindings+out_varbindings_len, &vb_data.oid))==0) return 0;
            out_varbindings_len+=temp;
        }
    }
    return out_varbindings_len;
}

// calculates hmac for v3 messages that have AUTH enabled, either MD5 or SHA
static void calculate_hmac(int auth_type, unsigned char *auth_key, unsigned char *data, unsigned int data_len, unsigned char *to)
{
    if (auth_type==AUTH_MD5)
    {
        HmacSetKey(&ap.auth.hmac, MD5, (const byte*)auth_key, 16);
    }
    else if (auth_type==AUTH_SHA)
    {
        HmacSetKey(&ap.auth.hmac, SHA, (const byte*)auth_key, 20);      
    }
    else
    {
        // not supported at the moment
       debug_printf("snmp: not supported auth_type: %d\n", auth_type);
    }
    HmacUpdate(&ap.auth.hmac, data, data_len);
    HmacFinal(&ap.auth.hmac, (byte*)ap.auth.digest);
    memcpy(to,ap.auth.digest,12);
  
}

// decrypts a v3 PDU messages
static void decrypt_pdu(int priv_type, unsigned char *priv_key, unsigned char *data, unsigned int data_len, unsigned char *salt, unsigned int engine_boots, unsigned int engine_time)
{
    int i;
    
    if (priv_type==PRIV_DES)
    {
        memcpy(ap.priv.key, priv_key, 8);
        memcpy(ap.priv.iv, priv_key+8, 8);
    
        for(i=0; i<8; i++)
        {
            ap.priv.iv[i]=ap.priv.iv[i]^salt[i];
        }
    
        Des_SetKey(&ap.priv.t.des, ap.priv.key, ap.priv.iv, DES_DECRYPTION);
        Des_CbcDecrypt(&ap.priv.t.des, data, data, data_len);
    }
    else if (priv_type==PRIV_AES)
    {
        ap.priv.iv[0]=((char*)&engine_boots)[3];
        ap.priv.iv[1]=((char*)&engine_boots)[2];
        ap.priv.iv[2]=((char*)&engine_boots)[1];
        ap.priv.iv[3]=((char*)&engine_boots)[0];
        ap.priv.iv[4]=((char*)&engine_time)[3];
        ap.priv.iv[5]=((char*)&engine_time)[2];
        ap.priv.iv[6]=((char*)&engine_time)[1];
        ap.priv.iv[7]=((char*)&engine_time)[0];
        memcpy(ap.priv.iv+8, salt, 8);
        
        memcpy(ap.priv.key, priv_key, 16);
       
        AesSetKey(&ap.priv.t.aes, ap.priv.key, 16, ap.priv.iv, AES_ENCRYPTION);
        AesCfbDecrypt(&ap.priv.t.aes, data, data, data_len);
      
    }
    else
    {
        // not supported at the moment
        debug_printf("snmp: not supported decryption!\n");
    }
}

// encrypts a v3 PDU message
static void encrypt_pdu(int priv_type, unsigned char *priv_key, unsigned char *data, unsigned int data_len, unsigned char *salt, unsigned int engine_boots, unsigned int engine_time)
{
    int i;
    
    if (priv_type==PRIV_DES)
    {
        // calculate a salt
        ((unsigned int*)salt)[0]=engine_boots;
        ((unsigned int*)salt)[1]=rand();
      
        memcpy(ap.priv.key, priv_key, 8);
        memcpy(ap.priv.iv, priv_key+8, 8);
    
        for(i=0; i<8; i++)
        {
            ap.priv.iv[i]=ap.priv.iv[i]^salt[i];
        }
    
        Des_SetKey(&ap.priv.t.des, ap.priv.key, ap.priv.iv, DES_ENCRYPTION);
        Des_CbcEncrypt(&ap.priv.t.des, data, data, data_len);
    }
    else if (priv_type==PRIV_AES)
    {
         // calculate a salt
        ((unsigned int*)salt)[0]=rand();
        ((unsigned int*)salt)[1]^=((unsigned int*)salt)[0];
      
        ap.priv.iv[0]=((char*)&engine_boots)[3];
        ap.priv.iv[1]=((char*)&engine_boots)[2];
        ap.priv.iv[2]=((char*)&engine_boots)[1];
        ap.priv.iv[3]=((char*)&engine_boots)[0];
        ap.priv.iv[4]=((char*)&engine_time)[3];
        ap.priv.iv[5]=((char*)&engine_time)[2];
        ap.priv.iv[6]=((char*)&engine_time)[1];
        ap.priv.iv[7]=((char*)&engine_time)[0];
        memcpy(ap.priv.iv+8, salt, 8);
        
        memcpy(ap.priv.key, priv_key, 16);
       
        AesSetKey(&ap.priv.t.aes, ap.priv.key, 16, ap.priv.iv, AES_ENCRYPTION);
        AesCfbEncrypt(&ap.priv.t.aes, data, data, data_len);
      
    }
    else
    {
        // not supported at the moment
        debug_printf("snmp: not supported non-DES Decryption!\n");
    }
  
}

static void localize_key(unsigned int auth_type, unsigned char *key, unsigned char *lkey, unsigned char *engine_id, unsigned int engine_id_len)
{
  // Now localize the key with the engineID and pass through MD5/SHA to procure the final key
    if (auth_type==AUTH_MD5)
    {
        memcpy(ap.auth.password_buf, key, 16);
        memcpy(ap.auth.password_buf+16, engine_id, engine_id_len);
        memcpy(ap.auth.password_buf+16+engine_id_len, key, 16);
      
        InitMd5(&ap.auth.t.md5);
        Md5Update(&ap.auth.t.md5, ap.auth.password_buf, 32+engine_id_len);
        Md5Final(&ap.auth.t.md5, lkey);
    }
    else if (auth_type==AUTH_SHA)
    {
        memcpy(ap.auth.password_buf, key, 20);
        memcpy(ap.auth.password_buf+20, engine_id, engine_id_len);
        memcpy(ap.auth.password_buf+20+engine_id_len, key, 20);
      
        InitSha(&ap.auth.t.sha);
        ShaUpdate(&ap.auth.t.sha, ap.auth.password_buf, 40+engine_id_len);
        ShaFinal(&ap.auth.t.sha, lkey);
    }
}

// calculates the KEY from a PASSWORD, needs to be done every time a password, engine id, auth_type or priv_type is changed for a user
static void password_to_key(char *password, unsigned char *key, unsigned int auth_type)
{
    unsigned char *cp;
    unsigned int password_index=0;
    unsigned int count=0;
    unsigned int i;
    unsigned int password_len;
    
    if (auth_type==AUTH_MD5)
    {
        InitMd5(&ap.auth.t.md5);
    }
    else if (auth_type==AUTH_SHA)
    {
        InitSha(&ap.auth.t.sha);
    }
    else
    {
        return;
    }
    
    password_len=strlen((const char*)password);
    
    // Use while loop until we've done 1 Megabyte
    while(count<1048576)
    {
        cp=ap.auth.password_buf;
        for(i=0; i<64; i++)
        {
            // take the next octet of the password, wrapping to the beginning of the password as necessary
            *cp++ = password[password_index++ % password_len];
        }
        if (auth_type==AUTH_MD5) Md5Update(&ap.auth.t.md5, ap.auth.password_buf, 64);
        else if (auth_type==AUTH_SHA) ShaUpdate(&ap.auth.t.sha, ap.auth.password_buf, 64);
        count+=64;
    }
    if (auth_type==AUTH_MD5) Md5Final(&ap.auth.t.md5, key);
    else if (auth_type==AUTH_SHA) ShaFinal(&ap.auth.t.sha, key);
}

// handles keeping track of v3 errors, gets registered as a MIB handler for 1.3.6.1.6.3.15.1.1
static int snmp_v3_error_oid_handler(void **data, int *data_len, _oid *oid, int request_type, int data_type, void *data_in, int data_in_len, int *error)
{
    debug_printf("snmp_v3_error_oid_handler called with :");
    //print_oid(oid);
    
    if (oid->val[RPT_ERR_INDEX]>=RPT_ERR_LAST_ONE) return ASN_NULL;

    snmp_v3_oid_errors[oid->val[RPT_ERR_INDEX]]++;
    *data=&snmp_v3_oid_errors[oid->val[RPT_ERR_INDEX]];
    return ASN_SNMP_COUNTER;
}

// setup snmp system by registering UDP socket, and registering some mib's
void snmp_init(_snmp_params *snmp_params_in)
{
    struct udp_pcb *pcb;

    debug_printf("SNMP init:\t\t");

    pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
    udp_bind(pcb, IP_ADDR_ANY, SNMP_PORT);
    udp_recv(pcb, snmp_recv, NULL);
    

    debug_printf("done\r\n");
    snmp_setup(snmp_params_in);

}

void snmp_setup(_snmp_params *snmp_params_in)
{
	snmp_params = snmp_params_in;
	rfc_1066_init();
    mib_register((void*)&snmp_v3_error_oid_mib); // register v3 error OID handler
    snmp_init_keys();
    memset(&cb_struct, 0, sizeof(_cb_struct));
}	

// calculates keys from passwords for all users, this should be called
// every time a username, password, auth_type or priv_type changes and NetParmas should be saved
void snmp_init_keys(void)
{
    int i;
    
    debug_printf("SNMP Init Keys:\t");
    
    // setup HMAC keys
    for(i=0; i<MAX_SNMPV3_USERS; i++)
    {
        if ((strlen((const char*)snmp_params->users[i].username)>0)&&(strlen((const char*)snmp_params->users[i].auth_key)>0))
        {
            password_to_key(snmp_params->users[i].auth_pass, snmp_params->users[i].auth_key, snmp_params->users[i].auth_type);
            
            if ((snmp_params->users[i].priv_type!=PRIV_NONE)&&(strlen((const char*)snmp_params->users[i].priv_key)>0))
            {
                password_to_key(snmp_params->users[i].priv_pass, snmp_params->users[i].priv_key, snmp_params->users[i].auth_type);
            }
        }
    }

    debug_printf("done\r\n");
}


/************* TEST CODE ********************/
// This is some test code 
/*
unsigned int got_reply=1;

int snmp_test_cb(_oid *oid, int type, void *val, int val_len)
{
    got_reply=1;
  
    switch(type)
    {
        case ASN_OCTET_STRING:
            ((char*)val)[val_len]='\0';
            debug_printf("String Reply '%s'\n", val);
            break;
        case ASN_SNMP_TIMETICKS:
            debug_printf("TimeTicks Reply '%d'\n", *(int*)val);
            break;
        case ASN_OID:
            debug_printf("Got OID: ");
            print_oid((_oid*)val);
            break;
        default:
            debug_printf("unhandled type '%d'\n", type);
            break;
    }

    return 0;
}


unsigned int stage=0;

int snmp_test_request(void)
{
    ip_addr_t ipaddr;
    _oid oid;
    int user_index;
    IP4_ADDR(&ipaddr, 192,168,20,89);
    
    if (got_reply==0) return 0;
    
    switch(stage)
    {
        case 0:
          oid.val[0]=1;
          oid.val[1]=3;
          oid.val[2]=6;
          oid.val[3]=1;
          oid.val[4]=2;
          oid.val[5]=1;
          oid.val[6]=1;
          oid.val[7]=1;
          oid.val[8]=0;
          oid.len=9;
          
          user_index=2;
          got_reply=0;
          stage++;
          snmp_start_request(&ipaddr, 161, &oid, 3, snmp_test_cb, &user_index);
          //snmp_start_request(&ipaddr, 161, &oid, 0, snmp_test_cb, "public");
          break;
          
      case 1:
        oid.val[0]=1;
        oid.val[1]=3;
        oid.val[2]=6;
        oid.val[3]=1;
        oid.val[4]=2;
        oid.val[5]=1;
        oid.val[6]=1;
        oid.val[7]=1;
        oid.val[8]=0;
        oid.len=9;
        
        user_index=2;
        got_reply=0;
        stage++;
        //snmp_start_request(&ipaddr, 161, &oid, 3, snmp_test_cb, &user_index);
        //snmp_start_request(&ipaddr, 161, &oid, 0, snmp_test_cb, "public");
        break;
    }

    return 0;
}



int snmp_start_request(ip_addr_t *ipaddr, u16_t port, _oid *oid, int version, snmp_cb cb, void *auth)
{
    int send_len;
    struct pbuf *p;
    struct udp_pcb *pcb;
    
    if ((version==0)||(version==1)) // version 1, 2c
    {
        // setup callback struct
        cb_struct.request_cb=cb;
        cb_struct.wait_reply=1;
        cb_struct.wait_report=0;
        strcpy((char*)cb_struct.community, (const char*)auth);
        
        // add OID and NULL var-binding for the request
        out_data.v1.var_bindings_len=mib_add_var_binding(snmp_varbindings, 0, oid, 0, ASN_NULL);
      
        // configure packet
        out_data.v1.msg_version=version;
        strcpy((char *)out_data.v1.community, (const char*)auth);
        out_data.v1.request_type=GET_REQUEST_PDU;
        out_data.v1.request_id=rand();
        out_data.v1.error_status=0;
        out_data.v1.error_index=0;
        out_data.v1.non_repeaters=0;
        out_data.v1.max_repetitions=0;
        out_data.v1.var_bindings=snmp_varbindings;
       
        // build packet
        send_len = build_snmp_v1(snmp_buffer, &out_data);
        
        // send it
        p=pbuf_alloc(PBUF_RAW, send_len, PBUF_POOL);
        if (p!=NULL)
        {
	        array_to_pbuf(p, snmp_buffer, send_len);
	        pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
	        udp_bind(pcb, IP_ADDR_ANY, SNMP_PORT);
	        udp_sendto(pcb ,p, ipaddr, port);
	        pbuf_free(p);
	        udp_remove(pcb);
        }
        else
        {
        	debug_printf("snmp: error allocating pbuf\r\n");
        }
        return 0;
    }
    else if (version==3) // version 3
    {
        // setup callback struct
        cb_struct.request_cb=cb;
        cb_struct.wait_reply=0;
        cb_struct.wait_report=1;
        cb_struct.user_index=*(int*)auth;
        memcpy(&cb_struct.oid, oid, sizeof(_oid));
        
        // build packet to get report
        out_data.v3.msg_version=3;
        out_data.v3.msg_id=rand();
        out_data.v3.msg_max_size=SNMP_MAX_LEN;
        out_data.v3.msg_flags=4; // reportable
        out_data.v3.msg_security_model=3;
        out_data.v3.msg_authoritative_engine_id_len=0;
        out_data.v3.msg_authoritative_engine_boots=0;
        out_data.v3.msg_authoritative_engine_time=0;
        out_data.v3.msg_username[0]='\0';
        out_data.v3.request_type=GET_REQUEST_PDU;
        out_data.v3.request_id=rand();
        out_data.v3.error_status=0;
        out_data.v3.error_index=0;
        out_data.v3.non_repeaters=0;
        out_data.v3.max_repetitions=0;
        out_data.v3.var_bindings_len=0;
        out_data.v3.user=&snmp_params->users[0];
        
        send_len=build_snmp_v3(snmp_buffer, &out_data);

        
        p=pbuf_alloc(PBUF_RAW, send_len, PBUF_POOL);
        if (p!=NULL)
        {
	        array_to_pbuf(p, snmp_buffer, send_len);
	        pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
	        udp_bind(pcb, IP_ADDR_ANY, SNMP_PORT);
	        udp_sendto(pcb ,p, ipaddr, port);
	        pbuf_free(p);
	        udp_remove(pcb);
        }
        else
        {
        	debug_printf("snmp: error allocating pbuf\r\n");
        }
        return 0;
    }
    else
    {
        debug_printf("snmp_request unknown version request %d\n", version);
        return -1;
    }
}
*/ 
/***   End Of File   ***/
