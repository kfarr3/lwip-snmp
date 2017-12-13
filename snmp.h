#ifndef SNMP_H
#define SNMP_H

#include "asn.1.h"
#include "lwip/ip_addr.h"
#include "Crypto/des3.h"
#include "Crypto/aes.h"
#include "Crypto/hmac.h"
#include "lwip/udp.h"

#define SNMP_PORT 161
#define SNMP_MAX_LEN 1000

typedef struct
{
	_oid          oid;
	unsigned int  data_length;
	void         *data;
	int           type;
}_trap_varbinding;

typedef  int(*snmp_cb)(_oid *oid, int type, void *val, int val_len);

/******* SNMP CONFIGURATION **************/

#define AUTH_NONE   0
#define AUTH_MD5    1
#define AUTH_SHA    2

#define PRIV_NONE   0
#define PRIV_DES    1
#define PRIV_AES    2

#define NUM_SNMP_BUFFERS 5

#define MAX_COMMUNITY_NAME 	20
#define MAX_ENGINE_ID      	20
#define MAX_SNMPV3_USERS   	6
#define MAX_USERNAME_LEN 	20
#define MAX_PASSWORD_LEN 	20

#define USER_LEVEL_NONE			0
#define USER_LEVEL_READ			1
#define USER_LEVEL_READ_WRITE	2

#define SNMP_LAN_ENABLED 0x01
#define SNMP_WAN_ENABLED 0x02

// niver niver niver, oose de 1st ooser
typedef struct
{
    char          username[MAX_PASSWORD_LEN];
    char          auth_pass[MAX_PASSWORD_LEN];
    char          priv_pass[MAX_PASSWORD_LEN];
    unsigned char auth_type;
    unsigned char priv_type;
    unsigned char auth_key[20];
    unsigned char priv_key[20];
    unsigned char user_level;
}_snmpv3_user;

typedef struct
{
	unsigned char enabled;
	unsigned char OLD1;
	unsigned char use_v3;
    char          read_community[MAX_COMMUNITY_NAME];
    char          write_community[MAX_COMMUNITY_NAME];
    unsigned char engine_id[MAX_ENGINE_ID];
    unsigned int engine_id_len;
    unsigned int boots;
    unsigned char traps_enabled;
	unsigned char trap_ip[4];
    _snmpv3_user users[MAX_SNMPV3_USERS];
}_snmp_params;

#define MAX_MSG_AUTH_PARAM 20
#define MAX_MSG_PRIV_PARAM 20
#define OCTET_STRING_VB_LEN 100

typedef union
{
    struct
    {
        // AUTH data structures
        Hmac hmac;
        unsigned char password_buf[72];
        union
        {
            Md5 md5;
            Sha sha;
        }t;

        unsigned char digest[20];
    }auth;

    struct
    {
        // PRIV data structures
        union
        {
            Des des;
            Aes aes;
        }t;
        unsigned char key[16];
        unsigned char iv[16];
    }priv;
}_auth_priv_str;

typedef struct
{
    unsigned int  msg_version;
    unsigned char community[MAX_COMMUNITY_NAME];
    _oid          enterprise;
    unsigned int  generic_trap;
    unsigned int  specific_trap;
    unsigned int  request_type;
    unsigned int  request_id;
    unsigned int  error_status;
    unsigned int  error_index;
    unsigned int  non_repeaters;
    unsigned int  max_repetitions;
    unsigned char *var_bindings;
    unsigned int  var_bindings_len;
}_v1_struct;

typedef struct
{
    unsigned int  msg_version;
    unsigned int  msg_id;
    unsigned int  msg_max_size;
    unsigned int  msg_flags;
    unsigned int  msg_security_model;
    unsigned char msg_authoritative_engine_id[MAX_ENGINE_ID];
    unsigned int  msg_authoritative_engine_id_len;
    unsigned int  msg_authoritative_engine_boots;
    unsigned int  msg_authoritative_engine_time;
    unsigned char msg_username[MAX_USERNAME_LEN];
    unsigned char msg_authentication_parameters[MAX_MSG_AUTH_PARAM];
    unsigned char msg_privacy_parameters[MAX_MSG_PRIV_PARAM];
    unsigned int  request_type;
    unsigned int  request_id;
    unsigned int  error_status;
    unsigned int  error_index;
    unsigned int  non_repeaters;
    unsigned int  max_repetitions;
    unsigned char *var_bindings;
    unsigned int  var_bindings_len;
    unsigned char lkey[20];
    _snmpv3_user  *user;
}_v3_struct;

typedef union
{
    unsigned int msg_version;
    _v1_struct v1;
    _v3_struct v3;
}_snmp_data;

typedef struct
{
    int wait_report;
    int wait_reply;
    int user_index;
    snmp_cb request_cb;
    char community[MAX_COMMUNITY_NAME];
    _oid oid;
}_cb_struct;

typedef union
{
    _oid oid;
    char octet_string[OCTET_STRING_VB_LEN];
    unsigned int intv;
}_varbinding_val;

typedef struct
{
    _oid oid;
    _varbinding_val val;
}_varbinding_data;

typedef struct
{
	_snmp_data in_data;
	_snmp_data out_data;
	_cb_struct cb_struct;
	_varbinding_data vb_data;
	_auth_priv_str ap;
	struct udp_pcb* pcb;
	unsigned char snmp_buffer[SNMP_MAX_LEN];
	unsigned char snmp_varbindings[SNMP_MAX_LEN];

}_snmp_buffer;


// ONLY Call snmp_init OR snmp_setup since snmp_init calls snmp_setup
// snmp_init  -- initializes UDP handler
// snmp_setup -- sets up internal system

void snmp_init(_snmp_params *snmp_params);
void snmp_setup(_snmp_params *snmp_params);
void snmp_init_keys(void);

int snmp_build_trap(unsigned char *buffer, int version, void *auth, _trap_varbinding *var_bindings, unsigned int num_bindings);
int snmp_send_trap(int version, ip_addr_t *ipaddr, u16_t port, void *auth, _trap_varbinding *var_bindings, unsigned int num_bindings);
int snmp_process(unsigned char *packet_in, unsigned int length_in, unsigned char *packet_out);
// for version 1 and 2c, void *auth points to the community name
// for version 2, void *auth points to an integer representing the user_index
int snmp_start_request(ip_addr_t *ipaddr, u16_t port, _oid *oid, int version, snmp_cb cb, void *auth);
#endif
/***   End Of File   ***/
