# from subprocess import run, CalledProcessError
# from sys import exit
# from termcolor import cprint

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


def generate_key(public_exponent=65537, key_size=4096):
    key = rsa.generate_private_key(public_exponent, key_size, backend=default_backend())
    return key


def write_key_to_disk(key,path="/Users/kelleher/Documents/keys/key.pem", passphrase=b"passphrase"):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        ))


def generate_csr(common_name, subject, password=b"passphrase", altnames=[], key="", path="/Users/kelleher/Documents/keys/csr.pem"):
    # need to split subject by / and assign new vars
    subjectStr = str(subject)
    subjects = subjectStr.split("/")
    print(subjects)
    country_name = subjects[1][2:4]
    print(country_name)
    state_or_province = subjects[2][3:]
    print(state_or_province)
    locality_name = subjects[3][2:]
    print(locality_name)
    organization_name = subjects[4][2:]
    print(organization_name)
    with open(path, key) as key_file:
        key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
            backend=default_backend()
        )
    dnsNames = []
    print("altname", altnames)
    if altnames is not []:
        for altname in dnsNames:
            print("altname",altname)
            dnsNames.append(x509.DNSName(altname))
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])).add_extension(
            x509.SubjectAlternativeName(dnsNames),
            critical=False,
            # Sign the CSR with our private key.
            ).sign(key, hashes.SHA256(), default_backend())

    # Write our CSR out to disk.
    with open(path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    with open(path, "r") as f:
        return f.read()


# we then need to send this cert to the ca


#1
def cert_with_key(common_name, subject, password=None,altnames=None,key = "", path="/Users/kelleher/Documents/keys/csr.pem"):
    csr = generate_csr(common_name, subject, password,altnames, key,path)
    return csr


# 2
def cert_with_no_key(common_name, subject, password=None,altnames="", path="/Users/kelleher/Documents/keys/csr.pem"):
    key = generate_key()
    write_key_to_disk(key,"/Users/kelleher/Documents/keys/csr.pem")

    csr = generate_csr(common_name, subject, password,altnames, key, path="/Users/kelleher/Documents/keys/csr.pem")
    return csr


# This needs to be replaced with a new command.
# keyout is location of where key is going to be stored.
# req means request.
# -out is where to put completed request
# -subj sets subject
# password can be used to specify whether use des or not. this is true or false in config.
# should i take in password if i cant use it.
# 2
# def gen_csr_with_new_cert(fqdn, subject, password, altnames=None):
#     command = [
#         'openssl', 'req', '-newkey', 'rsa:4096', '-keyout',
#         '{}.key'.format(fqdn), '-out', '{}.req'.format(fqdn), '-subj',
#         subject
#     ]
#     if altnames is not None:
#         for domain in altnames:
#             command.append('-addext')
#             command.append('"subjectAltName = {}"'.format(domain))
#         print(command)
#     if not password:
#         command.append('-nodes')
#     try:
#         run(command, check=True)
#     except CalledProcessError:
#         cprint('There was an error in openssl, please check the output', 'red')
#         exit(1)
#     with open('{}.req'.format(fqdn)) as f:
#         return f.read()


# This also need to be replaced with a new command.
# 1
# def gen_csr_with_existing_cert(key_path, fqdn, subject, additional=None):
#     try:
#         run([
#             'openssl', 'req', '-new', '-key', key_path, '-out',
#             '{}.req'.format(fqdn), '-subj', subject
#         ])
#     except CalledProcessError:
#         cprint('There was an error in openssl, please check the output', 'red')
#         exit(1)
#     with open('{}.req'.format(fqdn)) as f:
#         return f.read()


# key = generate_key()
# print(generate_csr("/C=DE/ST=Baden-Wuerttemberg/L=Heidelberg/O=European Molecular Biology Laboratory/CN={fqdn}",
#     ["test.embl.de"],key))


