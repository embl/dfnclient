from subprocess import run, CalledProcessError
from sys import exit

from termcolor import cprint
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


def generate_key(public_exponent=65537, key_size=4096):
    key = rsa.generate_private_key(public_exponent, key_size, backend=default_backend())
    return key


def write_key_to_disk(key,path="/Users/kelleher/Documents/keys/key.pem"):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))


def generate_csr(country_name, state_or_province, locality_name, organization_name, common_name, san1, san2, san3, key,path="/Users/kelleher/Documents/keys/csr.pem"):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])).add_extension(
            x509.SubjectAlternativeName([
                # Describe what sites we want this certificate for.
                x509.DNSName(san1),
                x509.DNSName(san2),
                x509.DNSName(san3),
                ]),
            critical=False,
            # Sign the CSR with our private key.
            ).sign(key, hashes.SHA256(), default_backend())

    # Write our CSR out to disk.
    with open(path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
        return f.read()


# we then need to send this cert to the ca


def cert_with_key(country_name, state_or_province, locality_name, organization_name, common_name, san1, san2, san3, key):
    csr = generate_csr(country_name, state_or_province, locality_name, organization_name, common_name, san1, san2, san3, key)
    return csr

def cert_with_no_key():
    country_name = u"US"
    state_or_province = u"California"
    locality_name = u"San Francisco"
    organization_name =  u"My Company"
    common_name = u"mysite.com"
    san1 = u"mysite.com"
    san2 = u"www.mysite.com"
    san3 = u"subdomain.mysite.com",

    key = generate_key()
    write_key_to_disk(key)
    csr = generate_csr(country_name,state_or_province,locality_name,organization_name,common_name,san1,san2,san3,key)

    print(csr)
    return csr




def gen_csr_with_new_cert(fqdn, subject, password, altnames=None):
    command = [
        'openssl', 'req', '-newkey', 'rsa:4096', '-keyout',
        '{}.key'.format(fqdn), '-out', '{}.req'.format(fqdn), '-subj',
        subject
    ]
    if altnames is not None:
        for domain in altnames:
            command.append('-addext')
            command.append('"subjectAltName = {}"'.format(domain))
        print(command)
    if not password:
        command.append('-nodes')
    try:
        run(command, check=True)
    except CalledProcessError:
        cprint('There was an error in openssl, please check the output', 'red')
        exit(1)
    with open('{}.req'.format(fqdn)) as f:
        return f.read()


def gen_csr_with_existing_cert(key_path, fqdn, subject, additional=None):
    try:
        run([
            'openssl', 'req', '-new', '-key', key_path, '-out',
            '{}.req'.format(fqdn), '-subj', subject
        ])
    except CalledProcessError:
        cprint('There was an error in openssl, please check the output', 'red')
        exit(1)
    with open('{}.req'.format(fqdn)) as f:
        return f.read()
