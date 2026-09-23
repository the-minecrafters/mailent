"""Record real loopback Postfix/Dovecot conversations; no mail is delivered.
Run in the isolated fixture container with /out mounted to fixtures/pcap.
TLS bytes and TCP streams come from real sockets, not hand-crafted packets.
"""
import datetime
import hashlib
import imaplib
import json
import os
from pathlib import Path
import poplib
import signal
import smtplib
import socket
import ssl
import subprocess
import time
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from scapy.all import rdpcap, wrpcap, PcapNgWriter, TCP, IP

OUT = Path('/out')
OUT.mkdir(exist_ok=True)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'mail.mailent.test')])
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(datetime.datetime(2020, 1, 1)).not_valid_after(datetime.datetime(2021, 1, 1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('mail.mailent.test')]), False).sign(key, hashes.SHA256()))
Path('/tmp/lab.key').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
Path('/tmp/lab.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
os.chmod('/tmp/lab.key', 0o600)
# The deliberately expired certificate tests policy at capture time. Clients in
# this isolated lab disable trust validation to record the server's TLS exchange.
Path('/etc/postfix/main.cf').write_text('''myhostname = mail.mailent.test
mydestination = localhost
inet_interfaces = loopback-only
inet_protocols = ipv4
mynetworks = 127.0.0.0/8
smtpd_tls_security_level = may
smtpd_tls_cert_file = /tmp/lab.crt
smtpd_tls_key_file = /tmp/lab.key
smtpd_tls_protocols = >=TLSv1
smtpd_tls_ciphers = medium
tls_medium_cipherlist = ALL:@SECLEVEL=0
smtpd_relay_restrictions = reject
''')
Path('/etc/dovecot/dovecot.conf').write_text('''protocols = imap pop3
listen = 127.0.0.1
ssl = yes
ssl_cert = </tmp/lab.crt
ssl_key = </tmp/lab.key
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ALL:@SECLEVEL=0
mail_location = mbox:~/mail:INBOX=/var/mail/%u
passdb {\n driver = static\n args = password=unused\n}\nuserdb {\n driver = static\n args = uid=nobody gid=nogroup home=/tmp\n}
''')
if '--serve' in sys.argv:
 if os.environ.get('MAILENT_LAB_SMTP_PORT'):
  port = int(os.environ['MAILENT_LAB_SMTP_PORT'])
  assert 1024 <= port <= 65535
  with open('/etc/postfix/master.cf', 'a') as master: master.write(f'\n{port} inet n - n - - smtpd\n')
 Path('/etc/postfix/main.cf').write_text(Path('/etc/postfix/main.cf').read_text().replace('inet_interfaces = loopback-only', 'inet_interfaces = all'))
 Path('/etc/dovecot/dovecot.conf').write_text(Path('/etc/dovecot/dovecot.conf').read_text().replace('listen = 127.0.0.1', 'listen = *'))
subprocess.run(['postfix','start'],check=True)
dovecot = subprocess.Popen(['dovecot','-F'])
for _ in range(50):
 try:
  with socket.create_connection(('127.0.0.1',143),timeout=1):break
 except OSError:time.sleep(.1)

if '--serve' in sys.argv:
 print('Mailent local probe lab ready (SMTP 25, IMAPS 993, POP3S 995)', flush=True)
 try:
  while True: time.sleep(60)
 except KeyboardInterrupt:
  dovecot.terminate()
 sys.exit(0)

def context(version=ssl.TLSVersion.TLSv1_2, ciphers='ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0'):
 ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
 ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
 ctx.minimum_version=version;ctx.maximum_version=version;ctx.set_ciphers(ciphers)
 return ctx

def smtp(tls=True,legacy=False):
 with smtplib.SMTP('127.0.0.1',25,timeout=5) as client:
  client.ehlo('fixture.mailent.test')
  if tls:client.starttls(context=context(ssl.TLSVersion.TLSv1 if legacy else ssl.TLSVersion.TLSv1_2,'AES128-SHA:@SECLEVEL=0' if legacy else 'ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0'))
  client.noop()

def imap():
 client=imaplib.IMAP4('127.0.0.1',143)
 client.starttls(ssl_context=context());client.logout()

def pop3():
 client=poplib.POP3('127.0.0.1',110,timeout=5)
 client.capa();client.stls(context=context());client.quit()

def implicit_imap():
 client=imaplib.IMAP4_SSL('127.0.0.1',993,ssl_context=context(ssl.TLSVersion.TLSv1_3))
 client.logout()

captures=[('smtp_starttls',25,lambda:smtp()),('smtp_legacy',25,lambda:smtp(legacy=True)),
 ('smtp_unused',25,lambda:smtp(tls=False)),('imap_starttls',143,imap),('pop3_stls',110,pop3),('imap_tls13',993,implicit_imap)]
for index,(label,port,action) in enumerate(captures):
 raw=Path('/tmp')/(label+'.pcap')
 capture=subprocess.Popen(['tcpdump','--immediate-mode','-i','lo','-U','-s','0','-w',str(raw),'tcp','port',str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 # Wait for tcpdump's listening announcement, not a guess at capture startup.
 while True:
  line=capture.stderr.readline()
  if b'listening on' in line:break
  if not line:raise RuntimeError('tcpdump failed to start')
 try:
  action();time.sleep(1.2)
 finally:
  capture.send_signal(signal.SIGINT);capture.wait(timeout=5)
 packets=rdpcap(str(raw))
 # Normalize timestamps only; preserve captured packet bytes, order and timing.
 first=packets[0].time
 for packet in packets:packet.time=packet.time-first+1789992000+index*60
 wrpcap(str(OUT/(label+'.pcap')),packets)
 print(label,len(packets),'packets',flush=True)
 if label=='smtp_starttls':
  writer=PcapNgWriter(str(OUT/'smtp_starttls.pcapng'))
  for packet in packets:writer.write(packet)
  writer.close()
  # A valid file ending before TLS completion, and a midstream capture.
  wrpcap(str(OUT/'smtp_truncated.pcap'),packets[:10])
  wrpcap(str(OUT/'smtp_midstream.pcap'),packets[4:])
# Empty valid PCAP and a genuine non-mail socket exchange for failure coverage.
wrpcap(str(OUT/'empty.pcap'),[],linktype=1)
subprocess.run(['postfix','stop'],check=True)
dovecot.terminate();dovecot.wait(timeout=5)
manifest={p.name:{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size} for p in sorted(OUT.glob('*.pcap*'))}
(OUT/'manifest.json').write_text(json.dumps({'generator':'Postfix/Dovecot loopback lab','capture_epoch':1789992000,'certificate_sha256':cert.fingerprint(hashes.SHA256()).hex(),'files':manifest},indent=2)+'\n')
