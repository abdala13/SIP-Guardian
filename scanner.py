import socket
import random
import hashlib
import time
import threading

class SIPAuditEngine(threading.Thread):
    def __init__(self, target, port, username, password_list, callback):
        super().__init__()
        self.target = target
        self.port = int(port)
        self.username = username
        self.password_list = password_list
        self.callback = callback
        self.stop_event = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2)

    def generate_auth(self, response_header, password, method="REGISTER"):
        try:
            realm = response_header.split('realm="')[1].split('"')[0]
            nonce = response_header.split('nonce="')[1].split('"')[0]
            uri = f"sip:{self.target}"
            a1 = hashlib.md5(f"{self.username}:{realm}:{password}".encode()).hexdigest()
            a2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
            response = hashlib.md5(f"{a1}:{nonce}:{a2}".encode()).hexdigest()
            return f'Digest username="{self.username}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response}"'
        except: return None

    def create_packet(self, auth_str=None):
        branch = f"z9hG4bK-{random.getrandbits(32)}"
        call_id = f"{random.getrandbits(32)}@sip-guardian"
        msg = (
            f"REGISTER sip:{self.target} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch={branch}\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:{self.username}@{self.target}>;tag={random.getrandbits(16)}\r\n"
            f"To: <sip:{self.username}@{self.target}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 1 REGISTER\r\n"
            f"Contact: <sip:{self.username}@127.0.0.1:5060>\r\n"
        )
        if auth_str: msg += f"Authorization: {auth_str}\r\n"
        msg += "Content-Length: 0\r\n\r\n"
        return msg

    def run(self):
        self.callback(f"[*] Starting Security Audit on {self.target}...")
        for pwd in self.password_list:
            if self.stop_event.is_set(): break
            try:
                self.sock.sendto(self.create_packet().encode(), (self.target, self.port))
                data, _ = self.sock.recvfrom(2048)
                resp = data.decode()
                if "401" in resp or "407" in resp:
                    auth_header = self.generate_auth(resp, pwd)
                    if auth_header:
                        self.sock.sendto(self.create_packet(auth_header).encode(), (self.target, self.port))
                        data, _ = self.sock.recvfrom(2048)
                        if "200 OK" in data.decode():
                            self.callback(f"[!] VULNERABILITY FOUND: Password is '{pwd}'")
                            return
                self.callback(f"[.] Tested: {pwd}")
                time.sleep(0.1)
            except: pass
        self.callback("[*] Audit Finished.")
