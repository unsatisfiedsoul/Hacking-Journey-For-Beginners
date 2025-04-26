import socket

def get_cidrs_from_asn(asn):
    query = f'-i origin {asn}'
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('whois.radb.net', 43))
    s.send((query + '\n').encode())

    response = b""
    while True:
        data = s.recv(4096)
        if not data:
            break
        response += data
    s.close()

    cidrs = []
    for line in response.decode().splitlines():
        if line.lower().startswith('route:'):
            cidr = line.split(':')[1].strip()
            cidrs.append(cidr)
    return cidrs

asn = input("ASN: ") #"AS15169"  # Example: Google's ASN
cidr_list = get_cidrs_from_asn(asn)
for cidr in cidr_list:
    print(cidr)
