import socket
def main(HOST, PORT):
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + HOST.encode() + b"\r\n\r\n")
        res = s.recv(1024)
        headers = res.split(b"\r\n")
        (with_c, without_c) =header_parser(headers)
        print("with::::")
        print(with_c)


def header_parser(headers: list[bytes]) -> ():
    header_with_colon = []
    header_without_colon = []
    for header in headers:
        if b':' in header:
            header_with_colon.append(header)
        
        else:
            header_without_colon.append(header)
        
    return (header_with_colon, header_without_colon)

main("www.google.com", 80)