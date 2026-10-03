import socket

#
# CONSTANTS
#
HOST = "127.0.0.1"
PORT = 2053

def int_to_binary_str(integer: int, bits_length: int = 0) -> str:
    if type(bits_length) != int or bits_length < 0:
        bits_length = 0
    return format(integer, f"0{bits_length}b")

# See RFC 1035 for details: https://www.rfc-editor.org/info/rfc1035/#section-4.1
class DNSMessage:
    def __init__(self, options: dict[str, int] = {}):
        self.header = {
            # packet identifier (16 bits)
            "ID": 0,

            # query / response indicator (1 bit)
            "QR": 1,

            # operation code (4 bits)
            "OPCODE": 0,

            # authoritative answer (1 bit)
            "AA": 0,

            # truncation (1 bit)
            "TC": 0,

            # recursion desired (1 bit)
            "RD": 0,

            # recursive available (1 bit)
            "RA": 0,

            # reserved (3 bits)
            "Z": 0,

            # response code (4 bits)
            "RCODE": 0,

            # question count (16 bits)
            "QDCOUNT": 0,

            # answer record count (16 bits)
            "ANCOUNT": 0,

            # authority record count (16 bits)
            "NSCOUNT": 0,

            # additional record count (16 bits)
            "ARCOUNT": 0
        }

        for field, integer in options.items():
            if not (field in self.header) or type(integer) != int:
                continue
            self.header[field] = integer

    # TODO: to test
    def header(self, field: str) -> int:
        if not (field in self.header):
            return -1
        return self.header[field]

    def set_header(self, field_to_int: dict[str, int]) -> None:
        for field, integer in field_to_int.items():
            if not (field in self.header) or type(integer) != int:
                continue
            self.header[field] = integer
    
    def header_bytes(self) -> bytes:
        ID_bytes = self.header["ID"].to_bytes(length=2, byteorder='big')

        # build byte 3 in DNS message header (from field `QR` to `RD`)
        flags_byte_3_str = (
            int_to_binary_str(self.header["QR"], 1) +
            int_to_binary_str(self.header["OPCODE"], 4) +
            int_to_binary_str(self.header["AA"], 1) +
            int_to_binary_str(self.header["TC"], 1) +
            int_to_binary_str(self.header["RD"], 1)
        )

        # build byte 4 in DNS message header (from field `RA` to `RCODE`)
        flags_byte_4_str = (
            int_to_binary_str(self.header["RA"], 1) +
            int_to_binary_str(self.header["Z"], 3) +
            int_to_binary_str(self.header["RCODE"], 4)
        )

        flag_bytes = bytes([int(flags_byte_3_str, 2), int(flags_byte_4_str, 2)])

        QDCOUNT_bytes = self.header["QDCOUNT"].to_bytes(length=2, byteorder='big')
        ANCOUNT_bytes = self.header["ANCOUNT"].to_bytes(length=2, byteorder='big')
        NSCOUNT_bytes = self.header["NSCOUNT"].to_bytes(length=2, byteorder='big')
        ARCOUNT_bytes = self.header["ARCOUNT"].to_bytes(length=2, byteorder='big')

        return (
            ID_bytes + flag_bytes + QDCOUNT_bytes + 
            ANCOUNT_bytes + NSCOUNT_bytes + ARCOUNT_bytes
        )

    @staticmethod
    def udp_bytes_to_dns_header(udp_packet: bytes) -> dict[str, int]:
        res = {}
        res["ID"] = int.from_bytes(udp_packet[:2], byteorder='big')

        # TODO: extract flag bytes from bytes 3 and 4

        res["QDCOUNT"] = int.from_bytes(udp_packet[4:6], byteorder='big')
        res["ANCOUNT"] = int.from_bytes(udp_packet[6:8], byteorder='big')
        res["NSCOUNT"] = int.from_bytes(udp_packet[8:10], byteorder='big')
        res["ARCOUNT"] = int.from_bytes(udp_packet[10:12], byteorder='big')

        return res

def main():
    udp_socket: socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((HOST, PORT))

    print(f"DNS Server running at {HOST}:{PORT}")
    
    while True:
        try:
            # `buffer`: bytes
            # `source`: (host: string, port: integer) because is a AF_INET socket (IPv4)
            buffer, source = udp_socket.recvfrom(512)
    
            query_header: dict[str, int] = DNSMessage.udp_bytes_to_dns_header(buffer)
            print(f"Received DNS message with packet ID: {query_header["ID"]}")

            dns_message_reply = DNSMessage()
            dns_message_reply.set_header({ "ID": query_header["ID"], "QR": 1 })
            # print(f"DNS message reply header: {dns_message_reply.header}")

            response = dns_message_reply.header_bytes()

            # DNS message header should be 12 bytes
            assert len(response) == 12
    
            udp_socket.sendto(response, source)
            print(f"Sent DNS message reply with header: '{response}'")

        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
