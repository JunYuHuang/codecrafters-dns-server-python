import socket

#
# CONSTANTS
#
HOST = "127.0.0.1"
PORT = 2053
HEADER_BYTES = 12

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
        self.questions_bytes = b''

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

    def set_questions_bytes(self, questions_bytes: bytes) -> None:
        self.questions_bytes = questions_bytes

    @staticmethod
    def header_entries(dns_message_bytes: bytes) -> dict[str, int]:
        res = {}
        res["ID"] = int.from_bytes(dns_message_bytes[:2], byteorder='big')

        # TODO: extract flag bytes from bytes 3 and 4

        res["QDCOUNT"] = int.from_bytes(dns_message_bytes[4:6], byteorder='big')
        res["ANCOUNT"] = int.from_bytes(dns_message_bytes[6:8], byteorder='big')
        res["NSCOUNT"] = int.from_bytes(dns_message_bytes[8:10], byteorder='big')
        res["ARCOUNT"] = int.from_bytes(dns_message_bytes[10:12], byteorder='big')

        return res
    
    # TODO: to test for question sections with 2+ (question) entries
    @staticmethod
    def questions_end_pos(dns_message_bytes: bytes) -> int:
        dns_message_bytes_length = len(dns_message_bytes)
        if dns_message_bytes_length <= HEADER_BYTES:
            print("Error: DNS message has header only")
            return -1
        
        i = HEADER_BYTES
        res = i
        while i < dns_message_bytes_length:
            # print(f"At pos {i}, at byte '{dns_message_bytes[i]}'")

            # In question section, reached end of last entry (null byte)
            # Last entry is followed by 4 bytes = `QTYPE` (2 bytes) + `QCLASS` (2 bytes)
            if dns_message_bytes[i:i + 1] == b'\x00':
                # print("At DNS message questions section end")
                # print(f"Last 4 bytes: '{dns_message_bytes[i + 1:i + 5]}")

                # Question section's last 3 bytes = `QNAME` (2 bytes) + `QTYPE` (1 byte)
                res = i + 4
                break

            subname_length = int.from_bytes(dns_message_bytes[i:i + 1], byteorder='big')
            # print("==> Go to next label start pos")
            # print(f"Chars in next subname: {subname_length}")
            # print(f"Subname: '{dns_message_bytes[i + 1:i + subname_length + 1].decode()}'")
            i = i + subname_length + 1

        return res

    @staticmethod
    def questions_from_bytes(dns_message_bytes: bytes) -> bytes:
        if len(dns_message_bytes) < HEADER_BYTES:
            return b''
        end_pos = DNSMessage.questions_end_pos(dns_message_bytes)
        return dns_message_bytes[HEADER_BYTES:end_pos + 1]

def main():
    udp_socket: socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((HOST, PORT))

    print(f"==> DNS Server running at {HOST}:{PORT}")
    
    while True:
        # try:
        #     pass
        # except Exception as e:
        #     print(f"Error receiving data: {e}")
        #     break
        
        # `buffer`: bytes
        # `source`: (host: string, port: integer) because is a AF_INET socket (IPv4)
        buffer, source = udp_socket.recvfrom(512)

        query_header: dict[str, int] = DNSMessage.header_entries(buffer)
        print(f"==> Received DNS message ({len(buffer)} bytes) with ID {query_header["ID"]}")

        dns_reply = DNSMessage()
        dns_reply_options = query_header
        dns_reply_options["QR"] = 1
        dns_reply.set_header(dns_reply_options)
        print(f"==> DNS message reply header: {dns_reply.header}")

        response: bytes = dns_reply.header_bytes()

        if len(buffer) > HEADER_BYTES:
            questions_bytes = DNSMessage.questions_from_bytes(buffer)
            dns_reply.set_questions_bytes(questions_bytes)
            response += dns_reply.questions_bytes

        udp_socket.sendto(response, source)
        print("==> Sent DNS message reply:")
        print(response)

if __name__ == "__main__":
    main()
