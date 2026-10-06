#
# IMPORTS
#
import socket

#
# CONSTANTS
#
HOST = "127.0.0.1"
PORT = 2053
HEADER_BYTES = 12
BUFFER_SIZE = 512

#
# HELPER FUNCTIONS
#
def int_to_binary_str(integer: int, bit_length: int = 0) -> str:
    if type(bit_length) != int or bit_length < 0:
        bit_length = 0
    return format(integer, f"0{bit_length}b")

# See RFC 1035 for details: https://www.rfc-editor.org/info/rfc1035/#section-4.1
class DNSMessage:
    def __init__(self):
        self.data = {
            #
            # HEADER section
            #
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
            "ARCOUNT": 0,

            #
            # QUESTION section
            #
            # name (variable-length bytes)
            "QNAME": "example.com",

            # type (2 bytes)
            "QTYPE": 0,

            # class (2 bytes)
            "QCLASS": 0,

            #
            # ANSWER section
            #
            # name (variable-length bytes)
            "NAME": "example.com",

            # type (2 bytes)
            "TYPE": 0,

            # class (2 bytes)
            "CLASS": 0,

            # time-to-live (4 bytes)
            "TTL": 0,

            # length (2 bytes)
            "RDLENGTH": 0,

            # data (variable-length bytes)
            "RDATA": "8.8.8.8"
        }

    def set_data(self, field_to_values: dict) -> None:
        for field, value in field_to_values.items():
            self.data[field] = value

    def copy_header(self, dns_query: bytes) -> None:
        data: dict = {}
        data["ID"] = int.from_bytes(dns_query[:2], byteorder='big')

        # Extract flag bits from byte 3 in `dns_query`
        byte_3 = int.from_bytes(dns_query[2:3], byteorder='big')
        byte_3_str = int_to_binary_str(byte_3, 8)
        data["QR"] = 1
        data["OPCODE"] = int(byte_3_str[1:5], 2)
        data["AA"] = 0
        data["TC"] = 0
        data["RD"] = int(byte_3_str[7:8], 2)

        # Set flag bits for byte 4 in DNS reply
        data["RA"] = 0
        data["Z"] = 0
        data["RCODE"] = 0 if data["OPCODE"] == 0 else 4

        data["QDCOUNT"] = int.from_bytes(dns_query[4:6], byteorder='big')
        data["ANCOUNT"] = int.from_bytes(dns_query[6:8], byteorder='big')
        data["NSCOUNT"] = int.from_bytes(
            dns_query[8:10], byteorder='big'
        )
        data["ARCOUNT"] = int.from_bytes(
            dns_query[10:12], byteorder='big'
        )

        self.set_data(data)

    def copy_question(self, dns_query: bytes) -> None:
        dns_query_length = len(dns_query)
        if dns_query_length <= HEADER_BYTES:
            return

        data: dict = { "QDCOUNT": 1 }
        domain_labels = []

        # Traverse bytes in Question section        
        i = HEADER_BYTES
        while i < dns_query_length:

            # In question section, reached end of last entry (null byte)
            # Last entry is followed by 4 bytes = `QTYPE` (2B) + `QCLASS` (2B)
            if dns_query[i:i + 1] == b'\x00':
                break

            label_length = int.from_bytes(dns_query[i:i + 1], byteorder='big')
            domain_labels.append(dns_query[i + 1:i + label_length + 1].decode())
            i = i + label_length + 1

        data["QNAME"] = ".".join(domain_labels)
        data["QTYPE"] = int.from_bytes(dns_query[i + 1:i + 3], byteorder='big')
        data["QCLASS"] = int.from_bytes(dns_query[i + 3:i + 5], byteorder='big')

        self.set_data(data)

    def set_answer(self, dns_query: bytes) -> None:
        if len(dns_query) <= HEADER_BYTES:
            print("Error: DNS message has header only")
            return

        data: dict = {
            "ANCOUNT": 1,
            "NAME": str(self.data["QNAME"]),
            "TYPE": self.data["QTYPE"],
            "CLASS": self.data["QCLASS"],
            "TTL": 60,
            "RDATA": "8.8.8.8"
        }
        data["RDLENGTH"] = len(data["RDATA"].split("."))

        self.set_data(data)

    def header_bytes(self) -> bytes:
        ID_bytes = self.data["ID"].to_bytes(length=2, byteorder='big')

        # build byte 3 in DNS message header (from field `QR` to `RD`)
        flags_byte_3_str = (
            int_to_binary_str(self.data["QR"], 1) +
            int_to_binary_str(self.data["OPCODE"], 4) +
            int_to_binary_str(self.data["AA"], 1) +
            int_to_binary_str(self.data["TC"], 1) +
            int_to_binary_str(self.data["RD"], 1)
        )

        # build byte 4 in DNS message header (from field `RA` to `RCODE`)
        flags_byte_4_str = (
            int_to_binary_str(self.data["RA"], 1) +
            int_to_binary_str(self.data["Z"], 3) +
            int_to_binary_str(self.data["RCODE"], 4)
        )

        flag_bytes = bytes([int(flags_byte_3_str, 2), int(flags_byte_4_str, 2)])

        QDCOUNT_bytes = self.data["QDCOUNT"].to_bytes(length=2, byteorder='big')
        ANCOUNT_bytes = self.data["ANCOUNT"].to_bytes(length=2, byteorder='big')
        NSCOUNT_bytes = self.data["NSCOUNT"].to_bytes(length=2, byteorder='big')
        ARCOUNT_bytes = self.data["ARCOUNT"].to_bytes(length=2, byteorder='big')

        return (
            ID_bytes + flag_bytes + QDCOUNT_bytes + 
            ANCOUNT_bytes + NSCOUNT_bytes + ARCOUNT_bytes
        )

    def question_bytes(self, dns_query_size: int) -> bytes:
        if dns_query_size <= HEADER_BYTES:
            return b''

        QNAME_bytes = b''
        domain_labels = self.data["QNAME"].split(".")
        for label in domain_labels:
            QNAME_bytes += len(label).to_bytes(length=1, byteorder='big')
            QNAME_bytes += label.encode()
        QNAME_bytes += b'\0'

        QTYPE_bytes = self.data["QTYPE"].to_bytes(length=2, byteorder='big')
        QCLASS_bytes = self.data["QCLASS"].to_bytes(length=2, byteorder='big')

        return (QNAME_bytes + QTYPE_bytes + QCLASS_bytes)

    def answer_bytes(self, dns_query_size: int) -> bytes:
        if dns_query_size <= HEADER_BYTES:
            return b''

        NAME_bytes = b''
        domain_labels = self.data["NAME"].split(".")
        for label in domain_labels:
            NAME_bytes += len(label).to_bytes(length=1, byteorder='big')
            NAME_bytes += label.encode()
        NAME_bytes += b'\0'

        TYPE_bytes = self.data["TYPE"].to_bytes(length=2, byteorder='big')
        CLASS_bytes = self.data["CLASS"].to_bytes(length=2, byteorder='big')
        TTL_bytes = self.data["TTL"].to_bytes(length=4, byteorder='big')
        RDLENGTH_bytes = self.data["RDLENGTH"].to_bytes(length=2, byteorder='big')

        RDATA_bytes = b''
        ipv4_octets = self.data["RDATA"].split(".")
        for octet in ipv4_octets:
            RDATA_bytes += int(octet).to_bytes(length=1, byteorder='big')

        return (
            NAME_bytes + TYPE_bytes + CLASS_bytes +
            TTL_bytes + RDLENGTH_bytes + RDATA_bytes
        )

    def header_entries(self) -> dict:
        res = {}
        keys = [
            "ID", "QR", "OPCODE", "AA", "TC", "RD", "RA", "Z", "RCODE",
            "QDCOUNT", "ANCOUNT", "NSCOUNT", "ARCOUNT"
        ]
        for key in keys:
            res[key] = self.data[key]
        return res

    def question_entries(self) -> dict:
        res = {}
        keys = ["QNAME", "QTYPE", "QCLASS"]
        for key in keys:
            res[key] = self.data[key]
        return res

    def answer_entries(self) -> dict:
        res = {}
        keys = ["NAME", "TYPE", "CLASS", "TTL", "RDLENGTH", "RDATA"]
        for key in keys:
            res[key] = self.data[key]
        return res

def main():
    udp_socket: socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((HOST, PORT))
    print(f"==> DNS Server running at {HOST}:{PORT}")
    
    while True:
        # `buffer`: bytes
        # `source`: (host: string, port: integer) because is a AF_INET socket (IPv4)
        buffer, source = udp_socket.recvfrom(BUFFER_SIZE)
        dns_reply = DNSMessage()
        dns_reply.copy_header(buffer)
        dns_reply.copy_question(buffer)
        dns_reply.set_answer(buffer)

        print("==> DNS message reply header:")
        print(dns_reply.header_entries())
        print("==> DNS message reply question:")
        print(dns_reply.question_entries())
        print("==> DNS message reply answer:")
        print(dns_reply.answer_entries())

        buffer_length = len(buffer)
        response: bytes = dns_reply.header_bytes()
        response += dns_reply.question_bytes(buffer_length)
        response += dns_reply.answer_bytes(buffer_length)

        udp_socket.sendto(response, source)
        print("==> Sent DNS message reply:")
        print(response)

if __name__ == "__main__":
    main()
