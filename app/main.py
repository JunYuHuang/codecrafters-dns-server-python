#
# IMPORTS
#
import socket
import copy
import re
import sys
import random

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

def has_dns_resolver(argv: list[str]):
    if len(argv) != 3:
        return False
    if argv[1] != "--resolver":
        return False
    address = argv[2]
    if not address:
        return False
    ipv4, port = address.split(":")
    if len(ipv4) < 1 or len(port) < 1:
        return False
    port_regex = r'^(\d){1,5}$'
    if not re.match(port_regex, port):
        return False
    return True

def create_dns_packet_id(bit_length: int = 16) -> int:
    if type(bit_length) != int or bit_length < 1:
        bit_length = 16
    return random.randint(0, (2 ** bit_length - 1))

# See RFC 1035 for details: https://www.rfc-editor.org/info/rfc1035/#section-4.1
class DNSMessage:
    def __init__(self):
        #
        # HEADER section
        #
        self.header: dict = {
            "ID": 0,        # packet identifier (16 bits = 2 bytes)
            "QR": 1,        # query (0) / response (1) indicator (1 bit)
            "OPCODE": 0,    # operation code (4 bits)
            "AA": 0,        # authoritative answer (1 bit)
            "TC": 0,        # truncation (1 bit)
            "RD": 0,        # recursion desired (1 bit)
            "RA": 0,        # recursive available (1 bit)
            "Z": 0,         # reserved (3 bits)
            "RCODE": 0,     # response code (4 bits)
            "QDCOUNT": 0,   # question count (16 bits = 2 bytes)
            "ANCOUNT": 0,   # answer record count (16 bits = 2 bytes)
            "NSCOUNT": 0,   # authority record count (16 bits = 2 bytes)
            "ARCOUNT": 0    # additional record count (16 bits = 2 bytes)
        }

        #
        # QUESTION section
        #
        # Example question entry hashmap:
        # {
        #   "QNAME": "example.com", # name (variable-length bytes)
        #   "QTYPE": 0,             # type (2 bytes)
        #   "QCLASS": 0             # class (2 bytes)
        # }
        self.questions: list[dict] = []

        #
        # ANSWER section
        #
        # Example answer entry hashmap:
        # {
        #   "NAME": "example.com",  # name (variable-length bytes)
        #   "TYPE": 0,              # type (2 bytes)
        #   "CLASS": 0,             # class (2 bytes)
        #   "TTL": 0,               # time-to-live (4 bytes)
        #   "RDLENGTH": 0,          # length (2 bytes)
        #   "RDATA": "8.8.8.8"      # data (variable-length bytes)
        # }
        self.answers: list[dict] = []

    def set_header(self, field_to_values: dict) -> None:
        for field, value in field_to_values.items():
            self.header[field] = value

    def add_question(self, field_to_values: dict, index: int = -1) -> None:
        entry: dict = {}
        for field, value in field_to_values.items():
            entry[field] = copy.deepcopy(value)
        if index < 0 or index >= len(self.questions):
            self.questions.append(entry)
        else:
            self.questions[index] = entry
    
    def add_answer(self, field_to_values: dict, index: int = -1) -> None:
        entry: dict = {}
        for field, value in field_to_values.items():
            entry[field] = copy.deepcopy(value)
        if index < 0 or index >= len(self.answers):
            self.answers.append(entry)
        else:
            self.answers[index] = entry

    def build_header_from(self, dns_message: bytes) -> None:
        data: dict = {}
        data["ID"] = int.from_bytes(dns_message[:2], byteorder='big')

        # Extract flag bits from byte 3 in `dns_message`
        byte_3 = int.from_bytes(dns_message[2:3], byteorder='big')
        byte_3_str = int_to_binary_str(byte_3, 8)
        data["QR"] = int(byte_3_str[0:1], 2)
        data["OPCODE"] = int(byte_3_str[1:5], 2)
        data["AA"] = 0
        data["TC"] = 0
        data["RD"] = int(byte_3_str[7:8], 2)

        # Set flag bits for byte 4 in DNS reply
        data["RA"] = 0
        data["Z"] = 0
        data["RCODE"] = 0 if data["OPCODE"] == 0 else 4

        data["QDCOUNT"] = int.from_bytes(dns_message[4:6], byteorder='big')
        data["ANCOUNT"] = int.from_bytes(dns_message[6:8], byteorder='big')
        data["NSCOUNT"] = int.from_bytes(
            dns_message[8:10], byteorder='big'
        )
        data["ARCOUNT"] = int.from_bytes(
            dns_message[10:12], byteorder='big'
        )

        self.set_header(data)

    def build_questions_from(self, dns_message: bytes) -> None:
        dns_message_length = len(dns_message)
        if dns_message_length <= HEADER_BYTES:
            return

        # Traverse bytes in Question section  
        question: dict = {}
        domain_labels = []      
        i = HEADER_BYTES
        questions_left = self.header["QDCOUNT"]

        while i < dns_message_length and questions_left > 0:
            # In question section, reached end of last entry (null byte)
            # Last entry is followed by 4 bytes = `QTYPE` (2B) + `QCLASS` (2B)
            if dns_message[i:i + 1] == b'\x00':
                # Add question entry
                question["QNAME"] = "." if not domain_labels else ".".join(domain_labels)
                question["QTYPE"] = int.from_bytes(
                    dns_message[i + 1:i + 3], byteorder='big'
                )
                question["QCLASS"] = int.from_bytes(
                    dns_message[i + 3:i + 5], byteorder='big'
                )
                self.add_question(question)
                question = {}
                domain_labels = []

                # Go to next (uncompressed) question entry which is 5 positions
                # ahead (current entry's `QTYPE` (2B) + `QCLASS` (2B) + first
                # length byte of next entry))
                i += 5
                questions_left -= 1
                continue

            label_byte_1_int = int.from_bytes(dns_message[i:i + 1], byteorder='big')
            label_byte_1_str = int_to_binary_str(label_byte_1_int, 8)
            is_label_pointer = label_byte_1_str[:2] == "11"
            
            # Found compressed question entry
            if is_label_pointer:
                label_byte_2_int = int.from_bytes(
                    dns_message[i + 1:i + 2], byteorder='big'
                )
                offset = int("00" + label_byte_1_str[2:], 2) + label_byte_2_int
                while (
                    offset < dns_message_length and
                    dns_message[offset:offset + 1] != b'\x00'
                ):
                    label_length = int.from_bytes(
                        dns_message[offset:offset + 1], byteorder='big'
                    )
                    domain_labels.append(
                        dns_message[offset + 1:offset + label_length + 1].decode()
                    )
                    offset = offset + label_length + 1

                # Add question entry
                question["QNAME"] = "." if not domain_labels else ".".join(domain_labels)
                question["QTYPE"] = int.from_bytes(
                    dns_message[i + 2:i + 4], byteorder='big'
                )
                question["QCLASS"] = int.from_bytes(
                    dns_message[i + 4:i + 6], byteorder='big'
                )
                self.add_question(question)
                question = {}
                domain_labels = []

                i += 6
                questions_left -= 1
            # Found normal, uncompressed question entry
            else:
                label_length = label_byte_1_int
                domain_labels.append(
                    dns_message[i + 1:i + label_length + 1].decode()
                )
                i = i + label_length + 1

        self.set_header({ "QDCOUNT": len(self.questions) })

    def build_dummy_answers(self, dns_message: bytes) -> None:
        if len(dns_message) <= HEADER_BYTES:
            print("Error: DNS message has header only")
            return

        for question in self.questions:
            answer: dict = {
                "NAME": str(question["QNAME"]),
                "TYPE": question["QTYPE"],
                "CLASS": question["QCLASS"],
                "TTL": 60,
                "RDATA": "8.8.8.8"
            }
            answer["RDLENGTH"] = len(answer["RDATA"].split("."))
            self.add_answer(answer)

        self.set_header({ "ANCOUNT": len(self.answers) })

     # TODO: to fix
    def build_real_answer(self, dns_response: bytes) -> None:
        dns_response_length = len(dns_response)
        if dns_response_length <= HEADER_BYTES:
            print("Error: DNS message has header only")
            return

        # TODO: to fix
        i = HEADER_BYTES + len(self.question_bytes(dns_response_length))
        answer = {}
        domain_labels = []

        while i < dns_response_length:
            # In answer section, reached end of last label in domain name (null byte)
            # Domain name field `NAME` is followed by the following in order:
            # - `TYPE` (2 bytes)
            # - `CLASS` (2 bytes)
            # - `TTL` (4 bytes)
            # - `RDLENGTH` (2 bytes)
            # - `RDATA` (variable-length bytes)
            if dns_response[i:i + 1] == b'\x00':
                # Add answer entry
                answer["NAME"] = "." if not domain_labels else ".".join(domain_labels)
                answer["TYPE"] = int.from_bytes(
                    dns_response[i + 1:i + 3], byteorder='big'
                )
                answer["CLASS"] = int.from_bytes(
                    dns_response[i + 3:i + 5], byteorder='big'
                )
                answer["TTL"] = int.from_bytes(
                    dns_response[i + 5:i + 9], byteorder='big'
                )

                # Should always be 4 because we assume answer entry is always an
                # A-record
                answer["RDLENGTH"] = int.from_bytes(
                    dns_response[i + 9:i + 11], byteorder='big'
                )
                break

            label_length = int.from_bytes(dns_response[i:i + 1], byteorder='big')
            domain_labels.append(dns_response[i + 1:i + label_length + 1].decode())
            i = i + label_length + 1

        # Deserialize `RDATA` bytes into an IPv4 address string because we assume
        # `dns_response` always contains an A-record answer entry
        ipv4_octets = []
        i += 11

        for j in range(answer["RDLENGTH"]):
            ipv4_octets.append(str
                (int.from_bytes(dns_response[i + j:i + j + 1], byteorder='big')
            ))
        answer["RDATA"] = ipv4_octets.join(".")

        self.add_answer(answer)
        self.set_header({ "ANCOUNT": len(self.answers) })

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

    def question_bytes(self, dns_message_size: int) -> bytes:
        if dns_message_size <= HEADER_BYTES:
            return b''

        res = b''
        for question in self.questions:
            QNAME_bytes = b''
            domain_labels = question["QNAME"].split(".")
            for label in domain_labels:
                QNAME_bytes += len(label).to_bytes(length=1, byteorder='big')
                QNAME_bytes += label.encode()
            QNAME_bytes += b'\0'

            QTYPE_bytes = question["QTYPE"].to_bytes(length=2, byteorder='big')
            QCLASS_bytes = question["QCLASS"].to_bytes(length=2, byteorder='big')

            res += (QNAME_bytes + QTYPE_bytes + QCLASS_bytes)

        return res

    def answer_bytes(self, dns_message_size: int) -> bytes:
        if dns_message_size <= HEADER_BYTES:
            return b''

        res = b''
        for answer in self.answers:
            NAME_bytes = b''
            domain_labels = answer["NAME"].split(".")
            for label in domain_labels:
                NAME_bytes += len(label).to_bytes(length=1, byteorder='big')
                NAME_bytes += label.encode()
            NAME_bytes += b'\0'

            TYPE_bytes = answer["TYPE"].to_bytes(length=2, byteorder='big')
            CLASS_bytes = answer["CLASS"].to_bytes(length=2, byteorder='big')
            TTL_bytes = answer["TTL"].to_bytes(length=4, byteorder='big')
            RDLENGTH_bytes = answer["RDLENGTH"].to_bytes(length=2, byteorder='big')

            RDATA_bytes = b''
            ipv4_octets = answer["RDATA"].split(".")
            for octet in ipv4_octets:
                RDATA_bytes += int(octet).to_bytes(length=1, byteorder='big')

            res += (
                NAME_bytes + TYPE_bytes + CLASS_bytes +
                TTL_bytes + RDLENGTH_bytes + RDATA_bytes
            )
        
        return res

    def header_entries(self) -> dict:
        res = {}
        keys = [
            "ID", "QR", "OPCODE", "AA", "TC", "RD", "RA", "Z", "RCODE",
            "QDCOUNT", "ANCOUNT", "NSCOUNT", "ARCOUNT"
        ]
        for key in keys:
            res[key] = self.header[key]
        return res

    def question_entries(self) -> dict:
        res = []
        keys = ["QNAME", "QTYPE", "QCLASS"]
        for question in self.questions:
            entry = {}
            for key in keys:
                entry[key] = copy.deepcopy(question[key])
            res.append(entry)
        return res

    def answer_entries(self) -> dict:
        res = []
        keys = ["NAME", "TYPE", "CLASS", "TTL", "RDLENGTH", "RDATA"]
        for answer in self.answers:
            entry = {}
            for key in keys:
                entry[key] = copy.deepcopy(answer[key])
            res.append(entry)
        return res

def main():
    server_udp_socket: socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_udp_socket.bind((HOST, PORT))
    print(f"==> DNS Server listening to clients at {server_udp_socket.getsockname()}")

    resolver_address: tuple = ()
    client_udp_socket: socket = None
    is_forwarding_queries = has_dns_resolver(sys.argv)

    if is_forwarding_queries:
        resolver_ipv4, resolver_port = sys.argv[2].split(":")
        resolver_address = (resolver_ipv4, int(resolver_port))
        print(f"==> DNS Resolver is at {resolver_address}")

        client_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_udp_socket.settimeout(5)

        # Socket address tuple `("", 0)` asks OS to choose an available
        # local IP address and available network port
        client_udp_socket.bind(("", 0))
        print((
            "==> DNS Server listening to upstream DNS resolver at " +
            f"{client_udp_socket.getsockname()}" 
        ))
    
    while True:
        # `query_bytes`: bytes
        # `source`: (host: string, port: integer) because is a AF_INET socket (IPv4)
        query_bytes, source = server_udp_socket.recvfrom(BUFFER_SIZE)
        query_bytes_length = len(query_bytes)

        response_obj = DNSMessage()
        response_obj.build_header_from(query_bytes)
        response_obj.set_header({ "QR": 1 })
        response_obj.build_questions_from(query_bytes)

        if is_forwarding_queries:
            for question in response_obj.questions:
                # Build DNS query to forward to DNS resolver server
                forwarded_query_obj = DNSMessage()
                forwarded_query_obj.build_header_from(query_bytes)
                forwarded_query_obj.set_header(
                    { "ID": create_dns_packet_id(), "QR": 0, "QDCOUNT": 1 }
                )
                forwarded_query_obj.add_question(question)
                forwarded_query_bytes: bytes = forwarded_query_obj.header_bytes()
                forwarded_query_bytes += forwarded_query_obj.question_bytes(
                    query_bytes_length
                )

                # DEBUG logs
                print((
                    "==> To DNS resolver: DNS message query (header + " +
                    "question + answer) deserialized & as bytes:"
                ))
                print(forwarded_query_obj.header_entries())
                print(forwarded_query_obj.question_entries())
                print(forwarded_query_obj.answer_entries())
                print(forwarded_query_bytes)

                # Send query to DNS resolver
                print(f"==> DNS resolver address: {resolver_address}")
                client_udp_socket.sendto(forwarded_query_bytes, resolver_address)
                forwarded_response_bytes, dns_resolver = client_udp_socket.recvfrom(BUFFER_SIZE)
                
                # Build DNS response from DNS resolver server
                forwarded_response_obj = DNSMessage()
                forwarded_response_obj.build_header_from(forwarded_response_bytes)
                forwarded_response_obj.build_questions_from(
                    forwarded_response_bytes
                )

                # TODO: fix method `DNSMessage.build_real_answer()`
                # forwarded_response_obj.build_real_answer(forwarded_response_bytes)

                # # Add answer entry to DNS response to send to original sender
                # response_obj.add_answer(forwarded_response_obj.answers[-1])
                
                # DEBUG logs
                print((
                    "==> From DNS resolver: DNS message response (header + " +
                    "question + answer) deserialized & as bytes:"
                ))
                print(forwarded_response_obj.header_entries())
                print(forwarded_response_obj.question_entries())
                print(forwarded_response_obj.answer_entries())
                print(forwarded_response_bytes)

            # TODO: Comment out below line once we verify received DNS response
            # from DNS resolver is parsed correctly
            # response_obj.build_real_answer(forwarded_response_bytes)
        else:
            response_obj.build_dummy_answers(query_bytes)

        response_bytes: bytes = response_obj.header_bytes()
        response_bytes += response_obj.question_bytes(query_bytes_length)
        response_bytes += response_obj.answer_bytes(query_bytes_length)

        server_udp_socket.sendto(response_bytes, source)

        # DEBUG logs
        print((
            "==> To client: DNS message response (header + " +
            "question + answer) deserialized & as bytes:"
        ))
        print(response_obj.header_entries())
        print(response_obj.question_entries())
        print(response_obj.answer_entries())
        print(response_bytes)

if __name__ == "__main__":
    main()