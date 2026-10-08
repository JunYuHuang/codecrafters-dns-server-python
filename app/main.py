#
# IMPORTS
#
import socket
import copy

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
        #
        # HEADER section
        #
        self.header: dict = {
            "ID": 0,        # packet identifier (16 bits = 2 bytes)
            "QR": 1,        # query / response indicator (1 bit)
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

    def build_header_from(self, dns_query: bytes) -> None:
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

        self.set_header(data)

    # TODO: to test
    def build_questions_from(self, dns_query: bytes) -> None:
        dns_query_length = len(dns_query)
        if dns_query_length <= HEADER_BYTES:
            return

        # Traverse bytes in Question section  
        question: dict = {}
        domain_labels = []      
        i = HEADER_BYTES
        questions_left = self.header["QDCOUNT"]

        while i < dns_query_length and questions_left > 0:
            # In question section, reached end of last entry (null byte)
            # Last entry is followed by 4 bytes = `QTYPE` (2B) + `QCLASS` (2B)
            if dns_query[i:i + 1] == b'\x00':
                # Add question entry
                question["QNAME"] = "." if not domain_labels else ".".join(domain_labels)
                question["QTYPE"] = int.from_bytes(
                    dns_query[i + 1:i + 3], byteorder='big'
                )
                question["QCLASS"] = int.from_bytes(
                    dns_query[i + 3:i + 5], byteorder='big'
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

            label_byte_1_int = int.from_bytes(dns_query[i:i + 1], byteorder='big')
            label_byte_1_str = int_to_binary_str(label_byte_1_int, 8)
            is_label_pointer = label_byte_1_str[:2] == "11"
            
            # Found compressed question entry
            if is_label_pointer:
                label_byte_2_int = int.from_bytes(dns_query[i + 1:i + 2], byteorder='big')
                offset = int("00" + label_byte_1_str[2:], 2) + label_byte_2_int
                while offset < dns_query_length and dns_query[offset:offset + 1] != b'\x00':
                    label_length = int.from_bytes(dns_query[offset:offset + 1], byteorder='big')
                    domain_labels.append(
                        dns_query[offset + 1:offset + label_length + 1].decode()
                    )
                    offset = offset + label_length + 1

                # Add question entry
                question["QNAME"] = "." if not domain_labels else ".".join(domain_labels)
                question["QTYPE"] = int.from_bytes(
                    dns_query[i + 2:i + 4], byteorder='big'
                )
                question["QCLASS"] = int.from_bytes(
                    dns_query[i + 4:i + 6], byteorder='big'
                )
                self.add_question(question)
                question = {}
                domain_labels = []

                i += 6
                questions_left -= 1
            # Found normal, uncompressed question entry
            else:
                label_length = label_byte_1_int
                domain_labels.append(dns_query[i + 1:i + label_length + 1].decode())
                i = i + label_length + 1

        self.set_header({ "QDCOUNT": len(self.questions) })

    def build_answers(self, dns_query: bytes) -> None:
        if len(dns_query) <= HEADER_BYTES:
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

    def question_bytes(self, dns_query_size: int) -> bytes:
        if dns_query_size <= HEADER_BYTES:
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

    def answer_bytes(self, dns_query_size: int) -> bytes:
        if dns_query_size <= HEADER_BYTES:
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
    udp_socket: socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((HOST, PORT))
    print(f"==> DNS Server running at {HOST}:{PORT}")
    
    while True:
        # `buffer`: bytes
        # `source`: (host: string, port: integer) because is a AF_INET socket (IPv4)
        buffer, source = udp_socket.recvfrom(BUFFER_SIZE)

        dns_reply = DNSMessage()
        dns_reply.build_header_from(buffer)
        dns_reply.build_questions_from(buffer)
        dns_reply.build_answers(buffer)

        print("==> DNS message response header:")
        print(dns_reply.header_entries())
        print("==> DNS message response question:")
        print(dns_reply.question_entries())
        print("==> DNS message response answer:")
        print(dns_reply.answer_entries())

        buffer_length = len(buffer)
        response: bytes = dns_reply.header_bytes()
        response += dns_reply.question_bytes(buffer_length)
        response += dns_reply.answer_bytes(buffer_length)

        udp_socket.sendto(response, source)
        print("==> Sent DNS message response:")
        print(response)

if __name__ == "__main__":
    main()
