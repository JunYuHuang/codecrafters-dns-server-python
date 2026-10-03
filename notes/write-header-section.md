# Notes:

- PEDAC: Problem
    - input:
        - `udp_packet`: UDP packet containing a DNS query packet
            - sent to DNS server at port (TCP or UDP?) 2053
    - output:
        - `dns_reply`: UDP packet containing a DNS reply packet to host machine that sent the DNS server `udp_packet`
            - only contains DNS header; no DNS body
    - side effects:
        - N/A
    - DNS message
        - structure (for both requests and replies): 12 bytes long
            - = header +
                - = packet identifier (ID) +
                    - 16 bits = 2 bytes
                - query / response indicator (QR) + 
                    - 1 bit = 1/8 byte
                - operation code (OPCODE) +
                    - 4 bits = 1/2 byte
                - authoritative answer (AA) +
                    - 1 bit = 1/8 byte
                - truncation (TC) +
                    - 1 bit = 1/8 byte
                - recursion desired (RD) +
                    - 1 bit = 1/8 byte
                - recursion available (RA) +
                    - 1 bit = 1/8 byte
                - reserved (Z) +
                    - 1 bit = 1/8 byte
                - response code (RCODE) +
                    - 4 bits = 1/2 byte
                - question count (QDCOUNT) +
                    - 16 bits = 2 bytes
                - answer record count (ANCOUNT) +
                    - 16 bits = 2 bytes
                - authority record count (NSCOUNT) +
                    - 16 bits = 2 bytes
                - additional record count (ARCOUNT)
                    - 16 bits = 2 bytes
            - question +
            - answer +
            - authority +
            - space
        - integers are in big-endian (stores most significant bit first) format
- PEDAC: Examples
    - ex1. test running DNS server
        - in terminal 1:
            ```
            sh your_program.sh
            ```
        - in terminal 2:
            ```
            dig @127.0.0.1 -p 2053 +noedns codecrafters.io

            ; <<>> DiG 9.18.39-0ubuntu0.24.04.7-Ubuntu <<>> @127.0.0.1 -p 2053 +noedns codecrafters.io
            ; (1 server found)
            ;; global options: +cmd
            ;; Got answer:
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32963
            ;; flags: qr; QUERY: 0, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

            ;; Query time: 0 msec
            ;; SERVER: 127.0.0.1#2053(127.0.0.1) (UDP)
            ;; WHEN: Sat Oct 03 14:17:52 PDT 2026
            ;; MSG SIZE  rcvd: 12
            ```
- PEDAC: Data Structures And Algorithms
    - set `buffer` to data of UDP packet received from a sender client
    - get `packet_id` int field from header of `buffer` DNS message
        - how?
    - set `dns_message_reply` to new `DNSMessage` object
    - set `dns_message_reply`'s `id` field to `packet_id`
    - set bytesarray `dns_message_reply_bytes` to `dns_message_reply.header_bytes()`
    - send `dns_message_reply_bytes` to sender of DNS message in UDP packet stored in `buffer`
    - helper methods:
        - `int_to_binary_str(integer: int, bits_length: int): string` method:
            - returns integer `integer` as its binary representation of length `bits_length` as a string
        - `udp_bytes_to_dns_header(udp_packet: bytes): dict[str -> int]` method:
            - returns hashmap / dictionary of field-value entries in the DNS message of the `udp_packet` bytes object / buffer
    - helper class with methods:
        - `DNSMessage`
            - `header_bytes(): bytes` method: returns DNS message header as 12 bytes
                - set bytes `ID_bytes` to `int_to_bytes(get_header("ID"))`
                - build the 2nd 2 bytes (bytes 3 and 4) in the DNS message header:
                    - set string `QR_bits_str` to `int_to_binary_str(this.get_header("QR"), 1)`
                    - do likewise for header fields `OPCODE`, `AA`, `TC`, `RD`, `RA`, `Z`, `RCODE` ...
                    - set `flags_bits_str` to all substrings above concatenated together
                    - set `flags_bytes` to `flag_bits_str` converted to bytes
                - set bytes `QDCOUNT_bytes` to `int_to_bytes(get_header("QDCOUNT"))`
                - set bytes `ANCOUNT_bytes` to `int_to_bytes(get_header("ANCOUNT"))`
                - set bytes `NSCOUNT_bytes` to `int_to_bytes(get_header("NSCOUNT"))`
                - set bytes `ARCOUNT_bytes` to `int_to_bytes(get_header("ARCOUNT"))`
                - return bytes object that concatenates in order:
                    - `ID_bytes` + `flag_bytes` + ... + `ARCOUNT_bytes`
            - `constructor(): DNSMessage` constructor:
                - creates a `DNSMessage` object and returns a reference to it
            - `set_header(field_to_int: dict[string -> int]): null` method:
                - sets a DNS header field from a (string to integer) dictionary or hashmap
            - `get_header(field: string): int` method:
                - returns int value for a valid `field` in `DNSMessage` object
                - returns -1 if `field` doesn't exist
            - `int_to_bytes(integer: int): bytes` method:
                - returns a bytesarray for a given integer