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
                    - possible values: [0, 1]
                        - 0 = query
                        - 1 = response
                - operation code (OPCODE) +
                    - 4 bits = 1/2 byte
                    - possible values: [0, 15]
                        - 0 = standard query (QUERY)
                        - 1 = inverse query (IQUERY)
                        - 2 = server status request (STATUS)
                        - 3-15 = future reserved
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
                    - possible values: [0, 5]
                        - 0 = no error
                        - 1 = format error
                        - 2 = server fail
                        - 3 = name error
                        - 4 = not implemented
                        - 5 = refused
                        - 6-15 = future reserved
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
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54252
            ;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
            ;; WARNING: recursion requested but not available

            ;; QUESTION SECTION:
            ;codecrafters.io.               IN      A

            ;; ANSWER SECTION:
            codecrafters.io.        60      IN      A       8.8.8.8

            ;; Query time: 0 msec
            ;; SERVER: 127.0.0.1#2053(127.0.0.1) (UDP)
            ;; WHEN: Tue Oct 06 08:25:22 PDT 2026
            ;; MSG SIZE  rcvd: 64
            ```
- PEDAC: Data Structures And Algorithms
    - get bits from byte 3 in the DNS message header byte stream `udp_packet`
        - flags in this byte, in order:
            - `QR` (1 bit)
            - `OPCODE` (4 bits)
            - `AA` (1 bit)
            - `TC` (1 bit)
            - `RD` (1 bit)
        - set int `QR_int` to 1
        - set int `OPCODE_int` to byte `udp_packet[2]` converted to 8-lengthed binary string at substring indice `[1..4]` as int
        - set int `AA_int` to 0
        - set int `TC_int` to 0
        - set int `RD_int` to byte `udp_packet[2]` converted to 8-lengthed binary string at substring indice `[7]` as int
    - get bits from byte 4 in the DNS message header byte stream `udp_packet`
        - flags in this byte, in order:
            - `RA` (1 bit)
            - `Z` (3 bits)
            - `RCODE` (4 bits)
        - set int `RA_int` to 0
        - set int `Z_int` to 0
        - set int `RCODE_int` to 0 if `OPCODE` is 0, else set to 4