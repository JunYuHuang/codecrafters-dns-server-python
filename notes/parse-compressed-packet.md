# Notes:

- PEDAC: Problem
    - input:
        - `dns_query`: bytes that represents a UDP packet containing a DNS query packet
            - sent to DNS server at port (TCP or UDP?) 2053
    - output:
        - `dns_reply`: bytes that represent a UDP packet containing a DNS reply packet to host machine that sent the DNS server `dns_query`
    - side effects:
        - TODO
    - questions
        - what does a DNS message question section with 2+ question entries look like?
            - reflected in header section field `QDCOUNT`
            - each entry =
                - `QNAME` (variable-length bytes) +
                    - each label = label length as 1 byte + label encoded as bytes
                    - ends with a null byte `\0`
                - `QTYPE` (2 bytes) +
                - `QCLASS` (2 bytes)
            - if have 2+ question entries, they are all guaranteed to have the same `QTYPE` and `QCLASS` values?
                no
        - how to parse compressed question entries with compressed label sequences (per RFC 1035 section 4.1.4)?
            - todo
        - compressed question entry will never be the first question entry
            - b/c compression relies on an existing uncompressed question entry's label sequence
    - DNS message
        - structure (for both requests and replies): 12 bytes long
            - = header +
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
    - ex2. parsing a DNS message query's question section with 1 uncompressed + 1 compressed question entries
        ```

                                1 1 1   1 1 1 1   1  1    1   2
        0   1 2 3 4   5 6 7 8 9 0 1 2   3 4 5 6   7  8    9   0
        0x3 w w w 0x6 e x a m p l e 0x3 c o m 0x0 [QTYPE] [QCLASS]


        2   2 2 2 2 2                        2     2  2    3   3
        1   2 3 4 5 6                        7     8  9    0   1
        0x4 m a i l [0xc0 = 2^7 + 2^6 = 192] [0x4] [QTYPE] [QCLASS]
                    |____________________________|
                     V
                     label pointer (2 Bytes) =
                        2 '1' bits +
                        offset byte position (in DNS query)
        ```
        - confirm if this example is correct per [RFC 1035 section 4.1.4](https://www.rfc-editor.org/info/rfc1035/#section-4.1.4)
- PEDAC: Data Structures And Algorithms
    - parse DNS message query header section:
        - class method `DNSMessage.build_questions_from(dns_query: bytes) -> void`
        - set int `i` to 12 (bytes in DNS query header)
        - set int `questions_left` to `QDCOUNT` value
        - set `question` to empty hashmap
        - set `domain_labels` to empty array
        - set `dns_query_length` to length of `dns_query`
        - while `i` < `dns_query_length` and `questions_left` > 0,
            - todo
