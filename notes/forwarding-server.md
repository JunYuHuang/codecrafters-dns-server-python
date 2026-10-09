# Notes:

- PEDAC: Problem
    - input:
        - `dns_query`: bytes that represents a UDP packet containing a DNS query packet
            - sent to DNS server at port UDP 2053
            - includes these DNS message sections:
                - header (12 bytes)
                - question section
                    - will have 1+ `A` record question entries
            - excludes these DNS message sections:
                - answer section
                - authority section
                - additional section
        - `--resolver <address>`: 2 space-delimited strings that are passed as command-line arguments when the (DNS server) program starts
            - `<address>`: string of the format `<ip>:<port>` that represents another DNS server the program forwards its queries to fetch `A` records (i.e., entries in the answer section for all the question entries in the original DNS query)
                - `<ip>`: string that represents a valid IPv4 address e.g., `8.8.8.8`
                - `<port>`: string that represents a valid network port number e.g., `2053`
    - output:
        - `dns_reply`: bytes that represent a UDP packet containing a DNS reply packet to host machine that sent the DNS server `dns_query`
            - includes these DNS message sections:
                - header (12 bytes)
                - question section
                    - will have 1+ `A` record question entries
                - answer section
                    - will have 1+ answer entries (depends on question entries)
            - excludes these DNS message sections:
                - authority section
                - additional section
    - side effects:
        - if program is run with CLI arguments `--resolver <address>`,
            - sends DNS query `dns_query` to DNS server at `<address>`
            - gets DNS response from DNS server at `<address>`
            - sends DNS response from DNS server at `<address>` to sender of original DNS query `dns_query`
    - questions:
        - does packet ID need to be unique for every single-question DNS query sent to the upstream DNS resolver server (instead of being copied from the sender's initial DNS query)?
            - should be yes because don't how long it will take to receive the DNS response (via UDP) from the upstream DNS resolver server
- PEDAC: Examples
    - ex1. test running DNS server
        - in terminal 1:
            ```
            sh your_program.sh --resolver 8.8.8.8:53
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
    - build bytes `dns_reply` from `dns_query`'s header section, question section, and answer section bytes
    - if program is run with CLI arguments `--resolver <address>`,
        - remove answer section bytes from `dns_reply`
        - loop `n` times from 0 to `dns_query`'s `QDCOUNT` as int inclusive,
            - set DNS query bytes `dns_single_query` to empty bytes
            - copy header bytes from `dns_query` to `dns_single_query`
            - set `dns_single_query`'s header bytes' field `QDCOUNT` to 1 in binary
            - copy and append `n`th-indexed question entry bytes from `dns_query` to `dns_single_query`
            - send DNS query bytes `dns_single_query` to DNS server at `<address>`
            - get DNS response bytes `forwarded_single_response` from DNS server at `<address>`
            - append `forwarded_single_response`'s answer section bytes to `dns_reply`
    - sends DNS response from DNS server at `<address>` to sender of original DNS query `dns_query`
