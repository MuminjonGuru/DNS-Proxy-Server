# DNS Proxy Server with Merged Responses

This project is a Python-based implementation of a lightweight DNS proxy server that forwards DNS queries to an upstream resolver and merges the responses. The application uses the `socket` and `struct` libraries for low-level network communication and binary data parsing.

## Features

- **DNS Header Parsing:** Extracts and interprets critical fields like packet ID, flags, and section counts from DNS headers.
- **Question Section Parsing:** Supports parsing and encoding domain names in DNS queries.
- **Recursive Label Decoding:** Handles both uncompressed and compressed domain name labels as per the DNS protocol specification.
- **Response Forwarding:** Forwards individual DNS questions to an upstream resolver and aggregates their responses.
- **Response Merging:** Combines multiple DNS answers into a single response packet.
- **Customizable Resolver:** Allows users to specify the upstream resolver's IP and port.

## How It Works

1. **Parsing DNS Queries:** 
   - The DNS query is parsed to extract the header and question sections.
   - Each question is isolated for individual processing.

2. **Forwarding Queries:**
   - Queries are forwarded to the specified resolver using UDP.
   - A timeout mechanism ensures the server does not hang on unresponsive resolvers.

3. **Merging Responses:**
   - The responses from the resolver are parsed to extract the answer sections.
   - The server constructs a single response packet by combining all the answers.

4. **Serving Clients:**
   - The server listens on `127.0.0.1:2053` for incoming DNS queries.
   - It responds with the merged results for the forwarded queries.

## Usage

To run the DNS proxy server, execute the script with the following command:

```bash
python dns_proxy.py --resolver <ip>:<port>
```

- Replace <ip> with the IP address of the upstream resolver.
- Replace <port> with the port number of the resolver (e.g., 53 for DNS).

```bash
python dns_proxy.py --resolver 8.8.8.8:53
```

## Limitations
- Supports only single-question queries in a single packet
- Works with UDP-based DNS queries, not TCP

## Future Improvements
- Add support for TCP-based DNS queries.
- Implement caching for frequently queried domains.
- Extend support for multi-question DNS queries.

## Resources
- [RFC Section 4.1.4](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4)
- [DNS Guide](https://github.com/EmilHernvall/dnsguide/blob/b52da3b32b27c81e5c6729ac14fe01fef8b1b593/chapter1.md)

