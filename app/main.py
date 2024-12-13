import socket
import struct
import sys


def parse_dns_header(buf):
    header = struct.unpack("!HHHHHH", buf[:12])
    return {
        "packet_id": header[0],
        "flags": header[1],
        "qd_count": header[2],
        "an_count": header[3],
        "ns_count": header[4],
        "ar_count": header[5],
    }


def parse_question_section(buf, offset, qd_count):
    questions = []
    for _ in range(qd_count):
        labels, offset = parse_label_sequence(buf, offset)
        domain_name = ".".join(labels)
        question_type, question_class = struct.unpack("!HH", buf[offset:offset + 4])
        offset += 4
        questions.append((domain_name, question_type, question_class))
    return questions, offset


def parse_label_sequence(buf, offset):
    labels = []
    while True:
        length = buf[offset]
        if length == 0:
            offset += 1
            break
        # Check for compressed labels
        if (length & 0xC0) == 0xC0:
            pointer = struct.unpack("!H", buf[offset:offset+2])[0] & 0x3FFF
            offset += 2
            # Recursively parse at the pointer location
            labels.extend(parse_label_sequence(buf, pointer)[0])
            break
        offset += 1
        labels.append(buf[offset:offset+length].decode())
        offset += length
    return labels, offset


def construct_dns_header(packet_id, flags, qd_count, an_count):
    # ns_count and ar_count are 0 for this example
    return struct.pack("!HHHHHH", packet_id, flags, qd_count, an_count, 0, 0)


def construct_question_section(domain_name, question_type, question_class):
    labels = domain_name.split(".")
    encoded_name = b""
    for label in labels:
        encoded_name += bytes([len(label)]) + label.encode()
    encoded_name += b"\x00"
    question_section = struct.pack("!HH", question_type, question_class)
    return encoded_name + question_section


def forward_single_query(resolver_ip, resolver_port, packet_id, flags, question):
    """
    Forward a single-question DNS query to the upstream resolver using the original flags.
    """
    query = construct_dns_header(packet_id, flags, 1, 0) + question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(query, (resolver_ip, resolver_port))
        response, _ = sock.recvfrom(512)
    return response


def merge_responses(packet_id, original_questions, responses):
    """
    Merge the question section from the original packet and all answer sections
    from the upstream responses into a single DNS response packet.
    """
    # Combine all original questions
    question_section = b"".join(
        construct_question_section(q[0], q[1], q[2]) for q in original_questions
    )

    all_answers = []
    flags = None
    for resp in responses:
        header = parse_dns_header(resp)
        if flags is None:
            flags = header["flags"]
        # Move offset past the header and question section of the response
        _, offset = parse_question_section(resp, 12, header["qd_count"])

        # Parse each answer for robustness
        answer_offset = offset
        for _ in range(header["an_count"]):
            # Parse name
            ans_labels, tmp_off = parse_label_sequence(resp, answer_offset)
            # Parse the rest of the RR
            atype, aclass, ttl, rdlength = struct.unpack("!HHIH", resp[tmp_off:tmp_off+10])
            tmp_off += 10
            rdata = resp[tmp_off:tmp_off+rdlength]
            tmp_off += rdlength

            # The entire RR (including name and fields) is from answer_offset to tmp_off
            rr_data = resp[answer_offset:tmp_off]
            all_answers.append(rr_data)

            answer_offset = tmp_off

    qd_count = len(original_questions)
    an_count = sum(parse_dns_header(resp)["an_count"] for resp in responses)

    # Construct merged DNS message
    merged_header = construct_dns_header(packet_id, flags, qd_count, an_count)
    merged_response = merged_header + question_section + b"".join(all_answers)
    return merged_response


def main():
    if len(sys.argv) != 3 or sys.argv[1] != "--resolver":
        print("Usage: ./your_server --resolver <ip>:<port>")
        sys.exit(1)

    resolver_arg = sys.argv[2]
    resolver_ip, resolver_port = resolver_arg.split(":")
    resolver_port = int(resolver_port)

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            print(f"Received data from {source}: {buf}")

            # Parse the DNS header and question section from the client's query
            header = parse_dns_header(buf)
            packet_id = header["packet_id"]
            original_flags = header["flags"]
            qd_count = header["qd_count"]

            questions, offset = parse_question_section(buf, 12, qd_count)

            responses = []
            for q in questions:
                single_question = construct_question_section(q[0], q[1], q[2])
                # Forward each question individually, preserving original flags
                resp = forward_single_query(resolver_ip, resolver_port, packet_id, original_flags, single_question)
                responses.append(resp)

            final_response = merge_responses(packet_id, questions, responses)
            udp_socket.sendto(final_response, source)

        except Exception as e:
            print(f"Error: {e}")
            break


if __name__ == "__main__":
    main()
