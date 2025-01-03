from scapy.all import *
import struct

def extract_sni_from_client_hello(payload):
    try:
        if payload[0] == 0x16:  # TLS Handshake
            handshake_type = payload[5]
            if handshake_type == 0x01:  # Client Hello
                client_hello_start = 9
                handshake_length = struct.unpack('>I', b'\x00' + payload[6:9])[0]
                client_hello = payload[client_hello_start:client_hello_start + handshake_length]

                # Skip if not enough data in the Client Hello message
                if len(client_hello) < 34:
                    return None

                session_id_length_offset = 34
                session_id_length = client_hello[session_id_length_offset]
                session_id_end = session_id_length_offset + 1 + session_id_length

                # Locate extensions
                cipher_suites_length_offset = session_id_end
                cipher_suites_length = struct.unpack('>H', client_hello[cipher_suites_length_offset:cipher_suites_length_offset + 2])[0]
                cipher_suites_end = cipher_suites_length_offset + 2 + cipher_suites_length
                compression_methods_end = cipher_suites_end + 1 + client_hello[cipher_suites_end]

                extensions_offset = compression_methods_end + 2
                extensions_length = struct.unpack('>H', client_hello[compression_methods_end + 1:compression_methods_end + 3])[0]
                extensions_data = client_hello[extensions_offset:extensions_offset + extensions_length]

                # Extract SNI from extensions
                pos = 0
                while pos < len(extensions_data):
                    ext_type = struct.unpack('>H', extensions_data[pos:pos + 2])[0]
                    ext_length = struct.unpack('>H', extensions_data[pos + 2:pos + 4])[0]
                    if ext_type == 0x0000:  # SNI extension type
                        sni_len = struct.unpack('>H', extensions_data[pos + 9:pos + 11])[0]
                        sni = extensions_data[pos + 11:pos + 11 + sni_len].decode()
                        return sni
                    pos += 4 + ext_length
    except Exception as e:
        print(f"Error extracting SNI: {e}")
    return None

def extract_tls_handshakes(input_pcap):
    packets = rdpcap(input_pcap)
    sessions = {}  # Store Client Hello and Server Hello pairs

    for packet in packets:
        raw_payload = bytes(packet.payload)
        
        if len(raw_payload) > 5 and raw_payload.startswith(b'\x16\x03'):
            tls_version = raw_payload[1:3]

            # Skip TLS v1.0
            if tls_version == b'\x03\x01':
                continue
            
            handshake_type = raw_payload[5]
            if handshake_type == 0x01:  # Client Hello
                sni = extract_sni_from_client_hello(raw_payload)
                if sni and sni not in sessions:
                    sessions[sni] = {"client_hello": packet, "server_hello": None}

            elif handshake_type == 0x02:  # Server Hello
                for sni, session in sessions.items():
                    if session["client_hello"] and session["server_hello"] is None:
                        sessions[sni]["server_hello"] = packet
                        break

    # Save each Client Hello and Server Hello pair as a separate pcap file
    for sni, session in sessions.items():
        if session["client_hello"] and session["server_hello"]:
            output_pcap = f"{sni}.pcap"
            wrpcap(output_pcap, [session["client_hello"], session["server_hello"]])
            print(f"Saved handshake for SNI '{sni}' in {output_pcap}")

# Example usage
input_pcap = "input.pcap"  # Replace with the path to your input pcap file
extract_tls_handshakes(input_pcap)
