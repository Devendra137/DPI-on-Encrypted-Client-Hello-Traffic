from scapy.all import *
import struct
import os

# Define extension types to remove for Client Hello
EXTENSIONS_DATA_TO_REMOVE = [0x0000]  # Server Name Indication (SNI)

def modify_tls_client_hello(payload, version, record_length):
    try:
        if len(payload) > 5:
            content_type = payload[0]

            if content_type == 0x16:  # TLS Handshake
                handshake_type = payload[5]
                handshake_length = struct.unpack('>I', b'\x00' + payload[6:9])[0]

                if handshake_type == 0x01:  # Client Hello
                    client_hello_start = 9
                    client_hello_end = client_hello_start + handshake_length
                    client_hello = payload[client_hello_start:client_hello_end]

                    if len(client_hello) < 34:
                        return payload

                    # Extracting Client Hello fields
                    protocol_version = client_hello[:2]
                    random = client_hello[2:34]
                    session_id_length = client_hello[34]
                    session_id_end = 35 + session_id_length
                    session_id = client_hello[35:session_id_end]

                    cipher_suites_start = session_id_end
                    cipher_suites_length = struct.unpack('>H', client_hello[cipher_suites_start:cipher_suites_start + 2])[0]
                    cipher_suites_end = cipher_suites_start + 2 + cipher_suites_length
                    cipher_suites = client_hello[cipher_suites_start + 2:cipher_suites_end]

                    compression_methods_start = cipher_suites_end
                    compression_methods_length = client_hello[compression_methods_start]
                    compression_methods_end = compression_methods_start + 1 + compression_methods_length
                    compression_methods = client_hello[compression_methods_start + 1:compression_methods_end]

                    # Extensions
                    extensions_start = compression_methods_end
                    extensions_length = struct.unpack('>H', client_hello[extensions_start:extensions_start + 2])[0]
                    extensions = client_hello[extensions_start + 2:extensions_start + 2 + extensions_length]

                    filtered_extensions = bytearray()
                    pos = 0

                    while pos < len(extensions):
                        ext_type = extensions[pos:pos + 2]
                        ext_length = struct.unpack('>H', extensions[pos + 2:pos + 4])[0]
                        ext_data = extensions[pos + 4:pos + 4 + ext_length]

                        if ext_type == b'\x00\x00':  # Server Name Indication (SNI)
                            # Padding SNI data with zeros
                            filtered_extensions.extend(ext_type)
                            filtered_extensions.extend(struct.pack('>H', ext_length))
                            filtered_extensions.extend(b'\x00' * ext_length)  # Zero padding
                        else:
                            # Keeping other extensions
                            filtered_extensions.extend(ext_type)
                            filtered_extensions.extend(struct.pack('>H', ext_length))
                            filtered_extensions.extend(ext_data)

                        pos += 4 + ext_length

                    new_extensions_length = len(filtered_extensions)
                    new_handshake_length = handshake_length
                    new_record_length = record_length

                    # Zero out the first four bytes of the random field
                    new_random = b'\x00\x00\x00\x00' + random[4:]

                    # Update Client Hello
                    new_client_hello = (
                        protocol_version + new_random +
                        bytes([session_id_length]) + session_id +
                        struct.pack('>H', len(cipher_suites)) + cipher_suites +
                        bytes([compression_methods_length]) + compression_methods +
                        struct.pack('>H', new_extensions_length) +
                        filtered_extensions
                    )

                    
                    new_handshake_length_bytes = struct.pack('>I', new_handshake_length)[1:]

                    
                    new_payload = (
                        bytes([content_type]) +
                        struct.pack('>H', version) +
                        struct.pack('>H', new_record_length) +
                        bytes([handshake_type]) +
                        new_handshake_length_bytes +  
                        new_client_hello
                    )

                    return new_payload
    except Exception as e:
        print(f"Error processing Client Hello: {e}")
    return payload

def modify_pcap(input_dir, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for filename in os.listdir(input_dir):
        if filename.endswith('.pcap'):
            input_file = os.path.join(input_dir, filename)
            output_file = os.path.join(output_dir, filename)

            try:
                packets = rdpcap(input_file)
                modified_packets = []

                for packet in packets:
                    if packet.haslayer(Raw):
                        payload = bytes(packet[Raw].load)
                        content_type = payload[0]

                        # Extracting TLS record version and length
                        if len(payload) > 5:
                            version = struct.unpack('>H', payload[1:3])[0]
                            record_length = struct.unpack('>H', payload[3:5])[0]

                            
                            if content_type == 0x16:  # TLS Handshake
                                handshake_type = payload[5]

                                if handshake_type == 0x01:  # Client Hello
                                    new_payload = modify_tls_client_hello(payload, version, record_length)
                                    packet[Raw].load = new_payload

                    modified_packets.append(packet)

                wrpcap(output_file, modified_packets)
            except Exception as e:
                print(f"Error processing file '{filename}': {e}")


modify_pcap('Extracted', 'New_ESNI_Dataset')
