from scapy.all import *
import struct
import os

# Defining extension types which we keep for Client Hello and Server Hello
KEY_SHARE_EXTENSION_TYPE = b'\x00\x33'
PRE_SHARED_KEY_EXTENSION_TYPE = b'\x00\x29' 
SUPPORTED_VERSIONS_EXTENSION_TYPE = b'\x00\x2b' 
GREASE_EXTENSION_TYPES = [
   
]
EXTENSIONS_TO_REMOVE = [0x0010,  # Application Layer Protocol Negotiation (ALPN)
                        0x001a,  # Signed Certificate Timestamp (SCT)
                        0x002f,  # Post-Handshake Authentication
                        0x0000]
def modify_tls_client_hello(payload, version, record_length):
    if len(payload) > 5:
        content_type = payload[0]

        if content_type == 22:  
            handshake_type = payload[5]
            handshake_length = struct.unpack('>I', b'\x00' + payload[6:9])[0]

            if handshake_type == 1:  
                client_hello_start = 9
                client_hello_end = client_hello_start + handshake_length
                client_hello = payload[client_hello_start:client_hello_end]

                if len(client_hello) < 34:
                    return payload

                
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
                total_length_removed = 0

                while pos < len(extensions):
                    ext_type = extensions[pos:pos + 2]
                    ext_length = struct.unpack('>H', extensions[pos + 2:pos + 4])[0]
                    ext_data = extensions[pos + 4:pos + 4 + ext_length]

                    # Check for GREASE extensions
                    if ext_type in GREASE_EXTENSION_TYPES:
                        filtered_extensions.extend(ext_type)
                        filtered_extensions.extend(struct.pack('>H', ext_length))
                        filtered_extensions.extend(ext_data)
                    elif ext_type in (KEY_SHARE_EXTENSION_TYPE, PRE_SHARED_KEY_EXTENSION_TYPE, SUPPORTED_VERSIONS_EXTENSION_TYPE):
                        # Keep specified extensions
                        filtered_extensions.extend(ext_type)
                        filtered_extensions.extend(struct.pack('>H', ext_length))
                        filtered_extensions.extend(ext_data)
                    else:
                        # Removing this extension
                        total_length_removed += 4 + ext_length

                    pos += 4 + ext_length

                new_extensions_length = len(filtered_extensions)
                new_handshake_length = handshake_length - total_length_removed
                new_record_length = record_length - total_length_removed

                # Zero out the first four bytes of the random field
                new_random = b'\x00\x00\x00\x00' + random[4:]

                
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
    return payload

def modify_tls_server_hello(payload, version, record_length):
    if len(payload) > 5:
        content_type = payload[0]

        if content_type == 0x16:  # TLS Handshake
            handshake_type = payload[5]
            handshake_length = struct.unpack('>I', b'\x00' + payload[6:9])[0]

            if handshake_type == 0x02:  # Server Hello
                server_hello_start = 9
                server_hello_end = server_hello_start + handshake_length
                server_hello = payload[server_hello_start:server_hello_end]

                if len(server_hello) < 34:
                    return payload

                # Extract Server Hello fields
                protocol_version = server_hello[:2]
                random = server_hello[2:34]
                session_id_length = server_hello[34]
                session_id_end = 35 + session_id_length
                cipher_suite = server_hello[session_id_end:session_id_end + 2]
                compression_method = server_hello[session_id_end + 2]

                # Offset of Extensions Length
                extensions_length_offset = session_id_end + 3
                extensions_length = struct.unpack('>H', server_hello[extensions_length_offset:extensions_length_offset + 2])[0]
                extensions_start = extensions_length_offset + 2
                extensions_end = extensions_start + extensions_length

                # Process and filter extensions
                extensions = server_hello[extensions_start:extensions_end]
                filtered_extensions = bytearray()
                pos = 0
                total_length_removed = 0

                while pos < len(extensions):
                    ext_type = struct.unpack('>H', extensions[pos:pos + 2])[0]
                    ext_length = struct.unpack('>H', extensions[pos + 2:pos + 4])[0]
                    ext_data = extensions[pos + 4:pos + 4 + ext_length]

                    if ext_type in EXTENSIONS_TO_REMOVE:
                        
                        total_length_removed += 4 + ext_length
                    else:
                        # Keeping specified extensions
                        filtered_extensions.extend(extensions[pos:pos + 4 + ext_length])

                    pos += 4 + ext_length

                new_extensions_length = len(filtered_extensions)
                new_handshake_length = handshake_length - total_length_removed
                new_record_length = record_length - total_length_removed

                # Zero out the first four bytes of the random field
                new_random = b'\x00\x00\x00\x00' + random[4:]

               
                new_server_hello = (
                    protocol_version + new_random +
                    bytes([session_id_length]) + server_hello[35:session_id_end] +
                    cipher_suite +
                    bytes([compression_method]) +
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
                    new_server_hello
                )

                return new_payload
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
                                handshake_length = struct.unpack('>I', b'\x00' + payload[6:9])[0]

                                if handshake_type == 0x01:  # Client Hello
                                    new_payload = modify_tls_client_hello(payload, version, record_length)
                                    packet[Raw].load = new_payload
                                elif handshake_type == 0x02:  # Server Hello
                                    new_payload = modify_tls_server_hello(payload, version, record_length)
                                    packet[Raw].load = new_payload

                    modified_packets.append(packet)

                wrpcap(output_file, modified_packets)

            except Exception as e:
                print(f"Error processing file {filename}: {e}")
                continue  


modify_pcap('WNL_Dataset_Processed', 'ECH_Dataset')
