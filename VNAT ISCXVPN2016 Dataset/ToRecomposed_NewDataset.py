from scapy.all import *
import struct
import os
import csv

def extract_tls_extensions(hello_message, len_offset):
    """Extract TLS extensions from the Client Hello or Server Hello message."""
    extension_map = {}
    extensions = hello_message[len_offset :]  

    while len(extensions) >= 4:
        ext_type = struct.unpack('>H', extensions[:2])[0]
        ext_length = struct.unpack('>H', extensions[2:4])[0]

        
        if len(extensions) < 4 + ext_length:
            break

        # Storing the extension type, length, and data in the map
        ext_data = extensions[4:4 + ext_length]
        extension_map[ext_type] = (ext_length, list(ext_data))

        extensions = extensions[4 + ext_length:]  

    return extension_map

def add_extension_data(byte_array, extension_type, extension_data):
    """Add extension data to the byte array, padding or truncating as needed."""
    expected_lengths = {
        3: 2, 15: 2, 45: 2,       # Trusted
        27: 4, 30: 4, 6: 4, 11: 4, 19: 4,  # Compress Certificate
        20: 4, 50: 4, 43: 12, 10: 26, 13: 26,  # Server Cert type
        16: 4                       # ALPN
    }

    expected_length = expected_lengths.get(extension_type, 0)
    
    if extension_data:
        if len(extension_data) > expected_length:
            extension_data = extension_data[:expected_length]  # Truncating if too long
        else:
            extension_data += [0] * (expected_length - len(extension_data))    
    else:
        extension_data = [0] * expected_length  # Pad with zeros

    byte_array.extend(extension_data)

def create_byte_array(payload, hello_message, session_id_length, cipher_suites_content, compression_methods_length, extension_map, len_offset):
    """Create a byte array representation of the Client Hello or Server Hello message."""
    byte_array = bytearray()

    # Adding Record Version (2 bytes)
    byte_array.extend(payload[1:3])

    # Adding Record Length (2 bytes)
    byte_array.extend(payload[3:5])

    # Adding Message Length (3 bytes)
    message_length = len(hello_message)
    byte_array.extend([(message_length >> 16) & 0xFF, (message_length >> 8) & 0xFF, message_length & 0xFF])

    # Adding Message Version (2 bytes)
    byte_array.extend(hello_message[0:2])

    # Adding Session ID Length (1 byte)
    byte_array.append(session_id_length)

    # Adding Cipher Suites Length (2 bytes)
    cipher_suite_offset = 35 + session_id_length
    byte_array.extend(hello_message[cipher_suite_offset:cipher_suite_offset + 2])

    # Prepare Cipher Suites content (70 bytes)
    cipher_suites_bytes1 = bytearray(cipher_suites_content)
    cipher_suites_bytes = cipher_suites_bytes1
    # Truncating if greater than 70 bytes
    if len(cipher_suites_bytes) > 70:
        cipher_suites_bytes = cipher_suites_bytes[:70]
    else:
        # Padding with 0x00 if less than 70 bytes
        cipher_suites_bytes.extend(bytearray(70 - len(cipher_suites_bytes)))

    byte_array.extend(cipher_suites_bytes)  # Pad with 0x00
    compression_method_offset = cipher_suite_offset + 2 + len(cipher_suites_bytes1)
    
    # Calculate extension length offset
    byte_array.extend(hello_message[len_offset-2:len_offset ])

    number_of_extensions = len(extension_map)
    print(extension_map)

    
    if number_of_extensions > 20:
        extension_map = dict(list(extension_map.items())[:20])
        number_of_extensions = 20  

    
    for ext_type in extension_map.keys():
        byte_array.extend(struct.pack('>H', ext_type))

    
    if number_of_extensions < 20:
        padding_length = (20 - number_of_extensions) * 2  
        byte_array.extend(b'\x00' * padding_length)

    
    specific_extensions = [21, 35, 41, 44, 0, 25, 51, 16]

   
    for ext in specific_extensions:
        if ext in extension_map:
            byte_array.extend(struct.pack('>H', extension_map[ext][0]))  
        else:
            byte_array.extend(b'\x00\x00')  

    
    for ext in [3, 15, 45, 27, 30, 6, 11, 19, 20, 50, 43, 10, 13, 16]:
        data = extension_map.get(ext, (0, []))[1]  
        add_extension_data(byte_array, ext, data)

    return byte_array

def extract_tls_client_hello(pcap_file):
    """Extract TLS Client Hello messages from a PCAP file."""
    packets = rdpcap(pcap_file)
    all_byte_arrays = []

    for index, packet in enumerate(packets):
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
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
                            continue

                        # Extract Client Hello fields
                        session_id_length = client_hello[34]
                        session_id_end = 35 + session_id_length
                        cipher_suites_start = session_id_end + 2
                        cipher_suites_length = struct.unpack('>H', client_hello[session_id_end:session_id_end + 2])[0]
                        cipher_suites_content = client_hello[cipher_suites_start:cipher_suites_start + cipher_suites_length]

                        compression_methods_start = cipher_suites_start + cipher_suites_length + 2
                        compression_methods_length = client_hello[compression_methods_start]
                        len_offset = compression_methods_start+2

                       
                        extension_map = extract_tls_extensions(client_hello, len_offset)

                       
                        byte_array = create_byte_array(payload, client_hello, session_id_length, cipher_suites_content, compression_methods_length, extension_map, len_offset)
                        
                        all_byte_arrays.append(list(byte_array))  
                        print(all_byte_arrays)

    return all_byte_arrays

def create_server_hello_byte_array(payload, server_hello, session_id_length, cipher_suite, compression_method, extension_map, extensions_length_offset):
    """Create a byte array representation of the Server Hello message."""
    byte_array = bytearray()

    # Adding Record Version (2 bytes)
    byte_array.extend(payload[1:3])

    # Adding Record Length (2 bytes)
    byte_array.extend(payload[3:5])

    # Add Message Length (3 bytes)
    message_length = len(server_hello)
    byte_array.extend([(message_length >> 16) & 0xFF, (message_length >> 8) & 0xFF, message_length & 0xFF])

    # Adding Message Version (2 bytes)
    byte_array.extend(server_hello[0:2])

    # Adding Session ID Length (1 byte)
    byte_array.append(session_id_length)

    # Adding Cipher Suite (2 bytes)
    byte_array.extend(cipher_suite)

    # Addding Compression Method (1 byte)
    

    # Offset of Extensions Length
    byte_array.extend(server_hello[extensions_length_offset:extensions_length_offset + 2])  
    print(extension_map)
    # Adding extension types (up to 10)
    extension_types = list(extension_map.keys())
    number_of_extensions = len(extension_types)

    
    if number_of_extensions > 10:
        extension_types = extension_types[:10]  
        number_of_extensions = 10
    elif number_of_extensions < 10:
        padding_needed = 10 - number_of_extensions
        extension_types.extend([0] * padding_needed)  

    # Adding extension types (2 bytes each)
    for ext_type in extension_types:
        byte_array.extend(struct.pack('>H', ext_type))
    for ext in [41, 51]:
        if ext in extension_map:
            ext_length = extension_map[ext][0]  
            byte_array.extend(struct.pack('>H', ext_length))  
        else:
            byte_array.extend(b'\x00\x00')
    for ext in [51, 43]:
        if ext in extension_map:
            data_length = extension_map[ext][0] 
            data = extension_map[ext][1] 

            if len(data) > 2:
                data = data[:2] 
            elif len(data) < 2:
                data = list(data) + [0] * (2 - len(data))  

            byte_array.extend(data) 
        else:
            byte_array.extend(b'\x00\x00')      

    return byte_array

def extract_tls_server_hello(pcap_file):
    """Extract TLS Server Hello messages from a PCAP file."""
    packets = rdpcap(pcap_file)
    all_byte_arrays = []

    for index, packet in enumerate(packets):
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            if len(payload) > 5:
                content_type = payload[0]

                if content_type == 0x16:  # TLS Handshake
                    handshake_type = payload[5]
                    handshake_length = struct.unpack('>I', b'\x00' + payload[6:9])[0]

                    if handshake_type == 0x02:  # Server Hello
                        server_hello_start = 9
                        server_hello_end = server_hello_start + handshake_length
                        server_hello = payload[server_hello_start:server_hello_end]

                        

                        # Extract Server Hello fields
                        session_id_length = server_hello[34]
                        session_id_end = 35 + session_id_length
                        cipher_suite = server_hello[session_id_end:session_id_end + 2]
                        compression_method = server_hello[session_id_end + 2]

                        # Offset of Extensions Length
                        extensions_length_offset = session_id_end + 3
                        extensions_length = struct.unpack('>H', server_hello[extensions_length_offset:extensions_length_offset + 2])[0]
                        extensions = server_hello[extensions_length_offset + 2:extensions_length_offset + 2 + extensions_length]

                        # Create extension map
                        extension_map = extract_tls_extensions(server_hello, extensions_length_offset+2)

                        # Create byte array representation for Server Hello
                        byte_array = create_server_hello_byte_array(payload, server_hello, session_id_length, cipher_suite, compression_method, extension_map, extensions_length_offset)

                        all_byte_arrays.append(list(byte_array)) 
                         # Store byte array as list for printing
                         
                        print(all_byte_arrays)

    return all_byte_arrays



def extract_label_from_filename(filename, keywords):
    """Extract a label based on keywords from the filename, case-insensitively."""
    filename_lower = filename.lower()  # Convert filename to lowercase
    for keyword in keywords:
        if keyword.lower() in filename_lower:  # Convert keyword to lowercase
            return keyword
    return None

def process_directory(directory, output_csv_file, keywords):
    """Process all PCAP files in the directory and write to a CSV file."""
    with open(output_csv_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_NONE, escapechar='\\', delimiter=',')
        # Write the header for the label
        csv_writer.writerow(['Label', 'Client Hello Bytes', 'Server Hello Bytes'])

        for filename in os.listdir(directory):
            if filename.endswith('.pcap'):
                label = extract_label_from_filename(filename, keywords)
                if label:
                    pcap_file = os.path.join(directory, filename)
                    client_hello_bytes = extract_tls_client_hello(pcap_file)
                    server_hello_bytes = extract_tls_server_hello(pcap_file)

                    
                    for client_bytes in client_hello_bytes:
                        for server_bytes in server_hello_bytes:
                            csv_writer.writerow([label] + client_bytes + server_bytes)

if __name__ == "__main__":
    directory = 'New_ESNI_Dataset' 
    output_csv_file = 'RecomposedESNI.csv'
    keywords = [
        "Gmail", "FileTransfer", "Vimeo", "Youtube", "ssl.gstatic", 
        "Hangout", "Netflix", "Skype_Chat", "Google Services"
    ]

    process_directory(directory, output_csv_file, keywords)
