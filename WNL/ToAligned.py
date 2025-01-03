import csv
import os
from scapy.all import rdpcap, TCP
payload_len=185
def replace_random_field(payload):
    """Replacing the first 4 bytes of the random field with zeros."""
    RANDOM_FIELD_OFFSET = 12
    LENGTH_OF_RANDOM_FIELD = 32  

    if len(payload) > RANDOM_FIELD_OFFSET + LENGTH_OF_RANDOM_FIELD:
    
        # Replacing the first 4 bytes of the random field with zeros
        modified_payload = (
            payload[:RANDOM_FIELD_OFFSET] +
            bytes(4) +  # 4 bytes of zeros
            payload[RANDOM_FIELD_OFFSET + 4:RANDOM_FIELD_OFFSET + LENGTH_OF_RANDOM_FIELD] +
            payload[RANDOM_FIELD_OFFSET + LENGTH_OF_RANDOM_FIELD:]
        )
        return modified_payload
    return payload

def pad_bytes(payload, length=payload_len):
    """Pad the byte sequence with zeros to ensure it is of the specified length."""
    return payload.ljust(length, b'\x00')

def extract_tls_hello_messages(pcap_file):
    """Extract TLS Hello messages and modify payloads."""
    packets = rdpcap(pcap_file)
    
    client_hello_bytes = bytearray()
    server_hello_bytes = bytearray()
    
    for packet in packets:
        if packet.haslayer(TCP) and len(packet[TCP].payload) > 0:
            tcp_payload = bytes(packet[TCP].payload)
            
            if len(tcp_payload) > 5 and tcp_payload[0] == 0x16:
                handshake_type = tcp_payload[5]
                
                if handshake_type == 0x01:  # Client Hello
                    modified_payload = replace_random_field(tcp_payload)
                    client_hello_bytes.extend(modified_payload)
                
                elif handshake_type == 0x02:  # Server Hello
                    modified_payload = replace_random_field(tcp_payload)
                    server_hello_bytes.extend(modified_payload)
    
    client_hello_bytes = pad_bytes(client_hello_bytes[:payload_len])
    server_hello_bytes = pad_bytes(server_hello_bytes[:payload_len])
    
    return client_hello_bytes, server_hello_bytes

def extract_label_from_filename(filename, keywords):
    """Extract label from filename based on keywords."""
    filename_lower = filename.lower()
    for keyword in keywords:
        if keyword.lower() in filename_lower:
            return keyword
    return None

def process_directory(directory, output_csv_file, keywords):
    """Process all pcap files in the directory and write to a CSV file."""
    with open(output_csv_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_NONE, escapechar='\\', delimiter=',')
       
        csv_writer.writerow(['Label'])

        for filename in os.listdir(directory):
            if filename.endswith('.pcap'):
                label = extract_label_from_filename(filename, keywords)
                if label:
                    pcap_file = os.path.join(directory, filename)
                    client_hello_bytes, server_hello_bytes = extract_tls_hello_messages(pcap_file)
                    
                    
                    row = [label] + list(client_hello_bytes) + list(server_hello_bytes)
                    csv_writer.writerow(row)

if __name__ == "__main__":
    directory = 'ECH_Dataset4'
    output_csv_file = 'AlignedECH7.csv'
    keywords = ['ww', 'AppleMusic', 'Kinopoisk', 'Live_Facebook', 'Live_Youtube', 'Netflix', 'PrimeVideo', 'SoundCloud', 'Spotify', 'Vimeo', 'YouTube_PC', 'YandexMusic']

    process_directory(directory, output_csv_file, keywords)
