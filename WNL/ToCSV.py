import csv
import os
from scapy.all import rdpcap, TCP

def replace_random_field(payload):
    """Replacing the first 4 bytes of the random field with zeros."""
    RANDOM_FIELD_OFFSET = 12
    LENGTH_OF_RANDOM_FIELD = 32  

    if len(payload) > RANDOM_FIELD_OFFSET + LENGTH_OF_RANDOM_FIELD:
        # Replacing the first 4 bytes of the random field with zeros
        modified_payload = (
            payload[:RANDOM_FIELD_OFFSET] +
            bytes(4) +  
            payload[RANDOM_FIELD_OFFSET + 4:RANDOM_FIELD_OFFSET + LENGTH_OF_RANDOM_FIELD] +
            payload[RANDOM_FIELD_OFFSET + LENGTH_OF_RANDOM_FIELD:]
        )
        return modified_payload
    return payload

def extract_tls_hello_messages(pcap_file):
    """Extracting TLS Hello messages and modify payloads."""
    packets = rdpcap(pcap_file)
    
    client_hello_bytes = []
    server_hello_bytes = []
    
    for packet in packets:
        if packet.haslayer(TCP) and len(packet[TCP].payload) > 0:
            tcp_payload = bytes(packet[TCP].payload)
            
            if len(tcp_payload) > 5 and tcp_payload[0] == 0x16:
                handshake_type = tcp_payload[5]
                
                if handshake_type == 0x01:  # Client Hello
                    modified_payload = replace_random_field(tcp_payload)
                    client_hello_bytes.extend(tcp_payload)
                
                elif handshake_type == 0x02:  # Server Hello
                    modified_payload = replace_random_field(tcp_payload)
                    server_hello_bytes.extend(tcp_payload)
    
    return client_hello_bytes, server_hello_bytes

def extract_label_from_filename(filename, keywords):
    """Extracting label from filename based on keywords."""
    filename_lower = filename.lower()
    for keyword in keywords:
        if keyword.lower() in filename_lower:
            return keyword
    return None

def process_directory(directory, output_csv_file,keywords):
    """Processing all pcap files in the directory and write to a CSV file."""
    with open(output_csv_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_NONE, escapechar='\\', delimiter=',')
    #   Write the header for the label
        csv_writer.writerow(['Label'])

        for filename in os.listdir(directory):
            if filename.endswith('.pcap'):
              label = extract_label_from_filename(filename, keywords)
              if label:
                    pcap_file = os.path.join(directory, filename)
                    client_hello_bytes, server_hello_bytes = extract_tls_hello_messages(pcap_file)
                    
                    # Write the label, client hello bytes, separator, and server hello bytes to the CSV
                    csv_writer.writerow([label] + client_hello_bytes +  server_hello_bytes)

if __name__ == "__main__":
    directory = 'ECH_Dataset2' 
    output_csv_file = 'ECH2_CSV.csv'
    keywords = ['ww','AppleMusic','Kinopoisk','Live_Facebook','Live_Youtube','Netflix','PrimeVideo','SoundCloud','Spotify','Vimeo','YouTube_PC','YandexMusic']

    process_directory(directory, output_csv_file,keywords)
