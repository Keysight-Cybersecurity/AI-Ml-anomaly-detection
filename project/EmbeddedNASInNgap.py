import pyshark
import csv

# Input and output file paths
pcap_file = 'project/AMF_1_1_A.cap'
csv_file = 'ngapFields_packets.csv'  # Fixed typo in filename

# Open the pcap file
cap = pyshark.FileCapture(pcap_file, display_filter='ngap || nas-5gs')

# Define CSV headers
headers = [
    'Time', 'Length', 'Protocol', 'Source IP', 'Destination IP',
    'NGAP_Fields', 'NAS_Fields'
]

# Open the CSV file for writing with comma delimiter
with open(csv_file, 'w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=headers, delimiter=';')
    writer.writeheader()

    for pkt in cap:
        try:
            row = {
                'Time': pkt.sniff_time,
                'Length': pkt.length,
                'Protocol': pkt.highest_layer,
                'Source IP': pkt.ip.src if hasattr(pkt, 'ip') else '',
                'Destination IP': pkt.ip.dst if hasattr(pkt, 'ip') else '',
                'NGAP_Fields': '',
            }

            # Collect NGAP fields
            if hasattr(pkt, 'ngap'):
                ngap_data = []
                for field in pkt.ngap.field_names:
                    try:
                        value = getattr(pkt.ngap, field)
                        ngap_data.append(f"{field}={value}")
                       
                    except AttributeError:
                        continue
                row['NGAP_Fields'] = '; '.join(ngap_data)
            


            writer.writerow(row)

        except Exception as e:
            print(f"Error processing packet: {e}")


cap.close()

print(f"\nCSV file '{csv_file}' written successfully.")
