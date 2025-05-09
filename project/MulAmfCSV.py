import pyshark
import csv
import os

# List of pcap files to process
pcap_files = ['project/AMF_1_1_A.cap', 'project/AMF_1_1_B.cap ', 'project/AMF_1_2_A.cap', 
              'project/AMF_1_2_B.cap', 'project/AMF_1_2_C.cap', 'project/AMF_1_2_D.cap', 
              'project/AMF_3_1.cap', 'project/AMF_5_1_A.cap', 'project/AMF_5_1_B.cap', 
              'project/AMF_5_1_C.cap'
              ]  

# Output CSV file
csv_file = 'output_packets.csv'

# Define CSV headers
headers = ['Time', 'Length', 'Protocol', 'Source IP', 'Destination IP', 
           'procedurecode', 'Info', 'criticality', 'protocolies', 'tac', 
           'sst', 'sd','relativeamfcapacity', 
           'rrcestablishmentcause', 'nas_5gs_mm_suci_supi_fmt',
           'nas_5gs_mm_type_id', 'nas_5gs_mm_suci_routing_indicator',
            'nas_5gs_mm_suci_pki', 'nas_5gs_mm_suci_scheme_id',
           'suci_scheme_output', 'nas_pdu', 'per_octet_string_length', 
           'nas_5gs_epd', 'nas_5gs_security_header_type', 
           'nas_5gs_security_header_type', 'nas_5gs_mm_message_type', 
           "nas_5gs_mm_5gmm_cause", "gsm_a_dtap_rand", "gsm_a_dtap_autn", 
           'gsm_a_dtap_auts','gsm_a_dtap_autn_sqn_xor_ak', 'gsm_a_dtap_autn_mac',  
           ]

# Open the CSV file for writing (if it doesn't exist) or appending (if it does)
file_exists = os.path.exists(csv_file)

with open(csv_file, 'a', newline='', encoding='utf-8') as f:
    CSV = csv.DictWriter(f, fieldnames=headers, delimiter=';')
    
    # Write headers only if the file doesn't exist
    if not file_exists:
        CSV.writeheader()

    # Process each pcap file
    for pcap_file in pcap_files:
        try:
            capture_file = pyshark.FileCapture(pcap_file, display_filter='ngap || nas-5gs')

            # Iterate through packets in the capture file
            for packet in capture_file:
                try:
                    # Initialize row with basic info
                    row = {
                        'Time': packet.sniff_time,
                        'Length': packet.length,
                        'Protocol': packet.highest_layer,
                        'Source IP': packet.ip.src if hasattr(packet, 'ip') else '',
                        'Destination IP': packet.ip.dst if hasattr(packet, 'ip') else '',
                        'Info': '',
                        'procedurecode': '',
                        'criticality': '',
                        'protocolies': '',
                        'tac': '',
                        'sst': '',
                        'sd': '',
                        'relativeamfcapacity': '',
                        'rrcestablishmentcause': '',
                        'nas_5gs_mm_suci_supi_fmt': '',
                        'nas_5gs_mm_type_id': '',
                        'nas_5gs_mm_suci_routing_indicator': '',
                        'nas_5gs_mm_suci_scheme_id': '',
                        'nas_5gs_mm_suci_pki': '',
                        'nas_pdu': '',
                        'per_octet_string_length': '',
                        'nas_5gs_epd': '',
                        'nas_5gs_security_header_type': '',
                        'nas_5gs_mm_message_type': '',
                        'nas_5gs_mm_5gmm_cause': '',
                        'gsm_a_dtap_rand': '',
                        'gsm_a_dtap_autn': '',
                        'gsm_a_dtap_auts': '',
                        'gsm_a_dtap_autn_sqn_xor_ak': '',
                        'gsm_a_dtap_autn_mac': '',
                    }

                    # Collect NGAP fields (The NAS fields are embedded inside)
                    if hasattr(packet, 'ngap'):
                        for field in packet.ngap.field_names:
                            try:
                                value = getattr(packet.ngap, field)

                                # Match field values of interest for Info
                                if any(keyword in str(value) for keyword in ['InitialUEMessage', 'DownlinkNASTransport', 'UplinkNASTransport', 'PDUSESSION', 'HandoverRequest']):
                                    if row['Info']:
                                        row['Info'] += f" | {value}"  # Append if something is already there
                                    else:
                                        row['Info'] = value  # First match

                                # Store into appropriate fields 
                                if field == 'procedurecode':
                                    row['procedurecode'] = value
                                elif field == 'criticality':
                                    row['criticality'] = value
                                elif field == 'protocolies':
                                    row['protocolies'] = value
                                elif field == 'tac':
                                    row['tac'] = value
                                elif field == 'sst':
                                    row['sst'] = value
                                elif field == 'sd':
                                    row['sd'] = value
                                elif field == 'id-GlobalRANNodeID':
                                    row['id-GlobalRANNodeID'] = value
                                elif field == 'relativeamfcapacity':
                                    row['relativeamfcapacity'] = value
                                elif field == 'rrcestablishmentcause':
                                    row['rrcestablishmentcause'] = value
                                elif field == 'nas_5gs_mm_suci_supi_fmt':
                                    row['nas_5gs_mm_suci_supi_fmt'] = value
                                elif field == 'nas_5gs_mm_type_id':
                                    row['nas_5gs_mm_type_id'] = value
                                elif field == 'nas_5gs_mm_suci_routing_indicator':
                                    row['nas_5gs_mm_suci_routing_indicator'] = value
                                elif field == 'nas_5gs_mm_suci_scheme_id':
                                    row['nas_5gs_mm_suci_scheme_id'] = value
                                elif field == 'nas_5gs_mm_suci_pki':
                                    row['nas_5gs_mm_suci_pki'] = value
                                elif field == 'suci_scheme_output':
                                    row['suci_scheme_output'] = value
                                elif field == 'id-RAN-UE-NGAP-ID':
                                    row['id-RAN-UE-NGAP-ID'] = value
                                elif field == 'id-AMF-UE-NGAP-ID':
                                    row['id-AMF-UE-NGAP-ID'] = value
                                elif field == 'nas_pdu':
                                    row['nas_pdu'] = value
                                elif field == 'per_octet_string_length':
                                    row['per_octet_string_length'] = value
                                elif field == 'nas_5gs_epd':
                                    row['nas_5gs_epd'] = value
                                elif field == 'nas_5gs_security_header_type':
                                    row['nas_5gs_security_header_type'] = value
                                elif field == 'nas_5gs_mm_message_type':
                                    row['nas_5gs_mm_message_type'] = value
                                elif field == 'nas_5gs_mm_5gmm_cause':
                                    row['nas_5gs_mm_5gmm_cause'] = value
                                elif field == 'gsm_a_dtap_rand':
                                    row['gsm_a_dtap_rand'] = value
                                elif field == 'gsm_a_dtap_autn':
                                    row['gsm_a_dtap_autn'] = value
                                elif field == 'gsm_a_dtap_auts':
                                    row['gsm_a_dtap_auts'] = value
                                elif field == 'gsm_a_dtap_autn_sqn_xor_ak':
                                    row['gsm_a_dtap_autn_sqn_xor_ak'] = value
                                elif field == 'gsm_a_dtap_autn_mac':
                                    row['gsm_a_dtap_autn_mac'] = value

                            except AttributeError:
                                continue


                    # Write row to CSV
                    CSV.writerow(row)

                except Exception as e:
                    print(f"Error processing packet: {e}")

            capture_file.close()

        except Exception as e:
            print(f"Error processing pcap file '{pcap_file}': {e}")

print(f"\nCSV file '{csv_file}' written successfully with data from all pcap files.")
