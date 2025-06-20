
import pandas as pd

from lib.functions import*
# Set up basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)




# List of multiple pcap files to process
pcap_files = [
    "pcap/AMF_3_1.cap", # Dataset with malicious samples (Replay attack)
    "pcap/ens20.pcap", # Dataset with malicious samples (Replay attack)
    "pcap/lo.pcap", # Benign samples
    
    # more can be added here as needed
]


packet_data_list = []
all_keys = set()

for file_path in pcap_files:
    print(f"Processing {file_path} ...")
    capture_file = pyshark.FileCapture(
        file_path,
        include_raw=True,
        display_filter='nas-5gs',
        use_ek=True,
        keep_packets=False
    )
    for wr_packet in capture_file:
        try:
            packet_data = {}
            time = wr_packet.frame_info.time.relative
            ip_source = wr_packet.ip.src.value

            if hasattr(wr_packet, 'ngap') and hasattr(wr_packet.ngap, 'NAS_PDU'):
                amf_field = wr_packet.ngap.get_field('AMF.UE.NGAP.ID')
                procedureCode = int(wr_packet.ngap.procedureCode.value)

                raw_data = wr_packet.ngap.NAS_PDU.raw
                nas_bytes = unhexlify(raw_data)
                pdu, err = parse_NAS5G(nas_bytes)

                packet_data["Time"] = time
                packet_data["AMF_UE_NGAP_ID"] = str(amf_field.value) if amf_field else "-1"
                packet_data["ip_source"] = ip_source
                packet_data["procedureCode"] = procedureCode

                if pdu and pdu.CLASS in ["Envelope", "Alt", "Sequence"]:
                    print("=" * 10)
                    print(f"time: {time}")
                    print(f"AMF_UE_NGAP_ID: {packet_data['AMF_UE_NGAP_ID']}")
                    print(f"ip_source: {ip_source}")
                    print(f"procedureCode: {procedureCode}")

                    paths = getPathsFromNAS5G(pdu)
                    extracted = extract_basic_pdu_info(paths, packet_data, all_keys)
                    packet_data_list.append(extracted)

        except Exception as e:
            logger.error(f"Error parsing packet: {e}")




# Use the first packet's key order as the preferred order
if packet_data_list:
    first_keys_order = list(packet_data_list[0].keys())
    # Include any new keys discovered in later packets (to avoid missing columns)
    for pkt in packet_data_list[1:]:
        for k in pkt.keys():
            if k not in first_keys_order:
                first_keys_order.append(k)
else:
    first_keys_order = []

# Normalize all packet dicts to have all columns (preserve order)
normalized_data = []
for packet in packet_data_list:
    normalized_packet = {key: packet.get(key, "") for key in first_keys_order}
    normalized_data.append(normalized_packet)

# Convert to DataFrame using pandas
df = pd.DataFrame(normalized_data)

# Save to CSV with comma as delimiter
df.to_csv("data.csv", index=False, sep=";") 



