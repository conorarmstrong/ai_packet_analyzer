# preprocess.py
import argparse
import pandas as pd
from scapy.all import rdpcap, Scapy_Exception
from tqdm import tqdm # Progress bar
import logging

from packet_features import extract_features, FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def process_pcap(pcap_file, label, max_packets=None):
    """Reads a pcap file, extracts features, and assigns a label."""
    data = []
    packets_processed = 0
    try:
        logging.info(f"Processing {pcap_file} with label '{label}'...")
        # Use PcapReader for potentially large files if needed, but rdpcap is fine for moderate sizes
        packets = rdpcap(pcap_file)
        if max_packets:
            packets = packets[:max_packets]

        for packet in tqdm(packets, desc=f"Extracting features from {pcap_file}"):
            features = extract_features(packet)
            if features:
                features['label'] = label # Add the label
                data.append(features)
                packets_processed += 1

    except Scapy_Exception as e:
        logging.error(f"Error reading pcap file {pcap_file}: {e}")
    except FileNotFoundError:
        logging.error(f"Pcap file not found: {pcap_file}")
    except Exception as e:
        logging.error(f"An unexpected error occurred processing {pcap_file}: {e}")

    logging.info(f"Successfully extracted features from {packets_processed} IP packets in {pcap_file}.")
    return data

def main():
    parser = argparse.ArgumentParser(description="Preprocess pcap files to extract features for ML training.")
    parser.add_argument('--benign', required=True, help="Path to the benign pcap file.")
    parser.add_argument('--malicious', required=True, help="Path to the malicious pcap file.")
    parser.add_argument('--output', required=True, help="Path to save the output CSV file.")
    parser.add_argument('--max-benign', type=int, default=None, help="Maximum number of benign packets to process.")
    parser.add_argument('--max-malicious', type=int, default=None, help="Maximum number of malicious packets to process.")

    args = parser.parse_args()

    benign_data = process_pcap(args.benign, label=0, max_packets=args.max_benign) # 0 for benign
    malicious_data = process_pcap(args.malicious, label=1, max_packets=args.max_malicious) # 1 for malicious

    if not benign_data and not malicious_data:
        logging.error("No data extracted. Exiting.")
        return

    all_data = benign_data + malicious_data
    if not all_data:
        logging.error("No data to save after combining. Exiting.")
        return

    # Create DataFrame
    df = pd.DataFrame(all_data)

    # Ensure all feature columns exist, fill missing with 0 (though extract_features initializes them)
    for col in FEATURE_NAMES:
        if col not in df.columns:
            df[col] = 0

    # Reorder columns for consistency
    df = df[FEATURE_NAMES + ['label']]

    # Save to CSV
    try:
        df.to_csv(args.output, index=False)
        logging.info(f"Successfully saved combined features to {args.output}")
        logging.info(f"Dataset shape: {df.shape}")
        logging.info(f"Label distribution:\n{df['label'].value_counts()}")
    except IOError as e:
        logging.error(f"Error saving CSV file to {args.output}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during saving: {e}")


if __name__ == "__main__":
    main()
