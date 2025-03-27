# detect.py
import argparse
import pandas as pd
import numpy as np
from scapy.all import sniff, PcapReader, Scapy_Exception
import joblib
import logging
import time
import sys

# Important: Use the same feature extraction logic and feature names
from packet_features import extract_features, FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global variables to hold loaded model and scaler
MODEL = None
SCALER = None

def load_artifacts(model_path, scaler_path):
    """Loads the trained model and scaler."""
    global MODEL, SCALER
    try:
        logging.info(f"Loading model from {model_path}...")
        MODEL = joblib.load(model_path)
        logging.info("Model loaded successfully.")

        logging.info(f"Loading scaler from {scaler_path}...")
        SCALER = joblib.load(scaler_path)
        logging.info("Scaler loaded successfully.")
        return True
    except FileNotFoundError as e:
        logging.error(f"Error loading artifacts: {e}. Please check paths.")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred loading artifacts: {e}")
        return False

def predict_packet(packet):
    """Extracts features, scales, and predicts the class of a single packet."""
    if MODEL is None or SCALER is None:
        logging.error("Model or scaler not loaded. Cannot predict.")
        return

    features_dict = extract_features(packet)

    if features_dict:
        try:
            # Convert features to DataFrame for consistent processing
            features_df = pd.DataFrame([features_dict], columns=FEATURE_NAMES)
            features_df.fillna(0, inplace=True) # Handle potential NaNs if any feature wasn't extracted correctly

            # Ensure order is correct
            features_ordered = features_df[FEATURE_NAMES]

            # Scale features
            features_scaled = SCALER.transform(features_ordered)

            # Predict
            prediction = MODEL.predict(features_scaled)
            probability = MODEL.predict_proba(features_scaled) # Get probability scores

            label = "Benign" if prediction[0] == 0 else "MALICIOUS"
            confidence = probability[0][prediction[0]]

            # Basic packet info for context
            pkt_info = f"Src: {packet[IP].src}:{features_dict['src_port']} -> Dst: {packet[IP].dst}:{features_dict['dst_port']}"
            logging.warning(f"[{label}] Confidence: {confidence:.4f} | {pkt_info} | Proto: {features_dict['protocol']} | Len: {features_dict['pkt_len']}")

        except Exception as e:
            logging.error(f"Error processing packet for prediction: {e}")
            # Optionally print more packet details for debugging
            # packet.show()

    # Implicitly returns None if not IP or if error occurs

def start_live_capture(interface=None, packet_count=0):
    """Starts live packet capture and prediction."""
    if MODEL is None or SCALER is None:
        logging.error("Cannot start capture: Model or scaler not loaded.")
        return

    logging.info(f"Starting live packet capture on interface '{interface or 'default'}'. Press Ctrl+C to stop.")
    try:
        # Using prn=lambda pkt: predict_packet(pkt) calls predict_packet for each captured packet
        # filter="ip" ensures we only process IP packets, aligning with feature extraction
        # store=0 prevents storing packets in memory, essential for long captures
        sniff(iface=interface, prn=predict_packet, filter="ip", store=0, count=packet_count)
        logging.info("Packet capture finished (reached count limit or stopped manually).")
    except PermissionError:
        logging.error("Permission denied. Packet capturing usually requires root/administrator privileges.")
        logging.error("Try running with 'sudo python detect.py ...'")
    except Scapy_Exception as e:
        logging.error(f"Scapy error during capture: {e}")
        logging.error("Ensure the specified interface exists and drivers are installed.")
    except KeyboardInterrupt:
        logging.info("Capture stopped by user (Ctrl+C).")
    except Exception as e:
        logging.error(f"An unexpected error occurred during live capture: {e}")


def process_pcap_file(pcap_file):
    """Processes packets from a pcap file for detection."""
    if MODEL is None or SCALER is None:
        logging.error("Cannot process pcap: Model or scaler not loaded.")
        return

    logging.info(f"Processing packets from pcap file: {pcap_file}")
    packets_processed = 0
    try:
        for packet in PcapReader(pcap_file):
            predict_packet(packet)
            packets_processed += 1
        logging.info(f"Finished processing {packets_processed} packets from {pcap_file}.")
    except Scapy_Exception as e:
        logging.error(f"Scapy error reading pcap file {pcap_file}: {e}")
    except FileNotFoundError:
        logging.error(f"Pcap file not found: {pcap_file}")
    except Exception as e:
        logging.error(f"An unexpected error occurred processing {pcap_file}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Detect malicious network packets using a trained model.")
    parser.add_argument('--model', required=True, help="Path to the trained model (.joblib).")
    parser.add_argument('--scaler', required=True, help="Path to the fitted scaler (.joblib).")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--live', action='store_true', help="Capture live traffic.")
    group.add_argument('--pcap', type=str, help="Path to a pcap file to analyze.")

    parser.add_argument('--iface', type=str, default=None, help="Network interface for live capture (e.g., 'en0'). Uses default if not specified.")
    parser.add_argument('--count', type=int, default=0, help="Number of packets to capture in live mode (0 for infinite).")

    args = parser.parse_args()

    if not load_artifacts(args.model, args.scaler):
        sys.exit(1) # Exit if artifacts failed to load

    if args.live:
        start_live_capture(interface=args.iface, packet_count=args.count)
    elif args.pcap:
        process_pcap_file(args.pcap)

if __name__ == "__main__":
    main()
