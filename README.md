# AI Network Packet Analyzer

This project provides a set of Python scripts to train and run an AI model for detecting nefarious/malware content in network packets. It uses Scapy for packet manipulation, Pandas for data handling, and Scikit-learn for machine learning. All interactions are via the Command Line Interface (CLI).

**Current Date for Reference:** Thursday, March 27, 2025

## Table of Contents

1.  [Prerequisites](#prerequisites)
2.  [Project Setup](#project-setup)
3.  [Data Acquisition](#data-acquisition)
4.  [Preprocessing (Feature Extraction)](#preprocessing-feature-extraction)
5.  [Model Training](#model-training)
6.  [Detection](#detection)
    * [Live Traffic Analysis](#live-traffic-analysis)
    * [Offline PCAP Analysis](#offline-pcap-analysis)
7.  [Scripts Overview](#scripts-overview)
8.  [Important Considerations](#important-considerations)

## Prerequisites

1.  **Python:** Ensure you have Python 3.x installed.
2.  **Pip:** Python's package installer.
3.  **Required Libraries:** Install the necessary Python packages:
    ```bash
    pip install scapy pandas numpy scikit-learn joblib tqdm
    ```
4.  **Packet Capture Library:** Scapy relies on `libpcap` (or `Npcap` on Windows). On macOS, it's often included with Xcode Command Line Tools or can be installed via Homebrew:
    ```bash
    brew install libpcap
    ```
    On Debian/Ubuntu Linux:
    ```bash
    sudo apt-get update && sudo apt-get install -y python3-scapy libpcap-dev
    ```
5.  **Root/Administrator Privileges:** Live packet capture requires elevated privileges. You will need to use `sudo` (on macOS/Linux) or run as Administrator (on Windows) when running `detect.py` in live mode.

## Project Setup

1.  Create a directory for your project:
    ```bash
    mkdir packet_analyzer
    cd packet_analyzer
    ```
2.  Save the following Python scripts provided in the main guide into this directory:
    * `packet_features.py`
    * `preprocess.py`
    * `train.py`
    * `detect.py`

## Data Acquisition

This is a critical step. The model needs labeled data (packets known to be benign or malicious).

1.  **Obtain `.pcap` files:**
    * Find public datasets: Search online for "malware analysis pcap", "CTU-13 dataset", "CIC-IDS dataset", "Malware Traffic Analysis", etc. Download separate `.pcap` files representing benign (normal) traffic and malicious traffic.
    * **Generate your own (Use Caution):**
        * **Benign:** Use tools like `tcpdump` or Wireshark to capture traffic while performing normal, safe activities (e.g., Browse reputable websites).
        * **Malicious:** **In a secure, isolated environment (like a dedicated VM disconnected from sensitive networks)**, run known malware samples while capturing traffic. **Handle malware with extreme care.**
2.  Place the acquired `.pcap` files (e.g., `benign.pcap`, `malicious.pcap`) in your project directory or note their full paths.

## Preprocessing (Feature Extraction)

This step reads the raw `.pcap` files, extracts features defined in `packet_features.py`, assigns labels (0 for benign, 1 for malicious), and saves the results into a single CSV file.

* Run the `preprocess.py` script:
    ```bash
    python preprocess.py --benign /path/to/your/benign.pcap --malicious /path/to/your/malicious.pcap --output features.csv
    ```
* **Optional:** Limit the number of packets processed from each file, which can be useful for balancing the dataset or speeding up preprocessing on large files:
    ```bash
    python preprocess.py --benign benign.pcap --malicious malicious.pcap --output features.csv --max-benign 50000 --max-malicious 50000
    ```
* This command will generate the `features.csv` file in your project directory. Check the script's output for any errors or warnings.

## Model Training

This step loads the `features.csv` file, scales the numerical features, trains a Random Forest classifier (or other model defined in `train.py`), evaluates its performance on a test split, and saves the trained model and the scaler object.

* Run the `train.py` script:
    ```bash
    python train.py --data features.csv --model-out model/packet_model.joblib --scaler-out model/packet_scaler.joblib
    ```
* This will:
    * Create a `model/` subdirectory if it doesn't exist.
    * Save the trained machine learning model to `model/packet_model.joblib`.
    * Save the feature scaler object to `model/packet_scaler.joblib`.
* Review the classification report (accuracy, precision, recall, F1-score) printed to the console to assess the model's performance.

## Detection

This step uses the trained model and scaler to classify new, unseen network packets.

### Live Traffic Analysis

Analyzes network traffic directly from a network interface in real-time (or near real-time). **Requires root/administrator privileges.**

* Run the `detect.py` script with the `--live` flag:
    ```bash
    # On macOS/Linux:
    sudo python detect.py --model model/packet_model.joblib --scaler model/packet_scaler.joblib --live --iface en0

    # On Windows (in an Administrator terminal):
    # python detect.py --model model/packet_model.joblib --scaler model/packet_scaler.joblib --live --iface "Ethernet 3"
    ```
* **Replace `--iface en0`** (or `"Ethernet 3"`) with the actual name of the network interface you want to monitor. You can find interface names using `ifconfig`/`ip addr` on macOS/Linux or `ipconfig` on Windows. If `--iface` is omitted, Scapy might try to use a default interface.
* **Optional:** Limit the number of packets to capture using `--count`:
    ```bash
    sudo python detect.py --model ... --scaler ... --live --count 1000
    ```
    (Captures 1000 packets then stops). Use `--count 0` (default) for continuous capture.
* The script will print warnings for packets classified as potentially MALICIOUS, along with basic packet information and confidence score.
* Press `Ctrl+C` to stop the live capture.

### Offline PCAP Analysis

Analyzes packets from a pre-existing `.pcap` file.

* Run the `detect.py` script with the `--pcap` flag:
    ```bash
    python detect.py --model model/packet_model.joblib --scaler model/packet_scaler.joblib --pcap /path/to/unlabeled_traffic.pcap
    ```
* Replace `/path/to/unlabeled_traffic.pcap` with the path to the `.pcap` file you want to analyze.
* The script will process each packet in the file and print warnings for those classified as MALICIOUS.

## Scripts Overview

* `packet_features.py`: Contains the function `extract_features` which defines how raw packet data is converted into numerical/categorical features. Also defines `FEATURE_NAMES`.
* `preprocess.py`: Orchestrates reading `.pcap` files (benign and malicious), applying `extract_features`, adding labels, and saving the combined dataset to a CSV file.
* `train.py`: Handles loading the feature CSV, splitting data, scaling features, training the ML model (`RandomForestClassifier` by default), evaluating performance, and saving the `model` and `scaler` files using `joblib`.
* `detect.py`: Loads the saved model and scaler. Can either capture live packets using `scapy.sniff` or read from a `.pcap` file using `scapy.PcapReader`. It applies the feature extraction and scaling, then uses the model to predict if each packet is benign or malicious.

## Important Considerations

* **Data Quality:** The accuracy of this system heavily depends on the quality and representativeness of your training `.pcap` files.
* **Feature Engineering:** The current features are basic and packet-level. Consider exploring flow-based features for potentially better detection of malicious behaviors.
* **Performance:** Python-based packet processing might be slow for high-throughput networks. Consider sampling or flow analysis.
* **Encryption:** This model primarily analyzes unencrypted packet headers and basic payload characteristics (like entropy). It will struggle to detect threats within encrypted (TLS/SSL) payloads.
* **Evasion & Model Updates:** Malware constantly evolves. The model needs periodic retraining with new data to remain effective.
* **False Positives/Negatives:** Monitor the detection output. You may need to adjust features, retrain the model, or tune classification thresholds to balance detection rates with false alarms.
