## First Approach: Supervised Learning Algorithm — Random Forest


-  Supervised learning requires labeled data (benign or malicious) to learn patterns. Since the initial PCAP files ("pcap\AMF_3_1.cap") use to train the model contained replay attacks with very few malicious samples, I needed to generate labels for each data sample to train the model effectively.

- Data Preparation & Labeling:
        - Features were extracted from PCAP files focusing on 5G NAS message headers, including fields such as EPD, spare bits, security headers, and mandatory Information Elements (IEs) as defined by the 3GPP specification.
        - For mandatory IEs, uplink traffic was primarily considered since the focus is on uplink direction. For downlink, only the headers (EPD, spare bits, security header, and type) were extracted without including IEs.

- Label Generation:
  Labels were generated by validating extracted features against the 3GPP specifications to identify malformed, invalid, or unexpected messages. Messages failing validation were labeled invalid, while those passing validation were labeled benign (valid).

- Dataset Construction:
  The original PCAP file ("pcap\AMF_3_1.cap") contained less than 10 samples with just 1 malicious, which was insufficient for training. To address this, i merged multiple PCAP files.
    - One PCAP containing replay attack traffic (less than 10 samples, only 1 malicious).
    - One PCAP containing about 900 benign samples.

- Training Data:
  The combined dataset includes both benign and malicious traffic to enable better model training. 

- Note:
  Only mandatory IEs for some uplink messages are considered in this phase. Optional IEs are not included yet.



## Second Approach: Unsupervised Learning Algorithm — Isolation Forest

- Unsupervised learning does not require labeled datasets but needs to be trained on many benign samples. (## TODO)

