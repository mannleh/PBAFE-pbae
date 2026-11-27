# Data licenses and attribution

This repository redistributes processed subsets and reconstruction artifacts derived from the datasets below. Raw source corpora are not included.

## Edge-IIoTset

- Dataset: Edge-IIoTset: A New Comprehensive Realistic Cyber Security Dataset of IoT and IIoT Applications for Centralized and Federated Learning.
- Dataset DOI: https://doi.org/10.21227/mbc1-1h68
- Paper DOI: https://doi.org/10.1109/ACCESS.2022.3165809
- License: Creative Commons Attribution 4.0 International (CC BY 4.0), https://creativecommons.org/licenses/by/4.0/
- Required citation: Ferrag MA, Friha O, Hamouda D, Maglaras L, Janicke H. Edge-IIoTset: a new comprehensive realistic cyber security dataset of IoT and IIoT applications for centralized and federated learning. IEEE Access. 2022;10:40281-40306.
- Changes made for this package: exact feature/label deduplication, stratified train/test sampling, numeric feature encoding, training-only scaling, Dirichlet client partitioning, and storage as NumPy arrays with client indices and SHA-256 manifests.

## UNSW-NB15

- Source page: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- The source page grants free use for academic research in perpetuity; commercial use requires agreement with the authors.
- The source page requires citation of the following works:
  1. Moustafa N, Slay J. UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set). Military Communications and Information Systems Conference (MilCIS). 2015.
  2. Moustafa N, Slay J. The evaluation of Network Anomaly Detection Systems: statistical analysis of the UNSW-NB15 dataset and the comparison with KDD99. Information Security Journal. 2016.
  3. Moustafa N, et al. Novel geometric area analysis technique for anomaly detection using trapezoidal area estimation on large-scale networks. IEEE Transactions on Big Data. 2017.
  4. Moustafa N, et al. Big data analytics for intrusion detection system: statistical decision-making using finite Dirichlet mixture models. Data Analytics and Decision Support for Cybersecurity. 2017.
  5. Sarhan M, Layeghy S, Moustafa N, Portmann M. NetFlow Datasets for Machine Learning-Based Network Intrusion Detection Systems. 2020.
- Changes made for this package: bounded train/test sampling, categorical encoding, training-only scaling, Dirichlet client partitioning, and storage as NumPy arrays with client indices and SHA-256 manifests.
- Redistribution note: the source page explicitly grants academic use but does not state a general redistribution license for derived subsets. Users must verify the applicable terms before redistributing the processed UNSW-NB15 arrays, especially for non-academic or commercial use.
