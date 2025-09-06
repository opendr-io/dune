![things](/img/dune.jpg?raw=true "text")  
# DUNE 
### (discovery of novel unseen events)
A project for cloud threat hunting using a combination of anomaly detection, machine learning, and specification-based detection.

#### Contents

Cloudtrail

- a notebook for bulk loading of Cloudtrail events into a dataframe for processing by machine learning models in Jupyter

Dashboards

- a dashboard using the 'significant terms' function for cloud anomaly detection in Kibana
- a similar dashboard for hunting anomalous cloudtrail events in Splunk

Flow logs

- a notebook for bulk loading of VPC Flow Logs a dataframe for processing by machine learning models in Jupyter
- a notebook for de-duplication of flow logs by a compression factor between 20 - 30x without loss of signal
- a notebook for hunting exfiltration and C2 by examining north-south traffic in the flow logs
  
Jupyter

- an ensemble notebook using pyod to do anomaly detection
- a notebook using k-means to do anomaly detection
- a notebook containing a proof of concept of a compression / de-duplication method for threat hunting in cloudtrail events
- a sanitized cloudtrail dataset containing a few target outlier events, which these notebooks process by default

Getting Started With Jupyter:

1. Download and install Anaconda (https://www.anaconda.com/) or start a cloud instance
2. Download the repo and unzip
3. Start Jupyter Lab in a virtual environment 
4. Open the notebooks (you may need to install some of the dependencies in the first few cells)

Kubernetes

- a notebook for bulk loading of Kubernetes  API logs into a dataframe for processing by machine learning models in Jupyter

