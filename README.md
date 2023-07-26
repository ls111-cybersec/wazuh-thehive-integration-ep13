# Wazuh SIEM & The Hive Integration - Virtual Lab building series: Ep 13

In this episode, we will integrate Wazuh with The Hive to automatically send alerts issued by Wazuh to The Hive. SOC Analysts will then have the option to investigate and respond to these alerts and create cases if required.

(video link here)<br>

xxx

***STEP1 - Install Python & PIP on your Wazuh server*** <br>

This lab assumes you are using the provided Wazuh VirtualBox image (.OVA) as I have used.

```
sudo yum update
sudo yum install python3
```
***STEP2 - Install The Hive Python module using PIP*** <br>

This is the Python module that will be referenced in the custom integration script that we will be creating in the next step. I have tested this module with version 5.2.1 of The Hive and its working at the time of this writeup.

```
sudo /var/ossec/framework/python/bin/pip3 install thehive4py
```
