# Wazuh SIEM & The Hive Integration - Virtual Lab building series: Ep 13

In this episode, we will integrate Wazuh with The Hive to automatically send alerts issued by Wazuh to The Hive. SOC Analysts will then have the option to investigate and respond to these alerts and create cases if required.

(video link here)<br>

xxx

***STEP1 - Install Python & PIP on your Wazuh server*** <br>

This lab assumes you are using the provided Wazuh VirtualBox image (.OVA) that I used, which did not have Python preinstalled.

```
sudo yum update
sudo yum install python3
```
***STEP2 - Install The Hive Python module using PIP*** <br>

This is the Python module that will be referenced in the custom integration script that we will be creating in the next step. I have tested this module with version 5.2.1 of The Hive and its working at the time of this writeup.

```
sudo /var/ossec/framework/python/bin/pip3 install thehive4py
```
***STEP3 - Creating the custom integration script*** <br>

The below script will need to be created in /var/ossec/integrations/ and called custom-w2thive.py I used nano to create/edit the script, however, you can use whatever text editor you like for this.<br>
<br>
This script has the `lvl_threshold` variable set to `0`, meaning that all alerts created by Wazuh will be forwarded to The Hive. This has the potential to create a lot of noise if you have a lot of agents you are monitoring on your network so you may want to consider setting this to a higher level to only alert on more serious classifications. Please check the Wazuh ruleset classifications in the [manual](https://documentation.wazuh.com/current/user-manual/ruleset/rules-classification.html) they range from 0 - 15 with explanations for each. 
