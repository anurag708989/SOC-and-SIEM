# SOC-and-SIEM
soc and siem opensource tools and industry tools descriptions
## Soc (security operation center):
consists of people , processes and technology designed to deal with security events picked up from the SIEM log analysis.


## Siem (security incident event management):
collects and analyzes aggregated log data

<a href="https://www.comparitech.com/net-admin/siem-tools/">Top 10 Tools 2021 for SOC and SIEM </a>


## open source tools for soc and siem 
### volatility:<a href="https://github.com/volatilityfoundation/volatility">volatlity</a>
### Snort:Snort is the foremost Open Source Intrusion Prevention System (IPS) in the world. Snort IPS uses a series of rules that help define malicious network activity and uses those rules to find packets that match against them and generates alerts for users.

Snort can be deployed inline to stop these packets, as well. Snort has three primary uses: As a packet sniffer like tcpdump, as a packet logger — which is useful for network traffic debugging, or it can be used as a full-blown network intrusion prevention system. Snort can be downloaded and configured for personal and business use alike.<a href="https://www.snort.org/">SNORT</a>
### Apache metron:
Apache Metron provides a scalable advanced security analytics framework built with the Hadoop Community evolving from the Cisco OpenSOC Project. A cyber security application framework that provides organizations the ability to detect cyber anomalies and enable organizations to rapidly respond to identified anomalies.
<a href="https://metron.apache.org/">APACHEMETRON</a>
### alienvalult Ossim:AlienVault® OSSIM™, Open Source Security Information and Event Management (SIEM), provides you with a feature-rich open source SIEM complete with event collection, normalization and correlation. Launched by security engineers because of the lack of available open source products, AlienVault OSSIM was created specifically to address the reality many security professionals face: A SIEM, whether it is open source or commercial, is virtually useless without the basic security controls necessary for security visibility.<a href="https://cybersecurity.att.com/products/ossim">ALIENVAULTOSSIM</a>
### Elk stack:<a href="https://logz.io/blog/elk-siem/">ELKSTACK</a>
### Siemonster :<a href="https://siemonster.com/">SIEMONSTER</a> human based behavior ,threat intelligence , deep learning , machine learning , smb  & enterprise , cloud onsite
### Security Onion 2:<a href="https://securityonionsolutions.com/software/">SecurityOnion2</a>
### Smooth wall express:Security Onion is a free and open source Linux distribution for threat hunting, enterprise security monitoring, and log management. The easy-to-use Setup wizard allows you to build an army of distributed sensors for your enterprise in minutes!
Security Onion includes Elasticsearch, Logstash, Kibana, Suricata, Zeek (formerly known as Bro), Wazuh, Stenographer, TheHive, Cortex, CyberChef, NetworkMiner, and many other security tools.
### Ossec:https://www.ossec.net/ossec-downloads/
### Clamav : https://www.clamav.net/
### Cyphon : A good cybersecurity defense includes implementing tools like SIEM, UTM firewalls and advanced endpoint security technology. However, without the human component—someone to actively utilize the data coming from these tools—you are essentially still at square one. That’s because it’s not necessarily how good your tools are, but who’s leveraging those tools to keep watch over your environment.

According to Gartner: “The goal of MDR services is to rapidly identify and limit the impact of security incidents to customers. These services are focused on remote 24/7 threat monitoring, detection and targeted response activities. MDR providers may use a combination of host and network-layer technologies, as well as advanced analytics, threat intelligence, forensic data, and human expertise for investigation, threat hunting and response to detected threats.” (Gartner, “Market Guide for Managed Detection and Response Services,” July 2019.) <a href="https://www.cyphon.io/">CYPHON</a>
### Mod security
### Shadow demon
### Suricata:<a href="https://cybersecurity.att.com/blogs/security-essentials/open-source-intrusion-detection-tools-a-quick-overview">SURICATA</a>
### panther

## industry tools for soc and siem
### Data dog:Datadog’s more than 450 integrations let you collect metrics, logs, and traces from your entire stack as well as from your security tools, giving you end-to-end visibility into your environment. This lets you cast a wider net to catch possible security issues, and provides deeper context during your investigations. For example, if you detect abnormally high CPU utilization on a host, you can pinpoint which container or process is causing it to determine if you’re dealing with a crypto-miner.Datadog’s log processing pipelines automatically parse out key standard attributes from your ingested logs and events, unifying your logs across teams and data sources. This makes it easy to search and filter log data across your entire infrastructure for threat detection and investigation.

Log processing pipelines also enrich ingested logs and events with dynamic context that improves threat detection accuracy. For example, the geoip processor identifies the country and city of an IP, allowing you to detect anomalies in authentication patterns. The lookup processor lets you enrich events with your own business data to answer questions such as: have we blacklisted this IP? Does this MAC address belong to a stolen laptop? Is this user an administrator
### AT&T cybersecurity
### Sumologic
### Sysdig
### Splank enterprise
### Solar wind
### Logrithm
### Wazuh
### Sophos
### SoC radar


## use case for this tool:

1.logcollection
2.vulneribility detection
3.incident response
4.cloud security monitoring
5.security analytics
6.intrusion detection
















```
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata
apt-get update
apt-get upgrade
wget https://rules.emergingthreats.net/open/suricata-4.0/emerging.rules.tar.gz
tar zxvf emerging.rules.tar.gz
rm /etc/suricata/rules/* -f
mv rules/*.rules /etc/suricata/rules/
rm -f /etc/suricata/suricata.yaml
wget -O /etc/suricata/suricata.yaml http://www.branchnetconsulting.com/wazuh/suricata.yaml
systemctl daemon-reload
systemctl enable suricata
systemctl start suricata
tail -n1 /var/log/suricata/fast.log
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.13.1-amd64.deb
sudo dpkg -i filebeat-7.13.1-amd64.deb
nano /etc/filebeat/filebeat.yml
cloud.id: "security-deployment:YXAtc291dGgtMS5hd3MuZWxhc3RpYy1jbG91ZC5jb20kNzZkMmRjODM5MGY4NGVjNmFjZDM2NWQxMzBkZTQxODckNjAyNTY3NGI1NDEwNGM1NTg5MzI4YzgwMmY5ODNkMjE="
cloud.auth: "elastic:Cpfym3J9eXmYsGmMUe1n4y9v"
https://security-deployment-fe9d7a.kb.ap-south-1.aws.elastic-cloud.com:9243/
sudo filebeat modules enable suricata
sudo filebeat setup
sudo service filebeat start
```

