# FFS-Tools
Tools for managing and monitoring Freifunk-Stuttgart network

* Monitoring = Analysing all data from Alfred and Respondd to get complete list of all nodes and their relation ship. This is for checking
  - Availability of valid data
  - Correct Segment Assignment of the nodes to prevent "short cuts"
  - Creating statistcs data used for reports
  
* Onboarding = Automatically generating fastd peer files and DNS records for new nodes or nodes with changed MAC or Key. It uses the Database from Monitoring.
