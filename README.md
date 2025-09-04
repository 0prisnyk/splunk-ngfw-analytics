# Comprehensive NGFW Log Analytics in Splunk

This repository contains resources for reproducing a comprehensive analytics system based on Next-Generation Firewall (NGFW) event logs. The project is implemented on the **Splunk** platform using **Splunk Dashboard Studio**.

## Project Description

The goal of the project is to develop an approach for comprehensive analysis of NGFW logs to improve the threat detection process. The system includes mechanisms for enriching raw logs with data from external sources and their subsequent visualization on an interactive dashboard.

## Dashboard Structure

The dashboard has a two-level structure and consists of the following tabs:

1. **General traffic analysis and enriched information tab**
   - Provides an overview of network activity.
   - Visualizes data about public source and destination IP addresses with their TI ratings.
   - Displays the geographical distribution of communications, top domains, applications, and NGFW action statistics.

2. **Detailed threat analysis tab**
   - Designed for in-depth analysis of events identified as threats.
   - Shows the distribution of threats by severity levels and TI verdicts.
   - Displays the dynamics of threats over time and provides a detailed table for incident investigation.

## How to Reproduce

### Step 1: Prerequisites

1. Installed and configured **Splunk Enterprise** platform.
2. Installed apps from Splunkbase:
   - **AbuseIPDB App for Splunk**
   - **VT4Splunk (VirusTotal App)**
3. Obtained and configured **API keys** for AbuseIPDB and VirusTotal in the corresponding apps.

### Step 2: Data Upload

1. Prepare your own NGFW logs in **CSV** format.
2. In the Splunk web interface, go to `Settings > Add Data`.
3. Upload your CSV file, specifying `sourcetype=csv` for it.
4. Create a new index named `ngfw` and save the data into it.

### Step 3: Creating Calculated Fields

Go to `Settings > Fields > Calculated Fields` and create two fields:

- **dest_ip_type**:
  ```splunk
  if(cidrmatch("10.0.0.0/8", dest_ip) OR cidrmatch("192.168.0.0/16", dest_ip) OR cidrmatch("172.16.0.0/12", dest_ip) OR cidrmatch("127.0.0.0/8", dest_ip) OR cidrmatch("169.254.0.0/16", dest_ip), "private", "public")
  ```

- **src_ip_type**:
  ```splunk
  if(cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("192.168.0.0/16", src_ip) OR cidrmatch("172.16.0.0/12", src_ip) OR cidrmatch("127.0.0.0/8", src_ip) OR cidrmatch("169.254.0.0/16", src_ip), "private", "public")
  ```

### Step 4: Creating and Configuring Lookups

#### 4.1 Static Lookup

- Import the `suspicious_countries.csv` file into Splunk.

#### 4.2 Dynamic Lookups

##### `ip_candidates.csv`

```splunk
index=ngfw (src_ip_type=public OR dest_ip_type=public)
| eval ip1=if(src_ip_type="public", src_ip, null())
| eval ip2=if(dest_ip_type="public", dest_ip, null())
| table ip1 ip2
| eval ip=mvappend(ip1, ip2)
| mvexpand ip
| search ip=*
| dedup ip
| table ip
| outputlookup ip_candidates.csv
```

##### `public_ips_location.csv`

```splunk
| inputlookup ip_candidates.csv
| iplocation ip
| table ip, Country
| outputlookup public_ips_location.csv
```

##### `final_TI_info.csv`

###### 4.2.1 Enrichment via AbuseIPDB

```splunk
| inputlookup ip_candidates.csv
| abuseipdbcheck ip=ip
| table ip, abuseConfidenceScore, domain
| outputlookup final_TI_info.csv
```

###### 4.2.2 Enrichment via VirusTotal (scheduled search every 3 minutes to avoid exceeding VT limits)

```splunk
| inputlookup final_TI_info.csv
| append [
    | inputlookup final_TI_info.csv
    | where isnull(vt_detections)
    | head 1
    | vt4splunk ip=ip
]
| stats latest(*) as * by ip
| fields ip, abuseConfidenceScore, domain, vt_detections, vt_total_engines
| outputlookup final_TI_info.csv append=false
```

###### 4.2.3 Finalizing TI Information

```splunk
| inputlookup final_TI_info.csv
| fillnull value="N/A" domain
| eval vt_percentage_score=(vt_detections/vt_total_engines)*100, vt_percentage_score=round(vt_percentage_score, 2)
| eval VT_verdict = case(vt_percentage_score==0, "0", (vt_percentage_score>0 AND vt_percentage_score<10), "1", vt_percentage_score>=10, "2")
| eval AbuseIPDB_verdict = case(abuseConfidenceScore==0, "0", (abuseConfidenceScore>0 AND abuseConfidenceScore<20), "1", abuseConfidenceScore>=20, "2")
| eval Highest_TI_verdict_score = if(AbuseIPDB_verdict>VT_verdict, AbuseIPDB_verdict, VT_verdict)
| eval TI_verdict = case(Highest_TI_verdict_score==0, "Harmless", Highest_TI_verdict_score==1, "Suspicious", Highest_TI_verdict_score==2, "Malicious")
| table ip domain abuseConfidenceScore AbuseIPDB_verdict vt_detections vt_total_engines vt_percentage_score VT_verdict Highest_TI_verdict_score TI_verdict
| outputlookup final_TI_info.csv
```

### Step 5: Configuring Automatic Lookups

Go to `Settings > Lookups > Automatic lookups` and create four rules:

1. **Geolocation `src_ip`**:
   - Lookup table: `public_ips_location.csv`
   - Input: `ip = src_ip`
   - Output: `Country = src_geo_country`

2. **Geolocation `dest_ip`**:
   - Lookup table: `public_ips_location.csv`
   - Input: `ip = dest_ip`
   - Output: `Country = dest_geo_country`

3. **TI data `src_ip`**:
   - Lookup table: `final_TI_info.csv`
   - Input: `ip = src_ip`
   - Output:
     - `TI_verdict = src_TI_verdict`
     - `abuseConfidenceScore = src_AbuseIPDB_score`
     - `vt_percentage_score = src_VT_percentage_score`
     - `domain = src_domain`

4. **TI data `dest_ip`**:
   - Lookup table: `final_TI_info.csv`
   - Input: `ip = dest_ip`
   - Output:
     - `TI_verdict = dest_TI_verdict`
     - `abuseConfidenceScore = dest_AbuseIPDB_score`
     - `vt_percentage_score = dest_VT_percentage_score`
     - `domain = dest_domain`

### Step 6: Creating Event Types

Go to `Settings > Event types` and create four event types with the corresponding queries and priorities:

- **Malicious** (Priority: 1):
  ```splunk
  index=ngfw (src_TI_verdict="Malicious" OR dest_TI_verdict="Malicious")
  ```

- **Suspicious** (Priority: 2):
  ```splunk
  index=ngfw (src_TI_verdict="Suspicious" OR dest_TI_verdict="Suspicious") AND NOT (src_TI_verdict="Malicious" OR dest_TI_verdict="Malicious")
  ```

- **Harmless** (Priority: 3):
  ```splunk
  index=ngfw (src_TI_verdict="Harmless" OR dest_TI_verdict="Harmless") AND NOT (src_TI_verdict="Malicious" OR dest_TI_verdict="Malicious" OR src_TI_verdict="Suspicious" OR dest_TI_verdict="Suspicious")
  ```

- **Unknown** (Priority: 4):
  ```splunk
  index=ngfw NOT (src_TI_verdict=* OR dest_TI_verdict=*)
  ```

### Step 7: Importing the Dashboard

1. Go to the `Dashboards` section in Splunk.
2. Click `Create New Dashboard`.
3. Select **Dashboard Studio**.
4. Open the `Source` (</>) tab.
5. Paste the contents of the `ngfw_analytics_dashboard.json` file from the repository.
6. Save the dashboard.

After this, the dashboard will be ready for use and will automatically populate with data once searches are executed and lookups are generated.
