# GreyNoise App for Splunk #

This is an app powered by the Splunk Add-on Builder.

# OVERVIEW #
GreyNoise Splunk app provides multiple dashboards to effectively analyse and visualize the contextual and statistical data provided by GreyNoise. It also includes custom commands and alert actions which can be used along with Splunk searches to leverage GreyNoise APIs for custom use cases. It periodically scans the Splunk deployment through saved search to indicate the Internet Scanner and Business Service Intelligence IPs in the complete Splunk deployment. Along with this, the workflow action provided can be used to obtain live context information of any CIM compliant field containing an IP address.

 - Author: GreyNoise Intelligence Inc
 - Version: 3.1.0
 - Creates Index: False
 - Has index-time operation: True
 - Implements summarization: False
 - Prerequisites: GreyNoise API Key, Search heads without Enterprise Security requires the Splunk Common Information Model (CIM) Add-on to for the Modular Alerts to function.

# COMPATIBILITY MATRIX #
 - Splunk Enterprise version: 10.0.x, 9.4.x, and 9.3.x
 - OS: Platform independent
 - Vendor Products: GreyNoise API

# RELEASE NOTES (Version 3.1.0) #
 - Added new Executive Dashboard for Firewall traffic analysis
 - Added Callback IP Feed configuration for scheduled ingest of Callback IPs into `greynoise_callback_indicators`
 - Added Callback IP Lookup dashboard and `gncallback` / `gncallbackfeed` commands
 - Added Callback IP action on CIM IP fields
 - Added Include Community Dataset option on Feed Configuration to include community workspace results in feed queries
 - Updated indicator to now store `spoofable` and `source_workspace` fields
 - Added `gnrecall` command for Recall timeseries and stats lookups
 - Added `gnippsychic` command for Psychic IP lookups
 - Added `gnfeed` command to populate `greynoise_indicators` without storing per-IP `_raw` payloads
 - Rebuilt Overview dashboard using Dashboard Studio
 - Updated GreyNoise SDK to v3.1.0
 - Migrated the configuration UI to UCC 6.6.0
 - Added compatibility with Splunk Enterprise 10.2.x
 - Updated custom commands to require Python 3.13
 - Updated `splunklib` to v2.1.1

# RELEASE NOTES (Version 3.0.2) #
 - Fixed connection failures on RHEL systems caused by IPv6 resolution issues
 - Fixed issue with Live Investigation
 - Updated GreyNoise SDK to v3.0.3
 - Updated `gnquery` to include `excluded_fields` param
 - Updated Feed Import functionality to use new `excluded_fields` param, includes updates to the default savedsearches

# RELEASE NOTES (Version 3.0.1) #
 - Fixed Python file formatting

# RELEASE NOTES (Version 3.0.0) #
 - Implemented CIM (Common Information Model) mapping for better data normalization and integration with Splunk ES
 - Introduced support to update the Risk Score in Splunk Enterprise Security (ES) based on classification
 - Added the capability to ingest GreyNoise feed data into a Splunk index
 - Added support for Splunk ES Threat Intelligence
 - Updated the IP Timeline Lookup dashboard with new filters
 - Updated the GreyNoise SDK to version 3.0.1
 - Migrated the app to the latest version of Splunk Add-on Builder (v4.5.0)
 - Removed the commands `gnipsimilar` and `gnriot`
 - Removed the Similar IP Lookup dashboard

# RELEASE NOTES (Version 2.3.0) #
 - Add new `gncve` command to support GreyNoise CVE API lookups
 - Update dashboards and commands to support new Suspicious classification
 - Update Splunk SDK to version 2.1.0
 - Update GreyNoise SDK to version 2.3.0

# RELEASE NOTES (Version 2.2.4) #
 - Correct python3.7 compatibility issue

# RELEASE NOTES (Version 2.2.3) #
 - Upgrade GreyNoise SDK to v2.1.0
 - Updated to support Splunk Cloud requirements

# RELEASE NOTES (Version 2.2.2) #
 - Updated Splunk SDK to 1.7.4 to support Splunk Cloud requirements

# RELEASE NOTES (Version 2.2.1) #
 - Updated to support Splunk Cloud requirements

# RELEASE NOTES (Version 2.2.0) #
 - Added new FEED component to create lookuptable based on GreyNoise indicators
 - Added new command `gnipsimilar` and new `Similar IP Lookup` dashboard
 - Added new command `gniptimeline` and new `IP Timeline Lookup` dashboard
 - Updated `gnenrich` command to use batch lookups
 - Updated `gnquery` command with new parameters `page_size` and `exclude_raw`
 - Updated GreyNoise SDK to v2.0.1

# RELEASE NOTES (Version 2.1.5) #
 - Fix bug with `gnenrich`, `gnriot`, and `gnfilter` where proxy wasn't being used for API key validation
 - Fix credentials.py to deal with null API keys on fresh install

# RELEASE NOTES (Version 2.1.4) #
 - Add support for configuring proxy information in conf file
 - Add support for IP Destination Geo feature fields
 - Fix bug in `gnriot` when IPv6 address is sent for lookup
 - Update to use GreyNoise SDK 1.3.0
 - Update to use splunktaucclib 6.0.6

# RELEASE NOTES (Version 2.1.2) #
 - Fixed issue where API key could not be entered on new installs
 - IMPORTANT: GreyNoise API Key *must* be re-entered if upgrading from a previous version

# RELEASE NOTES (Version 2.1.1) #
 - Fixed JQuery 3.5.0 compatibility issue identified via Upgrade Readiness
 - Fixed Python3 compatibility issue identified via Upgrade Readiness
 - Fixed missing explict definition for cache_maintenance script to use py3
 - Update to use GreyNoise SDK 1.2.0
 - Updated splunklib to version 1.6.18

# RELEASE NOTES (Version 2.1.0) #
 - Python2 and Splunk7.x support is dropped starting from this release, GreyNoise now only supports Splunk 8.x and Python3
 - Updated to latest GreyNoise SDK 1.1.0
 - Added gnriot custom command for the RIOT endpoint
 - Improves error messages for non-routable and invalid IP address
 - Updated splunklib to version 1.6.16
 - Updated the time in gnoverview saved search to 6 hours
 - Added 2 new codes to the csv file
 - Updated the custom commands, saved searches and dashboards to handle the RIOT key
 - Fixed an issue to handle Splunk fields with unallowed characters
 - Added Caching feature for all the custom commands and saved searches.

# OPEN SOURCE COMPONENTS AND LICENSES #
The third party library and its license information is as follows:

 - concurrent.futures (vendored CPython stdlib) https://docs.python.org/3/library/concurrent.futures.html (LICENSE https://docs.python.org/3/license.html)
 - cachetools version 6.2.6 https://pypi.org/project/cachetools/ (LICENSE https://github.com/tkem/cachetools/blob/v6.2.6/LICENSE)
 - certifi version 2026.06.17 https://pypi.org/project/certifi/ (LICENSE https://github.com/certifi/python-certifi/blob/2026.06.17/LICENSE)
 - chardet version 4.0.0 https://pypi.org/project/chardet/ (LICENSE https://github.com/chardet/chardet/blob/4.0.0/LICENSE)
 - charset_normalizer version 3.4.9 https://pypi.org/project/charset-normalizer/ (LICENSE https://github.com/jawah/charset_normalizer/blob/3.4.9/LICENSE)
 - idna version 3.18 https://pypi.org/project/idna/ (LICENSE https://github.com/kjd/idna/blob/v3.18/LICENSE.md)
 - more_itertools version 10.8.0 https://pypi.org/project/more-itertools/ (LICENSE https://github.com/more-itertools/more-itertools/blob/10.8.0/LICENSE)
 - requests version 2.32.5 https://pypi.org/project/requests/ (LICENSE https://github.com/psf/requests/blob/v2.32.5/LICENSE)
 - schematics version 2.1.0 https://pypi.org/project/schematics/ (LICENSE https://github.com/schematics/schematics/blob/v2.1.0/LICENSE)
 - sortedcontainers version 2.4.0 https://pypi.org/project/sortedcontainers/ (LICENSE https://github.com/grantjenks/python-sortedcontainers/tree/v2.4.0)
 - splunklib version 2.1.1 https://github.com/splunk/splunk-sdk-python/tree/2.1.1/splunklib (LICENSE https://github.com/splunk/splunk-sdk-python/blob/2.1.1/LICENSE)
 - structlog version 22.3.0 https://pypi.org/project/structlog/ (LICENSE https://github.com/hynek/structlog/blob/22.3.0/LICENSE)
 - urllib3 version 1.26.20 https://pypi.org/project/urllib3/ (LICENSE https://github.com/urllib3/urllib3/blob/1.26.20/LICENSE.txt)
 - decorator.py version 5.1.1 https://pypi.org/project/decorator/ (LICENSE https://github.com/micheles/decorator/blob/5.1.1/LICENSE.txt)
 - six.py version 1.17.0 https://pypi.org/project/six/ (LICENSE https://github.com/benjaminp/six/blob/1.17.0/LICENSE)
 - daterangepicker.css version 3.14.1 (LICENSE https://www.daterangepicker.com/#license)
 - ipaddress.py version 1.0.23 https://pypi.org/project/ipaddress/ (LICENSE https://github.com/phihag/ipaddress/blob/v1.0.23/LICENSE)

# TOPOLOGY AND SETTING UP SPLUNK ENVIRONMENT #
Standalone Mode

 - Install GreyNoise App for Splunk. See INSTALLATION section for more details.
 - Configure the API key and log level. See CONFIGURATION section for details.

Search Head Cluster

 - In case of *Search Head Clustering*, make sure that the `GreyNoise Setup` and `Scan Deployment` is configured on only single search head. In such cases, the configuration will not be visible on other search heads. In case if user wants to configure the `Logging` (default is INFO), user can configure individually on every search head. This is recommended.
 - If user wants to replicate the configuration settings, follow these steps:
    - On search head deployer, extract the app at `$SPLUNK_HOME$/etc/shcluster/apps`.
    - Create stanza `shclustering` at path `$SPLUNK_HOME$/etc/shcluster/apps/SA-GreyNoise/local/server.conf` and add following information to the stanza: `conf_replication_include.app_greynoise_settings = true`
    - Push the bundle to search head.
    - Configure the API key and log level. See CONFIGURATION section for details. Following these steps will replicate the configuration on all search heads.

# Support for Splunk ES - Threat Intelligence #
The GreyNoise App for Splunk provides integration with Enterprise Security (ES) Threat Intelligence. Follow the steps below to add GreyNoise indicator data into Splunk ES:

1. Navigate to the Splunk UI: **Settings > Searches, Reports, and Alerts**
2. In the filter options:  
   - Select **“GreyNoise App for Splunk (SA-GreyNoise)”** from the *App* dropdown  
   - Select **“All”** from the *Owner* dropdown
3. Search for `greynoise_populate` in the filter. The following four saved searches will be displayed:  
   - `greynoise_populate_ip_intel_benign`  
   - `greynoise_populate_ip_intel_malicious`  
   - `greynoise_populate_ip_intel_suspicious`  
   - `greynoise_populate_ip_intel_unknown`
4. For the required classifications, click **Edit > Enable** on the desired searches.
5. Navigate to: **Apps > Enterprise Security**
6. From the navigation bar, go to: **Configuration > Threat Intelligence**
7. Click **New > Local**
8. Fill out all mandatory fields in the form. For specific fields:  
   - **Type:** `threatlist`  
   - **URL:** Select the appropriate lookup URL from the list below:
     - `lookup://greynoise_ip_intel_benign`  
     - `lookup://greynoise_ip_intel_malicious`  
     - `lookup://greynoise_ip_intel_suspicious`  
     - `lookup://greynoise_ip_intel_unknown`
9. The lookup data can be viewed under: **Analytics > Security Intelligence > Threat Intelligence > Indicators**
10. Findings related to the indicators can be reviewed under: **Analytics > Security Intelligence > Threat Intelligence > Findings (Threat Findings)**

# Support to Update Risk Score in Splunk Enterprise Security (ES) #

To update the risk score based on the classification of GreyNoise scan results, follow the steps below:

1. From the Splunk UI, navigate to: **GreyNoise > Configuration**
2. Go to the **Scan Deployment** tab.
3. Check the **"Update Risk Score to Splunk ES"** checkbox.
4. Enter the desired risk score for each classification:
   - `Malicious`
   - `Suspicious`
   - `Unknown`
   - `Benign`
5. Click **Save** to apply the settings.

## To Analyze the Risk Score in Splunk ES:

1. From the Splunk UI, navigate to the **Enterprise Security** app.
2. Go to: **Analytics > Security Intelligence > Risk Analysis**
3. Adjust the filters as needed and review the panels to analyze the risk scores.

# UPGRADING FROM VERSION 2.3.0 #
Follow the steps below to upgrade the app to the latest version:

 - Disable all saved searches that use alert actions and custom commands of GreyNoise.
 - Backup your current app/configurations outside the Splunk installation path.
 - To upgrade the app from the UI, follow the steps in the INSTALLATION section below. Ensure that the `Upgrade app.` checkbox is selected before clicking the Upload button.
 - From the UI, navigate to **Settings > Searches, Reports, and Alerts**.
 - Run the saved searches `greynoise_migrate_gn_scan_deployment_ip_lookup`, `greynoise_migrate_greynoise_indicators_lookup` and `greynoise_migrate_gn_overview_lookup` **ONCE**.
 - Make sure to enable the `Purge Cache` option under `Caching` for the first scan deployment.
 - Follow the steps mentioned in the CONFIGURATION section to reconfigure the app.
 - If SCAN DEPLOYMENT was configured before upgrading the app, go to the SCAN DEPLOYMENT tab inside the Configuration tab and click the Save button to reconfigure the scan deployment saved search in the backend.

# UPGRADING FROM VERSION 2.0.1#
Follow the below steps to upgrade the app to the latest version:

 - Disable all the saved searches which uses alert actions and custom commands of GreyNoise.
 - Backup your current app/configurations outside the Splunk install path.
 - To upgrade the app from the UI, follow the steps in the INSTALLATION section below. Ensure that `Upgrade app.` checkbox is selected before clicking on the Upload button.
 - Follow the steps mentioned in CONFIGURATION section to reconfigure the app.
 - If SCAN DEPLOYMENT was configured before app upgrading then go to SCAN DEPLOYMENT tab inside the Configuration tab and Click on Save button to re-configure the scan deployment saved search in the backend.

*Note: Upgrade is only supported from UI and not supported from the backend.*

# INSTALLATION #
Follow the below-listed steps to install an app from the bundle:

 - Download the App package.
 - From the UI navigate to Apps > Manage Apps.
 - In the top right corner select Install app from file.
 - Select Choose File and select the App package.
 - Select Upload and follow the prompts.
 - Restart the Splunk to complete the installation.

*Note: This app contains Adaptive Response Actions, which can be used along with Splunk Enterprise Security. To use these alert actions on the Splunk instance without Splunk Enterprise Security, kindly install `Splunk Common Information Model (CIM)`.*

# UPGRADES #
After applying an update to the app, ensure that the GreyNoise API key is re-entered on the Configuration page.

# CONFIGURATION #
The app can be configured in the following way:

 - From the Splunk UI navigate to `Apps > GreyNoise App for Splunk > Configuration`.
 - Click on GreyNoise Setup and enter the API Key.
 - Click on Save button.
 - The app is now configured and all the features apart from Scan Deployment and Caching are ready to be used.

# SCAN DEPLOYMENT #
This feature helps user to scan the Splunk Deployment and identify the Internet Scanner and Business Service Intelligence IP addresses from it. It can be configured in the following way:

 - From the Splunk UI navigate to `Apps > GreyNoise App for Splunk > Configuration`.
 - Click on Scan Deployment.
 - Enter the following details to set up the Scan Deployment:
    - Indexes: Indexes to be scanned in the deployment.
    - CIM Fields:  CIM fields containing IP address to scan for Internet Scanner status.
    - Other Fields: Other comma(,) separated fields containing IP address to scan for Internet Scanner and Business Service Intelligence status.
    - Scan Start Time: Time range for scanning the indexed Splunk data.
    - Enable Scan Deployment: Checkbox to enable or disable scanning of the deployment.
    - Force Scan Deployment: This is useful when user wants to override current running scan immediately and start a new one.
    - Update Risk Score To Splunk ES: This is useful when user wants to update the risk score to Splunk ES risk index.
    - Malicious: This is risk score threshold for Malicious classification.
    - Suspicious: This is risk score threshold for Suspicious classification.
    - Unknown: This is risk score threshold for Unknown classification.
    - Benign: This is risk score threshold for Benign classification.

# FEED #
This feature allows users to ingest GreyNoise indicators into a lookup table to be usage within the Splunk environment:

 - From the Splunk UI navigate to `Apps > GreyNoise App for Splunk > Configuration`.
 - Click on Feed Configuration tab.
 - Enter the following details to set up the Feed:
    - Enable Feed Import: turns the feature on to enable the daily ingest of GreyNoise indicators via feed.
    - Force Feed Run Now: starts a manual run of the feed import, rather than waiting for the daily scheduled run.
    - Feed Selection: select the appropriate option to choose which type of feed to ingest into the system.
    - Include Community Dataset: Checkbox to include community dataset results in the feed query. Defaults to false.
    - Ingest Feed To Index: Selecting this checkbox will ingest data into the Splunk index. Please check your licensing as this feature will consume license capacity. Enable this option only if you need to map feed data to Splunk CIM data models for specific use cases. Refer this document to understand how to create index: https://docs.splunk.com/Documentation/Splunk/latest/Indexer/Setupmultipleindexes#Create_events_indexes
    - Index: Select the index to ingest the feed to.

# CALLBACK IP FEED #
This feature allows users to ingest GreyNoise Callback IPs into the `greynoise_callback_indicators` lookup for use within the Splunk environment. A Callback-enabled GreyNoise license is required.

 - From the Splunk UI navigate to `Apps > GreyNoise App for Splunk > Configuration`.
 - Click on Callback IP Feed tab.
 - Enter the following details to set up the Callback IP Feed:
    - Enable Callback IP Feed: turns the feature on to enable scheduled ingest of Callback IPs into the `greynoise_callback_indicators` store.
    - Force Callback Feed Run Now: starts a manual run of the Callback feed import, rather than waiting for the scheduled run.
    - Stage 1 (File Downloaded): filter to IPs where a file was downloaded, exclude those IPs, or leave as Any.
    - Stage 2 (Suspected C2): filter to IPs suspected as C2 from VT/sandbox analysis, exclude those IPs, or leave as Any.
    - Has Files: filter to IPs that have malware files associated, only IPs without files, or Any.
    - First Seen After: only include IPs first seen after the selected relative date (1, 7, 14, 30, 45, 60, or 90 days ago). Leave as Any for no filter.
    - First Seen Before: only include IPs first seen before the selected relative date. Leave as Any for no filter.
    - Last Seen After: only include IPs last seen after the selected relative date. Leave as Any for no filter.
    - Last Seen Before: only include IPs last seen before the selected relative date. Leave as Any for no filter.
    - File Type: optional MIME type filter (for example `application/x-executable`). Leave blank for no filter.
    - File Name: optional file name substring filter. Leave blank for no filter.
    - File Hash (SHA256): optional file SHA256 hash filter. Leave blank for no filter.
    - Scanner IPs: optional comma-separated scanner IPs used to filter Callback results. Leave blank for no filter.
    - Callback IPs: optional comma-separated Callback IPs that restrict the feed to a specific set. Leave blank to ingest all matching Callback IPs.

# CACHING #
This feature helps user to enable/disable caching for all the custom commands and saved searches. It can be configured in the
following way:

 - From the Splunk UI navigate to `Apps > GreyNoise App for Splunk > Configuration`.
 - Click on Caching.
 - Enter the following details to set up the Caching:
    - Enable caching: Checkbox to enable caching for all custom commands and savedsearches.
    - Time to live: Time period (in hours) to configure the cache’s time to live. Responses whose age is greater than the TTL, will be removed from the cache by a savedsearch which will run every hour.
    - Purge Cache: Checkbox to purge the cache of all responses.

*Note: Configuration can only be done by admin but other custom commands can be used by admin and the users with list_storage_passwords capability.*

# LOGGING #

 - User can configure the log level by navigating to `Apps > GreyNoise App for Splunk > Configuration` and selecting Logging.

# PROXY SUPPORT #
To enable proxy support, modify the app_greynoise_settings.conf and add a proxy entry to the parameters section.

Example:
[parameters]
proxy = http://proxy.acme.com:8080

# CUSTOM COMMANDS #
The following commands are included as a part of the app:

 - gnenrich
    - Search format: `SPL_QUERY | gnenrich ip_field="<ip_field>"`
    - Purpose: Enrich the Splunk events returned by given SPL_QUERY with the context information of IP address represented by ip_field in Splunk Search.
 - gnmulti
    - Search format: `SPL_QUERY | gnmulti ip_field="<ip_field>"`
    - Purpose: Retrieves Internet Scanner and Business Service Intelligence status of the IP addresses represented by ip_field parameter present in each event, and adds the Internet Scanner and Business Service Intelligence information to each event.
 - gnip
    - Search format: `| gnip ip="<ip_address>"`
    - Purpose: Retrieves context information for a given IP address from GreyNoise.
 - gncontext
    - Search format: `| gncontext ip="<ip_address>"`
    - Purpose: Alias of `gnip`. Retrieves context information for a given IP address from GreyNoise.
 - gnquick
    - Search format: `| gnquick ip="<ip_address1>,<ip_address2>,<ip_address3>"` or `SPL_QUERY | gnquick ip_field="<ip_field>"`
    - Purpose: Retrieve the Internet Scanner and Business Service Intelligence status of the given IP addresses as separate events, or enrich events from SPL_QUERY using ip_field.
 - gnippsychic
    - Search format: `| gnippsychic ip="<ip_address1>,<ip_address2>,<ip_address3>"` or `SPL_QUERY | gnippsychic ip_field="<ip_field>"`
    - Purpose: Retrieve Psychic lookup results for the given IP addresses as separate events, or enrich events from SPL_QUERY using ip_field.
 - gnquery
    - Search format: `| gnquery query="<GNQL_query>" result_size="<result_size>" page_size="<page_size>" exclude_raw="<true/false>" exclude_fields="<comma-separated field names>"`
    - Purpose: Retrieve the results of the given GNQL query from GreyNoise. `result_size` is optional with a default of 50,000. `page_size` is optional with a default of 1,000. `exclude_raw` omits API `raw_data` from each hit. `exclude_fields` omits named fields from each GNQL hit.
 - gnfeed
    - Search format: `| gnfeed` or `| gnfeed query="<GNQL_query>" result_size="<result_size>" page_size="<page_size>" include_raw="<true/false>"`
    - Purpose: Retrieve GNQL results as lean indicator rows for the `greynoise_indicators` lookup. Does not store a Splunk `_raw` copy of each IP unless Feed ingest-to-index is enabled or `include_raw=true`. When `query` is omitted, the latest query from `gn_feed_lookup` is used.
 - gnrecall
    - Search format: `| gnrecall query="<GNQL_query>" mode="timeseries|stats" start="<datetime>" end="<datetime>" result_size="<result_size>" page_size="<page_size>" interval="<interval>"`
    - Purpose: Retrieve GreyNoise Recall activity over time. `mode=timeseries` (default) returns time-series rows; `mode=stats` returns aggregated stats. `start` and `end` default to the last seven days. `interval` applies to stats mode (for example `day`).
 - gnstats
    - Search format: `| gnstats query="<GNQL_query>" count="<stats_count>"`
    - Purpose: Fetch the aggregate statistics for the top organizations, actors, tags, ASNs, countries, classifications, and operating systems of all the results for a given GNQL query. `count` is optional and controls how many top stats are retrieved.
 - gnfilter
    - Search format: `SPL_QUERY | gnfilter ip_field="<ip_field>" noise_events="<true/false>"`
    - Purpose: Filter Splunk events returned by given SPL_QUERY based on the Internet Scanner status of IP address present in ip_field. `noise_events` is optional with a default of true, so events with noisy IP addresses are returned by default.
 - gncallback
    - Search format: `SPL_QUERY | gncallback ip_field="<ip_field>" source_workspace="<source_workspace>"`
    - Purpose: Enrich Splunk events with GreyNoise Callback intelligence for the IP address represented by ip_field. `source_workspace` is optional and defaults to `all`.
 - gncallbackfeed
    - Search format: `| gncallbackfeed`
    - Purpose: Retrieve Callback IP indicators using filters from the Callback IP Feed configuration page. Used by scheduled searches to populate the `greynoise_callback_indicators` lookup.
 - gniptimeline
    - Search format: `| gniptimeline ip_address="<ip_address>" days="<days>" field="<field>" granularity="<granularity>"`
    - Purpose: Retrieve timeline events for a given IP address from the GreyNoise Timeline API. `days` is optional (default 30, maximum 90). `field` is optional (default `classification`). `granularity` is required (default `1h`).
 - gncve
    - Search format: `| gncve cve="<cve_id>"` or `SPL_QUERY | gncve cve_field="<cve_field>"`
    - Purpose: Retrieve CVE information for a given CVE ID from GreyNoise, or enrich events from SPL_QUERY using the field specified by cve_field.

*Note : While executing the transforming commands from Splunk search UI, ensure that the event count passed to the command is less than 50,000, as per standard limits of Splunk. If the event count is higher than this number, user can create a Saved Search and pass higher number of Splunk statistical data to the command.*

# ALERT ACTIONS #
The following alert actions are included as a part of the app:

 - GreyNoise Quick Check: Returns Internet Scanner and Business Service Intelligence status from GreyNoise for IP addresses in the specified `ip_field`.
 - GreyNoise Context Check: Returns context information from GreyNoise for IP addresses in the specified `ip_field`.

These alert actions can be used from Splunk alerts and as Splunk Enterprise Security Adaptive Response actions. Results are written to `index=main sourcetype=greynoise`. The sources are `source=greynoise_quick` for Quick Check and `source=greynoise_context` for Context Check. Search heads without Enterprise Security require the Splunk Common Information Model (CIM) Add-on for these modular alerts to write results.

Usage with Splunk Enterprise Security:
 - These actions can be executed from Incident Review, and results can be accessed by refreshing the Adaptive Responses panel and opening the corresponding result link.

# WORKFLOW ACTIONS #
The following field-menu workflow actions are enabled for CIM IP fields (`dest`, `dvc`, `src`, `dest_ip`, `src_ip`, `dvc_ip`, `orig_src`, `orig_dest`, `host`, `source`, `dest_translated_ip`, `src_translated_ip`):

 - Identify Internet Scanner: Opens the Live Investigation dashboard with context information for the selected IP address.
 - Get Internet Scanner IP Timeline: Opens the IP Timeline Lookup dashboard for the selected IP address. Also enabled for `greynoise_ip`.
 - Get Callback IP Intelligence: Opens the Callback IP Lookup dashboard for the selected IP address. Also enabled for `greynoise_ip`.

# DASHBOARDS #
This app contains the following dashboards:

 - Overview: GreyNoise platform statistics and Internet Scanner / Business Service Intelligence counts for IPs scanned in the Splunk deployment. This is the default landing page.
 - GreyNoise Executive Dashboard: Firewall and VPN traffic enriched with GreyNoise feed intelligence, including executive summary and SOC triage views. Requires a configured Feed import and supported firewall or VPN logs.
 - Queried IP Addresses: Internet Scanner and Business Service Intelligence status for IPs discovered by Scan Deployment. This dashboard is populated when Scan Deployment is enabled.
 - Live Investigation: Runs a live GNQL query from form inputs (IP, classification, organization, actor, tag, OS, category, country, ASN, and relative date range).
 - IP Timeline Lookup: Retrieves a timeline of scanning activity for a submitted IP. Requires an IP Timeline license.
 - Callback IP Lookup: Retrieves Callback intelligence for a submitted IP, including stage indicators, observation dates, source workspaces, and enrichment details. Requires a Callback-enabled GreyNoise license.

# SAVED SEARCHES #
This app contains the following saved searches:

 - greynoise_scan_deployment_once: Populates `gn_scan_deployment_ip_lookup` and is triggered after configuring Scan Deployment using the Force option.
 - greynoise_scan_deployment: Populates `gn_scan_deployment_ip_lookup` hourly (`0 * * * *`) and using the configured options.
 - greynoise_overview_once: Populates `gn_overview_lookup` and is triggered after configuring the API key.
 - greynoise_overview: Populates `gn_overview_lookup` every 6 hours (`0 */6 * * *`).
 - greynoise_cache_maintenance: Removes cache entries whose TTL has expired. Runs hourly (`0 * * * *`).
 - greynoise_feed_once: Populates `greynoise_indicators` with `gnfeed` after configuring and using the Force option.
 - greynoise_feed: Populates `greynoise_indicators` with `gnfeed` daily at 03:00 (`0 3 * * *`). If Feed ingest-to-index is enabled, `greynoise_feed_partial_search` also collects events into the configured index.
 - greynoise_feed_purge: Removes indicators with `last_seen` older than 7 days from `greynoise_indicators`. Runs daily at 00:00 (`0 0 * * *`).
 - greynoise_callback_feed_once: Populates `greynoise_callback_indicators` with `gncallbackfeed` on demand after configuring and using the Force option.
 - greynoise_callback_feed: Populates `greynoise_callback_indicators` with `gncallbackfeed` daily at 04:00 (`0 4 * * *`).
 - greynoise_callback_feed_purge: Removes Callback indicators with `last_seen` older than 30 days from `greynoise_callback_indicators`. Runs daily at 00:30 (`30 0 * * *`).
 - greynoise_migrate_greynoise_indicators_lookup: Migrates `greynoise_indicators.csv` to the `greynoise_indicators` KV lookup (run once after upgrade to 3.x. Not needed for a fresh 3.0.0 or later install).
 - greynoise_migrate_gn_overview_lookup: Migrates `gn_overview_lookup.csv` to the `gn_overview_lookup` KV lookup (run once after upgrade to 3.x. Not needed for a fresh 3.0.0 or later install).
 - greynoise_migrate_gn_scan_deployment_ip_lookup: Migrates `gn_scan_deployment_ip_lookup` from the previous schema to the current schema (run once after upgrade to 3.x. Not needed for a fresh 3.0.0 or later install).
 - greynoise_populate_ip_intel_malicious: Copies malicious indicators from `greynoise_indicators` into `greynoise_ip_intel_malicious` for Splunk ES threat intelligence. Runs at :00 and :30 past each hour.
 - greynoise_populate_ip_intel_suspicious: Copies suspicious indicators from `greynoise_indicators` into `greynoise_ip_intel_suspicious`. Runs at :10 and :40 past each hour.
 - greynoise_populate_ip_intel_unknown: Copies unknown indicators from `greynoise_indicators` into `greynoise_ip_intel_unknown`. Runs at :20 and :50 past each hour.
 - greynoise_populate_ip_intel_benign: Copies benign indicators from `greynoise_indicators` into `greynoise_ip_intel_benign`. Runs at :25 and :55 past each hour.

# MACROS #
This app contains the following macros:

 - greynoise_fields: CIM IP fields used by Scan Deployment to extract IPs from events. Updated from the Scan Deployment configuration page.
 - greynoise_other_fields: Additional comma-separated IP fields used by Scan Deployment. Updated from the Scan Deployment configuration page.
 - greynoise_indexes: Indexes scanned by Scan Deployment. Default is `main`. Updated from the Scan Deployment configuration page.
 - greynoise_caching: Caching enable flag (`1` or `0`). Updated from the Caching configuration page.
 - greynoise_ttl: Cache time-to-live in hours. Default is `24`. Updated from the Caching configuration page.
 - greynoise_feed_partial_search: Inserted into `greynoise_feed_once` and `greynoise_feed`. Default is `| noop`. When Feed ingest-to-index is enabled, rewritten to `| collect` into the configured index.
 - gn_fw_index: Firewall events for the Executive Dashboard. Default is `index=pan* sourcetype=pan:traffic`. Customize this to match your firewall sourcetype.
 - gn_vpn_index: VPN events for the Executive Dashboard. Default is `index=pan* sourcetype=pan:globalprotect`. Customize this to match your VPN sourcetype.
 - gn_is_internal(ip_field): Returns `1` when the given field is in RFC1918, unique-local, or link-local ranges, otherwise `0`.
 - gn_fw_scope: Builds inbound/outbound firewall traffic from `gn_fw_index` and `gn_is_internal`, including `gn_ip`, `internal_ip`, `is_allowed`, and `xfer_bytes`. Used by the Executive Dashboard.
 - gn_vpn_scope: Normalizes VPN auth status from `gn_vpn_index`. Used by the Executive Dashboard.

# UNINSTALL APP #
To uninstall app, user can follow below steps:
 - SSH to the Splunk instance
 - Go to folder apps($SPLUNK_HOME/etc/apps)
 - Remove the SA-GreyNoise folder from apps directory
 - Restart Splunk

# TROUBLESHOOTING #
 - Alerts fail to write to index=main sourcetype=greynoise and Enterprise Security is not installed.
    -  Ensure that the Splunk Common Information Model (CIM) Add-on has been installed. No configuration of this add-on is necessary.
 - Data in Overview dashboard is not being populated.
    - Ensure that `greynoise_overview` Saved Search is enabled.
 - Data in Queried IP Addresses dashboard is not being populated.
    - Ensure that the Scan Deployment feature is enabled. The data must populate in an hour. In case the issue still persists, make sure that `greynoise_scan_deployment` Saved Search is enabled.
    - Ensure that the KV store is enabled.
 - Custom commands are not being executed and failing with unknown exception. For example: `Exception occurred while fetching the context of the ip=<ip>. See greynoise_main.log for more details.`
    - Ensure that the user executing custom command has list_storage_passwords capability.
 - Internet Scanner and Business Service Intelligence information of some of the IP addresses is being missed in Queried IP Addresses dashboard.
    - Ensure that the corresponding index and fields are entered as per the format while enabling Scan Deployment feature.
 - Custom commands exited unexpectedly.
    - Ensure that maximum 50000 results are passed to the custom command while executing search from the Splunk Search Interface, as Splunk supports maximum 50000 results. For processing more results, Saved Searches can be used.
 - Scan Deployment feature is not working as expected.
    - Check for the messages in Splunk UI. If message like `KV store not in ready state. Make sure it is enabled.` is shown, ensure that KV store is enabled.
    - Check in splunkd.log for messages like `External command based lookup 'gn_scan_deployment_ip_lookup' is disabled because KV Store is disabled.`
    - If such messages show up, then ensure that the KV store is enabled.
 - In search head clustering, configurations are visible on only one search head and not on others.
    - This is the expected behaviour when replication is not enabled. The functionalities will work on all the search heads.
 - If any of the transforming command is not working as expected, ensure that the events have IP field extracted which is passed to ip_field parameter in the transforming command.
 - Getting following error while using transforming custom commands.
    - Events might not be returned in sub-second order due to search memory limits.
      1. Create a file 'limits.conf' in the following directory `$SPLUNK_HOME/etc/SA-GreyNoise/local`.
      2. Add the following stanza in the file:
      ```
      [search]
      max_rawsize_perchunk = 500000000
      ```

# SUPPORT #
 - Email: support@greynoise.io
 - Hours: 9AM-5PM EDT Monday-Friday
 - Observed Holidays: Major US Holidays

# COPYRIGHT #
 - Copyright (C) 2026 GreyNoise Intelligence Inc. All Rights Reserved.