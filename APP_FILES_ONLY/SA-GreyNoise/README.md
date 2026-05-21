# GreyNoise App for Splunk #

This is an app powered by the Splunk Add-on Builder.

# OVERVIEW #
GreyNoise Splunk app provides multiple dashboards to effectively analyse and visualize the contextual and statistical data provided by GreyNoise. It also includes custom commands and alert actions which can be used along with Splunk searches to leverage GreyNoise APIs for custom use cases. It periodically scans the Splunk deployment through saved search to indicate the Internet Scanner and Business Service Intelligence IPs in the complete Splunk deployment. Along with this, the workflow action provided can be used to obtain live context information of any CIM compliant field containing an IP address.

 - Author: GreyNoise Intelligence Inc
 - Version: 3.0.2
 - Creates Index: False
 - Has index-time operation: True
 - Implements summarization: False
 - Prerequisites: GreyNoise API Key, Search heads without Enterprise Security requires the Splunk Common Information Model (CIM) Add-on to for the Modular Alerts to function.

# COMPATIBILITY MATRIX #
 - Splunk Enterprise version: 10.2.x, 10.0.x, 9.4.x, and 9.3.x
 - OS: Platform independent
 - Vendor Products: GreyNoise API

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

 - futures version 3.3.0 https://pypi.org/project/futures/ (LICENSE https://github.com/agronholm/pythonfutures/blob/master/LICENSE)
 - concurrent.futures version 3.7.4 https://docs.python.org/3/library/concurrent.futures.html (LICENSE https://github.com/python/cpython/blob/v3.7.4/LICENSE)
 - cachetools version 4.2.2 https://pypi.org/project/cachetools/ (LICENSE https://github.com/tkem/cachetools/blob/v4.2.2/LICENSE)
 - certifi version 2021.05.30 https://pypi.org/project/certifi/ (LICENSE https://github.com/certifi/python-certifi/blob/2021.05.30/LICENSE)
 - chardet version 4.0.0 https://pypi.org/project/chardet/ (LICENSE https://github.com/chardet/chardet/blob/4.0.0/LICENSE)
 - idna version 2.10 https://pypi.org/project/idna/ (LICENSE https://github.com/kjd/idna/blob/v2.10/LICENSE.rst)
 - more_itertools version 8.8.0 https://pypi.org/project/more-itertools/ (LICENSE https://github.com/more-itertools/more-itertools/blob/v8.8.0/LICENSE)
 - requests version 2.25.1 https://pypi.org/project/requests/ (LICENSE https://github.com/psf/requests/blob/v2.25.1/LICENSE)
 - schematics version 2.1.0 https://pypi.org/project/schematics/ (LICENSE https://github.com/schematics/schematics/blob/v2.1.0/LICENSE)
 - sortedcontainers version 2.1.0 https://pypi.org/project/sortedcontainers/ (LICENSE https://github.com/grantjenks/python-sortedcontainers/tree/v2.1.0)
 - splunklib version 1.6.16 https://github.com/splunk/splunk-sdk-python/tree/master/splunklib (LICENSE https://github.com/splunk/splunk-sdk-python/blob/1.6.16/LICENSE)
 - structlog version 21.1.0 https://pypi.org/project/structlog/ (LICENSE https://github.com/hynek/structlog/blob/21.1.0/LICENSE)
 - urllib3 version 1.26.6 https://pypi.org/project/urllib3/ (LICENSE https://github.com/urllib3/urllib3/blob/1.26.6/LICENSE.txt)
 - decorator.py version 4.1.2 https://pypi.org/project/decorator/ (LICENSE https://github.com/micheles/decorator/blob/4.1.2/LICENSE.txt)
 - six.py version 1.16.0 https://pypi.org/project/six/ (LICENSE https://github.com/benjaminp/six/blob/1.16.0/LICENSE)
 - daterangepicker.css and daterangepicker.min.js version 3.14.1 (LICENSE https://www.daterangepicker.com/#license)
 - moment.min.js version 2.18.1 (LICENSE https://github.com/moment/momentjs.com/blob/master/LICENSE)
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
10. Risk analysis against the indicators can be reviewed under: **Analytics > Security Intelligence > Risk Analysis**

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

Logging

 - User can configure the log level by navigating to `Apps > GreyNoise App for Splunk > Configuration` and selecting Logging.

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
    - Ingest Feed To Index: Selecting this checkbox will ingest data into the Splunk index. Please check your licensing as this feature will consume license capacity. Enable this option only if you need to map feed data to Splunk CIM data models for specific use cases. Refer this document to understand how to create index: https://docs.splunk.com/Documentation/Splunk/latest/Indexer/Setupmultipleindexes#Create_events_indexes
    - Index: Select the index to ingest the feed to.

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
    - Purpose: Retrieves context information for a given IP address from the GreyNoise.
 - gnquick
    - Search format: `| gnquick ip="<ip_address1>,<ip_address2>,<ip_address3>" [OR] SPL_QUERY | gnquick ip_field="<ip_field>"`
    - Purpose: Retrieve the Internet Scanner and Business Service Intelligence status of all the IP addresses as separate events [OR] Retrieve the Internet Scanner and Business Service Intelligence status for all the given IPs returned by the SPL_QUERY for specified ip_field.
 - gnquery
    - Search format: `| gnquery query="<GNQL_query>" result_size="<result_size>" page_size="<page_size>"`
    - Purpose: Retrieve the results of the given GNQL query from GreyNoise. result_size denotes the number of results to be retrieved which is capped at 50,000. result_size is an optional parameter with default value of 50,000. page_size is an option parameter with a default value of 1000.
 - gnstats
    - Search format: `| gnstats query="<GNQL_query>" count="<stats_count>"`
    - Purpose: Fetch the aggregate statistics for the top organizations, actors, tags, ASNs, countries, classifications, and operating systems of all the results for a given GNQL query. count denotes the number of stats to be retrieved. count is an optional parameter.
 - gnmulti
    - Search format: `SPL_QUERY | gnmulti ip_field="<ip_field>"`
    - Purpose: Retrieves Internet Scanner and Business Service Intelligence status of the IP addresses represented by ip_field parameter present in each event, and adds the Internet Scanner and Business Service Intelligence information to each event.
 - gncontext
    - Search format: `| gncontext ip="<ip_address>"`
    - Purpose: Retrieves context information for a given IP address from the GreyNoise.
 - gnfilter
    - Search format: `SPL_QUERY | gnfilter ip_field="<ip_field>" noise_events="<true/false>"`
    - Purpose: Filter Splunk events returned by given SPL_QUERY based on the Internet Scanner status of IP address present in ip_field of the events. noise_events is an optional parameter with default value true. So, it will return events with Queried IP Addresses by default.
 - gniptimeline
    - Search format: `| gniptimeline ip_address="<ip_address>" days=<days> limit=<limit>`
    - Purpose: Retrieves Timeline information for a given IP address from the GreyNoise Timeline API.
 - gncve
    - Search format: `| gncve cve="<cve_id>" [OR] SPL_QUERY | gncve cve_field="<cve_field>"`
    - Purpose: Retrieves CVE information for a given CVE ID from the GreyNoise [OR] for all the given IPs returned by the SPL_QUERY for specified ip_field.

*Note : While executing the transforming commands from Splunk search UI, ensure that the event count passed to the command is less than 50,000, as per standard limits of Splunk. If the event count is higher than this number, user can create a Saved Search and pass higher number of Splunk statistical data to the command.*

# ALERT ACTIONS #
The following alert actions are included as a part of the app:

 - GreyNoise Quick Check: Returns Internet Scanner information from GreyNoise for given IP addresses.
 - GreyNoise Context Check: Returns context information from GreyNoise for given IP Addresses.

These alert actions can be used independently as well as with Splunk Enterprise Security in the form of Adaptive Response Actions. Results from these actions can be found in `index=main sourcetype=greynoise`
The two sources for these adaptive response actions are: `source=greynoise_context` and `source=greynoise_quick`.

Usage with Splunk Enterprise Security:
 - These actions can be executed from Incident Review, and results can be accessed directly by refreshing the "Adaptive Responses" panel and clicking the appropriate link.

# WORKFLOW ACTION
Identify Internet Scanner workflow action is enabled for all the CIM compliant IP fields which can be used to fetch the context information for the corresponding IP addresses.

# DASHBOARDS #
This app contains the following three dashboards:

 - Overview: This dashboard represents an overall visualization of the statistics provided by GreyNoise platform as well as the statistics of the Internet Scanner IPs and the Business Service Intelligence IPs in the Splunk deployment.
 - Queried IP Addresses: This dashboard displays all the IP addresses along with their Internet Scanner and Business Service Intelligence status scanned by GreyNoise through Scan Deployment feature in the current Splunk deployment. This dashboard will be populated when Scan Deployment feature is enabled.
 - Live Investigation: This dashboard can be used to obtain context information fetched dynamically from the GreyNoise platform based on the form input provided.

*Note : In Overview, Percentage of Business Service Intelligence IPs is calculated only for the new IPs scanned after the App was upgraded. Also in the Queried IP Addresses, the Business Service Intelligence status won't be shown for those IPs that were scanned before the App was upgraded.*

# SAVED SEARCHES #
This app contains the following saved searches, which are used for populating data in the dashboard:
 - greynoise_scan_deployment_once: Used to populate `gn_scan_deployment_ip_lookup` lookup and is triggered after configuring Scan Deployment feature.
 - greynoise_scan_deployment: Used to populate `gn_scan_deployment_ip_lookup` lookup and is triggered at an interval of 60 minutes and scans the data of previous 70 minutes.
 - greynoise_overview_once: Used to populate `gn_overview_lookup` lookup, and is triggered after configuring the API key.
 - greynoise_overview: Used to populate `gn_overview_lookup` lookup, and is triggered at an interval of 6 hours.
 - greynoise_cache_maintenance: Used to remove those responses whose TTL is expired from the Cache for all the custom commands, and is triggered at an interval of 60 minutes.
 - greynoise_feed_once: Used to populate the `greynoise_indicators` lookup with feed results and is triggered on-demand when enabling a Feed.
 - greynoise_feed: Used to populate the `greynoise_indicators` lookup with feed results
 - greynoise_feed_purge: Used to purge stale indicators (last_seen value over 7 days ago) from the `greynoise_indicators` lookup
 - greynoise_migrate_greynoise_indicators_lookup: Migrates the contents of the greynoise_indicators.csv lookup to greynoise_indicators KV lookup (only run ONCE after upgrade to version 3.0.0. Not needed if installing version 3.0.0 or later.)
 - greynoise_migrate_gn_overview_lookup: Migrates the contents of the gn_overview_lookup.csv lookup to gn_overview_lookup KV lookup (only run ONCE after upgrade to version 3.0.0. Not needed if installing version 3.0.0 or later.)
 - greynoise_migrate_gn_scan_deployment_ip_lookup: Migrates the contents of the gn_scan_deployment_ip_lookup lookup from previous schema to new schema (only run ONCE after upgrade to version 3.0.0. Not needed if installing version 3.0.0 or later.)
 - greynoise_populate_ip_intel_malicious: This savedsearch retrieves ip from greynoise_indicators lookup and populate data in greynoise_ip_intel_malicious lookup
 - greynoise_populate_ip_intel_suspicious: This savedsearch retrieves ip from greynoise_indicators lookup and populate data in greynoise_ip_intel_suspicious lookup
 - greynoise_populate_ip_intel_unknown: This savedsearch retrieves ip from greynoise_indicators lookup and populate data in greynoise_ip_intel_unknown lookup
 - greynoise_populate_ip_intel_benign: This savedsearch retrieves ip from greynoise_indicators lookup and populate data in greynoise_ip_intel_benign lookup

*Note : greynoise_scan_deployment_once and greynoise_scan_deployment savedsearches are used for scanning the data indexed in Splunk. So, in case when these saved searches are skipped, the data indexed during that interval will not be scanned for Internet Scanner and Business Service Intelligence status.*

# Macros #
This app contains the following macros:
 - greynoise_fields: Used to update fields.
 - greynoise_indexes: Used to update indexes.
 - greynoise_caching: Used to update caching.
 - greynoise_ttl: Used to update TTL.
 - greynoise_other_fields: Used to update other fields.
 - greynoise_feed_partial_search: Used to update the `greynoise_feed_once` and `greynoise_feed` savedsearch based on indexing configuration.

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