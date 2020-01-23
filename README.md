# GreyNoise App for Splunk #

# OVERVIEW #
GreyNoise Splunk app provides multiple dashboards to effectively analyse and visualize the contextual and statistical data provided by GreyNoise. It also includes custom commands and alert actions which can be used along with Splunk searches to leverage GreyNoise APIs for custom use cases. It periodically scans the Splunk deployment through saved search to indicate the noise IPs in the complete Splunk deployment. Along with this, the workflow action provided can be used to obtain live context information of any CIM compliant field containing an IP address.

 - Author: GreyNoise Intelligence Inc
 - Version: 2.0.0
 - Creates Index: False
 - Has index-time operation: True
 - Implements summarization: False
 - Prerequisites: GreyNoise API Key, Search heads without Enterprise Security requires the Splunk Common Information Model (CIM) Add-on to for the Modular Alerts to function.

# COMPATIBILITY MATRIX #
 - Splunk Enterprise version: 8.0, 7.3, 7.2
 - OS: Platform independent
 - Vendor Products: GreyNoise API

# TOPOLOGY AND SETTING UP SPLUNK ENVIRONMENT #
Standalone Mode
 
 - Install GreyNoise App for Splunk. See INSTALLATION section for more details.
 - Configure the API key and log level. See CONFIGURATION section for details.

Search Head Cluster
 
 - In case of *Search Head Clustering*, make sure that the `GreyNoise Setup` and `Scan Deployment` is configured on only single search head. In such cases, the configuration will not be visible on other search heads. In case if user wants to configure the `Logging` (default is INFO), user can configure individually on every search head. This is recommended.
 - If user wants to replicate the configuration settings, follow these steps:
    - On search head deployer, extract the app at `$SPLUNK_HOME$/etc/shcluster/apps`.
    - Create stanza `shclustering` at path `$SPLUNK_HOME$/etc/shcluster/apps/app-greynoise/local/server.conf` and add following information to the stanza: `conf_replication_include.app_greynoise_settings = true`
    - Push the bundle to search head.
    - Configure the API key and log level. See CONFIGURATION section for details. Following these steps will replicate the configuration on all search heads.

# INSTALLATION #
Follow the below-listed steps to install an app from the bundle:

 - Download the App package.
 - From the UI navigate to Apps > Manage Apps.
 - In the top right corner select Install app from file.
 - Select Choose File and select the App package.
 - Select Upload and follow the prompts.
 - Restart the Splunk to complete the installation.

Note: This app contains Adaptive Response Actions, which can be used along with Splunk Enterprise Security. To use these alert actions on the Splunk instance without Splunk Enterprise Security, kindly install `Splunk Common Information Model (CIM)`.

# CONFIGURATION #
The app can be configured in the following way:

 - From the Splunk UI navigate to `Apps > GreyNoise App for Splunk > Configuration`.
 - Click on GreyNoise Setup and enter the API Key.
 - Click on Save button.
 - The app is now configured and all the features apart from Scan Deployment are ready to be used.

Logging

 - User can configure the log level by navigating to `Apps > GreyNoise App for Splunk > Configuration` and selecting Logging.

# SCAN DEPLOYMENT #
This feature helps user to scan the Splunk Deployment and identify the noise IP addresses from it. It can be configured in the following way:

 - From the Splunk UI navigate to `Apps > GreyNoise App for Splunk > Configuration`.
 - Click on Scan Deployment.
 - Enter the following details to set up the Scan Deployment:
    - Indexes: Indexes to be scanned in the deployment.
    - CIM Fields:  CIM fields containing IP address to scan for noise status.
    - Other Fields: Other comma(,) separated fields containing IP address to scan for noise status. 
    - Scan Start Time: Time range for scanning the indexed Splunk data.
    - Enable Scan Deployment: Checkbox to enable or disable scanning of the deployment.
    - Force Scan Deployment: This is useful when user wants to override current running scan immediately and start a new one.

# CUSTOM COMMANDS #
The following commands are included as a part of the app:

 - gnip
    - Search format: `| gnip ip="<ip_address>"`
    - Purpose: Retrieves context information for a given IP address from the GreyNoise.
 - gnquick
    - Search format: `| gnquick ip="<ip_address1>,<ip_address2>,<ip_address3>" [OR] SPL_QUERY | gnquick ip_field="<ip_field>"`
    - Purpose: Retrieve the noise status of all the IP addresses as separate events [OR] Retrieve the noise status for all the given IPs returned by the SPL_QUERY for specified ip_field. 
 - gnquery
    - Search format: `| gnquery query="<GNQL_query>" result_size="<result_size>"`
    - Purpose: Retrieve the results of the given GNQL query from GreyNoise. result_size denotes the number of results to be retrieved which is capped at 50,000. result_size is an optional parameter with default value of 50,000.
 - gnstats
    - Search format: `| gnstats query="<GNQL_query>" count="<stats_count>"`
    - Purpose: Fetch the aggregate statistics for the top organizations, actors, tags, ASNs, countries, classifications, and operating systems of all the results for a given GNQL query. count denotes the number of stats to be retrieved. count is an optional parameter.
 - gnmulti
    - Search format: `SPL_QUERY | gnmulti ip_field="<ip_field>"`
    - Purpose: Retrieves noise status of the IP addresses represented by ip_field parameter present in each event, and adds the noise information to each event.
 - gncontext
    - Search format: `| gncontext ip="<ip_address>"`
    - Purpose: Retrieves context information for a given IP address from the GreyNoise.
 - gnfilter
    - Search format: `SPL_QUERY | gnfilter ip_field="<ip_field>" noise_events="<true/false>"`
    - Purpose: Filter Splunk events returned by given SPL_QUERY based on the noise status of IP address present in ip_field of the events. noise_events is an optional parameter with default value true. So, it will return events with noise IP addresses by default. 
 - gnenrich
    - Search format: `SPL_QUERY | gnenrich ip_field="<ip_field>"`
    - Purpose: Enrich the Splunk events returned by given SPL_QUERY with the context information of IP address represented by ip_field in Splunk Search.

*Note : While executing the transforming commands from Splunk search UI, ensure that the event count passed to the command is less than 50,000, as per standard limits of Splunk. If the event count is higher than this number, user can create a Saved Search and pass higher number of Splunk statistical data to the command.* 

# ALERT ACTIONS #
The following alert actions are included as a part of the app:

 - GreyNoise Quick Check: Returns noise information from GreyNoise for given IP addresses.
 - GreyNoise Context Check: Returns context information from GreyNoise for given IP Addresses.

These alert actions can be used independently as well as with Splunk Enterprise Security in the form of Adaptive Response Actions. Results from these actions can be found in `index=main sourcetype=greynoise`
The two sources for these adaptive response actions are: `source=greynoise_context` and `source=greynoise_quick`.

Usage with Splunk Enterprise Security:
 - These actions can be executed from Incident Review, and results can be accessed directly by refreshing the "Adaptive Responses" panel and clicking the appropriate link.

# WORKFLOW ACTION  
Identify Noise workflow action is enabled for all the CIM compliant IP fields which can be used to fetch the context information for the corresponding IP addresses.

# DASHBOARDS #
This app contains the following three dashboards:

 - Overview: This dashboard represents an overall visualization of the statistics provided by GreyNoise platform as well as the statistics of the noise IPs in the Splunk deployment.
 - Noise IP Addresses: This dashboard displays all the IP addresses along with their noise status scanned by GreyNoise through Scan Deployment feature in the current Splunk deployment. This dashboard will be populated when Scan Deployment feature is enabled.
 - Live Investigation: This dashboard can be used to obtain context information fetched dynamically from the GreyNoise platform based on the form input provided.

# SAVED SEARCHES #
This app contains the following saved searches, which are used for populating data in the dashboard:

 - greynoise_scan_deployment_once: Used to populate `gn_scan_deployment_ip_lookup` lookup and is triggered after configuring Scan Deployment feature.
 - greynoise_scan_deployment: Used to populate `gn_scan_deployment_ip_lookup` lookup and is triggered at an interval of 60 minutes and scans the data of previous 70 minutes.
 - greynoise_overview_once: Used to populate `gn_overview_lookup` lookup, and is triggered after configuring the API key.
 - greynoise_overview: Used to populate `gn_overview_lookup` lookup, and is triggered at an interval of 30 minutes.

*Note : greynoise_scan_deployment_once and greynoise_scan_deployment savedsearches are used for scanning the data indexed in Splunk. So, in case when these saved searches are skipped, the data indexed during that interval will not be scanned for noise status.* 

# UNINSTALL APP #
To uninstall app, user can follow below steps: 

 - SSH to the Splunk instance 
 - Go to folder apps($SPLUNK_HOME/etc/apps) 
 - Remove the app-greynoise folder from apps directory 
 - Restart Splunk

# TROUBLESHOOTING #

 - Alerts fail to write to index=main sourcetype=greynoise and Enterprise Security is not installed.
    -  Ensure that the Splunk Common Information Model (CIM) Add-on has been installed. No configuration of this add-on is necessary.
 - Data in Overview dashboard is not being populated.
    - Ensure that `greynoise_overview` Saved Search is enabled.
 - Data in Noise IP Address dashboard is not being populated.
    - Ensure that the Scan Deployment feature is enabled. The data must populate in an hour. In case the issue still persists, make sure that `greynoise_scan_deployment` Saved Search is enabled.
    - Ensure that the KV store is enabled. 
 - Custom commands are not being executed and failing with unknown exception. For example: `Exception occurred while fetching the context of the ip=<ip>. See greynoise_main.log for more details.`
    - Ensure that the user executing custom command has list_storage_passwords capability. 
 - Noise information of some of the IP addresses is being missed in Noise IP Address dashboard.
    - Ensure that the corresponding index and fields are entered as per the format while enabling Scan Deployment feature.
 - Custom commands exited unexpectedly.
    - Ensure that maximum 50000 results are passed to the custom command while executing search from the Splunk Search Interface, as Splunk supports maximum 50000 results. For processing more results, Saved Searches can be used.
 - Scan Deployment feature is not working as expected.
    - Check for the messages in Splunk UI. If message like `KV store not in ready state. Make sure it is enabled.` is shown, ensure that KV store is enabled.
    - Check in splunkd.log for messages like `External command based lookup 'gn_scan_deployment_ip_lookup' is disabled because KV Store is disabled.`
    - If such messages show up, then ensure that the KV store is enabled.
 - In search head clustering, configurations are visible on only one search head and not on others.
    - This is the expected behaviour when replication is not enabled. The functionalities will work on all the search heads.

# SUPPORT #

 - Email: support@greynoise.io
 - Hours: 9AM-5PM EDT Monday-Friday
 - Observed Holidays: Major US Holidays

# OPEN SOURCE COMPONENTS AND LICENSES #
The third party library and its license information is as follows:

 - futures version 3.3.0 https://pypi.org/project/futures/ (LICENSE https://github.com/agronholm/pythonfutures/blob/master/LICENSE)
 - concurrent.futures version 3.7.4 https://docs.python.org/3/library/concurrent.futures.html (LICENSE https://github.com/python/cpython/blob/v3.7.4/LICENSE)
 - cachetools version 3.1.1 https://pypi.org/project/cachetools/ (LICENSE https://github.com/tkem/cachetools/blob/v3.1.1/LICENSE)
 - certifi version 2019.09.11 https://pypi.org/project/certifi/ (LICENSE https://github.com/certifi/python-certifi/blob/2019.09.11/LICENSE)
 - chardet version 3.0.4 https://pypi.org/project/chardet/ (LICENSE https://github.com/chardet/chardet/blob/3.0.4/LICENSE)
 - idna version 2.8 https://pypi.org/project/idna/ (LICENSE https://github.com/kjd/idna/blob/v2.8/LICENSE.rst)
 - more_itertools version 5.0.0 https://pypi.org/project/more-itertools/ (LICENSE https://github.com/erikrose/more-itertools/blob/5.0.0/LICENSE)
 - requests version 2.22.0 https://pypi.org/project/requests/ (LICENSE https://github.com/psf/requests/blob/v2.22.0/LICENSE)
 - schematics version 2.1.0 https://pypi.org/project/schematics/ (LICENSE https://github.com/schematics/schematics/blob/v2.1.0/LICENSE)
 - sortedcontainers version 2.1.0 https://pypi.org/project/sortedcontainers/ (LICENSE https://github.com/grantjenks/python-sortedcontainers/tree/v2.1.0)
 - splunklib version 1.6.11 https://github.com/splunk/splunk-sdk-python/tree/master/splunklib (LICENSE https://github.com/splunk/splunk-sdk-python/blob/1.6.11/LICENSE)
 - structlog version 19.2.0 https://pypi.org/project/structlog/ (LICENSE https://github.com/hynek/structlog/blob/19.2.0/LICENSE)
 - urllib3 version 1.25.7 https://pypi.org/project/urllib3/ (LICENSE https://github.com/urllib3/urllib3/blob/1.25.7/LICENSE.txt)
 - decorator.py version 4.1.2 https://pypi.org/project/decorator/ (LICENSE https://github.com/micheles/decorator/blob/4.1.2/LICENSE.txt)
 - six.py version 1.13.0 https://pypi.org/project/six/ (LICENSE https://github.com/benjaminp/six/blob/1.13.0/LICENSE)
 - daterangepicker.css and daterangepicker.min.js version 3.14.1 (LICENSE https://www.daterangepicker.com/#license)
 - moment.min.js version 2.18.1 (LICENSE https://github.com/moment/momentjs.com/blob/master/LICENSE)


# COPYRIGHT #

 - Copyright (C) 2019 GreyNoise Intelligence Inc. All Rights Reserved.
