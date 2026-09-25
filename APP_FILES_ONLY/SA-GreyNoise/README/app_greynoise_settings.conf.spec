[logging]
loglevel = 

[parameters]
api_key = 
proxy =

[scan_deployment]
ip_indexes = 
cim_ip_fields =
other_ip_fields = 
scan_start_time = 
enable_ss = 
force_enable_ss = 
job_id_overview = 
job_id_scan_deployment =
update_risk_score_to_splunk_es =
malicious_score =
suspicious_score =
benign_score =
unknown_score =

[feed_configuration]
enable_feed_import =
force_enable_ss =
feed_selection =
include_community_dataset =
ingest_feed_to_index =
feed_index =
job_id_feed =
job_id_feed_purge =

[callback_feed_configuration]
enable_callback_feed =
force_enable_callback_feed =
is_stage_1 =
is_stage_2 =
has_files =
first_seen_after =
first_seen_before =
last_seen_after =
last_seen_before =
file_type =
file_name =
file_hash =
scanner_ips =
ips =
job_id_callback_feed =
job_id_callback_feed_purge =

[caching]
enable_caching =
ttl =
purge_cache =
