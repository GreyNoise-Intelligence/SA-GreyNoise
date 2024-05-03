# Notes for releasing update

Files to be packaged in the app should be included in the APP_FILES_ONLY/SA-GreyNoise directory

Repo files (config files, etc) and any other information should be kept outside the APP_FILES_ONLY directory.

Both the `Splunk Packaging Toolkit` and the `Splunk Appinspect CLI` tools can be used to validate changes before submitting to Splunkbase.

To use the validation tool, navigate to APP_FILES_ONLY/SA-GreyNoise

Run the following command:

`slim validate .`

Then:

`splunk-appinspect inspect .`

Correct any issues identified. Once validation and inspection are clean, run the following to create the package:

`slim package . `

Move the created .tar.gz file to the spl_files folder at the repo root, then use this file to test in Splunk and Submit to Splunkbase for publishing.