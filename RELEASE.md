# Notes for releasing update

Files to be packaged in the app should be included in the APP_FILES_ONLY/SA-GreyNoise directory

## Configuration page footer (Add-on Version / Build Time)

The Configuration page footer shows **Add-on Version** and **Build Time**. Version comes from `appserver/static/js/build/globalConfig.json` (`meta.version`). Build Time comes from `[install] build` in `default/app.conf`, which UCC treats as a Unix epoch in seconds.

Update both when shipping a release:

1. Set the app version in:
   - `APP_FILES_ONLY/SA-GreyNoise/default/app.conf` (`[launcher] version`)
   - `APP_FILES_ONLY/SA-GreyNoise/appserver/static/js/build/globalConfig.json` (`meta.version`)
   - `APP_FILES_ONLY/SA-GreyNoise/app.manifest` (`info.id.version`)
2. Refresh the build timestamp in `APP_FILES_ONLY/SA-GreyNoise/default/app.conf`:

```
date +%s
```

Then set `[install] build` to that value. Keep the same number in `appserver/templates/base.html` if the `static/@<build>/` cache-busting paths are present.

Do not leave `build` as a small integer (for example `2`). The footer will render that as a date in 1970.

After changing `app.conf`, reload the app or restart Splunk so the footer picks up the new value.

Repo files (config files, etc) and any other information should be kept outside the APP_FILES_ONLY directory.

Both the `Splunk Packaging Toolkit` and the `Splunk Appinspect CLI` tools can be used to validate changes before submitting to Splunkbase.

Before running the validation tool, ensure no pycache folders exist by running this from the root level

`find APP_FILES_ONLY -type d -name "__pycache__" -prune -exec rm -rf {} \;`

Remove `.dist-info` and `.so` files

`find APP_FILES_ONLY/SA-GreyNoise/bin/SA_GreyNoise -name '*.dist-info' -delete`

`find APP_FILES_ONLY/SA-GreyNoise/bin/SA_GreyNoise -name '*.so' -delete`

To use the validation tool, navigate to APP_FILES_ONLY/SA-GreyNoise

Run the following command:

`slim validate .`

Then:

`splunk-appinspect inspect .`

Correct any issues identified. Once validation and inspection are clean, run the following to create the package:

`slim package .`

Move the created .tar.gz file to the spl_files folder at the repo root, then use this file to test in Splunk and Submit to Splunkbase for publishing.