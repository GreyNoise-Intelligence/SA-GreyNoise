require(["splunkjs/mvc/utils"], function (SplunkUtil) {
    var app_name = SplunkUtil.getCurrentApp();  
    require.config({
        paths: {
            'jquery_greynoise': '../app/'+app_name+'/jquery_greynoise',
            'datetime-range-picker': '../app/'+app_name+'/daterangepicker.min',
            'moment_greynoise': '../app/'+app_name+'/moment'
        }
});
require([
    'jquery_greynoise',
    'splunkjs/mvc',
    'splunkjs/mvc/searchmanager',
    'moment_greynoise',
    'datetime-range-picker',
    'splunkjs/mvc/simplexml/ready!'
], function ($, mvc, SearchManager, moment) {

    // Get token models
    var tokens = mvc.Components.getInstance("default");
    var tokensSub = mvc.Components.getInstance("submitted");
    
    var last_7_days = tokens.get("form.last_7_days");

    var start_date = moment.utc()
    var end_date =  moment.utc()

    if(last_7_days=="true")
    {
        start_date =  moment.utc().subtract(6, 'days')
        end_date =  moment.utc()
        // Setting the token to null so that on reload it will not auto run the process_inputs
        tokens.set("form.last_7_days", null);
        tokensSub.set("last_7_days", null)
    }

    // setting token for the selected default date in text box
    tokens.set("form.daterange", start_date.format('YYYY-MM-DD') + ' to ' + end_date.format('YYYY-MM-DD'))
    
    var min_date = ""
    var max_date = ""
    function setdatetimerange(start, end) {
                // setting token for the selected date in text box
                tokens.set("form.daterange",start.format('YYYY-MM-DD') + ' to ' + end.format('YYYY-MM-DD'))
                min_date = start.format('YYYY-MM-DD')
                max_date = end.format('YYYY-MM-DD')
            }

           $('#daterange').daterangepicker({
            startDate: start,
            endDate: end,
            opens: 'left',
            locale: {
                format: 'YYYY-MM-DD'
            },
            ranges: {
               'Today': [moment.utc(), moment.utc()],
               'Yesterday': [moment.utc().subtract(1, 'days'), moment.utc().subtract(1, 'days')],
               'Last 7 Days': [moment.utc().subtract(6, 'days'), moment.utc()],
               'Last 30 Days': [moment.utc().subtract(29, 'days'), moment.utc()],
               'This Month': [moment.utc().startOf('month'), moment.utc().endOf('month')],
               'Last Month': [moment.utc().subtract(1, 'month').startOf('month'), moment.utc().subtract(1, 'month').endOf('month')]
            }
        }, setdatetimerange);
        
    // Set tokens for start time and end time
    setdatetimerange(start_date, end_date);

    // Setting token for initializing the default value on load of dashboard
    tokens.set("tkn_start_time", start_date);
    tokens.set("tkn_end_time", end_date);
    $('#daterange').data('daterangepicker').setStartDate(start_date);
    $('#daterange').data('daterangepicker').setEndDate(end_date);
    $('#daterange :input').attr('readonly', 'true');
    $('#daterange :input').css('cursor', 'text');

    function process_inputs(){
        // Unset tokens which may be set previously
        var tokensToReset = ["message", "token_search_trigger"]
        for (var i = 0; i < tokensToReset.length; i++) {
              tokens.unset(tokensToReset[i]);
              tokensSub.unset(tokensToReset[i]);
        }

        // Validate the parameters
        var re = new RegExp("(^\\\"?[\\\*\\\s]*\\\"?$)");
        var is_invalid = 1;
        var requiredFields = ["tkn_ip_address", "tkn_organization", "tkn_actor", "tkn_tag", "tkn_asn"]
        for (i = 0; i < requiredFields.length; i++) {
            if (!re.test(tokens.get(requiredFields[i]).trim())) {
                is_invalid = 0;
                break;
            }
        }

        if (is_invalid == 1) {
            tokens.set("message", "Please enter value (without asterik) in atleast one of the following parameters: IP Address, Organization, Actor, Tags or ASN");
            tokensSub.set("message", "Please enter value (without asterik) in atleast one of the following parameters: IP Address, Organization, Actor, Tags or ASN");
            return;
        }

        // Escaping the '"'
        var tokensToEscapeSpecialCharacter = ["tkn_ip_address", "tkn_organization", "tkn_actor", "tkn_tag", "tkn_os", "tkn_category", "tkn_country", "tkn_asn"]
        for (i = 0; i < tokensToEscapeSpecialCharacter.length; i++) {
            let tokenVal = tokens.get(tokensToEscapeSpecialCharacter[i]).trim();
            tokenVal = tokenVal.replace(new RegExp('"','g'),'\\\\\\\"');
            tokens.set(tokensToEscapeSpecialCharacter[i] + "_escaped",tokenVal);
            tokensSub.set(tokensToEscapeSpecialCharacter[i] + "_escaped",tokenVal);
        }

        // setting token for API use
        tokens.set("tkn_start_time", min_date);
        tokens.set("tkn_end_time", max_date);

        // Setting the token to run the search again
        tokens.set("token_search_trigger", " ");
        tokensSub.set("token_search_trigger", " ");
    }

    // Call the function on click of the Submit button
    $("#submit .btn.btn-primary").on("click", process_inputs);

    // Token will have value if it is coming to Live Investigation using drilldown.
    var redirect = tokens.get("form.redirect");

    if(redirect=="redirect")
    {
        // Setting the token to null so that on reload it will not auto run the process_inputs
        tokens.set("form.redirect", null);
        tokensSub.set("redirect", null)
        $('.applyBtn.btn.btn-sm.btn-primary').click();
        $("#submit .btn.btn-primary").click();        
    }
});
});