/**
 * Created by raulbeniteznetto on 9/26/16.
 */
// window.onerror = function(msg, url, line)
// {
//   var req = new XMLHttpRequest();
//   var params = "msg=" + encodeURIComponent(msg) + '&amp;url=' + encodeURIComponent(url) + "&amp;line=" + line;
//   // req.open("POST", "/scripts/logerror.php");
//   // req.send(params);
//     console.log(params);
// };

function throw_error_logging(msg){
    console.error(msg);
    // throw msg;
}

var time = moment();
var DATETIME_FORMAT = "YYYY-MM-DD HH:mm:ss.SSSSSSZZ";

function getTimeNow () {
    return time.format(DATETIME_FORMAT);
}
function getTimeNowByPython(){
    return (window.performance.timing.navigationStart + window.performance.now()) / 1000
}
function getTimeNowByJS(){
    return (window.performance.timing.navigationStart + window.performance.now())
}


function EventReg(params, as_logic){
    var key;
    var as_logic = as_logic;
    var paramenters = params;
    var init = function () {
        var unique_d = new Date().valueOf();
        key = "EVENT_"+ unique_d.toString();
        if(paramenters == null || paramenters == undefined){
            paramenters = {};
        }
        paramenters['created_at'] = getTimeNow();
        paramenters['created_at_precision'] = getTimeNowByPython();
        paramenters['created_at_precision_js'] = getTimeNowByJS();
        paramenters['analysis_session_id'] = as_logic.getAnalysisSessionId();
        paramenters['analysis_session_uuid'] = as_logic.getAnalysisSessionUUID();
        paramenters['analysis_session_name'] = SHA256(as_logic.getAnalysisSessionName());
        paramenters['version_app'] = VERSION_APP;
    };
    init();

    this.getKey = function (){
        return key;
    };
    this.getParameters = function(){
        return paramenters;
    };
}
function Metrics(active, analysis_session_logic){
    var active = active;
    var thiz = this;
    this.as_logic = analysis_session_logic;
    this.blobURL = null;

    function init() {
        var blob = new Blob([ "onmessage = function(e) { " +
                "var rows_affected = e.data[0];"+
                "var rows_affected_new = [rows_affected.length];"+
                "var origin = e.data[1];"+
                "self.importScripts(origin+'/static/manati_ui/js/libs/underscore-min.js');"+
                "self.importScripts(origin+'/static/manati_ui/js/libs/cryptico.min.js');"+
                "self.importScripts(origin+'/static/manati_ui/js/utils.js');"+
                "for(var i = 0; i< rows_affected.length; i++) {" +
                    "var row = rows_affected[i];"+
                    "var r = {};"+
                    "for(var key in row){"+
                        "var d = findDomainOfURL(row[key]);"+
                        "if(d!=null)r[key] = SHA256(d);"+
                    "};"+
                    "r['dt_id']=row['dt_id'];"+
                    "r['uuid']=row['uuid'];"+
                    "rows_affected_new[i] = r;"+
                "};"+
                "self.postMessage(rows_affected_new);" +
            "}"]);

            // Obtain a blob URL reference to our worker 'file'.
        thiz.blobURL = window.URL.createObjectURL(blob);

    }
    init();

    function addValue(obj){
        if(obj instanceof EventReg){
            localStorage.setItem(obj.getKey(), JSON.stringify(obj.getParameters()));
        }
    }
    function removeValue(obj){
        if(obj instanceof EventReg){
            localStorage.removeItem(obj.getKey());
        }
    }
    function removeValueByKey(key){
        localStorage.removeItem(key);
    }
    function bulkRemoveValueByKey(keys){
        $.each(keys,function(index, v){
            removeValueByKey(v);
        })

    }
    this.listValues = function(){
        for (var i = 0; i < localStorage.length; i++)   {
            console.log(localStorage.key(i) + "=[" + localStorage.getItem(localStorage.key(i)) + "]");
        }
    };
    
    this.getAllValues = function () {
        var values = {"keys":[], "data":[]};
        for (var i = 0; i < localStorage.length; i++)   {
            var key = localStorage.key(i);
            if(key.indexOf('EVENT_') >= 0) {
                values["keys"].push(key);
                values["data"].push(localStorage.getItem(key));
            }
        }
        return values;
    };

    // save single labeling and if they/it were/was by Buttons or menucontext or hotkeys
    var EventMultipleLabelings = function(rows_affected, verdict, produced_by){
        if(!active) return false;
        if(rows_affected instanceof Array){
            if(rows_affected.length <= 0) return;
            var worker = new Worker(thiz.blobURL);
            worker.addEventListener('message', function(e) {
                var event_name;
                var data_wb = e.data;
                if(data_wb.length > 1){
                    event_name = "multiple_labelings";
                }else{
                    event_name = "single_labeling";
                }
                var event_reg = new EventReg({  'event_name': event_name,
                                            'weblogs_affected':data_wb,
                                            'amount_wbls': data_wb.length,
                                            'new_verdict': verdict,
                                            'event_produced_by': produced_by}, thiz.as_logic);
                addValue(event_reg);
            });
            worker.postMessage([rows_affected,document.location.origin]);
            return true;
        }else{
            throw_error_logging("the 'weblogs_old' must be an array");
            return false;
        }

    };
    this.EventMultipleLabelingsByButtons = function(rows_affected, verdict){
        EventMultipleLabelings(rows_affected,verdict, "buttons")

    };
    this.EventMultipleLabelingsByMenuContext = function(rows_affected, verdict){
        EventMultipleLabelings(rows_affected,verdict, "menucontext")

    };
    this.EventMultipleLabelingsByHotKeys = function(rows_affected, verdict){
        EventMultipleLabelings(rows_affected,verdict, "hotkeys")
    };

    var EventBulkLabeling = function (rows_affected, verdict, labeled_by, filter_by){
        if(!active)return false;
        if(rows_affected instanceof Array){
            if(rows_affected.length <= 0) return;
            var worker = new Worker(thiz.blobURL);
            worker.addEventListener('message', function(e) {
                var event_name = "bulk_labeling";
                var data_wb = e.data;
                var event_reg = new EventReg({  'event_name': event_name,
                                        'weblogs_affected':data_wb,
                                        'filter_by': SHA256(filter_by),
                                        'amount_wbls': data_wb.length,
                                        'new_verdict': verdict,
                                        'labeled_by': labeled_by},thiz.as_logic);
                addValue(event_reg);
            });
            worker.postMessage([rows_affected,document.location.origin]);
            return true;
        }else{
            throw_error_logging("the 'weblogs_old' must be an array");
            return false
        }




    };
    this.EventBulkLabelingByDomains = function(weblogs_old, verdict,domain){
        EventBulkLabeling(weblogs_old,verdict, "domains", domain)

    };
    this.EventBulkLabelingByEndServerIP = function(weblogs_old, verdict, ip){
        EventBulkLabeling(weblogs_old,verdict, "ip", ip)
    };

    this.EventSearching = function(amount_wbls_affected){
        if(!active)return false;
        var event_name = "searching";
        var event_reg = new EventReg({event_name: event_name,
                                    amount_wbls: amount_wbls_affected});
        addValue(event_reg);
        return true;
    };

    var fileUploadingStarted = false;
    this.EventFileUploadingStart = function(file_name_raw, size, type){
        if(!active) return false;
        var event_name = "file_uploading_start";
        if(!fileUploadingStarted){
            fileUploadingStarted = true;
            var event_reg = new EventReg({ event_name: event_name,
                                        file_name_raw: SHA256(file_name_raw),
                                        file_type: type,
                                        file_size: size},thiz.as_logic);
            addValue(event_reg);
            return true;
        }else{
            throw_error_logging("you must throw EventFileUploadingStart and then EventFileUploadingFinished, to close the circuit ");
        }

    };
    this.EventFileUploadingFinished = function(file_name_raw, number_rows){
        if(!active)return false;
        var event_name = "file_uploading_finished";
        if(fileUploadingStarted){
            var event_reg = new EventReg({ event_name: event_name,
                                        file_name_raw: SHA256(file_name_raw),
                                        number_rows: number_rows},thiz.as_logic);
            addValue(event_reg);
            fileUploadingStarted = false;
            return true;
        }else{
            throw_error_logging("you cannot throw EventFileUploadingFinished before of EventFileUploadingStart");
            return false;
        }

    };
    this.EventFileUploadingError = function(file_name_raw){
        if(!active) return false;
        var event_name = "file_uploading_error";
        if(fileUploadingStarted){
            var event_reg = new EventReg({  event_name: event_name,
                                        file_name_raw: SHA256(file_name_raw)},thiz.as_logic);
            addValue(event_reg);
            fileUploadingStarted = false;
            return true;
        }else{
            throw_error_logging("you cannot throw EventFileUploadingFinished before of EventFileUploadingStart");
            return false;
        }

    };
    var AnalysisSessionSavingStarted = false;
    this.EventAnalysisSessionSavingStart = function(number_rows, analysis_session_name){
        if(!active) return false;
        var event_name = "analysis_session_saving_start";
        if(!AnalysisSessionSavingStarted){
            AnalysisSessionSavingStarted = true;
            var event_reg = new EventReg({  event_name: event_name,
                                        analysis_session_name: SHA256(analysis_session_name),
                                        number_rows: number_rows},thiz.as_logic);
            addValue(event_reg);
            return true;
        }else{
            throw_error_logging("you must throw EventAnalysisSessionSavingStart and then EventAnalysisSessionSavingFinished, to close the circuit ");
        }
    };
    this.EventAnalysisSessionSavingFinished = function(analysis_session_name, analysis_session_id){
        if(!active)return false;
        var event_name = "analysis_session_saving_finished";
        if(AnalysisSessionSavingStarted){
            var event_reg = new EventReg({  event_name: event_name,
                                        analysis_session_name: SHA256(analysis_session_name),
                                        analysis_session_id: analysis_session_id},thiz.as_logic);
            addValue(event_reg);
            AnalysisSessionSavingStarted = false;
            return true;
        }else{
            throw_error_logging("EventAnalysisSessionSavingFinished: you cannot throw EventAnalysisSessionSavingFinished before of EventAnalysisSessionSavingStart");
            return false;
        }
    };
    this.EventAnalysisSessionSavingError = function (analysis_session_name) {
        if(!active)return false;
        var event_name = "analysis_session_saving_error";
        if(AnalysisSessionSavingStarted){
            var event_reg = new EventReg({ event_name: event_name,
                                        analysis_session_name: SHA256(analysis_session_name)},thiz.as_logic);
            addValue(event_reg);
            AnalysisSessionSavingStarted = false;
            return true;
        }else{
            throw_error_logging("EventAnalysisSessionSavingError: you cannot throw EventAnalysisSessionSavingFinished before of EventAnalysisSessionSavingStart");
            return false;
        }
    };
    var AS_loading_edit_started = false;
    this.EventLoadingEditingStart = function(analysis_session_id){
        if(!active) return false;
        var event_name = "anal_ses_loading_edit_start";
        if(!AS_loading_edit_started){
            AS_loading_edit_started = true;
            var event_reg = new EventReg({  event_name: event_name,
                                        analysis_session_id: analysis_session_id},thiz.as_logic);
            addValue(event_reg);
            return true;
        }else{
            throw_error_logging("you must throw EventLoadingEditingStart and then EventLoadingEditingFinished, to close the circuit ");
        }

    };
    this.EventLoadingEditingFinished = function(analysis_session_id,number_rows){
        if(!active)return false;
        var event_name = "anal_ses_loading_edit_finished";
        if(AS_loading_edit_started){
            var event_reg = new EventReg({  event_name: event_name,
                                        analysis_session_id: analysis_session_id,
                                        number_rows: number_rows},thiz.as_logic);
            addValue(event_reg);
            AS_loading_edit_started = false;
            return true;
        }else{
            throw_error_logging("you cannot throw EventLoadingEditingFinished before of EventLoadingEditingStart");
            return false;
        }
    };
    this.EventLoadingEditingError = function (analysis_session_id) {
        if(!active) return false;
        var event_name = "anal_ses_loading_edit_error";
        if(AS_loading_edit_started){
            var event_reg = new EventReg({  event_name: event_name,
                                        analysis_session_id: analysis_session_id},thiz.as_logic);
            addValue(event_reg);
            AS_loading_edit_started = false;
            return true;
        }else{
            throw_error_logging("EventLoadingEditingError: you cannot throw EventAnalysisSessionSavingFinished before of EventAnalysisSessionSavingStart");
            return false;
        }
    };
    this.EventExportingTable = function(number_rows, exporting_type){
        if(!active)return false;
        var event_name = "exporting";
        var event_reg = new EventReg({  event_name: event_name,
                                    number_rows: number_rows,
                                    exporting_type: exporting_type},thiz.as_logic);
        addValue(event_reg);
        return true;
    };
    this.EventMerging = function(rows_affected, verdict_merged){
        if(!active)return false;
        var event_name = "merging_detected";
        var event_reg = new EventReg({  event_name: event_name,
                                    rows_affected: rows_affected,
                                    verdict_merged: verdict_merged},thiz.as_logic);
        addValue(event_reg);
        return true;
    };
    var EventMakeComments = function (type_comments, object_id){
        //yet no implemented, add Worker to 'hash' it
        if(!active)return false;
        var event_name = "merging_detected";
        var event_reg = new EventReg({  event_name: event_name,
                                    rows_affected: rows_affected,
                                    verdict_merged: verdict_merged},thiz.as_logic);
        addValue(event_reg);
        return true;
    };
    this.EventMakeCommentsWeblog = function(weblog_id){
        return EventMakeComments("weblog",weblog_id)
    };
    this.EventMakeCommentsAnalysisSession = function(analysis_session_id){
        return EventMakeComments("analysis_session",analysis_session_id)
    };

    var EventWhoisConsultation = function (query_node, query_type){
        if(!active)return false;
        var event_name = "whois_consultation";
        var event_reg = new EventReg({ event_name: event_name,
                                    query_type: query_type,
                                    query_node: SHA256(query_node)},
                                    thiz.as_logic);
        addValue(event_reg);
        return true;

    };
    this.EventWhoisConsultationByIp = function(query_node){
        EventWhoisConsultation(query_node, "ip");
    };
    this.EventWhoisConsultationByDomian = function(query_node){
        EventWhoisConsultation(query_node, "domain");
    };

    var EventVirusTotalConsultation = function (query_node, query_type){
        if(!active)return false;
        var event_name = "virustotal_consultation";
        var event_reg = new EventReg({ event_name: event_name,
                                    query_type: query_type,
                                    query_node: SHA256(query_node)},
                                    thiz.as_logic);
        addValue(event_reg);
        return true;

    };
    this.EventVirusTotalConsultationByIp = function(query_node){
        EventVirusTotalConsultation(query_node, "ip");
    };
    this.EventVirusTotalConsultationByDomian = function(query_node){
        EventVirusTotalConsultation(query_node, "domain");
    };

    var syncWithDB = function(){
        var measurements = thiz.getAllValues();
        if(measurements['data'].length > 0){
            var data = {'measurements[]': JSON.stringify(measurements['data']), "keys[]": JSON.stringify(measurements['keys']) };
            $.ajax({
                    type:"POST",
                    data: data,
                    dataType: "json",
                    url: "/manati_project/manati_ui/analysis_session/sync_metrics",
                    success : function(json) {// handle a successful response
                        var keys = json.keys;
                        // console.log("Sync Metrics DONE, " + json.measurements_length + " registers were saved");
                        // console.log(keys);
                        bulkRemoveValueByKey(keys);

                    },
                    error : function(xhr,errmsg,err) { // handle a non-successful response
                        $.notify(xhr.status + ": " + xhr.responseText, "error");
                        console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
                    }
                });
        }

    };
    setInterval(syncWithDB, 1000 * 60 ); //each minute start synchronization
}