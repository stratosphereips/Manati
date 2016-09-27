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
    console.log(msg);
    throw msg;
}

var time = moment();
var DATETIME_FORMAT = "YYYY-MM-DD HH:mm:ss.SSSSSSZZ";
function getTimeNow(){
    return time.format(DATETIME_FORMAT);
}

function EventReg(params){
    var key;
    var paramenters = params;
    var init = function () {
        var unique_d = new Date().valueOf();
        key = "EVENT_"+ unique_d.toString();
        if(paramenters == null || paramenters == undefined){
            paramenters = {};
        }
        paramenters['created_at'] = getTimeNow();
    };
    init();

    this.getKey = function (){
        return key;
    };
    this.getParameters = function(){
        return paramenters;
    };
}
function Metrics(active){
    var active = active;
    var thiz = this;

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
    this.listValues = function(){
        for (var i = 0; i < localStorage.length; i++)   {
            console.log(localStorage.key(i) + "=[" + localStorage.getItem(localStorage.key(i)) + "]");
        }
    };
    
    this.getAllValues = function () {
        var values = [];
        for (var i = 0; i < localStorage.length; i++)   {
            values.add(localStorage.getItem(localStorage.key(i)));
        }
        return values;
        
    }

    // save single labeling and if they/it were/was by Buttons or menucontext or hotkeys
    var EventMultipleLabelings = function(rows_affected, verdict, produced_by){
        if(!active) return false;
        var event_name;
        var data_wb;
        if(rows_affected instanceof Array && rows_affected.length > 0){
            data_wb = rows_affected;
            if(rows_affected.length > 1){
                event_name = "multiple_labelings";
            }else{
                event_name = "single_labeling";
            }
            var event_reg = new EventReg({  'event_name': event_name,
                                        'weblogs_affected':data_wb,
                                        'amount_wbls': data_wb.length,
                                        'new_verdict': verdict,
                                        'event_produced_by': produced_by});
            addValue(event_reg);
            return true;

        }else{
            throw_error_logging("the 'weblogs_old' must be an array not empty")
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

    var EventBulkLabeling = function (weblogs_old, verdict, labeled_by){
        if(!active)return false;
        var event_name = "bulk_labeling";
        var data_wb;
        if(weblogs_old instanceof Array && rows_affected.length > 0){
            data_wb = weblogs_old;
            var event_reg = new EventReg({  'event_name': event_name,
                                        'weblogs_affected':data_wb,
                                        'amount_wbls': data_wb.length,
                                        'new_verdict': verdict,
                                        'labeled_by': labeled_by});
            addValue(event_reg);
            return true;
        }else{
           throw_error_logging("\'weblogs_old\' must be a Array");
            return false
        }
    };
    this.EventBulkLabelingByDomains = function(weblogs_old, verdict){
        EventBulkLabeling(weblogs_old,verdict, "domains")

    };
    this.EventBulkLabelingByEndServerIP = function(weblogs_old, verdict){
        EventBulkLabeling(weblogs_old,verdict, "domains")
    };

    this.EventSearching = function(amount_wbls_affected){
        if(!active)return false;
        var event_name = "searching";
        var event_reg = new EventReg({  'event_name': event_name,
                                    'amount_wbls': amount_wbls_affected});
        addValue(event_reg);
        return true;
    };

    var fileUploadingStarted = false;
    this.EventFileUploadingStart = function(file_name_raw, size, type){
        if(!active) return false;
        var event_name = "file_uploading_start";
        if(!fileUploadingStarted){
            fileUploadingStarted = true;
            var event_reg = new EventReg({  'event_name': event_name,
                                        'file_name_raw': file_name_raw,
                                        'file_type': type,
                                        'file_size': size});
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
            var event_reg = new EventReg({  'event_name': event_name,
                                        'file_name_raw': file_name_raw,
                                        'number_rows': number_rows});
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
            var event_reg = new EventReg({  'event_name': event_name,
                                        'file_name_raw': file_name_raw});
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
            var event_reg = new EventReg({  'event_name': event_name,
                                        'analysis_session_name': analysis_session_name,
                                        'number_rows': number_rows});
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
            var event_reg = new EventReg({  'event_name': event_name,
                                        'analysis_session_name': analysis_session_name,
                                        'analysis_session_id': analysis_session_id});
            addValue(event_reg);
            AnalysisSessionSavingStarted = false;
            return true;
        }else{
            throw_error_logging("you cannot throw EventAnalysisSessionSavingFinished before of EventAnalysisSessionSavingStart");
            return false;
        }
    };
    this.EventAnalysisSessionSavingError = function (analysis_session_id) {
        if(!active)return false;
        var event_name = "analysis_session_saving_error";
        if(AnalysisSessionSavingStarted){
            var event_reg = new EventReg({  'event_name': event_name,
                                        'analysis_session_id': analysis_session_id});
            addValue(event_reg);
            AnalysisSessionSavingStarted = false;
            return true;
        }else{
            throw_error_logging("you cannot throw EventAnalysisSessionSavingFinished before of EventAnalysisSessionSavingStart");
            return false;
        }
    };
    var AS_loading_edit_started = false;
    this.EventLoadingEditingStart = function(analysis_session_id){
        if(!active) return false;
        var event_name = "anal_ses_loading_edit_start";
        if(!AS_loading_edit_started){
            AS_loading_edit_started = true;
            var event_reg = new EventReg({  'event_name': event_name,
                                        'analysis_session_id': analysis_session_id});
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
            var event_reg = new EventReg({  'event_name': event_name,
                                        'analysis_session_id': analysis_session_id,
                                        'number_rows': number_rows});
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
            var event_reg = new EventReg({  'event_name': event_name,
                                        'analysis_session_id': analysis_session_id});
            addValue(event_reg);
            AS_loading_edit_started = false;
            return true;
        }else{
            throw_error_logging("you cannot throw EventAnalysisSessionSavingFinished before of EventAnalysisSessionSavingStart");
            return false;
        }
    };
    this.EventExportingTable = function(number_rows, exporting_type){
        if(!active)return false;
        var event_name = "exporting";
        var event_reg = new EventReg({  'event_name': event_name,
                                    'number_rows': number_rows,
                                    'exporting_type': exporting_type});
        addValue(event_reg);
        return true;
    };
    this.EventMerging = function(rows_affected, verdict_merged){
        if(!active)return false;
        var event_name = "merging_detected";
        var event_reg = new EventReg({  'event_name': event_name,
                                    'rows_affected': rows_affected,
                                    'verdict_merged': verdict_merged});
        addValue(event_reg);
        return true;
    };
    var EventMakeComments = function (type_comments, object_id){
        if(!active)return false;
        var event_name = "merging_detected";
        var event_reg = new EventReg({  'event_name': event_name,
                                    'rows_affected': rows_affected,
                                    'verdict_merged': verdict_merged});
        addValue(event_reg);
        return true;
    };
    this.EventMakeCommentsWeblog = function(weblog_id){
        return EventMakeComments("weblog",weblog_id)
    }
    this.EventMakeCommentsAnalysisSession = function(analysis_session_id){
        return EventMakeComments("analysis_session",analysis_session_id)
    }
}