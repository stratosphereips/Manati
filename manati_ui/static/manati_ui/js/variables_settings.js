//Concurrent variables for loading data in datatable
var _dt;
var _countID =1;
var thiz;
var _db;
var _filename = '';
var _size_file,_type_file;
var _analysis_session_type_file;
var _data_uploaded,_data_headers;
var _data_headers_keys = {};
var TIME_SYNC_DB = 15000;
var _sync_db_interval;
var refreshIntervalId;
var idSyncDBIntervalId;

//Concurrent variables for saving on PG DB
var _analysis_session_id = -1;
var _analysis_session_uuid;
var COLUMN_DT_ID,COLUMN_REG_STATUS,COLUMN_VERDICT, COLUMN_UUID;
var COLUMN_END_POINTS_SERVER, COLUMN_HTTP_URL;
var CLASS_MC_HTTP_URL_STR, CLASS_MC_END_POINTS_SERVER_STR;
var COL_HTTP_URL_STR, COL_END_POINTS_SERVER_STR;
var REG_STATUS = {modified: 1};
var COL_VERDICT_STR = 'verdict';
var COL_REG_STATUS_STR = 'register_status';
var COL_DT_ID_STR = 'dt_id';
var COL_UUID_STR = 'uuid';
var REG_EXP_DOMAINS = /[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+/;
var REG_EXP_IP = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/;
var _verdicts = ["malicious","legitimate","suspicious","falsepositive", "undefined"];
var _verdicts_merged = ['malicious','legitimate','suspicious','undefined','falsepositive','malicious_legitimate',
                        'suspicious_legitimate','undefined_legitimate','falsepositive_legitimate',
                        'undefined_malicious','suspicious_malicious','falsepositive_malicious',
                        'falsepositive_suspicious', 'undefined_suspicious','undefined_falsepositive'];
var NAMES_HTTP_URL = ["http.url", "http_url", "host"];
var NAMES_END_POINTS_SERVER = ["endpoints.server", "endpoints_server", "id.resp_h"];
var _flows_grouped;
var _helper;
var _filterDataTable;

var _m;


var _loadingPlugin;
function update_constant(str, index){
    if(COL_UUID_STR === str){
        COLUMN_UUID = index;
    }
    else if(COL_DT_ID_STR=== str){
        COLUMN_DT_ID = index;
    }
    else if(COL_REG_STATUS_STR === str){
        COLUMN_REG_STATUS = index;
    }
    else if(COL_VERDICT_STR === str){
        COLUMN_VERDICT = index;
    }
    else if(COL_HTTP_URL_STR === str){
        COLUMN_HTTP_URL = index
    }
    else if(COL_END_POINTS_SERVER_STR === str){
        COLUMN_END_POINTS_SERVER = index;
    }
}
function checkVerdict(_verdicts_merged, verdict){
    if (verdict === undefined || verdict === null) return verdict;
    var merged = verdict.split('_');

    if(merged.length > 1){
        var user_verdict = merged[0];
        var module_verdict = merged[1];
        var verdict_merge1 = user_verdict+"_"+module_verdict;
        var verdict_merge2 = module_verdict+"_"+user_verdict;
        if(_verdicts_merged.indexOf(verdict_merge1) > -1){
            return verdict_merge1;
        }else if(_verdicts_merged.indexOf(verdict_merge2) > -1){
            return verdict_merge2;
        }else{
            console.error("Error adding Verdict, Merged verdict is not known : " + verdict)
        }
    }else if(_verdicts_merged.indexOf(verdict) > -1){
        return verdict;
    }else {
        return null;
    }
}
 var copyTextToClipboard = function(text) {
      var textArea = document.createElement("textarea");

      //
      // *** This styling is an extra step which is likely not required. ***
      //
      // Why is it here? To ensure:
      // 1. the element is able to have focus and selection.
      // 2. if element was to flash render it has minimal visual impact.
      // 3. less flakyness with selection and copying which **might** occur if
      //    the textarea element is not visible.
      //
      // The likelihood is the element won't even render, not even a flash,
      // so some of these are just precautions. However in IE the element
      // is visible whilst the popup box asking the user for permission for
      // the web page to copy to the clipboard.
      //

      // Place in top-left corner of screen regardless of scroll position.
      textArea.style.position = 'fixed';
      textArea.style.top = 0;
      textArea.style.left = 0;

      // Ensure it has a small width and height. Setting to 1px / 1em
      // doesn't work as this gives a negative w/h on some browsers.
      textArea.style.width = '2em';
      textArea.style.height = '2em';

      // We don't need padding, reducing the size if it does flash render.
      textArea.style.padding = 0;

      // Clean up any borders.
      textArea.style.border = 'none';
      textArea.style.outline = 'none';
      textArea.style.boxShadow = 'none';

      // Avoid flash of white box if rendered for any reason.
      textArea.style.background = 'transparent';


      textArea.value = text;

      document.body.appendChild(textArea);

      textArea.select();

      try {
        var successful = document.execCommand('copy');
        var msg = successful ? 'successful' : 'unsuccessful';
        console.log('Copying text command was ' + msg);
      } catch (err) {
        console.log('Oops, unable to copy');
      }

      document.body.removeChild(textArea);
    }