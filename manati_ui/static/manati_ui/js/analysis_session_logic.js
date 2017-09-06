/**
 * Created by raulbeniteznetto on 8/10/16.
 */
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
                        'undefined_malicious','suspicious_malicious','falsepositive_malicious', 'falsepositive_suspicious',
                        'undefined_suspicious','undefined_falsepositive'];
var NAMES_HTTP_URL = ["http.url", "http_url", "host"];
var NAMES_END_POINTS_SERVER = ["endpoints.server", "endpoints_server", "id.resp_h"];
var _flows_grouped;
var _helper;
var _filterDataTable;

var _m;
var isMac = navigator.platform.toUpperCase().indexOf('MAC')>=0;

var _loadingPlugin;

function stopInterval (){
    clearInterval(_sync_db_interval);
}

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
function scrollIntoViewIfNeeded(target) {
    var rect = target.getBoundingClientRect();
    if (rect.bottom > window.innerHeight) {
        target.scrollIntoView(false);
    }
    if (rect.top < 0) {
        target.scrollIntoView();
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

function AnalysisSessionLogic(){
    /************************************************************
                            GLOBAL ATTRIBUTES
     *************************************************************/


    var stepped = 0;
    var rowCount, firstError, errorCount = 0;
    var db_name = 'weblogs_db';
    var reader_files;
    var datatable_setting = null;
    var contextmenu_setting = null;
    this.columns_order_changed = false;
    thiz = this;
    _m = new Metrics(true,this);
    var _verdict_sync = {};

    this.getColumnsOrderFlat =function(){
        return this.columns_order_changed;
    };
    this.setColumnsOrderFlat =function (v) {
        this.columns_order_changed = v;
    };
    this.getAnalysisSessionId = function () {
        return _analysis_session_id;
    };
    this.setAnalysisSessionId = function(id){
        _analysis_session_id = id;
    };
    this.getAnalysisSessionName = function () {
        return _filename;
    };
    this.isSaved = function (){
        return _analysis_session_id !== -1
    };
    this.generateAnalysisSessionUUID = function(){
        if (_analysis_session_uuid == undefined || _analysis_session_uuid == null){
            _analysis_session_uuid = uuid.v4();
        }
    };
    this.setAnalysisSessionUUID = function(uuid){
        _analysis_session_uuid = uuid;
    };
    this.getAnalysisSessionUUID = function(){
        return _analysis_session_uuid;
    };
    this.getAnalysisSessionTypeFile = function(){
       return _analysis_session_type_file
    };
    this.setAnalysisSessionTypeFile = function(type_file){
      _analysis_session_type_file = type_file
    };

     /************************************************************
                            PRIVATE FUNCTIONS
     *************************************************************/


    var syncDB = function (show_loading){
        if(show_loading === undefined || show_loading === null) show_loading = false;
        if(show_loading) showLoading();
        var arr_list = datatable_setting.cleanRowsLabeled();
        var data_row = {};
        for(var dt_id in arr_list){
            var elem = arr_list[dt_id];
            if(elem.register_status !== -1){
                var key_id = dt_id.split(':').length <= 1 ? thiz.getAnalysisSessionId()+":"+dt_id : dt_id;
                data_row[key_id]= elem.verdict;
            }
        }
        var data = {'analysis_session_id': _analysis_session_id, 'data': data_row };
        if(thiz.getColumnsOrderFlat()){
            data['headers[]'] = JSON.stringify(datatable_setting.get_headers_info());
            thiz.setColumnsOrderFlat(false);
        }
        $.ajax({
            type:"POST",
            data: JSON.stringify(data),
            dataType: "json",
            url: "/manati_project/manati_ui/analysis_session/sync_db",
            // handle a successful response
            success : function(json) {
                var data = JSON.parse(json['data']);
                // $.each(data,function (index, elem) {
                //     console.log(elem);
                //     var dt_id = parseInt(elem.pk.split(':')[1]);
                //     var row = _dt.rows('[data-dbid="'+dt_id+'"]');
                //     var index_row = row.indexes()[0];
                //      row.nodes().to$().addClass('selected-sync');
                //     thiz.setColumnsOrderFlat(false);
                //      thiz.markVerdict(elem.fields.verdict,'selected-sync');
                //     row.nodes().to$().removeClass('modified');
                //     _dt.cell(index_row, COLUMN_VERDICT).data(elem.fields.verdict);
                //     _dt.cell(index_row, COLUMN_REG_STATUS).data(elem.fields.register_status);
                // });
                datatable_setting.reloadAjax();
                console.log("DB Synchronized");
                if(show_loading) hideLoading();
            },

            // handle a non-successful response
            error : function(xhr,errmsg,err) {
                    $('#results').html("<div class='alert-box alert radius' data-alert>Oops! We have encountered an error: "+errmsg+
                        " <a href='#' class='close'>&times;</a></div>"); // add the error to the dom
                    console.error(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
                    $('#save-table').attr('disabled',false).removeClass('disabled');
                    // $.notify(xhr.status + ": " + xhr.responseText, "error");
                    $.notify(xhr.status + ": " + xhr.responseText);
                    //NOTIFY A ERROR
                    clearInterval(_sync_db_interval);
                    _m.EventAnalysisSessionSavingError(_filename);
                    hideLoading();
            }

        });
    };

    function saveDB(){
        try{

            showLoading();
            $.notify("Starting process to save the Analysis Session, it takes time", "info", {autoHideDelay: 6000 });
            $('#save-table').attr('disabled',true).addClass('disabled');
            var rows = datatable_setting.getRows();
            _m.EventAnalysisSessionSavingStart(rows.length, _filename);
            var data = {
                filename: _filename,
                "headers[]": JSON.stringify(datatable_setting.get_headers_info()),
                'data[]': JSON.stringify(rows),
                type_file: thiz.getAnalysisSessionTypeFile(),
                uuid: thiz.getAnalysisSessionUUID()
            };
            //send the name of the file, and the first 10 registers
            $.ajax({
                type:"POST",
                data: data,
                dataType: "json",
                url: "/manati_project/manati_ui/analysis_session/create",
                // handle a successful response
                success : function(json) {
                    // $('#post-text').val(''); // remove the value from the input
                    // console.log(json); // log the returned json to the console
                    // console.log("success"); // another sanity check
                    _analysis_session_id = json['data']['analysis_session_id'];
                    setFileName(json['data']['filename']);
                    datatable_setting.cleanModified();
                    datatable_setting.activeAjaxData(_analysis_session_id);
                    _m.EventAnalysisSessionSavingFinished(_filename,_analysis_session_id);
                    $.notify("All Weblogs ("+json['data']['data_length']+ ") were created successfully ", 'success');
                    $('#save-table').hide();
                    $('#public-btn').show();
                    $('#wrap-form-upload-file').hide();
                    history.pushState({},
                        "Edit AnalysisSession "  + _analysis_session_id,
                        "/manati_project/manati_ui/analysis_session/"+_analysis_session_id+"/edit");
                    _sync_db_interval = setInterval(syncDB, TIME_SYNC_DB );
                    hideLoading();
                    columns_order_changed = false;
                    $("#weblogfile-name").off('click');
                    $("#weblogfile-name").css('cursor','auto');
                    $("#sync-db-btn").show();
                    //show comment and update form
                    $("#coments-as-nav").show();
                    $('#comment-form').attr('action', '/manati_project/manati_ui/analysis_session/'+
                        _analysis_session_id+'/comment/create')
                },

                // handle a non-successful response
                error : function(xhr,errmsg,err) {
                    $('#results').html("<div class='alert-box alert radius' data-alert>Oops! We have encountered an error: "+errmsg+
                        " <a href='#' class='close'>&times;</a></div>"); // add the error to the dom
                    console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
                    $('#save-table').attr('disabled',false).removeClass('disabled');
                    $('#public-btn').hide();
                    $.notify(xhr.status + ": " + xhr.responseText, "error");
                    //NOTIFY A ERROR
                    _m.EventAnalysisSessionSavingError(_filename);
                    hideLoading();
                }
            });
        }catch(e){
            // thiz.destroyLoading();
            $.notify(e, "error");
            $('#public-btn').hide();
            $('#save-table').attr('disabled',false).removeClass('disabled');
        }




    }
    function showLoading(){
         $("#loading-img").show();
    }
    function hideLoading() {
        $("#loading-img").hide();
    }

    function refreshingDomainsWhoisRelatedModal(weblog_id){
        var data = {weblog_id: weblog_id};
        $.ajax({
            type:"GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/analysis_session/weblog/reload_modal_domains_whois_related",
            success : function(json) {// handle a successful response
                var whois_related_domains = json['whois_related_domains'];
                var was_related = json['was_related'];
                var table = buildTable_WeblogsWhoisRelated(whois_related_domains,was_related);
                updateBodyModal(table);
                if (was_related) {
                    closingModal()

                }
            },
            error : function(xhr,errmsg,err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }
        });



    }
    var closingModal = function(){
        clearInterval(refreshIntervalId);
        refreshIntervalId = null;
    };
    function getWeblogsWhoisRelated(weblog_id){

        updateFooterModal('<a id="search-domain-selected" class="btn btn-info" data-dismiss="modal">Search Selected</a>');
        initModal("Activating WHOIS Similarity Distance Module..." , closingModal);
        var data = {weblog_id: weblog_id};
        $.ajax({
            type:"GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/analysis_session/weblog/modules_whois_related",
            success : function(json) {// handle a successful response
               // / var whois_related_domains = json['whois_related_domains'];
                $.notify(json['msg'], "info");
                updateTitleModal("List of domains WHOIS related with: " + json['domain_primary']);
                // var was_whois_related = json['was_whois_related'];
                // if(!was_whois_related){
                //     $.notify("One request for the DB was realized, maybe it will take time to process it and" +
                //             " show the information in the modal.",
                //             "warn", {autoHideDelay: 2000});
                // }
                // var table = buildTable_WeblogsWhoisRelated(whois_related_domains);
                // updateBodyModal(table);
                refreshIntervalId = setInterval(refreshingDomainsWhoisRelatedModal, 3000,weblog_id)


            },
            error : function(xhr,errmsg,err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }

        });

    }
    function labelWeblogsWhoisRelated(weblog_id, verdict){
        $.notify("One request for the DB was realized, maybe it will take time to process it and" +
                            " show the information in the modal.",
                            "warn", {autoHideDelay: 2000});
        var data = {weblog_id: weblog_id, verdict: verdict};
        $.ajax({
            type:"POST",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/analysis_session/weblog/label_weblogs_whois_related",
            success : function(json) {// handle a successful response
                $.notify(json.msg, "info")
            },
            error : function(xhr,errmsg,err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }

        });

    }

    function findDomainOfURL(url){
        var matching_domain = null;
        var domain = ( (matching_domain = url.match(REG_EXP_DOMAINS)) != null )|| matching_domain != undefined && matching_domain.length > 0 ? matching_domain[0] : null ;
        domain = (domain == null)  && ((matching_domain = url.match(REG_EXP_IP)) != null) || matching_domain != undefined && matching_domain.length > 0 ? matching_domain[0] : null;
        return domain
    }


    var executeFilterBtn = function (verdict){
        $('.searching-buttons .btn').filter('[data-verdict="'+ verdict+'"]').click()
    };
    var setFileName = function(file_name){
        $("#weblogfile-name").html(file_name);
        _filename = file_name;
    };
    var getFileName = function (){
        return _filename;
    };
    var hotkeys_definition = function () {
        var preventDefault = function (e){
            if (e.preventDefault) {
                e.preventDefault();
            } else {
                // internet explorer
                e.returnValue = false;
            }
        };
        // active sync button
        Mousetrap.bind(['ctrl+s', 'command+s'], function(e) {
            preventDefault(e);
            if(thiz.isSaved()) syncDB(true);
        });
        // mark malicious
        Mousetrap.bind(['ctrl+m', 'command+m'], function(e) {
            preventDefault(e);
            contextmenu_setting.labelingRows('malicious');
        });
        // mark legitimate
        Mousetrap.bind(['ctrl+l', 'command+l'], function(e) {
            preventDefault(e);
            contextmenu_setting.labelingRows('legitimate');
        });
        // mark suspicious
        Mousetrap.bind(['ctrl+i', 'command+i'], function(e) {
            preventDefault(e);
            contextmenu_setting.labelingRows('suspicious');
        });
        // mark false positive
        Mousetrap.bind(['ctrl+p', 'command+p'], function(e) {
            preventDefault(e);
            contextmenu_setting.labelingRows('falsepositive');
        });
        // mark undefined
        Mousetrap.bind(['ctrl+u', 'command+u'], function(e) {
            preventDefault(e);
            contextmenu_setting.labelingRows('undefined');
        });
         // unselect selected rows
        Mousetrap.bind(['shift+ctrl+u', 'shift+command+u'], function(e) {
            preventDefault(e);
            $('tr.selected').removeClass('selected');
        });
        // Filter all Malicious
        Mousetrap.bind(['ctrl+1', 'command+1'], function(e) {
            preventDefault(e);
            executeFilterBtn('malicious');
        });
        // Filter all Legitimate
        Mousetrap.bind(['ctrl+2', 'command+2'], function(e) {
            preventDefault(e);
            executeFilterBtn('legitimate');
        });
        // Filter all Suspicious
        Mousetrap.bind(['ctrl+3', 'command+3'], function(e) {
            preventDefault(e);
            executeFilterBtn('suspicious');
        });
         // Filter all False Positive
        Mousetrap.bind(['ctrl+4', 'command+4'], function(e) {
            preventDefault(e);
            executeFilterBtn('falsepositive');
        });
         // Filter all Undefined
        Mousetrap.bind(['ctrl+5', 'command+5'], function(e) {
            preventDefault(e);
            executeFilterBtn('undefined');
        });
        //  // Unfilter everthing
        // Mousetrap.bind(['ctrl+5', 'command+0'], function(e) {
        //     preventDefault(e);
        //     // TO-DO
        // });
        //
        //  // Unfilter everthing
        // Mousetrap.bind(['space', 'space'], function(e) {
        //     preventDefault(e);
        //     // TO-DO
        // });
         // open VirusTotal Modal By domain, the first selected weblog
        Mousetrap.bind(['ctrl+shift+v', 'command+shift+v'], function(e) {
            preventDefault(e);
            var qn = _dt.rows('.action').data()[0][COLUMN_HTTP_URL];
            consultVirusTotal(qn, "domain");
        });
         // open WHOIS Modal By domain, the first selected weblog
        Mousetrap.bind(['ctrl+shift+p', 'command+shift+p'], function(e) {
            preventDefault(e);
            var qn = _dt.rows('.action').data()[0][COLUMN_HTTP_URL];
            consultWhois(qn, "domain");
        });
         // open VirusTotal Modal By IP, the first selected weblog
        Mousetrap.bind(['ctrl+shift+i', 'command+shift+i'], function(e) {
            preventDefault(e);
            var qn = _dt.rows('.action').data()[0][COLUMN_END_POINTS_SERVER];
            consultVirusTotal(qn, "ip");
        });
         // open WHOIS Modal By IP, the first selected weblog
        Mousetrap.bind(['ctrl+shift+o', 'command+shift+o'], function(e) {
            preventDefault(e);
            var verdict = _dt.rows('.action').data()[0][COLUMN_VERDICT];
             setBulkVerdict_WORKER(verdict, _bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR]);
        });
        //show whois similarity modal
        Mousetrap.bind(['ctrl+shift+d', 'command+shift+d'], function(e) {
            preventDefault(e);
            var weblog_id = _dt.rows('.action').data()[0][COLUMN_DT_ID].toString();
            weblog_id = weblog_id.split(":").length <= 1 ? thiz.getAnalysisSessionId() + ":" + weblog_id : weblog_id;
            getWeblogsWhoisRelated(weblog_id);
        });

        // VI-Style
        // moving down with J
        Mousetrap.bind(['j'], function(e) {
            preventDefault(e);
            var current_tr= $('#weblogs-datatable tbody tr.action').first();
            var next_tr;
            if(current_tr.length){
                next_tr = current_tr.next().first();
                if(!next_tr.length){
                    //move the page if it is possible
                    var current_page = _dt.page.info().page;
                    if(_dt.page.info().pages > current_page+1){
                        // moving to the next one
                        _dt.page(current_page+1).draw('page');
                    }else{
                        // moving to the first page, first row
                        _dt.page(0).draw('page');
                    }
                    next_tr = $('#weblogs-datatable tbody tr').first();
                    current_tr = null;
                }
            }else{
                next_tr = $('#weblogs-datatable tbody tr').first();
            }

            $('#weblogs-datatable tbody tr.action').removeClass('action');
            next_tr.addClass('action');
            if(current_tr){
                scrollIntoViewIfNeeded(current_tr[0])
            }else{
                $("html, body").animate({ scrollTop: 0 }, "slow");
            }

        });

         // moving up with k
        Mousetrap.bind(['k'], function(e) {
            preventDefault(e);
            var scroll_tr;
            var current_tr= $('#weblogs-datatable tbody tr.action').first();
            var prev_tr;
            if(current_tr.length){
                prev_tr = current_tr.prev().first();
                if(!prev_tr.length){
                    //move the page if it is possible
                    var current_page = _dt.page.info().page;
                    if(0 <= current_page-1){
                        // moving to the previous page
                        _dt.page(current_page-1).draw('page');
                    }else{
                        // moving to the last page, last row
                        var pages = _dt.page.info().pages;
                        _dt.page(pages-1).draw('page');
                    }
                    prev_tr = $('#weblogs-datatable tbody tr').last();
                    scroll_tr =prev_tr;
                    current_tr = null;
                }
            }else{
                prev_tr = $('#weblogs-datatable tbody tr').last();
            }

            $('#weblogs-datatable tbody tr.action').removeClass('action');
            prev_tr.addClass('action');
            scroll_tr = scroll_tr ? scroll_tr : prev_tr.prev();
            if(scroll_tr.length){
                scrollIntoViewIfNeeded(scroll_tr[0]);
            }else{
                $("html, body").animate({ scrollTop: 0 }, "slow");
            }

        });
        // select row to be label.
        Mousetrap.bind(['space'], function(e) {
            preventDefault(e);
            var current_tr= $('#weblogs-datatable tbody tr.action').first();
            current_tr.toggleClass('selected');

        });

        Mousetrap.bind(['left'], function (e) {
            preventDefault(e);
            var pages = _dt.page.info().pages;
            var current_page = _dt.page.info().page;
            if(current_page - 1 >= 0){
                _dt.page(current_page-1).draw('page');
            }else{
                _dt.page(pages-1).draw('page');
            }
        });

        Mousetrap.bind(['right'], function (e) {
            preventDefault(e);
            var pages = _dt.page.info().pages;
            var current_page = _dt.page.info().page;
            if(current_page + 1 < pages){
                _dt.page(current_page+1).draw('page');
            }else{
                _dt.page(0).draw('page');
            }
        });

        //mark all the weblogs in the current session with the same IP
        Mousetrap.bind(['p'],function (e) {
            preventDefault(e);
            var ip_value = _dt.rows('.action').data()[0][COLUMN_END_POINTS_SERVER].toString();
            var verdict = _dt.rows('.action').data()[0][COLUMN_VERDICT].toString();
            setBulkVerdict_WORKER(verdict, _helper.getFlowsGroupedBy(COL_END_POINTS_SERVER_STR,ip_value));
        });

        //mark all  the weblogs in the current session with the same domain
        Mousetrap.bind(['d'],function (e) {
            preventDefault(e);
            var url =  _dt.rows('.action').data()[0][COLUMN_HTTP_URL].toString();
            var domain = findDomainOfURL(url); // getting domain
            var verdict = _dt.rows('.action').data()[0][COLUMN_VERDICT].toString();
            setBulkVerdict_WORKER(verdict, _helper.getFlowsGroupedBy(COL_HTTP_URL_STR,domain));
        });





    };

    function on_ready_fn (){
        $(document).ready(function() {
            $(document).on('click', '#search-domain-selected', function(ev){
                var query_search = "(";
                var aux = '';
                $('#vt_consult_screen input[name="search_domain_table[]"]:checked').each(function (obj) {
                    query_search += aux + $(this).val();
                    if(aux == '') aux = '|';
                });
                query_search += ")";
                if(query_search.length > 2){
                    $("#weblogs-datatable_filter input[type='search']").html(query_search);
                    _dt.search(query_search).draw();
                }


            });
            $("#edit-input").hide();
            $("#weblogfile-name").on('click',function(){
                var _thiz = $(this);
                var input = $("#edit-input");
                input.val(_thiz.html());
                _thiz.hide();
                input.show();
                input.focus();
            });
            $("#edit-input").on('blur',function(){
                var _thiz = $(this);
                var label = $("#weblogfile-name");
                var text_name = _thiz.val();
                if(text_name.length > 0){
                    setFileName(text_name);
                }
                _thiz.val("");
                _thiz.hide();
                label.show();
            });
            //https://notifyjs.com/
            $.notify.defaults({
              autoHide: true,
              autoHideDelay: 3000
            });
            $('#panel-datatable').hide();
            $('#save-table, #public-btn').hide();



            contextmenu_setting.eventContextMenu();
            $('body').on('click','.unselect', function (ev){
                ev.preventDefault();
                _filterDataTable.removeFilter(_dt);
                $('.searching-buttons .btn').removeClass('active')
            });

            contextMenuSettings();
            $('#save-table').on('click',function(){
               saveDB();
            });

            //event for sync button
            $('#sync-db-btn').on('click',function (ev) {
               ev.preventDefault();
               syncDB(true);
            });

            $('body').on('submit','#comment-form',function(ev){
                ev.preventDefault();
                var form = $(this);
                $.ajax({
                    url: form.context.action,
                    type: 'POST',
                    data: form.serialize(),
                    dataType: 'json',
                    success: function (json){
                        $.notify(json.msg, "info");

                    },
                    error: function (xhr,errmsg,err) {
                        $.notify(xhr.status + ": " + xhr.responseText, "error");
                        console.log(xhr.status + ": " + xhr.responseText);


                    }
                })
            });

            hotkeys_definition();

            $("input#share-checkbox").change(function() {
                $.ajax({
                    url: '/manati_project/manati_ui/analysis_session/'+thiz.getAnalysisSessionId()+'/publish',
                    type: 'POST',
                    data: {'publish':$(this).prop('checked') ? "True": "False" },
                    dataType: 'json',
                    success: function (json){
                        $.notify(json.msg, "info");
                    },
                    error: function (xhr,errmsg,err) {
                        $.notify(xhr.status + ": " + xhr.responseText, "error");
                        console.log(xhr.status + ": " + xhr.responseText);


                    }
                })
            });

            $("button#change-status").on('click',function() {
                $.ajax({
                    url: '/manati_project/manati_ui/analysis_session/'+thiz.getAnalysisSessionId()+'/change_status',
                    type: 'POST',
                    data: {'status':$(this).data('status') },
                    dataType: 'json',
                    success: function (json){
                        $.notify(json.msg, "info");
                        var old_status = json.old_status;
                        var new_status = json.new_status;
                        var btn = $('#change-status');
                        btn.removeClass();
                        btn.addClass('btn btn-special-'+old_status);
                        btn.data('status',old_status);
                        var text = new_status === 'open' ? 'Close it !' : 'Open it !';
                        btn.text(text);
                        if(new_status === 'closed'){
                            $.notify("This Analysis Session is done, you will be redirect to the index page ", "info", {autoHideDelay: 3000 });
                            window.location.href = "/manati_project/manati_ui/analysis_sessions";
                        }
                    },
                    error: function (xhr,errmsg,err) {
                        $.notify(xhr.status + ": " + xhr.responseText, "error");
                        console.log(xhr.status + ": " + xhr.responseText);


                    }
                })
            });
        });
    };


    /************************************************************
                            PUBLIC FUNCTIONS
     *************************************************************/
    //INITIAL function , like a contructor
    thiz.init = function(){
        reader_files = ReaderFile(thiz);
        datatable_setting = new DataTableSettings(thiz);
        contextmenu_setting = new ContextMenuSettings(datatable_setting);
        on_ready_fn();
        // window.onbeforeunload = function() {
        //     return "Dude, are you sure you want to leave? Think of the kittens!";
        // }

    };
    thiz.eventBeforeParing = function(file){
        _size_file = file.size;
        _type_file = file.type;
        setFileName(file.name);
        showLoading();
        _m.EventFileUploadingStart(file.name,_size_file,_type_file);
        console.log("Parsing file...", file);
        $.notify("Parsing file...", "info");
    };
    thiz.parseData = function(file_rows){
        var completeFn = function (results,file){
            if (results && results.errors)
            {
                if (results.errors)
                {
                    errorCount = results.errors.length;
                    firstError = results.errors[0];
                }
                if (results.data && results.data.length > 0){

                    console.log("Done with all files");
                    //INIT DATA
                    rowCount = results.data.length;
                    var data = results.data;
                    var headers = results.meta.fields;
                    var headers_objs = [];
                    for(var i =0; i < headers.length; i++){
                        var cn = headers[i];
                        headers_objs.push({column_name:cn, title: cn , order: i});
                    }

                    datatable_setting.newDataTable(headers_objs,data);
                    // initData(data,headers);
                    thiz.generateAnalysisSessionUUID();
                    hideLoading();
                    _m.EventFileUploadingFinished(_filename, rowCount);
                }

            }
        };
        Papa.parse(file_rows,
            {
                delimiter: "",
                header: true,
                complete: completeFn,
                worker: true,
                skipEmptyLines: true,
                error: function(err, file, inputElem, reason)
                {
                    console.log("ERROR Parsing:", err, file);
                    $.notify("ERROR Parsing:" + " " + err + " "+ file, "error");
                    _m.EventFileUploadingError(file.name);
                }
            }
        );
    };

    var initDataEdit = function (weblogs, analysis_session_id,headers_info) {
        _analysis_session_id = analysis_session_id;
        var weblogs_id_uuid = {};
        var update_uuid_weblogs = false;
        if(weblogs.length > 1){
            // sorting header
            var headers;
            if(_.isEmpty(headers_info)){
                var elem = weblogs[0];
                var attributes = elem.attributes;
                if(!(attributes instanceof Object)) attributes = JSON.parse(attributes);
                headers_info = _.keys(attributes);
                headers_info.push(COL_VERDICT_STR);
                headers_info.push(COL_REG_STATUS_STR);
                headers_info.push(COL_DT_ID_STR);
                headers_info.push(COL_UUID_STR);
                thiz.setColumnsOrderFlat(true);
                headers = headers_info;
            }else{
                headers_info.sort(function(a,b) {
                    return a.order - b.order;
                });
                headers = $.map(headers_info,function(v,i){
                    return v.column_name
                });
                if(headers.indexOf(COL_UUID_STR) <= -1){
                    headers.push(COL_UUID_STR);
                    update_uuid_weblogs = true;
                }
            }

            //getting data
            var data = [];
            $.each(weblogs, function (index, elem){
                var id = elem.id;
                var attributes = elem.attributes;
                if(!(attributes instanceof Object)) attributes = JSON.parse(attributes);
                attributes[COL_VERDICT_STR] = elem.verdict.toString();
                attributes[COL_REG_STATUS_STR] = elem.register_status.toString();
                attributes[COL_DT_ID_STR] = id.toString();
                if (attributes.uuid == undefined || attributes.uuid == null){
                    var w_uuid = uuid.v4();
                    attributes[COL_UUID_STR] = w_uuid;
                    weblogs_id_uuid[id]=w_uuid;
                }
                var sorted_attributes = {};
                _.each(headers, function(value, index){
                    sorted_attributes[value] = attributes[value];
                });
                data.push(sorted_attributes);
            });

            initData(data, headers );
            //hide or show column
            $.each(headers_info,function(index,elem){
                _dt.columns(index).visible(elem.visible).draw()
            });

            $(document).ready(function(){
                $('#panel-datatable').show();
               idSyncDBIntervalId= setInterval(syncDB, TIME_SYNC_DB );

            });
            if(update_uuid_weblogs){
                updateAnalysisSessionUUID(thiz.getAnalysisSessionId(), weblogs_id_uuid);
            }
        }else{
            hideLoading();
            $.notify("The current AnalysisSession does not have weblogs saved", "info", {autoHideDelay: 5000 });
        }


    };
    var  updateAnalysisSessionUUID = function (analysis_session_id, weblogs_id_uuid){
        thiz.generateAnalysisSessionUUID();
        var ids = _.keys(weblogs_id_uuid);
        var uuids = _.values(weblogs_id_uuid);
        $.ajax({
                url: '/manati_project/manati_ui/analysis_session/'+analysis_session_id+'/update_uuid',
                type: 'POST',
                data: {'uuid': thiz.getAnalysisSessionUUID(),
                    "weblogs_ids[]": JSON.stringify(ids),
                    "weblogs_uuids[]": JSON.stringify(uuids)
                },
                dataType: "json",
                success: function (json){
                    $.notify(json.msg,"info");
                },
                error : function(xhr,errmsg,err) { // handle a non-successful response
                    $.notify(xhr.status + ": " + xhr.responseText, "error");
                    console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
                    _m.EventLoadingEditingError(analysis_session_id);

                }
        });

    };

    this.callingEditingData = function (analysis_session_id){
        thiz.setAnalysisSessionId(analysis_session_id);

        var data = {'analysis_session_id': thiz.getAnalysisSessionId()};
        $.notify("The page is being loaded, maybe it will take time", "info", {autoHideDelay: 3000 });
        showLoading();
        _m.EventLoadingEditingStart(thiz.getAnalysisSessionId());
        var ass_id = thiz.getAnalysisSessionId();
        datatable_setting.editDataTable(ass_id);

    };

    var setBulkVerdict_WORKER = function (verdict, flows_labelled){
        _dt.rows('.selected').nodes().to$().removeClass('selected');
        showLoading();
         var blob = new Blob([ "onmessage = function(e) { " +
            "var verdict = e.data[1];"+
            "var rows_data = e.data[2];"+
            "var col_dt_id = e.data[3];"+
            "var col_verdict = e.data[4];"+
            "var origin = e.data[5];"+
            "var col_reg_status = e.data[6];"+
            "var reg_status = e.data[7];"+
            "self.importScripts(origin+'/static/manati_ui/js/libs/underscore-min.js');"+
            "var flows_labelled = _.map(e.data[0],function(v,i){ return v.dt_id});"+
            "for(var i = 0; i< rows_data.length; i++) {"+
                "var row_dt_id = rows_data[i][col_dt_id]; "+
                "var index = flows_labelled.indexOf(row_dt_id); "+
                "if(index >=0){"+
                   "rows_data[i][col_verdict] = verdict ;"+
                   "rows_data[i][col_reg_status] = reg_status.modified ;"+
                "}"+
             "};" +
             "self.postMessage(rows_data)"+
        "}"]);
        var blobURL = window.URL.createObjectURL(blob);
        var worker = new Worker(blobURL);
        worker.addEventListener('message', function(e) {
            var rows_data = e.data;
            var current_page = _dt.page.info().page;
            _dt.clear().rows.add(rows_data).draw();
            _dt.page(current_page).draw('page');
            hideLoading();
	    });
        var rows_data = _dt.rows().data().toArray();
        worker.postMessage([flows_labelled,verdict,rows_data,
            COLUMN_DT_ID, COLUMN_VERDICT,document.location.origin, COLUMN_REG_STATUS, REG_STATUS]);
    };

    var processingFlows_WORKER = function (flows,col_host_str, col_ip_str) {
         $("#statical-section").html('');
        _flows_grouped = {};
        var blob = new Blob([ "onmessage = function(e) { " +
            "var flows = e.data[1];"+
            "var flows_grouped = e.data[0];"+
            "var origin = e.data[2];"+
            "var col_host_str = e.data[3];"+
            "var co_ip_str = e.data[4];"+
            "self.importScripts(origin+'/static/manati_ui/js/libs/underscore-min.js');"+
            "self.importScripts(origin+'/static/manati_ui/js/struct_helper.js');"+
            "var helper = new FlowsProcessed(col_host_str,co_ip_str);"+
            "helper.addBulkFlows(flows);"+
            "self.postMessage(helper.getFlowsGrouped());" +
        "}"]);

        // Obtain a blob URL reference to our worker 'file'.
        var blobURL = window.URL.createObjectURL(blob);

        var worker = new Worker(blobURL);
        worker.addEventListener('message', function(e) {
            worker.terminate();
            _flows_grouped = e.data;
            _helper = new FlowsProcessed(col_host_str, col_ip_str);
            _helper.setFlowsGrouped(_flows_grouped);
            _helper.makeStaticalSection();
            console.log("Worker Done");
	    });
        worker.postMessage([_flows_grouped,flows,document.location.origin, col_host_str, col_ip_str]);

    };

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






}
