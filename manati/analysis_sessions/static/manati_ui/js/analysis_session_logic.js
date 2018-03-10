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
var NAMES_END_POINTS_SERVER = ["endpoints.server", "endpoints_server", "id.resp_h", "id_resp_h"];
const DEFAULT_COLUMNS_NAMES = ["endpoints.server", "endpoints_server", "id.resp_h", "id_resp_h","http.url",
    "http_url", "host", 'url','Referer', 'time', 'User-agent', 'ioc', 'dest_ip', 'dest_port', 'local_ip', 'local_port',
    'partial_url'];
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
    if (verdict == undefined || verdict == null) return verdict;
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

    function initDatatable(headers, data){
        var columns = [];
        for(var i = 0; i< headers.length ; i++){
            var v = headers[i];
            columns.push({title: v, name: v, class: v});
        }
        //verifying if already exist a table, in that case, destroy it
        if(_dt !== null && _dt !== undefined) {
            _dt.clear();
            _dt.destroy();
            _dt = null;
            $('#weblogs-datatable').empty();
            $('#weblogs-datatable').html('');
        }
        // create or init datatable
        _dt = $('#weblogs-datatable').DataTable({
            data: data,
            columns: columns,
            fixedHeader: {
                header: true
            },
            columnReorder: true,
            "search": {
                "regex": true
            },
            columnDefs: [
                {"searchable": false, visible: false, "targets": headers.indexOf(COL_REG_STATUS_STR)},
                {"searchable": false, visible: false, "targets": headers.indexOf(COL_DT_ID_STR)},
                {"searchable": false, visible: false, "targets": headers.indexOf(COL_UUID_STR)}
            ],
            "scrollX": true,
            colReorder: true,
            renderer: "bootstrap",
            // responsive: true,
            buttons: [  {extend:'copy', title:thiz.getAnalysisSessionName()},
                        {extend:'excel', title: thiz.getAnalysisSessionName()},
                        {extend:'csv', title: thiz.getAnalysisSessionName()},
                        {extend:'colvis', title: thiz.getAnalysisSessionName()}
            ],
            "fnRowCallback": function( nRow, aData, iDisplayIndex, iDisplayIndexFull ) {
                //when you change the verdict, the color is updated
                var row = $(nRow);
                var id = aData[COLUMN_DT_ID];
                var str = id.split(":");
                var id_row = str.length > 1 ? str[1] : str[0];
                var verdict = aData[COLUMN_VERDICT];
                var reg_status = aData[COLUMN_REG_STATUS];
                if(_verdict_sync.hasOwnProperty(id)){
                    var internal_row = _dt.rows('[data-dbid="'+id_row+'"]');
                    var index_row = internal_row.indexes()[0];
                    var elem = _verdict_sync[id];
                    verdict = elem.verdict;
                    reg_status = elem.register_status;
                    internal_row.nodes().to$().addClass('selected-sync');
                    _dt.cell(index_row, COLUMN_VERDICT).data(verdict);
                    _dt.cell(index_row, COLUMN_REG_STATUS).data(reg_status);
                    addClassVerdict('selected-sync',verdict, false);
                    // thiz.markVerdict(verdict,'selected-sync');
                    // internal_row.nodes().to$().removeClass('modified');

                    delete _verdict_sync[id];
                }

                row.addClass(checkVerdict(_verdicts_merged,verdict ));
                if((reg_status === REG_STATUS.modified) && !row.hasClass('modified')){
                    row.addClass('modified');
                }else if((reg_status !== REG_STATUS.modified) &&  row.hasClass('modified')){
                    row.removeClass('modified');
                }
                row.attr("data-dbid", id_row);

            },
            drawCallback: function(){
              $('.paginate_button.next', this.api().table().container())
                 .on('click', function(){
                     $("html, body").animate({ scrollTop: 0 }, "slow");
                 });
           },
            initComplete:   function(){
              var div_filter = $("#weblogs-datatable_filter");//.detach();
              var input_filter = div_filter.find('input').detach();
              var label_filter = div_filter.find('label').detach();
              input_filter.attr('placeholder', 'Search:');
              input_filter.css('width', '100%');
              input_filter.removeClass();
              label_filter.removeClass();
              div_filter.addClass('fluid-label');
              div_filter.append(input_filter);
              div_filter.append(label_filter);

              $('.fluid-label').fluidLabel({ focusClass: 'focused' });
              $('.wrap-buttons').html($('.searching-buttons').clone());

              $('.wrap-select-page').html($('.wrap-page-select').clone());
            },
             // "sPaginationType": "listbox",
            dom:'<"top"<"row"<"col-md-2"f><"col-md-5 wrap-buttons"><"col-md-1 wrap-select-page"><"col-md-4"p>>>' +
                'rt' +
                '<"bottom"<"row"<"col-md-2"l><"col-md-5"B><"col-md-5"p>>>' +
                '<"row"<"col-md-offset-7 col-md-5"<"pull-right"i>>>'+
                '<"clear">',
            "lengthMenu": [[25, 50, 100, 500], [25, 50, 100, 500]]
        });


        _dt.buttons().container().appendTo( '#weblogs-datatable_wrapper .col-sm-6:eq(0)' );
        $('#weblogs-datatable tbody').on( 'click', 'tr', function (event) {
            event.preventDefault();
            $('tr.action').not(this).removeClass('action');
            if((isMac && event.metaKey ) || (!isMac && event.shiftKey)){
                $(this).toggleClass('selected');
            }
            $(this).toggleClass('action');
            $('.contextMenuPlugin').remove();
        }).on('dblclick', 'tr',function () {
            $(this).toggleClass('selected');
        });

        hideLoading();
        $('#panel-datatable').show();
         _dt.on( 'column-reorder', function ( e, settings, details ) {
            thiz.setColumnsOrderFlat(true);
            for(var i=0; i < settings.aoColumns.length; i++){
                var name = settings.aoColumns[i].name;
                update_constant(name, i);
                // TO-DO to fix problem when you move the columns and the attributes COLUMN_XXXX must be updated.
            }
         });
         _dt.on( 'buttons-action', function ( e, buttonApi, dataTable, node, config ) {
            thiz.setColumnsOrderFlat(true);
        } );
         _dt.columns(0).visible(true); // hack fixing one bug with the header of the table

         $("#weblogs-datatable").on("click", "a.virus-total-consult",function (ev) {
             ev.preventDefault();
             var elem = $(this);
             var row = elem.closest('tr');
             var query_node = elem.data('info') == 'domain' ? findDomainOfURL(elem.text()) : elem.text() ;
             row.removeClass('selected');
             consultVirusTotal(query_node);

        });
         // adding options to select datatable's pages
         var list = document.getElementsByClassName('page-select')[1];
         for(var index=0; index<_dt.page.info().pages; index++) {
             list.add(new Option((index+1).toString(), index));
         }
         $('.page-select').change(function (ev) {
             ev.preventDefault();
             var elem = $(this);

             _dt.page(parseInt(elem.val())).draw('page');

         });
         _dt.on( 'page.dt', function () {
            var info = _dt.page.info();
            $('.page-select').val(info.page);

        } );
         _dt.on('length.dt',function (){
             $('.page-select').html('');
             var list = document.getElementsByClassName('page-select')[1];
             for(var index=0; index<_dt.page.info().pages; index++) {
                 list.add(new Option((index+1).toString(), index));
             }
         });
         _dt.on('search.dt',function (){
             try{
                 $('.page-select').html('');
                 var list = document.getElementsByClassName('page-select')[1];
                 for(var index=0; index<_dt.page.info().pages; index++) {
                     list.add(new Option((index+1).toString(), index));
                 }
             }catch (e){
                 // pass. When you upload another file, in the same section that the previous one, there is an error
                 // TO-DO
             }

         });
         // _dt.on( 'column-reorder', function ( e, settings, details ) {
         //    for(var i=0; i < settings.aoColumns.length; i++){
         //        var name = settings.aoColumns[i].name;
         //
         //        // TO-DO to fix problem when you move the columns and the attributes COLUMN_XXXX must be updated.
         //    }

        // } );

    }
    function initData(data, headers) {

        _data_uploaded = data;
        _data_headers = headers;
        _data_headers_keys = {};
        _countID = 1;
        $("li#statical-nav").hide();
        var data_processed = _.map(_data_uploaded,function(v, i){
                                var values = _.values(v);
                                if(values.length < _data_headers.length){
                                    var uuid_str = uuid.v4();
                                    values.push('undefined');
                                    values.push(-1);
                                    values.push(_countID.toString());
                                    values.push(uuid_str);
                                    _data_uploaded[i][COL_VERDICT_STR] = "undefined";
                                    _data_uploaded[i][COL_REG_STATUS_STR] = (-1).toString();
                                    _data_uploaded[i][COL_DT_ID_STR] =_countID.toString();
                                    _data_uploaded[i][COL_UUID_STR] = uuid_str;
                                 }
                                _countID++;
                                return values
                            });

        $.each(_data_headers,function(i, v){
            _data_headers_keys[v] = i;
        });
        console.log(data.length);
        COLUMN_DT_ID = _data_headers_keys[COL_DT_ID_STR];
        COLUMN_REG_STATUS = _data_headers_keys[COL_REG_STATUS_STR];
        COLUMN_VERDICT =  _data_headers_keys[COL_VERDICT_STR];
        COLUMN_UUID = _data_headers_keys[COL_UUID_STR];

        for(var index = 0; index < NAMES_HTTP_URL.length; index++){
            var key = NAMES_HTTP_URL[index];
            if(_data_headers_keys[key]!== undefined && _data_headers_keys[key] !== null){
                COL_HTTP_URL_STR = key;
                break;
            }
        }
        for(var index = 0; index < NAMES_END_POINTS_SERVER.length; index++){
            var key = NAMES_END_POINTS_SERVER[index];
            if(_data_headers_keys[key]!== undefined && _data_headers_keys[key] !== null){
                COL_END_POINTS_SERVER_STR = key;
                break;
            }
        }
        if(isEmpty(COL_HTTP_URL_STR)){
            alert("None of these key column were found: " + NAMES_HTTP_URL.join(', ') + " several features will be disabled");
        }
        if(isEmpty(COL_END_POINTS_SERVER_STR)){
            alert("None of these key column were found: " + NAMES_END_POINTS_SERVER.join(', ') + " several features will be disabled");
        }

        if(!isEmpty(COL_HTTP_URL_STR) && !isEmpty(NAMES_END_POINTS_SERVER)){
            processingFlows_WORKER(_data_uploaded,COL_HTTP_URL_STR,COL_END_POINTS_SERVER_STR);
            COLUMN_HTTP_URL = _data_headers_keys[COL_HTTP_URL_STR];
            COLUMN_END_POINTS_SERVER = _data_headers_keys[COL_END_POINTS_SERVER_STR];
            CLASS_MC_END_POINTS_SERVER_STR =  COL_END_POINTS_SERVER_STR.replace(".", "_");
            CLASS_MC_HTTP_URL_STR = COL_HTTP_URL_STR.replace(".","_");
        }
        _filterDataTable = new FilterDataTable(COLUMN_VERDICT,_verdicts_merged);
        initDatatable(_data_headers, data_processed);
        $('#save-table').show();

    }


    function addClassVerdict(class_selector, verdict, add_modified) {
        add_modified = add_modified === null || add_modified === undefined ? true : add_modified;
        var checked_verdict = checkVerdict(_verdicts_merged, verdict);
        _dt.rows('.' + class_selector).nodes().to$().removeClass(_verdicts_merged.join(" ")).addClass(checked_verdict);
        if (add_modified) {
            _dt.rows('.' + class_selector).nodes().to$().addClass('modified');
        }
        _dt.rows('.' + class_selector).nodes().to$().removeClass(class_selector);

    }
    this.markVerdict= function (verdict, class_selector) {
        var rows_affected = [];
        if(class_selector === null || class_selector === undefined) class_selector = "selected";
        _dt.rows('.'+class_selector).every( function () {
            var d = this.data();
            var temp_data = {};
            if(!isEmpty(COLUMN_END_POINTS_SERVER) && !isEmpty(COLUMN_HTTP_URL)){
                temp_data[COL_END_POINTS_SERVER_STR] = d[COLUMN_END_POINTS_SERVER];
                temp_data[COL_HTTP_URL_STR] = d[COLUMN_HTTP_URL];
            }
            temp_data[COL_UUID_STR] = d[COLUMN_UUID];
            temp_data[COL_DT_ID_STR] = d[COLUMN_DT_ID];

            rows_affected.push(temp_data);
            var old_verdict = d[COLUMN_VERDICT];
            d[COLUMN_VERDICT]= verdict; // update data source for the row
            d[COLUMN_REG_STATUS] = REG_STATUS.modified;
            this.invalidate(); // invalidate the data DataTables has cached for this row

        } );
        // Draw once all updates are done
        _dt.draw(false);
        addClassVerdict(class_selector, verdict);
        return rows_affected;

    };

    var syncDB = function (show_loading){
        if(show_loading === undefined || show_loading === null) show_loading = false;
        if(show_loading) showLoading();
        var arr_list = _dt.rows('.modified').data();
        var $rows = _dt.rows('.modified').nodes().to$();
        $rows.addClass('modified-sync');
        $rows.removeClass('modified');
        var data_row = {};
        arr_list.each(function(elem){
            if(elem[COLUMN_REG_STATUS] !== -1){
                var key_id = elem[COLUMN_DT_ID].split(':').length <= 1 ? _analysis_session_id+":"+elem[COLUMN_DT_ID] : elem[COLUMN_DT_ID] ;
                data_row[key_id]=elem[COLUMN_VERDICT];
            }
        });
        var data = {'analysis_session_id': _analysis_session_id, 'data': data_row };
        if(thiz.getColumnsOrderFlat()){
            data['headers[]']=JSON.stringify(get_headers_info());
            thiz.setColumnsOrderFlat(false);
        }
        $.ajax({
            type:"POST",
            data: JSON.stringify(data),
            dataType: "json",
            url: "/manati_project/manati_ui/analysis_session/sync_db",
            // handle a successful response
            success : function(json) {
                // $('#post-text').val(''); // remove the value from the input
                // console.log(json); // log the returned json to the console
                var data = JSON.parse(json['data']);
                console.log(data);

                $.each(data,function (index, elem) {
                    var id = elem.pk;
                    _verdict_sync[id] = {
                        verdict: elem.fields.verdict,
                        register_status: elem.fields.register_status
                    };
                    // console.log(elem);
                    // var dt_id = parseInt(elem.pk.split(':')[1]);
                    // var row = _dt.rows('[data-dbid="'+id+'"]');
                    // var index_row = row.indexes()[0];
                    //  row.nodes().to$().addClass('selected-sync');
                    // thiz.setColumnsOrderFlat(false);
                    //  thiz.markVerdict(elem.fields.verdict,'selected-sync');
                    // row.nodes().to$().removeClass('modified');
                    // _dt.cell(index_row, COLUMN_VERDICT).data(elem.fields.verdict);
                    // _dt.cell(index_row, COLUMN_REG_STATUS).data(elem.fields.register_status);



                });
                $('tr.modified-sync').removeClass('modified-sync');
                _dt.draw(false);
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
    function get_headers_info(){
        // _data_headers
        var column_visibles = _dt.columns().visible();
        var headers = $.map(_dt.columns().header(),function (v,i) {
            return {order: i, column_name: v.innerHTML, visible: column_visibles[i] };
        });

        return headers;
    }
    function saveDB(){
        try{

            showLoading();
            $.notify("Starting process to save the Analysis Session, it takes time", "info", {autoHideDelay: 6000 });
            $('#save-table').attr('disabled',true).addClass('disabled');
            var rows = _dt.rows();
            _m.EventAnalysisSessionSavingStart(rows.length, _filename);
            var data = {
                filename: _filename,
                "headers[]": JSON.stringify(get_headers_info()),
                'data[]': JSON.stringify(rows.data().toArray()),
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
                    _dt.column(COLUMN_REG_STATUS, {search:'applied'}).nodes().each( function (cell, i) {
                        var tr = $(cell).closest('tr');
                        if(!tr.hasClass("modified")) cell.innerHTML = 0;
                    } );
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

    function contextMenuConfirmMsg(rows, verdict){
        $.confirm({
            title: 'Weblogs Affected',
            content: "Will " + rows.length.toString() + ' weblogs change their verdicts, is ok for you? ',
            confirm: function(){
                _dt.rows('.selected').nodes().to$().removeClass('selected');
                _dt.rows(rows).nodes().to$().addClass('selected');
                thiz.markVerdict(verdict);
            },
            cancel: function(){

            }
        });
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
                var root_whois_features = json['root_whois_features'];
                var was_related = json['was_related'];
                var table = buildTable_WeblogsWhoisRelated(whois_related_domains,was_related,root_whois_features);
                updateBodyModal(table);
                if (was_related) {
                    closingModal();
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

    var _bulk_marks_wbs = {};
    var _bulk_verdict;

    var generateContextMenuItems = function(tr_dom){
        // var tr_active = $("tr.menucontext-open.context-menu-active");
        var items_menu = {};
        _verdicts.forEach(function(v){
            items_menu[v] = {name: v, icon: "fa-paint-brush " + v }
        });
        if(isEmpty(COLUMN_HTTP_URL) || isEmpty(COLUMN_END_POINTS_SERVER)) return items_menu;
        var bigData = _dt.rows(tr_dom).data()[0];
        var ip_value = bigData[COLUMN_END_POINTS_SERVER]; // gettin end points server ip
        var url = bigData[COLUMN_HTTP_URL];
        var domain = findDomainOfURL(url); // getting domain

        _bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR] = _helper.getFlowsGroupedBy(COL_END_POINTS_SERVER_STR,ip_value);
        _bulk_marks_wbs[CLASS_MC_HTTP_URL_STR] = _helper.getFlowsGroupedBy(COL_HTTP_URL_STR,domain);
        _bulk_verdict = bigData[COLUMN_VERDICT];

        items_menu['unselect'] = {
            name: "Unselect",
            icon: "fa-paint-brush " + "unselect",
            callback: function(key, options){
                $('tr.selected').removeClass('selected');
            }
        };
        items_menu['sep1'] = "-----------";
        items_menu['fold1'] = {
            name: "Mark all WBs with same: ",
            icon: "fa-search-plus",
            // disabled: function(){ return !this.data('moreDisabled'); },
            items: {
            "fold1-key1": { name:  "By IP (of column: " + COL_END_POINTS_SERVER_STR+")" +
                                    "("+_bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR].length+")",
                            icon: "fa-paint-brush",
                            className: CLASS_MC_END_POINTS_SERVER_STR,
                            callback: function(key, options) {
                                setBulkVerdict_WORKER(_bulk_verdict, _bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR]);
                                _m.EventBulkLabelingByEndServerIP(_bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR],_bulk_verdict, ip_value);

                            }
                        },
            "fold1-key2": { name: "By Domain (of column:" + COL_HTTP_URL_STR +")" +
                                    "("+_bulk_marks_wbs[CLASS_MC_HTTP_URL_STR].length+")",
                            icon: "fa-paint-brush",
                            className: CLASS_MC_HTTP_URL_STR,
                            callback: function(key, options) {
                                setBulkVerdict_WORKER(_bulk_verdict, _bulk_marks_wbs[CLASS_MC_HTTP_URL_STR]);
                                _m.EventBulkLabelingByDomains(_bulk_marks_wbs[CLASS_MC_HTTP_URL_STR],_bulk_verdict, domain);
                            }
                    }
        }};
        items_menu['sep2'] = "-----------";
        items_submenu_external_query = {};
        items_submenu_external_query['virus_total_consult'] = {
            name: "VirusTotal", icon: "fa-search",
            items: {
                "fold2-key1": {
                    name: "Looking for domain (of column:" + COL_HTTP_URL_STR +")",
                    icon: "fa-paper-plane-o",
                    callback: function (key, options) {
                        var qn = bigData[COLUMN_HTTP_URL];
                        consultVirusTotal(qn, "domain");

                    }
                },
                "fold2-key2": {
                    name: "Looking for IP (of column: " + COL_END_POINTS_SERVER_STR+")",
                    icon: "fa-paper-plane-o",
                    callback: function (key, options) {
                        var qn = bigData[COLUMN_END_POINTS_SERVER];
                        consultVirusTotal(qn, "ip");
                    }
                }
            }
        };
        items_submenu_external_query['whois_consult'] = {
            name: "Whois", icon: "fa-search",
            items: {
                "fold2-key1": {
                    name: "Looking for domain (of column: " + COL_HTTP_URL_STR +")",
                    icon: "fa-paper-plane-o",
                    callback: function (key, options) {
                        var qn = bigData[COLUMN_HTTP_URL];
                        consultWhois(qn, "domain");

                    }
                },
                "fold2-key2": {
                    name: "Looking for IP (of column: " + COL_END_POINTS_SERVER_STR+")",
                    icon: "fa-paper-plane-o",
                    callback: function (key, options) {
                        var qn = bigData[COLUMN_END_POINTS_SERVER];
                        consultWhois(qn, "ip");
                    }
                }
            }
        };
        var fn = function (){ $('#button-ok-modal').off()};

        if(thiz.isSaved()) {
            items_menu['fold1']['items']['fold1-key3'] = {
                name: "Mark all WBs WHOIS related (domain from column:" + COL_HTTP_URL_STR +")",
                icon: "fa-paint-brush",
                className: CLASS_MC_HTTP_URL_STR,
                callback: function(key, options) {
                    var weblog_id = bigData[COLUMN_DT_ID].toString();
                    weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
                    labelWeblogsWhoisRelated(weblog_id,_bulk_verdict)

                    // setBulkVerdict_WORKER(_bulk_verdict, _bulk_marks_wbs[CLASS_MC_HTTP_URL_STR]);
                    // _m.EventBulkLabelingByDomains(_bulk_marks_wbs[CLASS_MC_HTTP_URL_STR],_bulk_verdict, domain);
                }

            };
            items_submenu_external_query['whois_consult']['items']['fold2-key3'] = {
                name: "Find WHOIS related domains (from column:" + COL_HTTP_URL_STR +")",
                icon: "fa-search",
                callback: function (key, option) {
                    var weblog_id = bigData[COLUMN_DT_ID].toString();
                    weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
                    getWeblogsWhoisRelated(weblog_id);

                }
            };


            items_menu['fold4'] = {
                name: "Registry History", icon: "fa-search",
                items: {
                    "fold2-key1": {
                        name: "Veredict History",
                        icon: "fa-paper-plane-o",
                        callback: function (key, options) {
                            var weblog_id = bigData[COLUMN_DT_ID].toString();
                                weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
                                getWeblogHistory(weblog_id);

                        }
                    },
                    "fold2-key2": {
                        name: "Modules Changes",
                        icon: "fa-paper-plane-o",
                        callback: function (key, options) {
                            var weblog_id = bigData[COLUMN_DT_ID].toString();
                            weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
                            getModulesChangesHistory(weblog_id);
                        }
                    }
                }
            };
            items_menu['fold4'] = {
                name: "Registry History", icon: "fa-search",
                items: {
                    "fold2-key1": {
                        name: "Veredict History",
                        icon: "fa-paper-plane-o",
                        callback: function (key, options) {
                            var weblog_id = bigData[COLUMN_DT_ID].toString();
                                weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
                                getWeblogHistory(weblog_id);

                        }
                    },
                    "fold2-key2": {
                        name: "Modules Changes",
                        icon: "fa-paper-plane-o",
                        callback: function (key, options) {
                            var weblog_id = bigData[COLUMN_DT_ID].toString();
                            weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
                            getModulesChangesHistory(weblog_id);
                        }
                    },
                    "fold2-key3": {
                        name: "IOCs",
                        icon: "fa-paper-plane-o",
                        callback: function (key, options) {
                            var weblog_id = bigData[COLUMN_DT_ID].toString();
                            weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
                            getIOCs(weblog_id);
                        }
                    }
                }
            };

            items_menu['sep5'] = "-----------";
            items_menu['fold5'] = {
                name: "Create a comment", icon: "fa-pencil-square-o",
                callback: function (key, options){
                    initModal("Add a comment",fn);
                    var weblog_id = bigData[COLUMN_DT_ID];
                    $('#button-ok-modal').on('click', function (ev){
                        var comment_data = $("#textarea-comment").val();
                        $.ajax({
                            url:'/manati_project/manati_ui/weblog/comment/create',
                            type:"POST",
                            dataType: "json",
                            data: {text: comment_data, weblog_id: weblog_id},
                            success: function (json){
                                $.notify(json['msg'], "info");
                            },
                            error: function (xhr,errmsg,err) {
                                $.notify(xhr.status + ": " + xhr.responseText, "error");
                                console.log(xhr.status + ": " + xhr.responseText);
                                // provide a bit more info about the
                                // error to the console
                            }
                        })

                    });
                    $.ajax({
                            url:'/manati_project/manati_ui/weblog/comment/get',
                            type:"GET",
                            dataType: "json",
                            data: {weblog_id: weblog_id},
                            success: function (json){
                                var comment = json['text'];
                                var str_data = "<textarea id='textarea-comment' maxlength='250' " +
                                    "class='form-control' " +
                                    "row='5'></textarea>";
                                updateBodyModal(str_data);
                                $("#textarea-comment").val(comment);
                            },
                            error: function (xhr,errmsg,err) {
                                $.notify(xhr.status + ": " + xhr.responseText, "error");
                                console.log(xhr.status + ": " + xhr.responseText);
                                // provide a bit more info about the
                                // error to the console
                            }
                        })


                }
            };
        }

        items_menu['fold6'] = {
            name: "External Intelligence", icon: "fa-search",
            items: items_submenu_external_query
        };
        items_menu['sep6'] = "-----------";
        items_menu['fold7'] = {
            name: "Copy to clipboard", icon: "fa-files-o",
            items: {
                "fold2-key1": {
                    name: "Copy URL (of column: " + COL_HTTP_URL_STR +")",
                    icon: "fa-file-o",
                    callback: function (key, options) {
                        copyTextToClipboard(bigData[COLUMN_HTTP_URL]);
                    }
                },
                "fold2-key2": {
                    name: "Copy IP (of column: " + COL_END_POINTS_SERVER_STR+")",
                    icon: "fa-file-o",
                    callback: function (key, options) {
                        copyTextToClipboard(bigData[COLUMN_END_POINTS_SERVER]);
                    }
                }
            }
        };
        items_menu['sep7'] = "-----------";
        items_menu['fold8'] = {
            name: "Hotkeys List", icon: "fa-files-o",
            callback: function (key, options){
                initModal("List of Hotkeys");
                $.ajax({url:'/manati_project/manati_ui/hotkeys/list',
                    type:"GET",
                    dataType: "json",
                    success: function (json){
                        var table = buildTableHotkeys(json['hotkeys']);
                        updateBodyModal(table);
                    },
                    error: function (xhr,errmsg,err) {
                        $.notify(xhr.status + ": " + xhr.responseText, "error");
                        console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
                    }
                })

            },
        };



        return items_menu;

    };
    function buildTableHotkeys(hotkeys){
        var table = "<table class='table table-bordered table-striped'>";
        table += "<thead><tr><th style='width: 110px;'>#</th><th>Description</th><th>Command</th></tr></thead>";
        table += "<tbody>";
            var count = 1;
            _.each(hotkeys, function (value){
                table += "<tr>";
                table += "<td>"+count+"</td>";
                table += "<td>"+value['description']+"</td>";
                table += "<td>"+value['command']+"</td>";
                table += "</tr>";
                count++;

            });

        table += "</tbody>";
        table += "</table>";
        return table;

    }
    function buildTableInfo_VT(info_report){
        var table = "<table class='table table-bordered table-striped'>";
        table += "<thead><tr><th style='width: 110px;'>List Attributes</th><th> Values</th></tr></thead>";
        table += "<tbody>";
            for(var key in info_report){
                table += "<tr>";
                table += "<th>"+key+"</th>";
                var info = info_report[key];
                if (info instanceof Array){
                    var html_temp = "";
                    for(var index = 0; index < info.length; index++){
                        var data = info[index];
                        if(data instanceof Object){
                             html_temp += buildTableInfo_VT(data, true) ;
                        }else if(typeof(data) === "string") {
                            table += "<td>" + info.join(", ") + "</td>" ;
                            break;
                        }

                    }
                    if(html_temp != "") table += "<td>"+ html_temp+ "</td>"
                }
                else if(info instanceof Object){
                    var html_temp = "";
                    html_temp += buildTableInfo_VT(info, true) ;
                    if(html_temp != "") table += "<td>"+ html_temp+ "</td>"
                }
                else{
                    table += "<td>" + info + "</td>" ;
                }

                table += "</tr>";
            }

        table += "</tbody>";
        table += "</table>";
        return table;

    }
    function buildTableInfo_Whois(info_report, no_title){
        if(no_title == undefined || no_title == null) no_title = false;
        var table = "<table class='table table-bordered table-striped'>";
        if(!no_title) table += "<thead><tr><th style='width: 110px;'>List Attributes</th><th> Values</th></tr></thead>";
        table += "<tbody>";
            for(var key in info_report){
                table += "<tr>";
                table += "<th>"+key+"</th>";
                var info = info_report[key];
                if (info instanceof Array) {
                    var html_temp = "";
                    for (var index = 0; index < info.length; index++) {
                        var data = info[index];
                        if (data instanceof Object) {
                            html_temp += buildTableInfo_Whois(data, true);
                        } else if (typeof(data) == "string") {
                            table += "<td>" + info.join(", ") + "</td>";
                            break;
                        }
                    }
                    if (html_temp != "") table += "<td>" + html_temp + "</td>";
                }else if(info instanceof Object){
                    var html_temp = "";
                    html_temp += buildTableInfo_Whois(info, false) ;
                    if(html_temp != "") table += "<td>"+ html_temp+ "</td>"
                }else{
                    table += "<td>" + info + "</td>" ;
                }

                table += "</tr>";
            }

        table += "</tbody>";
        table += "</table>";
        return table;

    }
    function initModal(title, after_hidden_function, before_hidden_function){
        after_hidden_function = set_default(after_hidden_function, null);
        before_hidden_function = set_default(before_hidden_function, null);
        $('#vt_consult_screen #vt_modal_title').html(title);
        $('#vt_consult_screen').modal('show');
        $('#vt_consult_screen').on('hidden.bs.modal', function (e) {
            if(before_hidden_function !== null){
                before_hidden_function();
            }
            $(this).find(".table-section").html('').hide();
            $(this).find(".loading").show();
            $(this).find("#vt_modal_title").html('');
            $(this).find(".append").html('');
            if(after_hidden_function !== undefined && after_hidden_function !== null){
                after_hidden_function();
            }

        });
    }
    function updateTitleModal(title){
        $('#vt_consult_screen #vt_modal_title').html(title);

    }
    this.updateBodyModal = function (table){
        updateBodyModal(table);
    }

    function updateBodyModal(table) {
        var modal_body = $('#vt_consult_screen .modal-body');
        if (table !== null) {
            modal_body.find('.table-section').html(table).show();
            modal_body.find(".loading").hide();
        }
    }
    function updateFooterModal(html_append){
        var modal_footer = $('#vt_consult_screen .modal-footer .append');
        modal_footer.html(html_append)
    }
    function consultVirusTotal(query_node, query_type){
        if(query_type === "domain") _m.EventVirusTotalConsultationByDomian(query_type);
        else if(query_type === "ip") _m.EventVirusTotalConsultationByIp(query_type);
        else{
            console.error("Error query_type for ConsultVirusTotal is incorrect")
        }
        initModal("Virus Total Query: <span>?????</span>");
        var data = {query_node: query_node, query_type: query_type};
        $.ajax({
            type:"GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/consult_virus_total",
            success : function(json) {// handle a successful response
                var info_report = JSON.parse(json['info_report']);
                var node = json['query_node'];
                var table = buildTableInfo_VT(info_report);
                if(query_type === 'ip'){
                    query_node = "<a target='_blank' href='https://virustotal" +
                        ".com/en/ip-address/"+node+"/information/'>"+node+"</a>"
                }
                else if(query_type === 'domain'){
                    query_node = "<a target='_blank' href='https://virustotal" +
                        ".com/en/domain/"+node+"/information/'>"+node+"</a>"
                }
                initModal("Virus Total Query: <span>"+query_node+"</span>");
                updateBodyModal(table);
            },
            error : function(xhr,errmsg,err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }

        })
    }
    function consultWhois(query_node, query_type){
        if(query_type == "domain") _m.EventWhoisConsultationByDomian(query_type);
        else if(query_type == "ip") _m.EventWhoisConsultationByIp(query_type);
        else{
            console.error("Error query_type for WhoisConsultation is incorrect")
        }
        initModal("Whois Query: <span>????</span>");
        var data = {query_node: query_node, query_type: query_type};
        $.ajax({
            type:"GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/consult_whois",
            success : function(json) {// handle a successful response
                var info_report = json['info_report'];
                var query_node = json['query_node'];
                var table = buildTableInfo_Whois(info_report);
                initModal("Whois Query: <span>"+query_node+"</span>");
                updateBodyModal(table);
            },
            error : function(xhr,errmsg,err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }

        })
    }

    function buildTableInfo_Wbl_History(weblog_history){
        var table = "<table class='table table-bordered table-striped'>";
        table += "<thead><tr><th>User/Module</th><th>Previous Verdict</th><th>Verdict</th><th>When?</th></tr></thead>";
        table += "<tbody>";
            _.each(weblog_history, function (value, index) {
                table += "<tr>";
                // for(var key in value){
                //     table += "<td>" + value[key]+ "</td>" ;
                // }
                table += "<td>" + value.author_name + "</td>";
                table += "<td>" + value.old_verdict + "</td>" ;
                table += "<td>" + value.verdict + "</td>" ;
                table += "<td>" + moment(value.created_at).format('llll') + "</td>" ;
                table += "</tr>";
            });


        table += "</tbody>";
        table += "</table>";
        return table;

    }
    function buildTableIOCs(iocs) {
        var table = "<table class='table table-bordered'>";
        table += "<thead><tr><th>#</th><th>IOCs</th><th>Value</th></tr></thead>";
        table += "<tbody>";
        var count = 1;
        _.each(iocs, function (ioc) {
            var tr = "<tr>";
            tr += "<td>" + count + "</td>";
            tr += "<td>" + ioc['ioc_type'] + "</td>";
            tr += "<td>" + ioc['value'] + "</td>";
            tr += "</tr>";
            count++;
            table += tr;
        });
        return table;
    }
    function buildTableInfo_Mod_attributes(mod_attributes) {
        var table = "<table class='table table-bordered'>";
        table += "<thead><tr><th>Module Name</th><th>Attributes</th><th>Values</th></tr></thead>";
        table += "<tbody>";
        console.log(mod_attributes);
        _.each(mod_attributes, function (value, mod_name) {
            var length = _.keys(value).length
            var tr = "<tr>";
            tr += "<td  rowspan='" + length + "'>" + mod_name + "</td>";
            _.each(value, function (parameter_value, key) {
                if (tr == null) tr = "<tr>";
                tr += "<td>" + key + "</td>";
                if (key == 'created_at') {
                    tr += "<td>" + moment(parameter_value).format('llll') + "</td>";
                } else {
                    tr += "<td>" + parameter_value + "</td>";
                }
                tr += "</tr>";
                table += tr;
                tr = null;
            });
        });
        return table;
    }
    function buildTable_WeblogsWhoisRelated(mod_attributes,was_related,root_whois_features){
        if(was_related === undefined || was_related === null) was_related = false;
        if(isEmpty(mod_attributes) && !was_related) return null;
        var threshold_default = 75;
        var count = 1;
        var feature_names_ref = {'emails':'diff_emails', 'domain_name':'dist_domain_name', 'name_servers':'diff_name_servers',
                'registrar':'dist_registrar', 'name':'dist_name', 'duration':'dist_duration', 'zipcode':'dist_zipcode',
                'org':'dist_org'};
        var html = '';
        html += "<span id='slider-range-span' class='example-val'></span>";
        html += "<div id='slider-range'></div>";

        html += "<br/>";
        html += '<div class="panel-group" id="accordion" role="tablist" aria-multiselectable="true">';
        if(isEmpty(mod_attributes) && was_related){
            html += "<div> NO WHOIS RELATED DOMAINS in this analysis session </div>";
        }else{
            _.each(mod_attributes, function (features, domain) {


                var table = "<table class='table table-bordered'>";
                table += "<thead><tr><th>Feature Name</th><th>WHOIS info A</th><th>WHOIS info B</th><th>Distance</th></tr></thead>";
                table += "<tbody>";
                var tmp_count = 0;
                var total_dist = 0;
                _.each(features[0], function (whois_info, feature_name) {
                    var local_dist = parseFloat(features[1][feature_names_ref[feature_name]]);
                    var tr = "<tr>";
                    tr += "<td>"+feature_name+"</td>";
                    tr += "<td>"+root_whois_features[feature_name]+"</td>";
                    tr += "<td>"+whois_info+"</td>";
                    tr += "<td>"+local_dist.toString()+"</td>";
                    tr += "</tr>";
                    table+=tr;
                    total_dist += local_dist;
                });
                var tr = "<tr>";
                tr += "<td colspan='3'>Total Distance</td>";
                tr += "<td>"+total_dist.toString()+"</td>";
                tr += "</tr>";
                table+=tr;
                table += "</tbody>";
                table += "</table>";
                var style = total_dist <= threshold_default ? "" : "display:none;";
                html += '<div class="panel panel-default panel-comparison" style="'+style+'" data-totaldist="'+total_dist+'">';
                    html += '<div class="panel-heading" role="tab" id="heading'+count+'">';
                        html += '<h4 class="panel-title" style="display: inline; margin-right: 10px">';
                        html += '<a role="button" data-toggle="collapse" data-parent="#accordion" href="#collapse'+count+'" aria-expanded="true" aria-controls="collapse'+count+'" >';
                        html += domain;
                        html += '</a></h4>';
                        html += "<input type='checkbox' name='search_domain_table[]' value='"+domain+"' checked='True'/>";
                    html += '</div>';
                    html += '<div id="collapse'+count+'"  class="panel-collapse collapse" role="tabpanel" aria-labelledby="heading'+count+'" >';
                        html += '<div class="panel-body">';
                                html += table;
                        html += '</div>';
                    html += '</div>';
                html += '</div>';
                count++;
            });

        }
        html += '</div>';
        html += '<script type="application/javascript">';
        html += "var slider1 = document.getElementById('slider-range');";
        html += "var slider1Value = document.getElementById('slider-range-span');";
        html += "noUiSlider.create(slider1, {start: "+threshold_default+", animate: true, range: { min: 5, max: 200}});";
        html += "slider1.noUiSlider.on('update', function( values, handle ){ " +
                    "var new_threshold = values[handle];" +
                    "slider1Value.innerHTML = new_threshold;" +
                    "$('.panel-comparison').each(function (){" +
                        "var elem = $(this);" +
                        "if(parseFloat(elem.data('totaldist')) <= new_threshold){" +
                            "elem.show();"+
                        "}else{" +
                            "elem.hide();"+
                        "}" +
                    "});" +
                "});";
        html += '</script>';
        return html;



    }
    function getIOCs(weblog_id){
        initModal("IOCs Selected:" + weblog_id);
        var data = {weblog_id:weblog_id};
        $.ajax({
            type:"GET",
            dataType: "json",
            data:data,
            url: "/manati_project/manati_ui/analysis_session/weblog/iocs",
            success : function(json) {// handle a successful response
                var iocs = json['iocs'];
                var table = buildTableIOCs(iocs);
                updateBodyModal(table);
            },
            error : function(xhr,errmsg,err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }

        })

    }
    function getModulesChangesHistory(weblog_id){
        initModal("Modules Changes History of Weblog ID:" + weblog_id);
        var data = {weblog_id: weblog_id};
        $.ajax({
            type:"GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/analysis_session/weblog/modules_changes_attributes",
            success : function(json) {// handle a successful response
                var mod_attributes = JSON.parse(json['data']);
                var table = buildTableInfo_Mod_attributes(mod_attributes);
                updateBodyModal(table);
                // var info_report = JSON.parse(json['info_report']);
                // var query_node = json['query_node'];
                // var table = buildTableInfo_VT(info_report);
                // updateBodyModal(table);
            },
            error : function(xhr,errmsg,err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }

        })

    }
    function getWeblogHistory(weblog_id){
        initModal("Weblog History ID:" + weblog_id);
        var data = {weblog_id: weblog_id};
        $.ajax({
            type:"GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/analysis_session/weblog/history",
            success : function(json) {// handle a successful response
                var weblog_history = JSON.parse(json['data']);
                var table = buildTableInfo_Wbl_History(weblog_history);
                updateBodyModal(table);
            },
            error : function(xhr,errmsg,err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
            }

        })

    }
    function findDomainOfURL(url){
        var matching_domain = null;
        var domain = ( (matching_domain = url.match(REG_EXP_DOMAINS)) != null )|| matching_domain != undefined && matching_domain.length > 0 ? matching_domain[0] : null ;
        domain = (domain == null)  && ((matching_domain = url.match(REG_EXP_IP)) != null) || matching_domain != undefined && matching_domain.length > 0 ? matching_domain[0] : null;
        return domain
    }
    function contextMenuSettings (){
        //events for verdicts buttons on context popup menu
        $.contextMenu({
            selector: '.weblogs-datatable tr',
            events: {
                show: function (options) {
                    // // Add class to the menu
                    if (!this.hasClass('selected')) {
                        this.addClass('selected');
                    }
                    this.addClass('menucontext-open');
                },
                hide: function (options) {
                    this.removeClass('menucontext-open');
                    this.removeClass('selected');
                    _bulk_marks_wbs = {};
                    _bulk_verdict = null;
                }
            },
            build: function ($trigger, e) {
                return {
                    callback: function (key, options) {
                        var verdict = key;
                        labelingRows(verdict);
                        return true;
                    },
                    items: generateContextMenuItems($trigger)

                }
            }


        });
    }
    var labelingRows = function (verdict){
        var rows_affected = thiz.markVerdict(verdict);
        _m.EventMultipleLabelingsByMenuContext(rows_affected,verdict);
    };
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
            labelingRows('malicious');
        });
        // mark legitimate
        Mousetrap.bind(['ctrl+l', 'command+l'], function(e) {
            preventDefault(e);
            labelingRows('legitimate');
        });
        // mark suspicious
        Mousetrap.bind(['ctrl+i', 'command+i'], function(e) {
            preventDefault(e);
            labelingRows('suspicious');
        });
        // mark false positive
        Mousetrap.bind(['ctrl+p', 'command+p'], function(e) {
            preventDefault(e);
            labelingRows('falsepositive');
        });
        // mark undefined
        Mousetrap.bind(['ctrl+u', 'command+u'], function(e) {
            preventDefault(e);
            labelingRows('undefined');
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
            // $('#upload').click(function (){
            //
            // });


            //filter table
            $('body').on('click','.searching-buttons .btn', function () {
                var btn = $(this);
                var verdict = btn.data('verdict');
                if(btn.hasClass('active')){
                    _filterDataTable.removeFilter(_dt,verdict);
                    btn.removeClass('active');
                }
                else{
                    _filterDataTable.applyFilter(_dt, verdict);
                    btn.addClass('active');
                }

            } );
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
        on_ready_fn();
        // window.onbeforeunload = function() {
        //     return "Mate, are you sure you want to leave? Think of the kittens!";
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

    function build_FilePreviewer(headers, data){
        var $html = $('<div class="content"></div>');
        var $ul = $('<ol id="list-column">');
        for (var i = 0; i < headers.length; i++){
            var header_options = ['column_'+i].concat([headers[i]].concat(DEFAULT_COLUMNS_NAMES));
            var select_tag = $('<select>');
            select_tag.attr('id', 'column_'+i);
            for (var x = 0; x < header_options.length; x++) {
                var value = header_options[x];
                select_tag.append($('<option>').html(value.substring(0,30)).attr("value", value));
            }
            $ul.append($('<li>').html(select_tag));

        }
        var $ul_list_key = $('<ol id="list-key">');
        $ul_list_key.append($('<li id="key-http-url">').html("http.url or host"));
        $ul_list_key.append($('<li id="key-endpoints-server">').html("endpoints.server or id.resp_h"));
        $html.html("<h4>ManaTI does not recognize uploaded file,  please, select the columns name of your data</h4>");
        var $wrap = $('<div class="row"></div>');
        $wrap.html($('<div class="col-md-6 list-select"></div>').html($ul));
        $wrap.append($('<div class="col-md-6 list-key"><h5>Mandatories columns </h5></div>').append($ul_list_key));
        $html.append($wrap);
        return $html;
    }

    var showModalCheckingTypeFile = function (filename, header, data){
        var before_hidden_func = function (){
            var  headers = $('#list-column select').map(function (){return this.value;}).toArray();
            thiz.settingsForInitData(headers, data);
        };
        initModal("Pre-visualize: <span>"+filename+"</span>", null, before_hidden_func);
        updateBodyModal(build_FilePreviewer(header, data));

    };

    this.settingsForInitData = function (headers, data){

        $.each([COL_VERDICT_STR, COL_REG_STATUS_STR, COL_DT_ID_STR, COL_UUID_STR],function (i, value){
            headers.push(value);
        });
        initData(data,headers);
        thiz.generateAnalysisSessionUUID();
        hideLoading();
        _m.EventFileUploadingFinished(_filename, rowCount);

    };

    thiz.parseData = function(file_rows, with_header, type_file, delimiter){
        with_header = set_default(with_header, true);
        type_file = set_default(type_file, '');
        delimiter = set_default(delimiter, "");
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
                    try{
                        if (thiz.getAnalysisSessionTypeFile() === 'apache_http_log'){
                            showModalCheckingTypeFile(getFileName(), data[0],data);
                        }
                        else{
                            var headers = Object.keys(data[0]);
                            thiz.settingsForInitData(headers, data);
                        }
                    }catch (e){
                        console.error(e);

                    }


                }

            }
        };
        thiz.setAnalysisSessionTypeFile(type_file);

        Papa.parse(file_rows,
            {
                delimiter: delimiter,
                header: with_header,
                quoteChar: '"',
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
                if (attributes.uuid === undefined || attributes.uuid === null){
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
               _sync_db_interval= setInterval(syncDB, TIME_SYNC_DB );

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
        $.ajax({
                type:"GET",
                data: data,
                dataType: "json",
                url: "/manati_project/manati_ui/analysis_session/get_weblogs",
                success : function(json) {// handle a successful response
                    var weblogs = json['weblogs'];
                    var analysis_session_id = json['analysissessionid'];
                    var analysis_session_uuid = json['analysissessionuuid'];
                    var file_name = json['name'];
                    var headers = JSON.parse(json['headers']);
                    setFileName(file_name);
                    if (analysis_session_uuid !== null && analysis_session_uuid !== '' ){
                        thiz.setAnalysisSessionUUID(analysis_session_uuid);
                    }

                    initDataEdit(weblogs, analysis_session_id,headers);
                    _m.EventLoadingEditingFinished(analysis_session_id, weblogs.length)
                },

                error : function(xhr,errmsg,err) { // handle a non-successful response
                    $.notify(xhr.status + ": " + xhr.responseText, "error");
                    console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
                    _m.EventLoadingEditingError(analysis_session_id);

                }
            });

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
