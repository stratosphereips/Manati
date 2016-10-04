/**
 * Created by raulbeniteznetto on 8/10/16.
 */
//Concurrent variables for loading data in datatable
var _dt;
var _countID =1;
var thiz;
var _db;
var _filename, _size_file,_type_file;
var _data_uploaded,_data_headers;
var _data_headers_keys = {};

//Concurrent variables for saving on PG DB
var _analysis_session_id = -1;
var COLUMN_DT_ID,COLUMN_REG_STATUS,COLUMN_VERDICT;
var COLUMN_END_POINTS_SERVER, COLUMN_HTTP_URL;
var COL_HTTP_URL_STR, COL_END_POINTS_SERVER_STR;
var CLASS_MC_HTTP_URL_STR, CLASS_MC_END_POINTS_SERVER_STR;
var REG_STATUS = {modified: 1};
var COL_VERDICT_STR = 'verdict';
var COL_REG_STATUS_STR = 'register_status';
var COL_DT_ID_STR = 'dt_id';
var REG_EXP_DOMAINS = /[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+/;
var REG_EXP_IP = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/;
var _verdicts = ["malicious","legitimate","suspicious","false_positive", "undefined"];
var _flows_grouped;
var _helper;
var _filterDataTable;

var _m;


var _loadingPlugin;

function AnalysisSessionLogic(){
    /************************************************************
                            GLOBAL ATTRIBUTES
     *************************************************************/


    var stepped = 0;
    var rowCount, firstError, errorCount = 0;
    var db_name = 'weblogs_db';
    this.columns_order_changed = false;
    thiz = this;
    _m = new Metrics(false);

    this.getColumnsOrderFlat =function(){
        return this.columns_order_changed;
    };
    this.setColumnsOrderFlat =function (v) {
        this.columns_order_changed = v;
    };
     /************************************************************
                            PRIVATE FUNCTIONS
     *************************************************************/

    function initDatatable(headers, data){
        var columns = [];
        for(var i = 0; i< headers.length ; i++){
            var v = headers[i];
            columns.add({title: v, name: v, class: v});
        }
        //verifying if already exist a table, in that case, destroy it
        if(_dt != null || _dt != undefined) {
            _dt.clear().draw();
            _dt.destroy();
            _dt = null;
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
                // {   "targets": headers.indexOf(COL_HTTP_URL_STR),
                //     "createdCell": function (td, cellData, rowData, row, col) {
                //
                //         $(td).html("<a href='#' data-info='domain' class='virus-total-consult' title='Make a Virus Total consult, with this domain'>"+rowData[col]+"</a>");
                //
                //     }
                // },
                // {   "targets": headers.indexOf(COL_END_POINTS_SERVER_STR),
                //     "createdCell": function (td, cellData, rowData, row, col) {
                //         $(td).html("<a href='#' data-info='ip-server' class='virus-total-consult' title='Make a Virus Total consult, with this IP'>"+rowData[col]+"</a>");
                //
                //     }
                // }
            ],
            "scrollX": true,
            "aLengthMenu": [[25, 50, 100, 500, -1], [25, 50, 100, 500, "All"]],
            colReorder: true,
            renderer: "bootstrap",
            responsive: true,
            buttons: ['copy', 'csv', 'excel','colvis',
                {
                    text: 'Filter by Verdicts',
                    className: 'filter-verdicts',
                    action: function ( e, dt, node, config ) {
                        _filterDataTable.showMenuContext(dt,node.offset());
                    }
                }
            ],
            "fnRowCallback": function( nRow, aData, iDisplayIndex, iDisplayIndexFull ) {
                //when you change the verdict, the color is updated
                $(nRow).addClass(aData[COLUMN_VERDICT]);
                var str = aData[COLUMN_DT_ID].split(":");
                if(str.length > 1){
                    $(nRow).attr("data-dbid", str[1]);
                }else{
                    $(nRow).attr("data-dbid", str[0]);
                }
            }
        });
        _dt.buttons().container().appendTo( '#weblogs-datatable_wrapper .col-sm-6:eq(0)' );
        $('#weblogs-datatable tbody').on( 'click', 'tr', function () {
            $(this).toggleClass('selected');
            $('.contextMenuPlugin').remove();
        } );
        hideLoading();
        $('#panel-datatable').show();
         _dt.on( 'column-reorder', function ( e, settings, details ) {
            thiz.setColumnsOrderFlat(true);
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
                                    values.add('undefined');
                                    values.add(-1);
                                    values.add(_countID.toString());
                                    _data_uploaded[i][COL_VERDICT_STR] = "undefined";
                                    _data_uploaded[i][COL_REG_STATUS_STR] = (-1).toString();
                                    _data_uploaded[i][COL_DT_ID_STR] =_countID.toString();
                                 }
                                _countID++;
                                return values
                            });
        processingFlows_WORKER(_data_uploaded);
        $.each(_data_headers,function(i, v){
            _data_headers_keys[v] = i;
        });
        console.log(data.length);
        COLUMN_DT_ID = _data_headers_keys[COL_DT_ID_STR];
        COLUMN_REG_STATUS = _data_headers_keys[COL_REG_STATUS_STR];
        COLUMN_VERDICT =  _data_headers_keys[COL_VERDICT_STR];
        COL_HTTP_URL_STR = "http.url";
        COL_END_POINTS_SERVER_STR = "endpoints.server";
        COLUMN_HTTP_URL = _data_headers_keys[COL_HTTP_URL_STR];
        COLUMN_END_POINTS_SERVER = _data_headers_keys[COL_END_POINTS_SERVER_STR];
        CLASS_MC_END_POINTS_SERVER_STR =  COL_END_POINTS_SERVER_STR.replace(".", "_");
        CLASS_MC_HTTP_URL_STR = COL_HTTP_URL_STR.replace(".","_");
        _filterDataTable = new FilterDataTable(COLUMN_VERDICT,_verdicts);
        initDatatable(_data_headers, data_processed);
        $('#save-table').show();

    }
    function completeFn(results,file){
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
                $.each([COL_VERDICT_STR, COL_REG_STATUS_STR, COL_DT_ID_STR],function (i, value){
                    headers.push(value);
                });
                initData(data,headers);
                _m.EventFileUploadingFinished(_filename, rowCount);
            }

        }
    }


    this.markVerdict= function (verdict, class_selector) {
        if(class_selector === null || class_selector === undefined) class_selector = "selected";
        // console.log(verdict);
        var rows_affected = [];
        _dt.rows('.'+class_selector).every( function () {
            var d = this.data();
            rows_affected.add(d);
            var old_verdict = d[COLUMN_VERDICT];
            d[COLUMN_VERDICT]= verdict; // update data source for the row
            d[COLUMN_REG_STATUS] = REG_STATUS.modified;
            this.invalidate(); // invalidate the data DataTables has cached for this row

        } );
        // Draw once all updates are done
        _dt.draw(false);
        _dt.rows('.'+class_selector).nodes().to$().removeClass(_verdicts.join(" ")).addClass(verdict);
        _dt.rows('.'+class_selector).nodes().to$().addClass('modified');
        _dt.rows('.'+class_selector).nodes().to$().removeClass(class_selector);
        return rows_affected;

    };
    var syncDB = function (){
        var arr_list = _dt.rows('.modified').data();
        var data_row = {};
        arr_list.each(function(elem){
            if(elem[COLUMN_REG_STATUS] != -1){
                var key_id = elem[COLUMN_DT_ID].split(':').length <= 1 ? _analysis_session_id+":"+elem[COLUMN_DT_ID] : elem[COLUMN_DT_ID] ;
                data_row[key_id]=elem[COLUMN_VERDICT];
            }
        });
        var data = {'analysis_session_id': _analysis_session_id,
                        'data': data_row };
        if(thiz.getColumnsOrderFlat()){
            data['headers[]']=JSON.stringify(get_headers_info());
            thiz.setColumnsOrderFlat(false);
        }
        $.ajax({
            type:"POST",
            data: JSON.stringify(data),
            dataType: "json",
            url: "/manati_ui/analysis_session/sync_db",
            // handle a successful response
            success : function(json) {
                // $('#post-text').val(''); // remove the value from the input
                // console.log(json); // log the returned json to the console
                var data = JSON.parse(json['data']);
                console.log(data);
                $.each(data,function (index, elem) {
                    console.log(elem);
                    var dt_id = parseInt(elem.pk.split(':')[1]);
                    var row = _dt.rows('[data-dbid="'+dt_id+'"]');
                    var index_row = row.indexes()[0];
                     row.nodes().to$().addClass('selected-sync');
                    thiz.setColumnsOrderFlat(false);
                     thiz.markVerdict(elem.fields.verdict,'selected-sync');
                    row.nodes().to$().removeClass('modified');
                    _dt.cell(index_row, COLUMN_VERDICT).data(elem.fields.verdict);
                    _dt.cell(index_row, COLUMN_REG_STATUS).data(elem.fields.register_status);



                });
                console.log("DB Synchronized");
            },

            // handle a non-successful response
            error : function(xhr,errmsg,err) {
                $('#results').html("<div class='alert-box alert radius' data-alert>Oops! We have encountered an error: "+errmsg+
                    " <a href='#' class='close'>&times;</a></div>"); // add the error to the dom
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
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
                'data[]': JSON.stringify(rows.data().toArray())
            };
            //send the name of the file, and the first 10 registers
            $.ajax({
                type:"POST",
                data: data,
                dataType: "json",
                url: "/manati_ui/analysis_session/create",
                // handle a successful response
                success : function(json) {
                    // $('#post-text').val(''); // remove the value from the input
                    console.log(json); // log the returned json to the console
                    console.log("success"); // another sanity check
                    _analysis_session_id = json['data']['analysis_session_id'];
                    _dt.column(COLUMN_REG_STATUS, {search:'applied'}).nodes().each( function (cell, i) {
                        var tr = $(cell).closest('tr');
                        if(!tr.hasClass("modified")) cell.innerHTML = 0;
                    } );
                    _m.EventAnalysisSessionSavingFinished(_filename,_analysis_session_id);
                    $.notify("All Weblogs ("+json['data_length']+ ") were created successfully ", 'success');
                    $('#save-table').hide();
                    $('#wrap-form-upload-file').hide();
                    history.pushState({},
                        "Edit AnalysisSession "  + _analysis_session_id,
                        "/manati_ui/analysis_session/"+_analysis_session_id+"/edit");
                    setInterval(syncDB, 10000 );
                    hideLoading();
                    columns_order_changed = false;
                },

                // handle a non-successful response
                error : function(xhr,errmsg,err) {
                    $('#results').html("<div class='alert-box alert radius' data-alert>Oops! We have encountered an error: "+errmsg+
                        " <a href='#' class='close'>&times;</a></div>"); // add the error to the dom
                    console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
                    $('#save-table').attr('disabled',false).removeClass('disabled');
                    $.notify(xhr.status + ": " + xhr.responseText, "error");
                    //NOTIFY A ERROR
                    _m.EventAnalysisSessionSavingError(_analysis_session_id);
                    hideLoading();
                }
            });
        }catch(e){
            // thiz.destroyLoading();
            $.notify(e, "error");
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

    var _bulk_marks_wbs = {};
    var _bulk_verdict;

    var generateContextMenuItems = function(tr_dom){
        // var tr_active = $("tr.menucontext-open.context-menu-active");
        var bigData = _dt.rows(tr_dom).data()[0];
        var ip_value = bigData[COLUMN_END_POINTS_SERVER]; // gettin end points server ip
        var url = bigData[COLUMN_HTTP_URL];
        var domain = findDomainOfURL(url); // getting domain
        var items_menu = {};
        _bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR] = _helper.getFlowsGroupedBy(COL_END_POINTS_SERVER_STR,ip_value);
        _bulk_marks_wbs[CLASS_MC_HTTP_URL_STR] = _helper.getFlowsGroupedBy(COL_HTTP_URL_STR,domain);
        _bulk_verdict = bigData[COLUMN_VERDICT];
        _verdicts.forEach(function(v){
            items_menu[v] = {name: v, icon: "fa-paint-brush " + v }
        });
        items_menu['sep1'] = "-----------";
        items_menu['fold1'] = {
            name: "Mark all WBs with same: ",
            icon: "fa-search-plus",
            // disabled: function(){ return !this.data('moreDisabled'); },
            items: {
            "fold1-key1": { name: "EndPoints Server ("+_bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR].length+"...)",
                            icon: "fa-paint-brush",
                            className: CLASS_MC_END_POINTS_SERVER_STR,
                            callback: function(key, options) {
                                var rows_affected = setBulkVerdict_WORKER(_bulk_verdict, _bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR]);
                                _m.EventBulkLabelingByEndServerIP(rows_affected,_bulk_verdict);

                            }
                        },
            "fold1-key2": { name: "Domain("+_bulk_marks_wbs[CLASS_MC_HTTP_URL_STR].length+"...)",
                            icon: "fa-paint-brush",
                            className: CLASS_MC_HTTP_URL_STR,
                            callback: function(key, options) {
                                var rows_affected = setBulkVerdict_WORKER(_bulk_verdict, _bulk_marks_wbs[CLASS_MC_HTTP_URL_STR]);
                                _m.EventBulkLabelingByDomains(rows_affected,_bulk_verdict);
                            }
                    }
        }};
        items_menu['sep2'] = "-----------";
        items_menu['fold3'] = {
            name: "Consult to VirusTotal", icon: "fa-search",
            items: {
                "fold2-key1": {
                    name: "using HTTP URL",
                    icon: "fa-paper-plane-o",
                    callback: function (key, options) {
                        consultVirusTotal(findDomainOfURL(bigData[COLUMN_HTTP_URL]));
                    }
                },
                "fold2-key2": {
                    name: "using Endpoints Server IP",
                    icon: "fa-paper-plane-o",
                    callback: function (key, options) {
                        consultVirusTotal(bigData[COLUMN_END_POINTS_SERVER]);
                    }
                }
            }
        };
        items_menu['weblog-history'] = {name: "Consult History of Weblogs", icon: "fa-search",
            callback: function (key, options) {
                var weblog_id = bigData[COLUMN_DT_ID].toString();
                weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
                getWeblogHistory(weblog_id);
            }
        };
        items_menu['sep3'] = "-----------";
        items_menu['fold2'] = {
            name: "Copy to clipboard", icon: "fa-files-o",
            items: {
                "fold2-key1": {
                    name: "HTTP URL",
                    icon: "fa-file-o",
                    callback: function (key, options) {
                        copyTextToClipboard(bigData[COLUMN_HTTP_URL]);
                    }
                },
                "fold2-key2": {
                    name: "Endpoints Server IP",
                    icon: "fa-file-o",
                    callback: function (key, options) {
                        copyTextToClipboard(bigData[COLUMN_END_POINTS_SERVER]);
                    }
                }
            }
        };



        return items_menu;

    };
    function buildTableInfo_VT(info_report){
        var table = "<table class='table table-bordered table-striped'>";
        table += "<thead><tr><th style='width: 110px;'>List Attributes</th><th> Values</th></tr></thead>";
        table += "<tbody>";
            for(var key in info_report){
                table += "<tr>";
                table += "<th>"+key+"</th>";
                table += "<td>" + info_report[key]+ "</td>" ;
                table += "</tr>";
            }

        table += "</tbody>";
        table += "</table>";
        return table;

    }
    function initModal(title){
        $('#vt_consult_screen #vt_modal_title').html(title);
        $('#vt_consult_screen').modal('show');
        $('#vt_consult_screen').on('hidden.bs.modal', function (e) {
            $(this).find(".table-section").html('').hide();
            $(this).find(".loading").show();
            $(this).find("#vt_modal_title").html('');
        });
    }
    function updateBodyModal(table){
        var modal_body = $('#vt_consult_screen .modal-body');
        modal_body.find('.table-section').html(table).show();
        modal_body.find(".loading").hide();
    }
    function consultVirusTotal(query_node){
        initModal("Virus Total Query: <span>"+query_node+"</span>");
        var data = {query_node: query_node};
        $.ajax({
            type:"GET",
            data: data,
            dataType: "json",
            url: "/manati_ui/consult_virus_total",
            success : function(json) {// handle a successful response
                var info_report = JSON.parse(json['info_report']);
                var query_node = json['query_node'];
                var table = buildTableInfo_VT(info_report);
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
        table += "<thead><tr><th>User</th><th>Previous Verdict</th><th>Verdict</th><th>When?</th></tr></thead>";
        table += "<tbody>";
            _.each(weblog_history, function (value, index) {
                table += "<tr>";
                // for(var key in value){
                //     table += "<td>" + value[key]+ "</td>" ;
                // }
                table += "<td>" +  "</td>";
                table += "<td>" + value.fields.old_verdict + "</td>" ;
                table += "<td>" + value.fields.verdict + "</td>" ;
                table += "<td>" + value.fields.created_at + "</td>" ;
                table += "</tr>";
            });


        table += "</tbody>";
        table += "</table>";
        return table;

    }
    function getWeblogHistory(weblog_id){
        initModal("Weblog History ID:" + weblog_id);
        var data = {weblog_id: weblog_id};
        $.ajax({
            type:"GET",
            data: data,
            dataType: "json",
            url: "/manati_ui/analysis_session/weblog/history",
            success : function(json) {// handle a successful response
                var weblog_history = JSON.parse(json['data']);
                var table = buildTableInfo_Wbl_History(weblog_history);
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
                   show : function(options){
                        // // Add class to the menu
                        if(!this.hasClass('selected')){
                            this.addClass('selected');
                        }
                        this.addClass('menucontext-open');
                   },
                   hide : function(options) {
                       this.removeClass('menucontext-open');
                       this.removeClass('selected');
                       _bulk_marks_wbs = {};
                       _bulk_verdict = null;
                   }
                },
                build: function ($trigger, e){
                    return {
                        callback: function(key, options) {
                            var verdict = key;
                            var rows_affected = thiz.markVerdict(verdict);
                            _m.EventMultipleLabelingsByMenuContext(rows_affected,verdict);
                            return true;
                        },
                        items: generateContextMenuItems($trigger)

                    }
                }


            });
    }
    var setFileName = function(file_name){
        $("#weblogfile-name").html(file_name);
        _filename = file_name;
    };
    function on_ready_fn (){
        $(document).ready(function() {
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
            $('#save-table').hide();
            $('#upload').click(function (){
                 $('input[type=file]').parse({
                    config: {
                        delimiter: "",
                        header: true,
                        complete: completeFn,
                        // step: stepFn,
                        worker: true,
                        skipEmptyLines: true
                        // base config to use for each file
                    },
                    before: function(file, inputElem)
                    {
                        _size_file = file.size;
                        _type_file = file.type;
                        _m.EventFileUploadingStart(_filename,_size_file,_type_file);
                        console.log("Parsing file...", file);
                        $.notify("Parsing file...", "info");
                        setFileName(file.name);

                    },
                    error: function(err, file, inputElem, reason)
                    {
                        console.log("ERROR Parsing:", err, file);
                        $.notify("ERROR Parsing:" + " " + err + " "+ file);
                        _m.EventFileUploadingError(file.name);
                    }
                });
            });
            $(':file').on('fileselect', function(event, numFiles, label) {

                  var input = $(this).parents('.input-group').find(':text'),
                      log = numFiles > 1 ? numFiles + ' files selected' : label;

                  if( input.length ) {
                      input.val(log);
                  } else {
                      if( log ) alert(log);
                  }

              });
            $(document).on('change', ':file', function() {
                var input = $(this),
                    numFiles = input.get(0).files ? input.get(0).files.length : 1,
                    label = input.val().replace(/\\/g, '/').replace(/.*\//, '');
                input.trigger('fileselect', [numFiles, label]);
            });

            //events for verdict buttons
            $('.btn.verdict').click( function () {
                var verdict = $(this).data('verdict');
                var rows_affected = thiz.markVerdict(verdict);
                _m.EventMultipleLabelingsByButtons(rows_affected,verdict);
            } );
            $('.unselect').on('click', function (ev){
                ev.preventDefault();
                _dt.rows('.selected').nodes().to$().removeClass('selected');
            });

            contextMenuSettings();
            $('#save-table').on('click',function(){
               saveDB();
            });
        });
    };


    /************************************************************
                            PUBLIC FUNCTIONS
     *************************************************************/
    //INITIAL function , like a contructor
    thiz.init = function(){
        on_ready_fn();
        // window.onbeforeunload = function() {
        //     return "Dude, are you sure you want to leave? Think of the kittens!";
        // }

    };
    var initDataEdit = function (weblogs, analysis_session_id,headers_info) {
        _analysis_session_id = analysis_session_id;
        if(weblogs.length > 1){
            // sorting header
            var headers;
            if(_.isEmpty(headers_info)){
                headers_info = _.keys(data[0]);
                thiz.setColumnsOrderFlat(true);
                headers = headers_info;
            }else{
                headers_info.sort(function(a,b) {
                    return a.order - b.order;
                });
                headers = $.map(headers_info,function(v,i){
                    return v.column_name
                });
            }
            //getting data
            var data = [];
            $.each(weblogs, function (index, elem){
                var id = elem.pk;
                var attributes = JSON.parse(elem.fields.attributes);
                if(!(attributes instanceof Object)) attributes = JSON.parse(attributes);
                attributes[COL_VERDICT_STR] = elem.fields.verdict.toString();
                attributes[COL_REG_STATUS_STR] = elem.fields.register_status.toString();
                attributes[COL_DT_ID_STR] = id.toString();
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
                setInterval(syncDB, 10000 );

            });
        }else{
            hideLoading();
            $.notify("The current AnalysisSession does not have weblogs saved", "info", {autoHideDelay: 5000 });
        }


    };
    this.callingEditingData = function (analysis_session_id){
        var data = {'analysis_session_id':analysis_session_id};
        $.notify("The page is being loaded, maybe it will take time", "info", {autoHideDelay: 3000 });
        showLoading();
        _m.EventLoadingEditingStart(analysis_session_id);
        $.ajax({
                type:"GET",
                data: data,
                dataType: "json",
                url: "/manati_ui/analysis_session/get_weblogs",
                success : function(json) {// handle a successful response
                    var weblogs = JSON.parse(json['weblogs']);
                    var analysis_session_id = json['analysissessionid'];
                    var file_name = json['name'];
                    var headers = JSON.parse(json['headers']);
                    setFileName(file_name);

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
            "self.importScripts(origin+'/static/manati_ui/js/libs/underscore-min.js');"+
            "var flows_labelled = _.map(e.data[0],function(v,i){ return v.dt_id});"+
            "for(var i = 0; i< rows_data.length; i++) {"+
                "var row_dt_id = rows_data[i][col_dt_id]; "+
                "var index = flows_labelled.indexOf(row_dt_id); "+
                "if(index >=0){"+
                   "rows_data[i][col_verdict] = verdict ;"+
                "}"+
             "};" +
             "self.postMessage(rows_data)"+
        "}"]);
        var blobURL = window.URL.createObjectURL(blob);
        var worker = new Worker(blobURL);
        worker.addEventListener('message', function(e) {
            var rows_data = e.data;
            _dt.clear().rows.add(rows_data).draw();
            hideLoading();
	    });
        var rows_data = _dt.rows().data().toArray();
        worker.postMessage([flows_labelled,verdict,rows_data, COLUMN_DT_ID, COLUMN_VERDICT,document.location.origin]);
    };

    var processingFlows_WORKER = function (flows) {
        _flows_grouped = {};
        var blob = new Blob([ "onmessage = function(e) { " +
            "var flows = e.data[1];"+
            "var flows_grouped = e.data[0];"+
            "var origin = e.data[2];"+
            "self.importScripts(origin+'/static/manati_ui/js/libs/underscore-min.js');"+
            "self.importScripts(origin+'/static/manati_ui/js/struct_helper.js');"+
            "var helper = new FlowsProcessed(flows_grouped);"+
            "for(var i = 0; i< flows.length; i++) helper.addFlows(flows[i]);"+
            "self.postMessage(helper.getFlowsGrouped());" +
        "}"]);

        // Obtain a blob URL reference to our worker 'file'.
        var blobURL = window.URL.createObjectURL(blob);

        var worker = new Worker(blobURL);
        worker.addEventListener('message', function(e) {
            _flows_grouped = e.data;
            _helper = new FlowsProcessed(_flows_grouped);
            _helper.makeStaticalSection();
            worker.terminate();
            console.log("Worker Done");
	    });
        worker.postMessage([_flows_grouped,flows,document.location.origin]);

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
