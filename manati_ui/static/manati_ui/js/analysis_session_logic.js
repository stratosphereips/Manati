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
var _flows_grouped = {};
var _helper;

var _m;


var _loadingPlugin;

function AnalysisSessionLogic(){
    /************************************************************
                            GLOBAL ATTRIBUTES
     *************************************************************/


    var stepped = 0;
    var rowCount, firstError, errorCount = 0;
    var db_name = 'weblogs_db';
    thiz = this;
    _m = new Metrics(false);


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
            "search": {
                "regex": true
            },
            columnDefs: [
                {"searchable": false, visible: false, "targets": headers.indexOf(COL_REG_STATUS_STR)},
                {"searchable": false, visible: false, "targets": headers.indexOf(COL_DT_ID_STR)}
            ],
            "scrollX": true,
            "aLengthMenu": [[25, 50, 100, 500, -1], [25, 50, 100, 500, "All"]],
        //     "sDom": "Rlfrtip",
            colReorder: true,
            renderer: "bootstrap",
            responsive: true,
            buttons: ['copy', 'csv', 'excel','colvis'],
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

    }
    function initData(data, headers) {
        _data_uploaded = data;
        _data_headers = headers;
        _data_headers_keys = {};
        _countID = 1;
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
            if(elem[COLUMN_REG_STATUS] != -1 ){
                data_row[_analysis_session_id+":"+elem[COLUMN_DT_ID]]=elem[COLUMN_VERDICT];
            }
        });
        var data = {'analysis_session_id': _analysis_session_id,
                        'data': data_row };
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

    function saveDB(){
        try{

            showLoading();
            $.notify("Starting process to save the Analysis Session, it takes time", "info", {autoHideDelay: 6000 });
            $('#save-table').attr('disabled',true).addClass('disabled');
            var rows = _dt.rows();
            _m.EventAnalysisSessionSavingStart(rows.length, _filename);
            var data = { filename: _filename,"keys[]": JSON.stringify(_data_headers),'data[]': JSON.stringify( rows.data().toArray())};
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
            className: "calculate",
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
        return items_menu;

    };
    function findDomainOfURL(url){
        var matching_domain = null;
        var domain = ( (matching_domain = url.match(REG_EXP_DOMAINS)) != null )|| matching_domain != undefined && matching_domain.length > 0 ? matching_domain[0] : null ;
        domain = (domain == null)  && ((matching_domain = url.match(REG_EXP_IP)) != null) || matching_domain != undefined && matching_domain.length > 0 ? matching_domain[0] : null;
        return domain
    }
    function contextMenuSettings (){
       //  $("body").on("mouseenter mouseleave", "ul.context-menu-list.context-menu-root li.context-menu-submenu.calculate", function (){
       //      var thiss = $(this);
       //      var tr_active = $("tr.menucontext-open.context-menu-active");
       //      var bigData = _dt.rows(tr_active).data()[0];
       //      _bulk_verdict = bigData[COLUMN_VERDICT];
       //      _bulk_marks_wbs[CLASS_MC_HTTP_URL_STR] = [];
       //      _bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR] = [];
       //      var ip_value = bigData[COLUMN_END_POINTS_SERVER]; // gettin end points server ip
       //      var url = bigData[COLUMN_HTTP_URL];
       //      var domain = findDomainOfURL(url); // getting domain
       //      _dt.rows().nodes().each(function (dom_row,i) {
       //          var data = _dt.row(dom_row).data();
       //          var local_url = data[COLUMN_HTTP_URL];
       //          var local_domain = findDomainOfURL(local_url);
       //          var local_ip_value = data[COLUMN_END_POINTS_SERVER];
       //          if(local_domain != null && local_domain === domain){
       //              _bulk_marks_wbs[CLASS_MC_HTTP_URL_STR].add(dom_row);
       //          }
       //          if(local_ip_value === ip_value){
       //              _bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR].add(dom_row);
       //          }
       //      });
       //      thiss.find("li."+CLASS_MC_END_POINTS_SERVER_STR).html("EndPoints Server ("+ _bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR].length+ ")");
       //      thiss.find("li."+CLASS_MC_HTTP_URL_STR).html("Domain ("+ _bulk_marks_wbs[CLASS_MC_HTTP_URL_STR].length+ ")");
       //      thiss.removeClass("calculate");
       // });
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
    function on_ready_fn (){
        $(document).ready(function() {
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
                        _filename = file.name;
                        _size_file = file.size;
                        _type_file = file.type;
                        _m.EventFileUploadingStart(_filename,_size_file,_type_file);

                        console.log("Parsing file...", file);
                        $.notify("Parsing file...", "info");
                        $("#weblogfile-name").html(file.name);

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
    var initDataEdit = function (weblogs, analysis_session_id) {
        _analysis_session_id = analysis_session_id;
        var headers = null;
        var data = [];
        $.each(weblogs, function (index, elem){
            var id = elem.pk;
            var attributes = JSON.parse(elem.fields.attributes);
            attributes[COL_VERDICT_STR] = elem.fields.verdict;
            attributes[COL_REG_STATUS_STR] = elem.fields.register_status;
            attributes[COL_DT_ID_STR] = id;

            if(headers == null){
                headers = _.keys(attributes);
            }
            data.push(attributes);
        });
        initData(data, headers );
        $(document).ready(function(){
            $('#panel-datatable').show();
            setInterval(syncDB, 10000 );

        })


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
                    initDataEdit(weblogs, analysis_session_id);
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
            "var flows_labelled = e.data[0];"+
            "var verdict = e.data[1];"+
            "var rows_data = e.data[2];"+
            "var col_dt_id = e.data[3];"+
            "var col_verdict = e.data[4];"+
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
        worker.postMessage([flows_labelled,verdict,rows_data, COLUMN_DT_ID, COLUMN_VERDICT]);
    };

    var processingFlows_WORKER = function (flows) {
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
        // var worker = new Worker('http://127.0.0.1:8000/static/manati_ui/js/libs/worker_processing_weblogs.js');
        worker.addEventListener('message', function(e) {
            _flows_grouped = e.data;
            _helper = new FlowsProcessed(_flows_grouped);
            worker.terminate();
            console.log("Worker Done");
	    });
        worker.postMessage([_flows_grouped,flows,document.location.origin]);

    };





}
