/**
 * Created by raulbeniteznetto on 8/10/16.
 */
//Concurrent variables for loading data in datatable
var _dt;
var _countID =1;
// var _attributes_db;
var thiz;
var _db;
var _filename, _size_file;
var _data_uploaded,_data_headers;
var _data_headers_keys = {};

//Concurrent variables for saving on PG DB
var SIZE_REQUEST = 1000;
var _data_wb = [];
var _data_rows_wb;
var _init_count = 0;
var _finish_count = SIZE_REQUEST;
var _total_data_wb;
var _analysis_session_id = -1;
var COLUMN_DT_ID, COLUMN_DB_ID,COLUMN_REG_STATUS,COLUMN_VERDICT;
var COLUMN_END_POINTS_SERVER, COLUMN_HTTP_URL;
var COL_HTTP_URL_STR, COL_END_POINTS_SERVER_STR;
var CLASS_MC_HTTP_URL_STR, CLASS_MC_END_POINTS_SERVER_STR;
var REG_STATUS = {modified: 1};
var COL_VERDICT_STR = 'verdict';
var COL_REG_STATUS_STR = 'register_status';
var COL_DT_ID_STR = 'dt_id';
var COL_DB_ID_STR = 'db_id';
var REG_EXP_DOMAINS = /[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+/;
var REG_EXP_IP = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/;
var _verdicts = ["malicious","legitimate","suspicious","false_positive", "undefined"];
var _data_updated = [];


var _loadingPlugin;

function AnalysisSessionLogic(){
    /************************************************************
                            GLOBAL ATTRIBUTES
     *************************************************************/


    var stepped = 0;
    var rowCount, firstError, errorCount = 0;
    var _keys = [];
    var db_name = 'weblogs_db';
    thiz = this;
    var _verdicts_weight = {
        "malicious":2,
        "legitimate":0,
        "suspicious":1,
        "false_positive":3,
        "undefined": -1
    };

    // var myDjangoList = ((attributes_db).replace(/&(l|g|quo)t;/g, function(a,b){
    //     return {
    //         l   : '<',
    //         g   : '>',
    //         quo : '"'
    //     }[b];
    // }));
    //
    // myDjangoList = myDjangoList.replace(/u'/g, '\'');
    // myDjangoList = myDjangoList.replace(/'/g, '\"');
    // _attributes_db = JSON.parse( myDjangoList );


     /************************************************************
                            PRIVATE FUNCTIONS
     *************************************************************/

     //useless function
    //  function addRowThread(data){
    //     var data = data;
    //      //only it should affect new WBs added
    //      if(data.length != _data_headers.length){
    //          data.add('undefined');
    //          data.add(-1);
    //          data.add(_countID.toString());
    //          data.add("DID NOT SAVE");
    //      }
    //
    //     if(data.length !== _data_headers.length) {
    //         console.log("ERROR Adding");
    //         console.log(data);
    //     }
    //     else{
    //         var row = _dt.row.add(data);
    //         var index = row[0];
    //         _dt.cell(index, COLUMN_DT_ID).data(index).draw(false);
    //         _dt.row(index).nodes().to$().attr('data-dbid',data[COLUMN_DB_ID]);
    //     }
    //     _countID++;
    //
    // }

    function initDatatable(headers, data_init){
        _countID = 1;
        var data = _.map(data_init,function(v, i){
            var values = _.values(v);
            if(values.length < headers.length){
                values.add('undefined');
                values.add(-1);
                values.add(_countID.toString());
            }
            _countID++;
            return values
        });
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
            columnDefs: [
                // {"searchable": false, visible: false, "targets": headers.indexOf(COL_DB_ID_STR)},
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
                $(nRow).attr("data-dbid", aData[COLUMN_DT_ID]);

            },
        });
        _dt.buttons().container().appendTo( '#weblogs-datatable_wrapper .col-sm-6:eq(0)' );
        $('#weblogs-datatable tbody').on( 'click', 'tr', function () {
            $(this).toggleClass('selected');
            $('.contextMenuPlugin').remove();
        } );
        $("#loading-img").hide();
        $('#panel-datatable').show();

    }
    function initData(data, headers) {
        _data_uploaded = data;
        _data_headers = headers;
        _data_headers_keys = {};
        $.each(_data_headers,function(i, v){
            _data_headers_keys[v] = i;
        });
        console.log(data.length);
        COLUMN_DT_ID = _data_headers_keys[COL_DT_ID_STR];
        // COLUMN_DB_ID = _data_headers_keys[COL_DB_ID_STR];
        COLUMN_REG_STATUS = _data_headers_keys[COL_REG_STATUS_STR];
        COLUMN_VERDICT =  _data_headers_keys[COL_VERDICT_STR];
        COL_HTTP_URL_STR = "http.url";
        COL_END_POINTS_SERVER_STR = "endpoints.server";
        COLUMN_HTTP_URL = _data_headers_keys[COL_HTTP_URL_STR];
        COLUMN_END_POINTS_SERVER = _data_headers_keys[COL_END_POINTS_SERVER_STR];
        CLASS_MC_END_POINTS_SERVER_STR =  COL_END_POINTS_SERVER_STR.replace(".", "_");
        CLASS_MC_HTTP_URL_STR = COL_HTTP_URL_STR.replace(".","_");

        initDatatable(_data_headers, _data_uploaded);
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
            }

        }
    }


    this.markVerdict= function (verdict, class_selector) {
        if(class_selector === null || class_selector === undefined) class_selector = "selected";
        console.log(verdict);
        _dt.rows('.'+class_selector).every( function () {
            var d = this.data();
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

    };
    this.loopInfiniteLoading = function (){
      _loadingPlugin = $('#loading-circle').cprogress({
                           percent: 1, // starting position
                           img1: '../../static/manati_ui/images/c1.png', // background
                           img2: '../../static/manati_ui/images/c3.png', // foreground
                           speed: 200, // speed (timeout)
                           PIStep : 0.1, // every step foreground area is bigger about this val
                           limit: 100, // end value
                           loop : true, //if true, no matter if limit is set, progressbar will be running
                           showPercent : false //show hide percent
                      });
    };

    this.createLoading = function(){
        _loadingPlugin = $('#loading-circle').cprogress({
                           percent: 1, // starting position
                           img1: '../../static/manati_ui/images/c1.png', // background
                           img2: '../../static/manati_ui/images/c3.png', // foreground
                           speed: 200, // speed (timeout)
                           PIStep : 0.1, // every step foreground area is bigger about this val
                           limit: 1, // end value
                           loop : false, //if true, no matter if limit is set, progressbar will be running
                           showPercent : false //show hide percent
                      });

        // // Create
        // options = {
        //      img1: 'v1.png',
        //      img2: 'v2.png',
        //      speed: 50,
        //      limit: 70,
        //
        // };
        //
        // myplugin = $('#p1').cprogress(options);

    };
    this.addStepsLoading= function(step){
        var previous_limit = _loadingPlugin.options('').limit;
        // console.log("Limit: " + previous_limit + " Step: " + step);
        _loadingPlugin.options({limit: previous_limit + step});
    }
    this.destroyLoading = function(){
        _loadingPlugin.destroy();
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
            $.notify("Starting process to save the Analysis Session, it takes time", "info", {autoHideDelay: 6000 });
            $('#save-table').attr('disabled',true).addClass('disabled');
            // thiz.createLoading();
            var rows = _dt.rows();
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

                    $.notify("All Weblogs ("+json['data_length']+ ") were created successfully ", 'success');
                    $('#save-table').hide();
                    $('#wrap-form-upload-file').hide();
                    setInterval(syncDB, 10000 );
                        //send the weblogs
                    // _data_rows_wb = _dt.rows();
                    // _data_wb = _data_rows_wb.data().toArray();
                    // _total_data_wb = _data_wb.length;
                    // thiz.sendWB();
                },

                // handle a non-successful response
                error : function(xhr,errmsg,err) {
                    $('#results').html("<div class='alert-box alert radius' data-alert>Oops! We have encountered an error: "+errmsg+
                        " <a href='#' class='close'>&times;</a></div>"); // add the error to the dom
                    console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
                    $('#save-table').attr('disabled',false).removeClass('disabled');
                    $.notify(xhr.status + ": " + xhr.responseText, "error");

                    // thiz.destroyLoading();
                }
            });
        }catch(e){
            // thiz.destroyLoading();
            $.notify(e, "error");
            $('#save-table').attr('disabled',false).removeClass('disabled');
        }




    }
    this.sendWB = function(){
        $("#loading-img").show();
        var data = {"keys[]": JSON.stringify(_data_headers),'data[]': JSON.stringify(_data_wb), 'analysis_session_id':_analysis_session_id};
        $.ajax({
            type:"POST",
            data: data,
            dataType: "json",
            url: "/manati_ui/analysis_session/add_weblogs",
            // handle a successful response
            success : function(json) {
                console.log(json); // log the returned json to the console
                $.notify("All Weblogs ("+json['data_length']+ ") were created successfully ", 'success');
                // _dt.rows(_data_rows_wb).nodes().to$().removeClass('modified');

                // $.notify("You will be redirected to a new page in few seconds", 'info', {autoHideDelay: 4000 });
                // var as_id = json['analysissessionid'];
                // setTimeout(function() {
                //     window.location.assign("/manati_ui/analysis_session/"+as_id+"/edit");
                // }, 3000)


                // var data = json['data'];
                // var data_length = data.length;
                // thiz.addStepsLoading( data_length * 100 / _total_data_wb );
                // //update state and id of all data used
                // data.forEach(function(elem) {
                //     console.log(elem);
                //     var dt_id = elem['dt_id'];
                //     var rs = elem['register_status'];
                //     var id = elem['id'];
                //     _dt.cell(dt_id,COLUMN_REG_STATUS).data(rs).draw(false);
                //     _dt.cell(dt_id,COLUMN_DB_ID).data(id).draw(false);
                //     _dt.cell(dt_id,COLUMN_DT_ID).data(dt_id).draw(false);
                //     _dt.row(dt_id).nodes().to$().removeClass('modified');
                //     _dt.row(dt_id).nodes().to$().attr('data-dbid',id);
                // });
                // // continue with the loop until all file are done
                // console.log("success sendWBLs"); // another sanity check
                //
                // // if(_finish_count >= _total_data_wb){ //stop to send request, all WB were saved
                //     _init_count = 0;
                //     _finish_count = SIZE_REQUEST;
                //     //hide button save
                //     $('#save-table').hide();
                //     $('#wrap-form-upload-file').hide();
                //     thiz.destroyLoading();
                //     $.notify("ALL Weblogs were created successfully ", 'success');
                //     setInterval(syncDB, 10000 );
                //     return true;
                // }
                // _init_count = _finish_count;
                // if(_finish_count + SIZE_REQUEST <= _total_data_wb){
                //     _finish_count+= SIZE_REQUEST;
                // }else{
                //     _finish_count+= (_total_data_wb - _finish_count) ;
                // }
                //
                // thiz.sendWB();

            },

            // handle a non-successful response
            error : function(xhr,errmsg,err) {
                $('#results').html("<div class='alert-box alert radius' data-alert>Oops! We have encountered an error: "+errmsg+
                    " <a href='#' class='close'>&times;</a></div>"); // add the error to the dom
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
                $('#save-table').attr('disabled',false).removeClass('disabled');
                $.notify(xhr.responseText, "error");
            }
        });
    };

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
    var generateContextMenuItems = function(){
        var setVerdict = function (verdict, rows){
            _dt.rows('.selected').nodes().to$().removeClass('selected');
            _dt.rows(rows).nodes().to$().addClass('selected');
            thiz.markVerdict(verdict);

        }
        var items_menu = {};
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
            "fold1-key1": { name: "EndPoints Server",
                            icon: "fa-paint-brush",
                            className: CLASS_MC_END_POINTS_SERVER_STR,
                            callback: function(key, options) {
                                setVerdict(_bulk_verdict, _bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR]);

                            }
                        },
            "fold1-key2": { name: "Domain",
                            icon: "fa-paint-brush",
                            className: CLASS_MC_HTTP_URL_STR,
                            callback: function(key, options) {
                                setVerdict(_bulk_verdict, _bulk_marks_wbs[CLASS_MC_HTTP_URL_STR]);
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
        $("body").on("mouseenter mouseleave", "ul.context-menu-list.context-menu-root li.context-menu-submenu.calculate", function (){
            var thiss = $(this);
            var tr_active = $("tr.menucontext-open.context-menu-active");
            var bigData = _dt.rows(tr_active).data()[0];
            _bulk_verdict = bigData[COLUMN_VERDICT];
            _bulk_marks_wbs[CLASS_MC_HTTP_URL_STR] = [];
            _bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR] = [];
            var ip_value = bigData[COLUMN_END_POINTS_SERVER]; // gettin end points server ip
            var url = bigData[COLUMN_HTTP_URL];
            var domain = findDomainOfURL(url); // getting domain
            _dt.rows().nodes().each(function (dom_row,i) {
                var data = _dt.row(dom_row).data();
                var local_url = data[COLUMN_HTTP_URL];
                var local_domain = findDomainOfURL(local_url);
                var local_ip_value = data[COLUMN_END_POINTS_SERVER];
                if(local_domain != null && local_domain === domain){
                    _bulk_marks_wbs[CLASS_MC_HTTP_URL_STR].add(dom_row);
                }
                if(local_ip_value === ip_value){
                    _bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR].add(dom_row);
                }
            });
            thiss.find("li."+CLASS_MC_END_POINTS_SERVER_STR).html("EndPoints Server ("+ _bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR].length+ ")");
            thiss.find("li."+CLASS_MC_HTTP_URL_STR).html("Domain ("+ _bulk_marks_wbs[CLASS_MC_HTTP_URL_STR].length+ ")");
            thiss.removeClass("calculate");
       });
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
                            // if(key != 'undefined'){
                            //     this.data('moreDisabled', !this.data('moreDisabled'));
                            // }else{
                            //     this.data('moreDisabled', false);
                            // }
                            thiz.markVerdict(key);
                            return true;
                        },
                        items: generateContextMenuItems()

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
                        delimiter: ',',
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
                        console.log("Parsing file...", file);
                        $.notify("Parsing file...", "info");
                        $("#weblogfile-name").html(file.name);

                    },
                    error: function(err, file, inputElem, reason)
                    {
                        console.log("ERROR Parsing:", err, file);
                        $.notify("ERROR Parsing:" + " " + err + " "+ file, "error");
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
                thiz.markVerdict(verdict);
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
            attributes[COL_DT_ID_STR] = 0;
            attributes[COL_DB_ID_STR] = id;

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


    }
    this.callingEditingData = function (analysis_session_id){
        var data = {'analysis_session_id':analysis_session_id};
        $.notify("The page is being loaded, maybe it will take time", "info", {autoHideDelay: 3000 });
        $.ajax({
                type:"GET",
                data: data,
                dataType: "json",
                url: "/manati_ui/analysis_session/get_weblogs",
                success : function(json) {// handle a successful response
                    var weblogs = JSON.parse(json['weblogs']);
                    var analysis_session_id = json['analysissessionid'];
                    initDataEdit(weblogs, analysis_session_id)
                },

                error : function(xhr,errmsg,err) { // handle a non-successful response
                    $.notify(xhr.status + ": " + xhr.responseText, "error");
                    console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

                }
            });

    }



}
