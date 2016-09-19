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
var SIZE_REQUEST = 30;
var _data_wb = [];
var _init_count = 0;
var _finish_count = SIZE_REQUEST;
var _total_data_wb;
var _analysis_session_id = -1;
var COLUMN_DT_ID, COLUMN_DB_ID,COLUMN_REG_STATUS,COLUMN_VERDICT;
var COLUMN_END_POINTS_SERVER, COLUMN_HTTP_URL;
var COL_END_POINTS_SERVER_STR;
var REG_STATUS = {modified: 1};
var COL_VERDICT_STR = 'verdict';
var COL_REG_STATUS_STR = 'register_status';
var COL_DT_ID_STR = 'dt_id';
var COL_DB_ID_STR = 'db_id';
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
     function addRowThread(data){
        var data = data;
         //only it should affect new WBs added
         if(data.length != _data_headers.length){
             data.add('undefined');
             data.add(-1);
             data.add(_countID.toString());
             data.add("DID NOT SAVE");
         }

        if(data.length !== _data_headers.length) {
            console.log("ERROR Adding");
            console.log(data);
        }
        else{
            var row = _dt.row.add(data);
            var index = row[0];
            _dt.cell(index, COLUMN_DT_ID).data(index).draw(false);
            _dt.row(index).nodes().to$().attr('data-dbid',data[COLUMN_DB_ID]);
        }
        _countID++;

    }
    function initDatatable(headers, data_init){
        var data = data_init;
        var columns = [];
        for(var i = 0; i< headers.length ; i++){
            var v = headers[i];
            columns.add({title: v, name: v, class: v});
        }
        _dt = $('#weblogs-datatable').DataTable({
            columns: columns,
            columnDefs: [
                {'visible':false,"searchable": false, "targets": headers.indexOf("db_id")},
                {'visible':false,"searchable": false, "targets": headers.indexOf("register_status")},
                {'visible':false,"searchable": false, "targets": headers.indexOf("dt_id")}
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
                // $('td', nRow).addClass(aData[COLUMN_VERDICT]);
                $(nRow).addClass(aData[COLUMN_VERDICT]);
            }
        });
        _dt.clear().row();
        _dt.buttons().container().appendTo( '#weblogs-datatable_wrapper .col-sm-6:eq(0)' );
        $('#weblogs-datatable tbody').on( 'click', 'tr', function () {
            $(this).toggleClass('selected');
            $('.contextMenuPlugin').remove();
        } );
        $('#panel-datatable').show();

        //adding init data
        $.each(data, function (index, objectData){
            var objectValues = _.values(objectData);
            Concurrent.Thread.create(addRowThread,objectValues);
            // addRowThread(objectValues);
        });

    }
    function initData(data, headers) {
        _data_uploaded = data;
        _data_headers = headers;
        _data_headers_keys = {};
        $.each(_data_headers,function(i, v){
            _data_headers_keys[v] = i;
        });
        COLUMN_DT_ID = _data_headers_keys[COL_DT_ID_STR];
        COLUMN_DB_ID = _data_headers_keys[COL_DB_ID_STR];
        COLUMN_REG_STATUS = _data_headers_keys[COL_REG_STATUS_STR];
        COLUMN_VERDICT =  _data_headers_keys[COL_VERDICT_STR];
        COL_END_POINTS_SERVER_STR = "endpoints.server";
        COLUMN_END_POINTS_SERVER = _data_headers_keys[COL_END_POINTS_SERVER_STR];
        COLUMN_HTTP_URL = _data_headers_keys["http.url"];
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
                var headers = results.meta.fields;
                $.each([COL_VERDICT_STR, COL_REG_STATUS_STR, COL_DT_ID_STR, COL_DB_ID_STR],function (i, value){
                    headers.push(value);
                });
                initData(results.data,headers);


            }

        }
    }


    // function stepFn(results, parser) {
    //     stepped++;
    //     if (results)
    //     {
    //         if (results.data){
    //             rowCount += results.data.length;
    //             if(stepped > 1){
    //                 var data = results.data[0];
    //                 Concurrent.Thread.create(addRowThread,data);
    //             }else{
    //                 var data = results.data;
    //                 var columns = [];
    //                 for(var i = 0; i< data.length ; i++){
    //                     columns.add({title: data[i], name: data[i], class: data[i]});
    //                 }
    //                 _keys = columns;
    //                 _dt = $('#weblogs-datatable').DataTable({
    //                     columns: columns,
    //                     columnDefs: [
    //                         {'visible':false,"searchable": false, "targets": COLUMN_DB_ID},
    //                         {'visible':false,"searchable": false, "targets": COLUMN_REG_STATUS},
    //                         {'visible':false,"searchable": false, "targets": getColumnIndexesWithClass(columns, "dt_id")}
    //                     ],
    //                     "scrollX": true,
    //                     "aLengthMenu": [[25, 50, 100, -1], [25, 50, 100, "All"]],
    //                 //     "sDom": "Rlfrtip",
    //                     colReorder: true,
    //                     renderer: "bootstrap",
    //                     responsive: true,
    //                     buttons: ['copy', 'csv', 'excel','colvis'],
    //                     "fnRowCallback": function( nRow, aData, iDisplayIndex, iDisplayIndexFull ) {
    //                         $('td', nRow).addClass(aData[11]);
    //                     }
    //                 });
    //                 _dt.clear().row();
    //                 _dt.buttons().container().appendTo( '#weblogs-datatable_wrapper .col-sm-6:eq(0)' );
    //                 $('#weblogs-datatable tbody').on( 'click', 'tr', function () {
    //                     $(this).toggleClass('selected');
    //                     $('.contextMenuPlugin').remove();
    //                 } );
    //
    //                 /**
    //                 $('#weblogs-datatable tbody').on( 'mouseenter', 'td', function () {
    //                     var colIdx = _dt.cell(this).index().column;
    //                     $( _dt.cells().nodes() ).removeClass( 'highlight' );
    //                     $( _dt.column( colIdx ).nodes() ).addClass( 'highlight' );
    //                 } );
    //                  */
    //                 $('#panel-datatable').show();
    //             }
    //
    //         }
    //
    //         if (results.errors)
    //         {
    //             errorCount += results.errors.length;
    //             firstError = firstError || results.errors[0];
    //         }
    //     }
    // }
    this.markVerdict= function (verdict) {
        console.log(verdict);
        _dt.rows('.selected').every( function () {
            var d = this.data();
            var old_verdict = d[COLUMN_VERDICT];
            d[COLUMN_VERDICT]= verdict; // update data source for the row
            d[COLUMN_REG_STATUS] = REG_STATUS.modified;
            this.invalidate(); // invalidate the data DataTables has cached for this row

        } );
        // Draw once all updates are done
        _dt.draw(false);
        _dt.rows('.selected').nodes().to$().removeClass(_verdicts.join(" ")).addClass(verdict);
        _dt.rows('.selected').nodes().to$().addClass('modified');
        _dt.rows('.selected').nodes().to$().removeClass('selected');

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
        var data_pos = {};
        arr_list.each(function(elem){
            if(elem[COLUMN_REG_STATUS] != -1 ){
                data_row[elem[COLUMN_DB_ID]]=elem[COLUMN_VERDICT];
                data_pos[elem[COLUMN_DB_ID]]=elem[COLUMN_DT_ID];
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
                    var row = _dt.rows('[data-dbid="'+elem.pk+'"]');
                    var dt_id = row.data()[0][COLUMN_DT_ID];
                    _dt.cell(dt_id, COLUMN_VERDICT).data(elem.fields.verdict);
                    row.nodes().to$().addClass('selected');
                    thiz.markVerdict(elem.fields.verdict);
                    _dt.row(dt_id).nodes().to$().removeClass('modified');
                    _dt.cell(dt_id, COLUMN_REG_STATUS).data(elem.fields.register_status);
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
            thiz.createLoading();
            var data = { filename: _filename};
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
                        //send the weblogs
                    _data_wb = _dt.rows().data().toArray();
                    _total_data_wb = _data_wb.length;

                    // var i = 0;
                    // while(i < _total_data_wb){
                    //     _dt.cell(i,COLUMN_DT_ID).data(i).draw(false); // updating _id column with the correct id of the datatable;
                    //     _data_wb[i] = _dt.rows(i).data().toArray();
                    //     i++;
                    // }
                    thiz.sendWB();
                },

                // handle a non-successful response
                error : function(xhr,errmsg,err) {
                    $('#results').html("<div class='alert-box alert radius' data-alert>Oops! We have encountered an error: "+errmsg+
                        " <a href='#' class='close'>&times;</a></div>"); // add the error to the dom
                    console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
                    $('#save-table').attr('disabled',false).removeClass('disabled');
                    thiz.destroyLoading();
                }
            });
        }catch(e){
            thiz.destroyLoading();
            $('#save-table').attr('disabled',false).removeClass('disabled');
        }




    }
    this.sendWB = function(){
        var data = {"keys[]": _data_headers,'data[]': _data_wb.slice(_init_count,_finish_count), 'analysis_session_id':_analysis_session_id};
        $.ajax({
            type:"POST",
            data: data,
            dataType: "json",
            url: "/manati_ui/analysis_session/add_weblogs",
            // handle a successful response
            success : function(json) {
                console.log(json); // log the returned json to the console
                var data = json['data'];
                var data_length = data.length;
                thiz.addStepsLoading( data_length * 100 / _total_data_wb );
                //update state and id of all data used
                data.forEach(function(elem) {
                    var dt_id = elem['dt_id'];
                    var rs = elem['register_status'];
                    var id = elem['id'];
                    _dt.cell(dt_id,COLUMN_REG_STATUS).data(rs).draw(false);
                    _dt.cell(dt_id,COLUMN_DB_ID).data(id).draw(false);
                    _dt.cell(dt_id,COLUMN_DT_ID).data(dt_id).draw(false);
                    _dt.row(dt_id).nodes().to$().removeClass('modified');
                    _dt.row(dt_id).nodes().to$().attr('data-dbid',id);
                });
                // continue with the loop until all file are done
                console.log("success"); // another sanity check

                if(_finish_count >= _total_data_wb){ //stop to send request, all WB were saved
                    _init_count = 0;
                    _finish_count = SIZE_REQUEST;
                    //hide button save
                    $('#save-table').hide();
                    $('#wrap-form-upload-file').hide();
                    thiz.destroyLoading();
                    $.notify("ALL Weblogs were created successfully ", 'success');
                    setInterval(syncDB, 10000 );
                    return true;
                }
                _init_count = _finish_count;
                if(_finish_count + SIZE_REQUEST <= _total_data_wb){
                    _finish_count+= SIZE_REQUEST;
                }else{
                    _finish_count+= (_total_data_wb - _finish_count) ;
                }

                thiz.sendWB();

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
    function contextMenuSettings (){
        //events for verdicts buttons on context popup menu
            var items_menu = {};
            _verdicts.forEach(function(v){
                items_menu[v] = {name: v, icon: v }
            });
            items_menu['sep1'] = "-----------";
            items_menu['fold1'] = {
                name: "Mark all WB with same: ",
                // disabled: function(){ return !this.data('moreDisabled'); },
                items: {
                "fold1-key1": {name: "EndPoints Server",
                                callback: function(key, options) {
                                    var verdict = _dt.rows(this).data()[0][COLUMN_VERDICT];
                                    var ip_value = _dt.rows('.menucontext-open').data()[0][COLUMN_END_POINTS_SERVER];
                                    var rows = [];
                                    _dt.column(COLUMN_END_POINTS_SERVER).nodes().each(function (v){
                                        var tr_dom = $(v);
                                        if(tr_dom.html() === ip_value){
                                            rows.add(tr_dom.closest('tr'));
                                        }
                                    });
                                    contextMenuConfirmMsg(rows, verdict);

                                }
                            },
                "fold1-key2": {name: "Domain",
                            callback: function(key, options) {
                                var verdict = _dt.rows(this).data()[0][COLUMN_VERDICT];
                                var url = _dt.rows('.menucontext-open').data()[0][COLUMN_HTTP_URL];
                                var reg_exp_domains = /[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+/;
                                var domain = url.match(reg_exp_domains)[0];
                                var rows = [];
                                _dt.column(COLUMN_HTTP_URL).nodes().each(function (v){
                                    var tr_dom = $(v);
                                    var local_url = tr_dom.html();
                                    var local_domain = local_url.match(reg_exp_domains)[0];
                                    if(local_domain === domain){
                                        rows.add(tr_dom.closest('tr'));
                                    }
                                });
                                contextMenuConfirmMsg(rows, verdict);
                            }
                        }
            }};

            $.contextMenu({
                selector: '.weblogs-datatable tr',
                callback: function(key, options) {
                    // if(key != 'undefined'){
                    //     this.data('moreDisabled', !this.data('moreDisabled'));
                    // }else{
                    //     this.data('moreDisabled', false);
                    // }
                    thiz.markVerdict(key);
                    return true;
                },
                events: {
                   show : function(options){
                        // // Add class to the menu
                        if(!this.hasClass('selected')){
                            this.addClass('selected');
                        }
                        // if(!this.find('td').first().hasClass('undefined')){
                        //    this.data('moreDisabled', true);
                        // }else{
                        //    this.data('moreDisabled', false);
                        // }
                        this.addClass('menucontext-open');
                        //
                        // // Show an alert with the selector of the menu
                        // if( confirm('Open menu with selector ' + options.selector + '?') === true ){
                        //     return true;
                        // } else {
                        //     // Prevent the menu to be shown.
                        //     return false;
                        // }

                       // console.log($triggerElement);
                       // console.log(event);
                   },
                   hide : function(options) {
                       // if (confirm('Hide menu with selector ' + options.selector + '?') === true) {
                       //     return true;
                       // } else {
                       //     // Prevent the menu to be hidden.
                       //     return false;
                       // }
                       this.removeClass('menucontext-open');
                       this.removeClass('selected');
                   }
                },
                items: items_menu

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
                    },
                    // complete: function()
                    // {
                    //     $('#save-table').show();
                    //     console.log("Done with all files");
                    //
                    // }
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
                Concurrent.Thread.create(saveDB);
               // saveDB();
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
    this.initData = function (weblogs, analysis_session_id) {
        _analysis_session_id = analysis_session_id;
        $.notify("The page is being loaded, maybe it will take time", "info");
        // stepFn({data:_attributes_db}, null);
        // console.log(data);
        var headers = null;
        var data = [];
        $.each(weblogs, function (index, elem){
            var id = elem.pk;
            var attributes = JSON.parse(JSON.parse(elem.fields.attributes))[0];
            attributes[COL_VERDICT_STR] = elem.fields.verdict;
            attributes[COL_REG_STATUS_STR] = elem.fields.register_status;
            attributes[COL_DT_ID_STR] = 0;
            attributes[COL_DB_ID_STR] = id;

            if(headers == null){
                headers = _.keys(attributes);
            }
            data.push(attributes);
            // $.each(, function (k, v) {
            //     values_sorted.push(elem.fields[att]);
            // });
            // values_sorted[COLUMN_DT_ID] = 0; //just to set it
            // values_sorted[COLUMN_DB_ID] = id;
            // var row = _dt.row.add(values_sorted);
            // var index = row[0];
            // _dt.row(index).nodes().to$().attr('data-dbid',id);
            // _dt.cell(index, COLUMN_DT_ID).data(index).draw(false);


        });
        initData(data, headers );
        $(document).ready(function(){
            $('#panel-datatable').show();
            setInterval(syncDB, 10000 );

        })


    }


}
