/**
 * Created by raulbeniteznetto on 8/10/16.
 */
//Concurrent variables for loading data in datatable
var _dt;
var _countID =1;
var _attributes_db;
var thiz;
var _db;
var _filename;

//Concurrent variables for saving on PG DB
var SIZE_REQUEST = 30;
var _data_wb = [];
var _init_count = 0;
var _finish_count = SIZE_REQUEST;
var _total_data_wb;
var _analysis_session_id = -1;
var COLUMN_DT_ID = 13;
var COLUMN_DB_ID = 14;
var COLUMN_REG_STATUS = 12;
var COLUMN_VERDICT = 11;
var COLUMN_END_POINTS_SERVER = 3;
var COLUMN_HTTP_URL = 1;
var REG_STATUS = {modified: 1};
var _data_updated = [];


var _loadingPlugin;
function AnalysisSessionLogic(attributes_db){
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
    var _verdicts = ["malicious","legitimate","suspicious","false_positive", "undefined"];
    var myDjangoList = ((attributes_db).replace(/&(l|g|quo)t;/g, function(a,b){
        return {
            l   : '<',
            g   : '>',
            quo : '"'
        }[b];
    }));

    myDjangoList = myDjangoList.replace(/u'/g, '\'');
    myDjangoList = myDjangoList.replace(/'/g, '\"');
    _attributes_db = JSON.parse( myDjangoList );
    _attributes_db.push('dt_id');
    _attributes_db.push('db_id');

     /************************************************************
                            PRIVATE FUNCTIONS
     *************************************************************/
     this.addWeblog = function (weblog) {
/**
          var todo = {

            _id: new Date().toISOString(),
            title: text,
            completed: false
          }; */
           // weblog['_id'] =  _countID; //new Date().toISOString()
          _db.put(weblog, function callback(err, result) {
            if (!err) {
              console.log('Successfully save a weblog!');
            }else{
                console.log('ERROR saving');
                console.log(err);
            }
          });
          //  _countID++;
     };
    function updateWeblog(weblog){
        _db.put(weblog, function callback(err, result) {
        if (!err) {
          console.log('Successfully updated a weblog!');
        }else{
            console.log('ERROR updating');
            console.log(err);
        }
      });

    }
    function showAllWeblogs() {
      _db.allDocs({include_docs: true, descending: true}, function(err, doc) {
        for(var i = 0 ; i < doc.rows.length ; i++){
            console.log(doc.rows[i]);
        }
      });
    }
    function completeFn(results,file){
        if (results && results.errors)
        {
            if (results.errors)
            {
                errorCount = results.errors.length;
                firstError = results.errors[0];
            }
            if (results.data && results.data.length > 0)
                rowCount = results.data.length;
        }
    }

    function addRowThread(data){
        var data = data;
        data.add('undefined');
        data.add(-1);
        data.add(_countID.toString());
        data.add("NOT SAVE");
        if(data.length !== _attributes_db.length) {
            console.log("ERROR");
            console.log(data);
        }
        else{
            var row = _dt.row.add(data);
            var index = row[0];
            _dt.cell(index, COLUMN_DT_ID).data(index).draw(false);
            // add to local DB
            // var weblog = {};
            // for(var i_attr = 0; i_attr < _attributes_db.length; i_attr++ ){
            //     var attr = _attributes_db[i_attr];
            //     weblog[attr] = data[i_attr];
            // }
            // thiz.addWeblog(weblog);
        }
        _countID++;

    }
    function stepFn(results, parser) {
        stepped++;
        if (results)
        {
            if (results.data){
                rowCount += results.data.length;
                var data = results.data[0];
                if(stepped > 1){
                    Concurrent.Thread.create(addRowThread,data);
                }else{
                    var columns = [];
                    for(var i = 0; i< _attributes_db.length ; i++){
                        columns.add({title: _attributes_db[i], name: _attributes_db[i]});
                    }
                    _keys = _attributes_db;
                    _dt = $('#weblogs-datatable').DataTable({
                        columns: columns,
                        columnDefs: [
                            {'visible':false,"searchable": false, "targets": COLUMN_DB_ID},
                            {'visible':false,"searchable": false, "targets": COLUMN_REG_STATUS},
                            {'visible':false,"searchable": false, "targets": COLUMN_DT_ID}
                        ],
                        "scrollX": true,
                        "aLengthMenu": [[25, 50, 100, -1], [25, 50, 100, "All"]],
                    //     "sDom": "Rlfrtip",
                        colReorder: true,
                        renderer: "bootstrap",
                        responsive: true,
                        buttons: ['copy', 'csv', 'excel','colvis'],
                        "fnRowCallback": function( nRow, aData, iDisplayIndex, iDisplayIndexFull ) {
                            $('td', nRow).addClass(aData[11]);
                        }
                    });
                    _dt.clear().row();
                    _dt.buttons().container().appendTo( '#weblogs-datatable_wrapper .col-sm-6:eq(0)' );
                    $('#weblogs-datatable tbody').on( 'click', 'tr', function () {
                        $(this).toggleClass('selected');
                        $('.contextMenuPlugin').remove();
                    } );

                    /**
                    $('#weblogs-datatable tbody').on( 'mouseenter', 'td', function () {
                        var colIdx = _dt.cell(this).index().column;
                        $( _dt.cells().nodes() ).removeClass( 'highlight' );
                        $( _dt.column( colIdx ).nodes() ).addClass( 'highlight' );
                    } );
                     */
                    $('#panel-datatable').show();
                }

            }

            if (results.errors)
            {
                errorCount += results.errors.length;
                firstError = firstError || results.errors[0];
            }
        }
    }
    this.markVerdict= function (verdict) {
        console.log(verdict);
        _dt.rows('.selected').every( function () {
            var d = this.data();
            var size_d = d.length;
            /**
            var new_w = _verdicts_weight[verdict];
            var old_w = _verdicts_weight[d[size_d - 2]];
            if(new_w >= old_w){
            */
            var old_verdict = d[COLUMN_VERDICT];
            d[COLUMN_VERDICT]= verdict; // update data source for the row
            d[COLUMN_REG_STATUS] = REG_STATUS.modified;
            /**
                    var weblog = {};
                    for(var i_attr = 0; i_attr < _attributes_db.length; i_attr++ ){
                        var attr = _attributes_db[i_attr];
                        if(attr === 'verdict'){
                            weblog[attr] = verdict;
                        }else {
                            weblog[attr] = d[i_attr];
                        }

                    }
                    updateWeblog(weblog);
            **/
                this.invalidate(); // invalidate the data DataTables has cached for this row
            /**
            }else{
                alert("You cannot assign a verdict lower than the previous one Ex: False Positive > Legitimate");
            }
             **/

        } );
        // Draw once all updates are done
        _dt.draw(false);
        _dt.rows('.selected').nodes().to$().find('td').removeClass().addClass(verdict);
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
        var data = {'data[]': JSON.stringify(_data_wb.slice(_init_count,_finish_count)), 'analysis_session_id':_analysis_session_id};
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
    var findDomainOfURL = function (url){
        var reg_exp_domains = /[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+/;
        var reg_exp_ip = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/;
        var matching_domain = null;
        var domain = ( (matching_domain = url.match(reg_exp_domains)) != null )|| matching_domain != undefined && matching_domain.length > 0 ? matching_domain[0] : null ;
        domain = (domain == null)  && ((matching_domain = url.match(reg_exp_ip)) != null) || matching_domain != undefined && matching_domain.length > 0 ? matching_domain[0] : null;
        return domain
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
                        complete: completeFn,
                        step: stepFn
                        // base config to use for each file
                    },
                    before: function(file, inputElem)
                    {
                        // if(_db == undefined || _db == null) {
                        //     _db =  new PouchDB(db_name);
                        // }
                        // else{
                        //     _db.destroy().then(function () {
                        //       _db =  new PouchDB(db_name);
                        //     }).catch(function (err) {
                        //         // error occurred
                        //     });
                        // }
                        // var changes = _db.changes({
                        //   since: 'now',
                        //   live: true,
                        //   include_docs: true
                        // }).on('change', function(change) {
                        //   console.log(change);
                        // }).on('complete', function(info) {
                        //   // changes() was canceled
                        // }).on('error', function (err) {
                        //   console.log(err);
                        // });
                        _filename = file.name;
                        console.log("Parsing file...", file);
                        $.notify("Parsing file...", "info");
                        $("#weblogfile-name").html(file.name)
                    },
                    error: function(err, file, inputElem, reason)
                    {
                        console.log("ERROR:", err, file);
                    },
                    complete: function()
                    {
                        console.log("Done with all files");
                        $('#save-table').show();


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

            //events for verdicts buttons on context popup menu
            var items_menu = {};
            _verdicts.forEach(function(v){
                items_menu[v] = {name: v, icon: v }
            });
            items_menu['sep1'] = "-----------";
            items_menu['fold1'] = {
                name: "Mark all WB with same: ",
                disabled: function(){ return !this.data('moreDisabled'); },
                items: {
                "fold1-key1": {name: "EndPoints Server",
                                callback: function(key, options) {
                                    var verdict = _dt.rows(this).data()[0][COLUMN_VERDICT];
                                    var ip_value = _dt.rows('.menucontext-open').data()[0][COLUMN_END_POINTS_SERVER];
                                    var rows = [];
                                    _dt.column('endpoints_server:name').nodes().each(function (v){
                                        var tr_dom = $(v);
                                        if(tr_dom.html() === ip_value){
                                            rows.add(tr_dom.closest('tr'));
                                        }
                                    });
                                    _dt.rows('.selected').nodes().to$().removeClass('selected');
                                    _dt.rows(rows).nodes().to$().addClass('selected');
                                    thiz.markVerdict(verdict);
                                    // _dt.columns(key_source_ip).search(ip_value);
                                }
                            },
                "fold1-key2": {name: "Domain",
                            callback: function(key, options) {
                                var verdict = _dt.rows(this).data()[0][COLUMN_VERDICT];
                                var url = _dt.rows('.menucontext-open').data()[0][COLUMN_HTTP_URL];
                                var domain = findDomainOfURL(url);
                                var rows = [];
                                _dt.column('http_url:name').nodes().each(function (v){
                                    var tr_dom = $(v);
                                    var local_url = tr_dom.html();
                                    var local_domain = findDomainOfURL(local_url);
                                    if(local_domain != null && local_domain === domain){
                                        rows.add(tr_dom.closest('tr'));
                                    }
                                });
                                _dt.rows('.selected').nodes().to$().removeClass('selected');
                                _dt.rows(rows).nodes().to$().addClass('selected');
                                thiz.markVerdict(verdict);
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
                        if(!this.find('td').first().hasClass('undefined')){
                           this.data('moreDisabled', true);
                        }else{
                           this.data('moreDisabled', false);
                        }
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
    this.initData = function (data, analysis_session_id) {
        _analysis_session_id = analysis_session_id;
        $.notify("The page is being loaded, maybe it will take time", "info");
        stepFn({data:_attributes_db}, null);
        // console.log(data);
        $.each(data, function (index, elem){
            var values_sorted = [];
            var id = elem.pk;
            $.each(_attributes_db, function (i, att) {
                values_sorted.push(elem.fields[att]);
            });
            values_sorted[COLUMN_DT_ID] = 0; //just to set it
            values_sorted[COLUMN_DB_ID] = id;
            var row = _dt.row.add(values_sorted);
            var index = row[0];
            _dt.row(index).nodes().to$().attr('data-dbid',id);
            _dt.cell(index, COLUMN_DT_ID).data(index).draw(false);


        });
        $(document).ready(function(){
            $('#panel-datatable').show();
            setInterval(syncDB, 10000 );

        })


    }


}
