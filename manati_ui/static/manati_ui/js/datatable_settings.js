/**
 * Created by raulbeniteznetto on 7/3/17.
 */

var AUX_COLUMNS = {
    VERDICT:{index:null, str: "verdict", class: "verdict"},
    REG_STATUS:{index:null, str: "register_status", class: "register_status"},
    UUID:{index:null, str: "uuid", class: "uuid"},
    DT_ID:{index:null, str: "dt_id", class: "dt_id"},
    DIST_IP:{index:null, str: "", class: ""},
    URL:{index:null, str: "", class: ""}
};
var NAMES_HTTP_URL = ["http.url", "http_url", "host"];
var NAMES_END_POINTS_SERVER = ["endpoints.server", "endpoints_server", "id.resp_h"];
var _data_headers_keys = {};
var _filterDataTable = null;
var _verdicts = ["malicious","legitimate","suspicious","falsepositive", "undefined"];
var _verdicts_merged = ['malicious','legitimate','suspicious','undefined','falsepositive','malicious_legitimate',
                        'suspicious_legitimate','undefined_legitimate','falsepositive_legitimate',
                        'undefined_malicious','suspicious_malicious','falsepositive_malicious',
                        'falsepositive_suspicious', 'undefined_suspicious','undefined_falsepositive'];

var REG_STATUS = {modified: 1};





function DataTableSettings(analysis_session_logic){
    var thiz = this;
    var _dt = null;
    var analysis_session_logic = analysis_session_logic;
    var table_options = {
            fixedHeader: {
                header: true
            },
            columnReorder: true,
            "search": {
                "regex": true
            },
            ordering: false,
            "scrollX": true,
            colReorder: true,
            renderer: "bootstrap",
            buttons: ['copy','csv','excel', 'colvis'],
            "fnRowCallback": function( nRow, aData, iDisplayIndex, iDisplayIndexFull ) {
                //when you change the verdict, the color is updated
                var row = $(nRow);
                var dt_id = aData[AUX_COLUMNS.DT_ID.str];
                row.addClass(checkVerdict(_verdicts_merged, aData[AUX_COLUMNS.VERDICT.str]));
                if(_rows_labeled.hasOwnProperty(dt_id)){
                    row.addClass(checkVerdict(_verdicts_merged, _rows_labeled[dt_id].verdict));
                }

                var str = aData[AUX_COLUMNS.DT_ID.str].split(":");

                if(aData[AUX_COLUMNS.REG_STATUS.str] === REG_STATUS.modified){
                    if(!row.hasClass('modified')) row.addClass('modified');
                }
                if(str.length > 1){
                    row.attr("data-dbid", str[1]);
                }else{
                    row.attr("data-dbid", str[0]);
                }
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
              input_filter.css('width', 260);
              input_filter.removeClass();
              label_filter.removeClass();
              div_filter.addClass('fluid-label');
              div_filter.append(input_filter);
              div_filter.append(label_filter);

              // div_filter.appendTo('#new-search-area');

              $('.fluid-label').fluidLabel({
                focusClass: 'focused'
              });
              $('.wrap-buttons').html($('.searching-buttons').clone());
              $('.wrap-select-page').html($('.wrap-page-select').clone());
              $('#panel-datatable').show();
            },
             // "sPaginationType": "listbox",
            dom:'<"top"<"row"<"col-md-3"f><"col-md-3 wrap-buttons-unused"><"col-md-1 wrap-select-page-unused"><"col-md-5"p>>>' +
                'rt' +
                '<"bottom"<"row"<"col-md-2"l><"col-md-5"B><"col-md-5"p>>>' +
                '<"row"<"col-md-offset-7 col-md-5"<"pull-right"i>>>'+
                '<"clear">',
            "lengthMenu": [[25, 50, 100, 500], [25, 50, 100, 500]]
        };
    var _analysis_session_id = null;

    function getAnalysisSessionId(){
        return _analysis_session_id;
    }

    function showLoading(){
         $("#loading-img").show();
    }
    function hideLoading() {
        $("#loading-img").hide();
    }
    function activeFilterTable(){
        _filterDataTable = new FilterDataTable(AUX_COLUMNS.VERDICT.index,_verdicts_merged);
    }
    function checkNullDataTable(){
        //verifying if already exist a table, in that case, destroy it
        if(_dt !== null && _dt !== undefined) {
            _dt.clear().draw();
            _dt.destroy();
            _dt = null;
            $('#weblogs-datatable').html('');
        }
    }
    function DataTableEvents(headers_info){
         _dt.buttons().container().appendTo( '#weblogs-datatable_wrapper .col-sm-6:eq(0)' );
        $('#weblogs-datatable tbody').on( 'click', 'tr', function () {
            $(this).toggleClass('selected');
            $('.contextMenuPlugin').remove();
        } );
        hideLoading();
        $('#panel-datatable').show();
        //  _dt.on( 'column-reorder', function ( e, settings, details ) {
        //     analysis_session_logic.setColumnsOrderFlat(true);
        //     for(var i=0; i < settings.aoColumns.length; i++){
        //         var name = settings.aoColumns[i].name;
        //         update_constant(name, i);
        //     }
        //  });
        //  _dt.on('buttons-action', function ( e, buttonApi, dataTable, node, config ) {
        //     analysis_session_logic.setColumnsOrderFlat(true);
        //  });
         _dt.columns(0).visible(true); // hack fixing one bug with the header of the table
        //
        //  // adding options to select datatable's pages
        //  // var list = document.getElementsByClassName('page-select')[1];
        //  // for(var index=0; index<_dt.page.info().pages; index++) {
        //  //     list.add(new Option((index+1).toString(), index));
        //  // }
        //  $('.page-select').change(function (ev) {
        //      ev.preventDefault();
        //      var elem = $(this);
        //      _dt.page(parseInt(elem.val())).draw('page');
        //
        //  });
        //  _dt.on('page.dt', function () {
        //     var info = _dt.page.info();
        //     $('.page-select').val(info.page);
        //
        // } );
        //  _dt.on('length.dt',function (){
        //      $('.page-select').html('');
        //      var list = document.getElementsByClassName('page-select')[1];
        //      // for(var index=0; index<_dt.page.info().pages; index++) {
        //      //     list.add(new Option((index+1).toString(), index));
        //      // }
        //  });
        //  _dt.on('search.dt',function (){
        //      $('.page-select').html('');
        //      var list = document.getElementsByClassName('page-select')[1];
        //      // for(var index=0; index<_dt.page.info().pages; index++) {
        //      //     list.add(new Option((index+1).toString(), index));
        //      // }
        //
        //  });

         //hide or show column
        // $.each(headers_info,function(index,elem){
        //     _dt.columns(index).visible(elem.visible).draw()
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
            $('#searching-buttons .btn').removeClass('active')
        });

    }
    function setConstants(data_headers_keys){
        // settings name and index for control columns
        AUX_COLUMNS.DT_ID.index = data_headers_keys[AUX_COLUMNS.DT_ID.str];
        AUX_COLUMNS.REG_STATUS.index = data_headers_keys[AUX_COLUMNS.REG_STATUS.str];
        AUX_COLUMNS.VERDICT.index =  data_headers_keys[AUX_COLUMNS.VERDICT.str];
        AUX_COLUMNS.UUID.index = data_headers_keys[AUX_COLUMNS.UUID.str];


        // looking for the name of the column depending of the type of the file of DIST_IP and HTTP_URL
        for(var index = 0; index < NAMES_HTTP_URL.length; index++){
            var key = NAMES_HTTP_URL[index];
            if(data_headers_keys[key]!== undefined && data_headers_keys[key] !== null){
                AUX_COLUMNS.URL.str = key;
                break;
            }
        }
        for(var index = 0; index < NAMES_END_POINTS_SERVER.length; index++){
            var key = NAMES_END_POINTS_SERVER[index];
            if(data_headers_keys[key]!== undefined && data_headers_keys[key] !== null){
                AUX_COLUMNS.DIST_IP.str = key;
                break;
            }
        }

        // updating indexes and names from the table
        AUX_COLUMNS.URL.index = data_headers_keys[AUX_COLUMNS.URL.str];
        AUX_COLUMNS.URL.class  = AUX_COLUMNS.URL.str.replace(".","_");
        AUX_COLUMNS.DIST_IP.index = data_headers_keys[AUX_COLUMNS.DIST_IP.str];
        AUX_COLUMNS.DIST_IP.class =  AUX_COLUMNS.DIST_IP.str.replace(".", "_");

    }


    function initDatatable(headers, datatable_setting){
        _data_headers_keys = checkHeaderDataTable(headers);
        setConstants(_data_headers_keys);
        datatable_setting['columns'] = headers;
        datatable_setting['columnDefs']= [
            {   "searchable": false, visible: false, "targets": [AUX_COLUMNS.REG_STATUS.str, AUX_COLUMNS.REG_STATUS.index]},
            {   "searchable": false, visible: false, "targets": [AUX_COLUMNS.DT_ID.str, AUX_COLUMNS.DT_ID.index]},
            {   "searchable": false, visible: false, "targets": [AUX_COLUMNS.UUID.str, AUX_COLUMNS.UUID.index],
                "defaultContent": null, render: function ( data, type, full, meta ) {
                                                        if (data === null|| data === undefined) {
                                                            return getRowShortId(getAnalysisSessionId());
                                                        }
                                                 }
            }
        ];
        activeFilterTable();
        checkNullDataTable();
        _dt = $('#weblogs-datatable').DataTable(datatable_setting);
        DataTableEvents(_data_headers_keys);

    }
    function checkHeaderDataTable(headers){
        var headers_key = {};
        for(var i = 0; i < headers.length; i++){
            var cn = headers[i]['column_name'];
            headers[i]['title'] = cn;
            headers_key[cn] = headers[i]['order'];
            var key_splitted = cn.split('.');
            if(key_splitted.length > 1){
                cn = key_splitted.join('\\.');
            }
            headers[i]['data'] = cn;
        }
        return headers_key
    }
    function showERRORMessage(xhr,errmsg,err){
        $.notify(xhr.status + ": " + xhr.responseText, "error");
        console.error(xhr.status + ": " + xhr.responseText);

    }
    function addClassVerdict(class_selector,verdict) {
        var checked_verdict = checkVerdict(_verdicts_merged, verdict);
        _dt.rows('.'+class_selector).nodes().to$().removeClass(_verdicts_merged.join(" ")).addClass(checked_verdict);
        _dt.rows('.'+class_selector).nodes().to$().addClass('modified');
        _dt.rows('.'+class_selector).nodes().to$().removeClass(class_selector);


    }

    var _rows_labeled = {};
    // ################ PUBLIC EVENTS ################################
    this.markVerdict= function (verdict, class_selector) {
        if(class_selector === null || class_selector === undefined) class_selector = "selected";
        var rows_affected = [];
        _dt.rows('.'+class_selector).every( function () {
            var d = this.data();
            var temp_data = {};
            temp_data[AUX_COLUMNS.UUID.str] = d[AUX_COLUMNS.UUID.str];
            temp_data[AUX_COLUMNS.DIST_IP.str] = d[AUX_COLUMNS.DIST_IP.str];
            temp_data[AUX_COLUMNS.URL.str] = d[AUX_COLUMNS.URL.str];
            temp_data[AUX_COLUMNS.DT_ID.str] = d[AUX_COLUMNS.DT_ID.str];
            rows_affected.push(temp_data);
            var old_verdict = d[AUX_COLUMNS.VERDICT.str];
            d[AUX_COLUMNS.VERDICT.str]= verdict; // update data source for the row
            d[AUX_COLUMNS.REG_STATUS.str] = REG_STATUS.modified;
            _rows_labeled[d.dt_id] = {register_status: REG_STATUS.modified, verdict: verdict};
            this.invalidate(); // invalidate the data DataTables has cached for this row

        } );
        // Draw once all updates are done
        // _dt.draw(false);
        addClassVerdict(class_selector, verdict);
        return rows_affected;

    };
    this.newDataTable = function(headers, data){
        var header_length = headers.length;
        $.each([AUX_COLUMNS.VERDICT.str, AUX_COLUMNS.REG_STATUS.str,
            AUX_COLUMNS.DT_ID.str, AUX_COLUMNS.UUID.str],
            function (i, value){
               headers.push({column_name: value, title: value, order: header_length + i, defaultContent: 'undefined'});
            }
        );

        $.each(data, function (i, v){
            v[AUX_COLUMNS.VERDICT.str] = 'undefined';
            v[AUX_COLUMNS.DT_ID.str] = (i+1).toString();
            v[AUX_COLUMNS.REG_STATUS.str] = (-1).toString();
        });
        var new_table_options = $.extend({}, table_options);
        new_table_options['data'] = data;
        initDatatable(headers, new_table_options);
        $('#save-table').show();

    };
    this.editDataTable = function(analysis_session_id){
        _analysis_session_id = analysis_session_id;
        $.ajax({
            type: "GET",
            dataType: 'json',
            url: "/manati_project/manati_ui/analysis_session/"+analysis_session_id+"/get_table_columns",
            success : function(json) {// handle a successful response
                var headers = json['headers'];
                var edit_table_options = $.extend({}, table_options);
                edit_table_options['processing'] = true;
                edit_table_options['serverSide'] = true;
                edit_table_options['ajax'] = "/manati_project/manati_ui/datatable/data?json=true&analysis_session_id" +
                    "="+analysis_session_id;
                initDatatable(headers, edit_table_options);
            },
            error: function(xhr,errmsg,err) {
                showERRORMessage(xhr,errmsg,err);
            }

        });
    };

    this.getRows = function (class_filter){
        if (class_filter === undefined || class_filter === null) return _dt.rows().data().toArray();
        else return _dt.rows(class_filter).data().toArray();
    };
    this.cleanRowsLabeled = function (){
        var clone = $.extend({}, _rows_labeled);
        _rows_labeled = {};
        return clone;

    };


    this.cleanModified = function (){
        _dt.column(AUX_COLUMNS.REG_STATUS.index, {search:'applied'}).nodes().each( function (cell, i) {
            var tr = $(cell).closest('tr');
            if(!tr.hasClass("modified")) cell.innerHTML = 0;
        } );
    };
    this.get_headers_info = function (){
        // _data_headers
        var column_visibles = _dt.columns().visible();
        var headers = $.map(_dt.columns().header(),function (v,i) {
            return {order: i, column_name: v.innerHTML, visible: column_visibles[i] };
        });

        return headers;
    };

    this.reloadAjax = function(){
        _dt.ajax.reload(null,false);
    };
    this.activeAjaxData = function (analysis_session_id){
        _analysis_session_id = analysis_session_id;
        var settings = _dt.settings();
        // settings['processing'] = true;
        // settings['serverSide'] = true;
        // settings['ajax'] = "/manati_project/manati_ui/datatable/data?json=true&analysis_session_id" + analysis_session_id

    }
}