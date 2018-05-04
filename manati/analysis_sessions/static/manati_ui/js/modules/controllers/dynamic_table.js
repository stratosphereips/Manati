import {check_verdict, check_verdict_merged, isEmpty, hideLoading, findDomainOfURL, showLoading, isMac} from '../helpers/utils.js';
import {TIME_SYNC_DB, REG_STATUS, VERDICTS_MERGED_AVAILABLE, NAMES_HTTP_URL, NAMES_END_POINTS_SERVER, COL_VERDICT_STR, COL_REG_STATUS_STR, COL_DT_ID_STR, COL_UUID_STR} from '../helpers/constants.js'
import FilterDataTable from '../helpers/filtering_datatable.js';
import {syncDB} from '../../analysis_session_logic.js';
let _m;

class DynamicTable {

    constructor(analysis_session_obj) {
        this.analysis_session_obj = analysis_session_obj;
        this.dt = null;
        this.aux_columns = {
            verdict: {index: null, str: COL_VERDICT_STR, class: "verdict"},
            reg_status: {index: null, str: COL_REG_STATUS_STR, class: "register_status"},
            uuid: {index: null, str: COL_UUID_STR, class: "uuid"},
            dt_id: {index: null, str: COL_DT_ID_STR, class: "dt_id"},
            dist_ip: {index: null, str: "", class: ""},
            url: {index: null, str: "", class: ""}
        };
        this.verdict_sync = {};
        this._filterDataTable = null;

    }

    _update_constant(str, index) {
        if (this.aux_columns.uuid.str === str) {
            this.aux_columns.uuid.index = index;
        }
        else if (this.aux_columns.dt_id.str === str) {
            this.aux_columns.dt_id.index = index;
        }
        else if (this.aux_columns.reg_status.str === str) {
            this.aux_columns.reg_status.index = index;
        }
        else if (this.aux_columns.verdict.str === str) {
            this.aux_columns.verdict.index = index;
        }
        else if (this.aux_columns.url.str === str) {
            this.aux_columns.url.index = index
        }
        else if (this.aux_columns.dist_ip.str === str) {
            this.aux_columns.dist_ip.index = index;
        }
    }

    init_datatable(headers, data) {
        let thiz = this;
        let columns = [];
        let $weblog_datatable = $('#weblogs-datatable');
        let analysis_session_name = this.analysis_session_obj.getAnalysisSessionName();
        for (let i = 0; i < headers.length; i++) {
            let v = headers[i];
            columns.push({title: v, name: v, class: v});
        }
        //verifying if already exist a table, in that case, destroy it
        if (this.dt !== null && this.dt !== undefined) {
            this.dt.clear();
            this.dt.destroy();
            this.dt = null;
            $weblog_datatable.empty();
            $weblog_datatable.html('');
        }
        // create or init datatable
        this.dt = $weblog_datatable.DataTable({
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
                {"searchable": false, visible: false, "targets": headers.indexOf(thiz.aux_columns.reg_status.str)},
                {"searchable": false, visible: false, "targets": headers.indexOf(thiz.aux_columns.dt_id.str)},
                {"searchable": false, visible: false, "targets": headers.indexOf(thiz.aux_columns.uuid.str)}
            ],
            "scrollX": true,
            colReorder: true,
            renderer: "bootstrap",
            // responsive: true,
            buttons: [
                {extend: 'copy', title: analysis_session_name},
                {extend: 'excel', title: analysis_session_name},
                {extend: 'csv', title: analysis_session_name},
                {extend: 'colvis', title: analysis_session_name}
            ],
            "fnRowCallback": function (nRow, aData, iDisplayIndex, iDisplayIndexFull) {
                //when you change the verdict, the color is updated
                let row = $(nRow);
                let id = aData[thiz.aux_columns.dt_id.index];
                let str = id.split(":");
                let id_row = str.length > 1 ? str[1] : str[0];
                let verdict = aData[thiz.aux_columns.verdict.index];
                let reg_status = aData[thiz.aux_columns.reg_status.index];
                if (thiz.verdict_sync.hasOwnProperty(id)) {
                    let internal_row = _dt.rows('[data-dbid="' + id_row + '"]');
                    let index_row = internal_row.indexes()[0];
                    let elem = thiz.verdict_sync[id];
                    verdict = elem.verdict;
                    reg_status = elem.register_status;
                    internal_row.nodes().to$().addClass('selected-sync');
                    thiz.dt.cell(index_row, thiz.aux_columns.verdict.index).data(verdict);
                    thiz.dt.cell(index_row, thiz.aux_columns.reg_status.index).data(reg_status);
                    thiz.add_class_verdict('selected-sync', verdict, false);
                    // thiz.markVerdict(verdict,'selected-sync');
                    // internal_row.nodes().to$().removeClass('modified');

                    delete thiz.verdict_sync[id];
                }

                row.addClass(check_verdict_merged(verdict));
                if ((reg_status === REG_STATUS.modified) && !row.hasClass('modified')) {
                    row.addClass('modified');
                } else if ((reg_status !== REG_STATUS.modified) && row.hasClass('modified')) {
                    row.removeClass('modified');
                }
                row.attr("data-dbid", id_row);

            },
            drawCallback: function () {
                $('.paginate_button.next', this.api().table().container())
                    .on('click', function () {
                        $("html, body").animate({scrollTop: 0}, "slow");
                    });
            },
            initComplete: function () {
                let div_filter = $("#weblogs-datatable_filter");//.detach();
                let input_filter = div_filter.find('input').detach();
                let label_filter = div_filter.find('label').detach();
                input_filter.attr('placeholder', 'Search:');
                input_filter.css('width', '100%');
                input_filter.removeClass();
                label_filter.removeClass();
                div_filter.addClass('fluid-label');
                div_filter.append(input_filter);
                div_filter.append(label_filter);

                $('.fluid-label').fluidLabel({focusClass: 'focused'});
                $('.wrap-buttons').html($('.searching-buttons').clone());

                $('.wrap-select-page').html($('.wrap-page-select').clone());
            },
            // "sPaginationType": "listbox",
            dom: '<"top"<"row"<"col-md-2"f><"col-md-5 wrap-buttons"><"col-md-1 wrap-select-page"><"col-md-4"p>>>' +
            'rt' +
            '<"bottom"<"row"<"col-md-2"l><"col-md-5"B><"col-md-5"p>>>' +
            '<"row"<"col-md-offset-7 col-md-5"<"pull-right"i>>>' +
            '<"clear">',
            "lengthMenu": [[25, 50, 100, 500], [25, 50, 100, 500]]
        });


        this.dt.buttons().container().appendTo('#weblogs-datatable_wrapper .col-sm-6:eq(0)');
        $weblog_datatable.find('tbody').on('click', 'tr', function (event) {
            event.preventDefault();
            $('tr.action').not(this).removeClass('action');
            if ((isMac() && event.metaKey ) || (!isMac() && event.shiftKey)) {
                $(this).toggleClass('selected');
            }
            $(this).toggleClass('action');
            $('.contextMenuPlugin').remove();
        }).on('dblclick', 'tr', function () {
            $(this).toggleClass('selected');
        });

        hideLoading();
        $('#panel-datatable').show();
        this.dt.on('column-reorder', function (e, settings, details) {
            thiz.setColumnsOrderFlat(true);
            for (let i = 0; i < settings.aoColumns.length; i++) {
                let name = settings.aoColumns[i].name;
                thiz._update_constant(name, i);
                // TO-DO to fix problem when you move the columns and the attributes COLUMN_XXXX must be updated.
            }
        });
        this.dt.on('buttons-action', function (e, buttonApi, dataTable, node, config) {
            thiz.setColumnsOrderFlat(true);
        });
        this.dt.columns(0).visible(true); // hack fixing one bug with the header of the table

        $weblog_datatable.on("click", "a.virus-total-consult", function (ev) {
            ev.preventDefault();
            let elem = $(this);
            let row = elem.closest('tr');
            let query_node = elem.data('info') === 'domain' ? findDomainOfURL(elem.text()) : elem.text();
            row.removeClass('selected');
            thiz.modals.consultVirusTotal(query_node);

        });
        let _dt = this.dt;
        // adding options to select datatable's pages
        let list = document.getElementsByClassName('page-select')[1];
        for (let index = 0; index < _dt.page.info().pages; index++) {
            list.add(new Option((index + 1).toString(), index));
        }
        $('.page-select').change(function (ev) {
            ev.preventDefault();
            let elem = $(this);

            thiz.dt.page(parseInt(elem.val())).draw('page');

        });
        thiz.dt.on('page.dt', function () {
            let info = _dt.page.info();
            $('.page-select').val(info.page);

        });
        thiz.dt.on('length.dt', function () {
            $('.page-select').html('');
            let list = document.getElementsByClassName('page-select')[1];
            for (let index = 0; index < _dt.page.info().pages; index++) {
                list.add(new Option((index + 1).toString(), index));
            }
        });
        thiz.dt.on('search.dt', function () {
            try {
                $('.page-select').html('');
                let list = document.getElementsByClassName('page-select')[1];
                for (let index = 0; index < _dt.page.info().pages; index++) {
                    list.add(new Option((index + 1).toString(), index));
                }
            } catch (e) {
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

    initData(data, headers) {

        let _data_uploaded = data;
        let _data_headers = headers;
        let _data_headers_keys = {};
        let _countID = 1;
        let verdict_str = this.aux_columns.verdict.str;
        let reg_status_str = this.aux_columns.reg_status.str;
        let dt_id_str = this.aux_columns.dt_id.str;
        let uuid_str = this.aux_columns.uuid.str;
        $("li#statical-nav").hide();
        let data_processed = _.map(_data_uploaded, function (v, i) {
            let values = _.values(v);
            if (values.length < _data_headers.length) {
                let uuid_str = uuid.v4();
                values.push('undefined');
                values.push(-1);
                values.push(_countID.toString());
                values.push(uuid_str);
                _data_uploaded[i][verdict_str] = "undefined";
                _data_uploaded[i][reg_status_str] = (-1).toString();
                _data_uploaded[i][dt_id_str] = _countID.toString();
                _data_uploaded[i][uuid_str] = uuid_str;
            }
            _countID++;
            return values
        });

        $.each(_data_headers, function (i, v) {
            _data_headers_keys[v] = i;
        });
        console.log(data.length);
        this.aux_columns.dt_id.index = _data_headers_keys[dt_id_str];
        this.aux_columns.reg_status.index = _data_headers_keys[reg_status_str];
        this.aux_columns.verdict.index = _data_headers_keys[verdict_str];
        this.aux_columns.uuid.index = _data_headers_keys[uuid_str];

        for (let index = 0; index < NAMES_HTTP_URL.length; index++) {
            let key = NAMES_HTTP_URL[index];
            if (_data_headers_keys[key] !== undefined && _data_headers_keys[key] !== null) {
                this.aux_columns.url.str = key;
                this.aux_columns.url.index = _data_headers_keys[key];
                this.aux_columns.url.class = key.replace(".", "_");
                break;
            }
        }
        if (isEmpty(this.aux_columns.url.str)) {
            // alert("None of these key column were found: " + NAMES_HTTP_URL.join(', ') + " several features will be disabled");
        }

        for (let index = 0; index < NAMES_END_POINTS_SERVER.length; index++) {
            let key = NAMES_END_POINTS_SERVER[index];
            if (_data_headers_keys[key] !== undefined && _data_headers_keys[key] !== null) {
                this.aux_columns.dist_ip.str = key;
                this.aux_columns.dist_ip.index = _data_headers_keys[key];
                this.aux_columns.dist_ip.class = key.replace(".", "_");
                break;
            }
        }
        if (isEmpty(this.aux_columns.dist_ip.str)) {
            // alert("None of these key column were found: " + NAMES_END_POINTS_SERVER.join(', ') + " several features will be disabled");
        }
        this.analysis_session_obj.processingFlows_WORKER(_data_uploaded, this.aux_columns.url.str, this.aux_columns.dist_ip.str);
        this._filterDataTable = new FilterDataTable(this.aux_columns.verdict.index, VERDICTS_MERGED_AVAILABLE);
        this.init_datatable(_data_headers, data_processed);
        $('#save-table').show();

    }

    settingsForInitData(headers, data) {

        $.each([COL_VERDICT_STR, COL_REG_STATUS_STR, COL_DT_ID_STR, COL_UUID_STR], function (i, value) {
            headers.push(value);
        });
        this.initData(data, headers);
        this.analysis_session_obj.generateAnalysisSessionUUID();
        hideLoading();
        // _m.EventFileUploadingFinished(_filename, rowCount);

    };


    initDataEdit (weblogs, analysis_session_id, headers_info) {
        let thiz = this;
        this.analysis_session_obj.setAnalysisSessionId(analysis_session_id);
        let weblogs_id_uuid = {};
        let update_uuid_weblogs = false;

        if (weblogs.length > 1) {
            // sorting header
            let headers;
            if (_.isEmpty(headers_info)) {
                let elem = weblogs[0];
                let attributes = elem.attributes;
                if (!(attributes instanceof Object)) attributes = JSON.parse(attributes);
                headers_info = _.keys(attributes);
                headers_info.push(COL_VERDICT_STR);
                headers_info.push(COL_REG_STATUS_STR);
                headers_info.push(COL_DT_ID_STR);
                headers_info.push(COL_UUID_STR);
                this.analysis_session_obj.setColumnsOrderFlat(true);
                headers = headers_info;
            } else {
                headers_info.sort(function (a, b) {
                    return a.order - b.order;
                });
                headers = $.map(headers_info, function (v, i) {
                    return v.column_name
                });
                if (headers.indexOf(COL_UUID_STR) <= -1) {
                    headers.push(COL_UUID_STR);
                    update_uuid_weblogs = true;
                }
            }

            //getting data
            let data = [];
            $.each(weblogs, function (index, elem) {
                let id = elem.id;
                let attributes = elem.attributes;
                if (!(attributes instanceof Object)) attributes = JSON.parse(attributes);
                attributes[COL_VERDICT_STR] = elem.verdict.toString();
                attributes[COL_REG_STATUS_STR] = elem.register_status.toString();
                attributes[COL_DT_ID_STR] = id.toString();
                if (attributes.uuid === undefined || attributes.uuid === null) {
                    let w_uuid = uuid.v4();
                    attributes[COL_UUID_STR] = w_uuid;
                    weblogs_id_uuid[id] = w_uuid;
                }
                let sorted_attributes = {};
                _.each(headers, function (value, index) {
                    sorted_attributes[value] = attributes[value];
                });
                data.push(sorted_attributes);
            });

            this.initData(data, headers);
            //hide or show column
            $.each(headers_info, function (index, elem) {
                thiz.dt.columns(index).visible(elem.visible).draw()
            });

            $(document).ready(function () {
                $('#panel-datatable').show();
                thiz._sync_db_interval = setInterval(syncDB, TIME_SYNC_DB);

            });
            if (update_uuid_weblogs) {
                thiz.analysis_session_obj.updateAnalysisSessionUUID(thiz.analysis_session_obj.getAnalysisSessionId(), weblogs_id_uuid);
            }
        } else {
            hideLoading();
            $.notify("The current AnalysisSession does not have weblogs saved", "info", {autoHideDelay: 5000});
        }


    };

    add_class_verdict(class_selector, verdict, add_modified = true) {
        let checked_verdict = check_verdict_merged(verdict);
        this.dt.rows('.' + class_selector).nodes().to$().removeClass(VERDICTS_MERGED_AVAILABLE.join(" ")).addClass(checked_verdict);
        if (add_modified) {
            this.dt.rows('.' + class_selector).nodes().to$().addClass('modified');
        }
        this.dt.rows('.' + class_selector).nodes().to$().removeClass(class_selector);

    }

    mark_verdict(verdict, class_selector = "selected") {
        let rows_affected = [];
        let thiz = this;
        this.dt.rows('.' + class_selector).every(function () {
            let d = this.data();
            let temp_data = {};
            let dist_ip_index = thiz.aux_columns.dist_ip.index;
            let dist_url_index = thiz.aux_columns.url.index;
            if (!isEmpty(dist_ip_index)) {
                temp_data[thiz.aux_columns.dist_ip.str] = d[dist_ip_index];

            }
            if (!isEmpty(dist_url_index)) {
                temp_data[thiz.aux_columns.url.str] = d[dist_url_index];
            }
            temp_data[thiz.aux_columns.uuid.str] = d[thiz.aux_columns.uuid.index];
            temp_data[thiz.aux_columns.dt_id.str] = d[thiz.aux_columns.dt_id.index];

            rows_affected.push(temp_data);
            // let old_verdict = d[COLUMN_VERDICT];
            d[thiz.aux_columns.verdict.index] = verdict; // update data source for the row
            d[thiz.aux_columns.reg_status.index] = REG_STATUS.modified;
            this.invalidate(); // invalidate the data DataTables has cached for this row

        });
        // Draw once all updates are done
        this.dt.draw(false);
        this.add_class_verdict(class_selector, verdict);
        return rows_affected;

    };

    get_headers_info() {
        // _data_headers
        let column_visibles = this.dt.columns().visible();
        return $.map(this.dt.columns().header(), function (v, i) {
            return {order: i, column_name: v.innerHTML, visible: column_visibles[i]};
        });
    }

    labelingRows(verdict) {
        let rows_affected = this.mark_verdict(verdict);
        //_m.EventMultipleLabelingsByMenuContext(rows_affected, verdict);
    };

    get_row_data(tr_dom) {
        return this.dt.rows(tr_dom).data()[0];
    }

    get_dist_ip_data_by_class(klass = '.action'){
        return this.dt.rows(klass).data()[0][this.aux_columns.dist_ip.index].toString()
    }

    get_dt_id_data_by_class(klass = '.action'){
        return this.dt.rows(klass).data()[0][this.aux_columns.dt_id.index].toString()
    }

    get_url_data_by_class(klass = '.action'){
        return this.dt.rows(klass).data()[0][this.aux_columns.url.index].toString()
    }

    get_verdict_data_by_class(klass = '.action'){
        return this.dt.rows(klass).data()[0][this.aux_columns.verdict.index].toString()
    }

    // WORKERS
    getHelperFlowsGroupedBy(ioc){
        return this.analysis_session_obj._helper.getFlowsGroupedBy(COL_END_POINTS_SERVER_STR, ioc);
    }
    setBulkVerdict_WORKER (verdict, flows_labelled) {
        let thiz = this;
        let COLUMN_VERDICT = this.aux_columns.verdict.index,
            COLUMN_REG_STATUS = this.aux_columns.reg_status.index,
            COLUMN_DT_ID = this.aux_columns.dt_id.index;
        this.dt.rows('.selected').nodes().to$().removeClass('selected');
        showLoading();
        let blob = new Blob(["onmessage = function(e) { " +
            "let verdict = e.data[1];" +
            "let rows_data = e.data[2];" +
            "let col_dt_id = e.data[3];" +
            "let col_verdict = e.data[4];" +
            "let origin = e.data[5];" +
            "let col_reg_status = e.data[6];" +
            "let reg_status = e.data[7];" +
            "self.importScripts(origin+'/static/manati_ui/js/libs/underscore-min.js');" +
            "let flows_labelled = _.map(e.data[0],function(v,i){ return v.dt_id});" +
            "for(let i = 0; i< rows_data.length; i++) {" +
                "let row_dt_id = rows_data[i][col_dt_id]; " +
                "let index = flows_labelled.indexOf(row_dt_id); " +
                "if(index >=0){" +
                    "rows_data[i][col_verdict] = verdict ;" +
                    "rows_data[i][col_reg_status] = reg_status.modified ;" +
                "}" +
            "};" +
            "self.postMessage(rows_data);" +
        "}"]);
        let blobURL = window.URL.createObjectURL(blob);
        let worker = new Worker(blobURL);
        worker.addEventListener('message', function (e) {
            let rows_data = e.data;
            let current_page = thiz.dt.page.info().page;
            thiz.dt.clear().rows.add(rows_data).draw();
            thiz.dt.page(current_page).draw('page');
            hideLoading();
        });
        let rows_data = thiz.dt.rows().data().toArray();
        worker.postMessage([flows_labelled, verdict, rows_data,
            COLUMN_DT_ID, COLUMN_VERDICT, document.location.origin, COLUMN_REG_STATUS, REG_STATUS]);
    };

}

export default DynamicTable;

