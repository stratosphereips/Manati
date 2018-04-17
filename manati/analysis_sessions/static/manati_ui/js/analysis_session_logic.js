/**
 * Created by raulbeniteznetto on 8/10/16.
 */



import {showLoading, hideLoading, set_default} from "./modules/helpers/utils.js";
import {TIME_SYNC_DB} from "./modules/helpers/constants.js";
import DynamicTable from "./modules/controllers/dynamic_table.js";
import Modals from "./modules/controllers/modals.js";
import Metrics from "./modules/controllers/users_metrics.js";
import ReaderFile from "./modules/controllers/reader_files.js";
import ContextualMenu from "./modules/controllers/contextual_menu.js";
import Shortcuts from "./modules/controllers/shortcuts.js"

export function syncDB(show_loading = false) {
        let thiz = _analysisSessionLogic; // super general variable
        if (show_loading) showLoading();
        let $dt = thiz.dynamic_table.dt;
        let arr_list = $dt.rows('.modified').data();
        let $rows = $dt.rows('.modified').nodes().to$();
        let COLUMN_REG_STATUS = thiz.dynamic_table.aux_columns.reg_status.index,
            COLUMN_DT_ID = thiz.dynamic_table.aux_columns.dt_id.index,
            COLUMN_VERDICT = thiz.dynamic_table.aux_columns.verdict.index;
        let _analysis_session_id = thiz.getAnalysisSessionId();
        $rows.addClass('modified-sync');
        $rows.removeClass('modified');
        let data_row = {};
        arr_list.each(function (elem) {
            if (elem[COLUMN_REG_STATUS] !== -1) {
                let key_id = elem[COLUMN_DT_ID].split(':').length <= 1 ? _analysis_session_id + ":" + elem[COLUMN_DT_ID] : elem[COLUMN_DT_ID];
                data_row[key_id] = elem[COLUMN_VERDICT];
            }
        });
        let data = {'analysis_session_id': _analysis_session_id, 'data': data_row};
        if (thiz.getColumnsOrderFlat()) {
            data['headers[]'] = JSON.stringify(thiz.dynamic_table.get_headers_info());
            thiz.setColumnsOrderFlat(false);
        }
        $.ajax({
            type: "POST",
            data: JSON.stringify(data),
            dataType: "json",
            url: "/manati_project/manati_ui/analysis_session/sync_db",
            // handle a successful response
            success: function (json) {
                // $('#post-text').val(''); // remove the value from the input
                // console.log(json); // log the returned json to the console
                let data = JSON.parse(json['data']);
                console.log(data);

                $.each(data, function (index, elem) {
                    let id = elem.pk;
                    thiz._verdict_sync[id] = {
                        verdict: elem.fields.verdict,
                        register_status: elem.fields.register_status
                    };
                    // console.log(elem);
                    // let dt_id = parseInt(elem.pk.split(':')[1]);
                    // let row = _dt.rows('[data-dbid="'+id+'"]');
                    // let index_row = row.indexes()[0];
                    //  row.nodes().to$().addClass('selected-sync');
                    // thiz.setColumnsOrderFlat(false);
                    //  thiz.markVerdict(elem.fields.verdict,'selected-sync');
                    // row.nodes().to$().removeClass('modified');
                    // _dt.cell(index_row, COLUMN_VERDICT).data(elem.fields.verdict);
                    // _dt.cell(index_row, COLUMN_REG_STATUS).data(elem.fields.register_status);


                });
                $('tr.modified-sync').removeClass('modified-sync');
                thiz.dynamic_table.dt.draw(false);
                console.log("DB Synchronized");
                if (show_loading) hideLoading();
            },

            // handle a non-successful response
            error: function (xhr, errmsg, err) {
                $('#results').html("<div class='alert-box alert radius' data-alert>Oops! We have encountered an error: " + errmsg +
                    " <a href='#' class='close'>&times;</a></div>"); // add the error to the dom
                console.error(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
                $('#save-table').attr('disabled', false).removeClass('disabled');
                // $.notify(xhr.status + ": " + xhr.responseText, "error");
                $.notify(xhr.status + ": " + xhr.responseText);
                //NOTIFY A ERROR
                clearInterval(thiz._sync_db_interval);
                // _m.EventAnalysisSessionSavingError(_filename);
                hideLoading();
            }

        });
    };

class AnalysisSessionLogic {
    constructor() {
        this._m = new Metrics(true, this);
        this.modals = new Modals();
        this.dynamic_table = new DynamicTable(this);
        this.reader_files = new ReaderFile(this);
        this.contextual_menu = new ContextualMenu(this);
        this.shortcuts = new Shortcuts(this);

        this._verdict_sync = {};
        this.columns_order_changed = false;
        this._analysis_session_id = -1;
        this._analysis_session_uuid = null;
        this._filename = null;
        this._analysis_session_type_file = null;
        this._size_file = null;
        this._type_file = null;
        this._sync_db_interval = null;
        this._helper = null;
        this._flows_grouped = null;


        this.on_ready_fn();
        // window.onbeforeunload = function() {
        //     return "Mate, are you sure you want to leave? Think of the kittens!";
        // }
    }

    /************************************************************
     GLOBAL ATTRIBUTES
     *************************************************************/

    setFileName (file_name) {
        $("#weblogfile-name").html(file_name);
        this._filename = file_name;
    };

    getFileName () {
        return this._filename;
    };

    getAnalysisSessionName () {
        return this._filename;
    };
    getColumnsOrderFlat () {
        return this.columns_order_changed;
    };
    setColumnsOrderFlat (v) {
        this.columns_order_changed = v;
    };
    getAnalysisSessionId  () {
        return this._analysis_session_id;
    };
    setAnalysisSessionId (id) {
        this._analysis_session_id = id;
    };

    setAnalysisSessionUUID (uuid) {
        this._analysis_session_uuid = uuid;
    };
    getAnalysisSessionUUID () {
        return this._analysis_session_uuid;
    };
    getAnalysisSessionTypeFile () {
        return this._analysis_session_type_file
    };
    setAnalysisSessionTypeFile (type_file) {
        this._analysis_session_type_file = type_file
    };

    generateAnalysisSessionUUID() {
        if (this._analysis_session_uuid === undefined || this._analysis_session_uuid === null) {
            this._analysis_session_uuid = uuid.v4();
        }
    };

    isSaved () {
        return this._analysis_session_id !== -1
    };


    /************************************************************
     PRIVATE FUNCTIONS
     *************************************************************/

    stopInterval() {
        clearInterval(this._sync_db_interval);
    }



    saveDB(){
        try {
            var thiz = this;
            showLoading();
            $.notify("Starting process to save the Analysis Session, it takes time", "info", {autoHideDelay: 6000});
            $('#save-table').attr('disabled', true).addClass('disabled');
            let rows = this.dynamic_table.dt.rows();
            // _m.EventAnalysisSessionSavingStart(rows.length, _filename);
            let data = {
                filename: this.getFileName(),
                "headers[]": JSON.stringify(this.dynamic_table.get_headers_info()),
                'data[]': JSON.stringify(rows.data().toArray()),
                type_file: this.getAnalysisSessionTypeFile(),
                uuid: this.getAnalysisSessionUUID()
            };
            //send the name of the file, and the first 10 registers
            $.ajax({
                type: "POST",
                data: data,
                dataType: "json",
                url: "/manati_project/manati_ui/analysis_session/create",
                // handle a successful response
                success: function (json) {
                    let analysis_session_id = json['data']['analysis_session_id'];
                    thiz.setAnalysisSessionId(analysis_session_id);
                    thiz.setFileName(json['data']['filename']);
                    thiz.dynamic_table.dt.column(thiz.dynamic_table.aux_columns.reg_status.index, {search: 'applied'}).nodes().each(function (cell, i) {
                        let tr = $(cell).closest('tr');
                        if (!tr.hasClass("modified")) cell.innerHTML = 0;
                    });
                    // _m.EventAnalysisSessionSavingFinished(_filename, _analysis_session_id);
                    $.notify("All Weblogs (" + json['data']['data_length'] + ") were created successfully ", 'success');
                    $('#save-table').hide();
                    $('#public-btn').show();
                    $('#wrap-form-upload-file').hide();
                    history.pushState({},
                        "Edit AnalysisSession " + analysis_session_id,
                        "/manati_project/manati_ui/analysis_session/" + analysis_session_id + "/edit");
                    thiz._sync_db_interval = setInterval(syncDB, TIME_SYNC_DB);
                    hideLoading();
                    thiz.setColumnsOrderFlat(false);
                    $("#weblogfile-name").off('click');
                    $("#weblogfile-name").css('cursor', 'auto');
                    $("#sync-db-btn").show();
                    //show comment and update form
                    $("#coments-as-nav").show();
                    $('#comment-form').attr('action', '/manati_project/manati_ui/analysis_session/' + analysis_session_id + '/comment/create')
                },

                // handle a non-successful response
                error: function (xhr, errmsg, err) {
                    $('#results').html("<div class='alert-box alert radius' data-alert>Oops! We have encountered an error: " + errmsg +
                        " <a href='#' class='close'>&times;</a></div>"); // add the error to the dom
                    console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
                    $('#save-table').attr('disabled', false).removeClass('disabled');
                    $('#public-btn').hide();
                    $.notify(xhr.status + ": " + xhr.responseText, "error");
                    //NOTIFY A ERROR
                    // _m.EventAnalysisSessionSavingError(_filename);
                    hideLoading();
                }
            });
        } catch (e) {
            // thiz.destroyLoading();
            $.notify(e, "error");
            $('#public-btn').hide();
            $('#save-table').attr('disabled', false).removeClass('disabled');
        }
    }


    static executeFilterBtn (verdict) {
        $('.searching-buttons .btn').filter('[data-verdict="' + verdict + '"]').click()
    };


    on_ready_fn() {
        let thiz = this;
        $(document).ready(function () {
            $(document).on('click', '#search-domain-selected', function (ev) {
                let query_search = "(";
                let aux = '';
                $('#vt_consult_screen input[name="search_domain_table[]"]:checked').each(function (obj) {
                    query_search += aux + $(this).val();
                    if (aux == '') aux = '|';
                });
                query_search += ")";
                if (query_search.length > 2) {
                    $("#weblogs-datatable_filter input[type='search']").html(query_search);
                    _dt.search(query_search).draw();
                }


            });
            $("#edit-input").hide();
            $("#weblogfile-name").on('click', function () {
                let _thiz = $(this);
                let input = $("#edit-input");
                input.val(_thiz.html());
                _thiz.hide();
                input.show();
                input.focus();
            });
            $("#edit-input").on('blur', function () {
                let _thiz = $(this);
                let label = $("#weblogfile-name");
                let text_name = _thiz.val();
                if (text_name.length > 0) {
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
            $('body').on('click', '.searching-buttons .btn', function () {
                let btn = $(this);
                let verdict = btn.data('verdict');
                if (btn.hasClass('active')) {
                    thiz.dynamic_table._filterDataTable.removeFilter(_dt, verdict);
                    btn.removeClass('active');
                }
                else {
                    thiz.dynamic_table._filterDataTable.applyFilter(_dt, verdict);
                    btn.addClass('active');
                }

            });
            $('body').on('click', '.unselect', function (ev) {
                ev.preventDefault();
                thiz.dynamic_table._filterDataTable.removeFilter(_dt);
                $('.searching-buttons .btn').removeClass('active')
            });

            thiz.contextual_menu.contextMenuSettings();
            $('#save-table').on('click', function () {
                thiz.saveDB();
            });

            //event for sync button
            $('#sync-db-btn').on('click', function (ev) {
                ev.preventDefault();
                syncDB(true);
            });

            $('body').on('submit', '#comment-form', function (ev) {
                ev.preventDefault();
                let form = $(this);
                $.ajax({
                    url: form.context.action,
                    type: 'POST',
                    data: form.serialize(),
                    dataType: 'json',
                    success: function (json) {
                        $.notify(json.msg, "info");

                    },
                    error: function (xhr, errmsg, err) {
                        $.notify(xhr.status + ": " + xhr.responseText, "error");
                        console.log(xhr.status + ": " + xhr.responseText);


                    }
                })
            });

            thiz.shortcuts.define_hotkeys();

            $("input#share-checkbox").change(function () {
                $.ajax({
                    url: '/manati_project/manati_ui/analysis_session/' + thiz.getAnalysisSessionId() + '/publish',
                    type: 'POST',
                    data: {'publish': $(this).prop('checked') ? "True" : "False"},
                    dataType: 'json',
                    success: function (json) {
                        $.notify(json.msg, "info");
                    },
                    error: function (xhr, errmsg, err) {
                        $.notify(xhr.status + ": " + xhr.responseText, "error");
                        console.log(xhr.status + ": " + xhr.responseText);


                    }
                })
            });

            $("button#change-status").on('click', function () {
                $.ajax({
                    url: '/manati_project/manati_ui/analysis_session/' + thiz.getAnalysisSessionId() + '/change_status',
                    type: 'POST',
                    data: {'status': $(this).data('status')},
                    dataType: 'json',
                    success: function (json) {
                        $.notify(json.msg, "info");
                        let old_status = json.old_status;
                        let new_status = json.new_status;
                        let btn = $('#change-status');
                        btn.removeClass();
                        btn.addClass('btn btn-special-' + old_status);
                        btn.data('status', old_status);
                        let text = new_status === 'open' ? 'Close it !' : 'Open it !';
                        btn.text(text);
                        if (new_status === 'closed') {
                            $.notify("This Analysis Session is done, you will be redirect to the index page ", "info", {autoHideDelay: 3000});
                            window.location.href = "/manati_project/manati_ui/analysis_sessions";
                        }
                    },
                    error: function (xhr, errmsg, err) {
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
      eventBeforeParing(file) {
        this._size_file = file.size;
        this._type_file = file.type;
        this.setFileName(file.name);
        showLoading();
        // _m.EventFileUploadingStart(file.name, _size_file, _type_file);
        console.log("Parsing file...", file);
        $.notify("Parsing file...", "info");
    };


    build_FilePreviewer(headers, data) {
        let $html = $('<div class="content"></div>');
        let $ul = $('<ol id="list-column">');
        for (let i = 0; i < headers.length; i++) {
            let header_options = ['column_' + i].concat([headers[i]].concat(DEFAULT_COLUMNS_NAMES));
            let select_tag = $('<select>');
            select_tag.attr('id', 'column_' + i);
            for (let x = 0; x < header_options.length; x++) {
                let value = header_options[x];
                select_tag.append($('<option>').html(value.substring(0, 30)).attr("value", value));
            }
            $ul.append($('<li>').html(select_tag));

        }
        let $ul_list_key = $('<ol id="list-key">');
        $ul_list_key.append($('<li id="key-http-url">').html("http.url or host"));
        $ul_list_key.append($('<li id="key-endpoints-server">').html("endpoints.server or id.resp_h"));
        $html.html("<h4>ManaTI does not recognize uploaded file,  please, select the columns name of your data</h4>");
        let $wrap = $('<div class="row"></div>');
        $wrap.html($('<div class="col-md-6 list-select"></div>').html($ul));
        $wrap.append($('<div class="col-md-6 list-key"><h5>Mandatories columns </h5></div>').append($ul_list_key));
        $html.append($wrap);
        return $html;
    }

    parseData(file_rows, with_header, type_file, delimiter) {
        with_header = set_default(with_header, true);
        type_file = set_default(type_file, '');
        delimiter = set_default(delimiter, "");
        var thiz = this;
        let completeFn = function (results, file) {
            if (results && results.errors) {
                if (results.errors) {
                    let errorCount = results.errors.length;
                    let firstError = results.errors[0];
                    console.error(errorCount,firstError);
                }
                if (results.data && results.data.length > 0) {

                    console.log("Done with all files");
                    //INIT DATA
                    let rowCount = results.data.length;
                    let data = results.data;
                    try {
                        if (thiz.getAnalysisSessionTypeFile() === 'apache_http_log') {
                            thiz.modals.showModalCheckingTypeFile(thiz.getFileName(), data[0], data);
                        }
                        else {
                            let headers = Object.keys(data[0]);
                            thiz.dynamic_table.settingsForInitData(headers, data);
                        }
                    } catch (e) {
                        console.error(e);

                    }


                }

            }
        };
        this.setAnalysisSessionTypeFile(type_file);

        Papa.parse(file_rows,
            {
                delimiter: delimiter,
                header: with_header,
                quoteChar: '"',
                complete: completeFn,
                worker: true,
                skipEmptyLines: true,
                error: function (err, file, inputElem, reason) {
                    console.log("ERROR Parsing:", err, file);
                    $.notify("ERROR Parsing:" + " " + err + " " + file, "error");
                    _m.EventFileUploadingError(file.name);
                }
            }
        );
    };



    updateAnalysisSessionUUID (analysis_session_id, weblogs_id_uuid) {
        thiz.generateAnalysisSessionUUID();
        let ids = _.keys(weblogs_id_uuid);
        let uuids = _.values(weblogs_id_uuid);
        $.ajax({
            url: '/manati_project/manati_ui/analysis_session/' + analysis_session_id + '/update_uuid',
            type: 'POST',
            data: {
                'uuid': thiz.getAnalysisSessionUUID(),
                "weblogs_ids[]": JSON.stringify(ids),
                "weblogs_uuids[]": JSON.stringify(uuids)
            },
            dataType: "json",
            success: function (json) {
                $.notify(json.msg, "info");
            },
            error: function (xhr, errmsg, err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
                _m.EventLoadingEditingError(analysis_session_id);

            }
        });

    };

    callingEditingData (analysis_session_id) {
        let thiz = this;
        this.setAnalysisSessionId(analysis_session_id);
        let data = {'analysis_session_id': thiz.getAnalysisSessionId()};
        $.notify("The page is being loaded, maybe it will take time", "info", {autoHideDelay: 3000});
        showLoading();
        // _m.EventLoadingEditingStart(thiz.getAnalysisSessionId());
        $.ajax({
            type: "GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/analysis_session/get_weblogs",
            success: function (json) {// handle a successful response
                let weblogs = json['weblogs'];
                let analysis_session_id = json['analysissessionid'];
                let analysis_session_uuid = json['analysissessionuuid'];
                let file_name = json['name'];
                let headers = JSON.parse(json['headers']);
                thiz.setFileName(file_name);
                if (analysis_session_uuid !== null && analysis_session_uuid !== '') {
                    thiz.setAnalysisSessionUUID(analysis_session_uuid);
                }

                thiz.dynamic_table.initDataEdit(weblogs, analysis_session_id, headers);
                // _m.EventLoadingEditingFinished(analysis_session_id, weblogs.length)
            },

            error: function (xhr, errmsg, err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
                _m.EventLoadingEditingError(analysis_session_id);

            }
        });

    };



    processingFlows_WORKER (flows, col_host_str, col_ip_str) {
        let thiz = this;
        $("#statical-section").html('');
        this._flows_grouped = {};
        let blob = new Blob(["onmessage = function(e) { " +
            "let flows = e.data[1];" +
            "let flows_grouped = e.data[0];" +
            "let origin = e.data[2];" +
            "let col_host_str = e.data[3];" +
            "let co_ip_str = e.data[4];" +
            "self.importScripts(origin+'/static/manati_ui/js/libs/underscore-min.js');\n" +
            "self.importScripts(origin+'/static/manati_ui/js/struct_helper.js');\n" +
            "let helper = new FlowsProcessed(col_host_str,co_ip_str);" +
            "helper.addBulkFlows(flows);" +
            "self.postMessage(helper.getFlowsGrouped());" +
        "}"]);

        // Obtain a blob URL reference to our worker 'file'.
        let blobURL = window.URL.createObjectURL(blob);
        let worker = new Worker(blobURL);
        worker.addEventListener('message', function (e) {
            worker.terminate();
            thiz._flows_grouped = e.data;
            thiz._helper = new FlowsProcessed(col_host_str, col_ip_str);
            thiz._helper.setFlowsGrouped(thiz._flows_grouped);
            thiz._helper.makeStaticalSection();
            console.log("Worker Done");
        });
        worker.postMessage([thiz._flows_grouped, flows, document.location.origin, col_host_str, col_ip_str]);

    };


}

export default AnalysisSessionLogic;
