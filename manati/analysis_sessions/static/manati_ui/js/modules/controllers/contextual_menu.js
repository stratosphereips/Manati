import {VERDICTS_AVAILABLE} from '../helpers/constants.js';
import {isEmpty, findDomainOfURL, copyTextToClipboard} from '../helpers/utils.js';

class ContextualMenu {
    constructor(analysis_session_obj) {
        this._bulk_marks_wbs = {};
        this.dynamic_table_obj = analysis_session_obj.dynamic_table;
        this.analysis_session_obj = analysis_session_obj;
        this.modals = analysis_session_obj.modals;

    }

    contextMenuSettings() {
        let thiz = this;
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
                    thiz._bulk_marks_wbs = {};
                    thiz._bulk_verdict = null;
                }
            },
            build: function ($trigger, e) {
                return {
                    callback: function (key, options) {
                        thiz.dynamic_table_obj.labelingRows(key);
                        return true;
                    },
                    items: thiz._generateContextMenuItems($trigger)

                }
            }


        });
    }

    // contextMenuConfirmMsg(rows, verdict) {
    //     $.confirm({
    //         title: 'Weblogs Affected',
    //         content: "Will " + rows.length.toString() + ' weblogs change their verdicts, is ok for you? ',
    //         confirm: function () {
    //             _dt.rows('.selected').nodes().to$().removeClass('selected');
    //             _dt.rows(rows).nodes().to$().addClass('selected');
    //             thiz.markVerdict(verdict);
    //         },
    //         cancel: function () {
    //
    //         }
    //     });
    // }

    _generateContextMenuItems(tr_dom) {
        // let tr_active = $("tr.menucontext-open.context-menu-active");
        let thiz = this;
        let items_menu = {};
        let _analysis_session_id = thiz.analysis_session_obj.getAnalysisSessionId();
        VERDICTS_AVAILABLE.forEach(function (v) {
            items_menu[v] = {name: v, icon: "fa-paint-brush " + v}
        });
        let col_url_index = this.dynamic_table_obj.aux_columns.url.index,
            col_dist_ip_index = this.dynamic_table_obj.aux_columns.dist_ip.index,
            col_dist_ip_class = this.dynamic_table_obj.aux_columns.dist_ip.class,
            col_url_class = this.dynamic_table_obj.aux_columns.url.class,
            col_dist_ip_str = this.dynamic_table_obj.aux_columns.dist_ip.str,
            col_url_str = this.dynamic_table_obj.aux_columns.url.str,
            col_verdict = this.dynamic_table_obj.aux_columns.verdict.index,
            col_dt_id_index = this.dynamic_table_obj.aux_columns.dt_id.index;

        let items_submenu_external_query = {};
        items_submenu_external_query['virus_total_consult'] = {
            name: "VirusTotal", icon: "fa-search",
            items: {}
        };
        items_submenu_external_query['whois_consult'] = {
            name: "Whois", icon: "fa-search",
            items: {}
        };

        let tr_dom_data = this.dynamic_table_obj.get_row_data(tr_dom);
        items_menu['unselect'] = {
            name: "Unselect",
            icon: "fa-paint-brush " + "unselect",
            callback: function (key, options) {
                $('tr.selected').removeClass('selected');
            }
        };
        items_menu['sep1'] = "-----------";
        items_menu['fold1'] = {
            name: "Mark all WBs with same: ",
            icon: "fa-search-plus",
            // disabled: function(){ return !this.data('moreDisabled'); },
            items: {}
        };
        items_menu['fold4'] = {};
        items_menu['fold6'] = {
            name: "External Intelligence", icon: "fa-search",
            items: {}
        };
        items_menu['sep6'] = "-----------";
        items_menu['fold7'] = {
            name: "Copy to clipboard", icon: "fa-files-o",
            items: {}
        };
        items_menu['sep2'] = "-----------";

        let _bulk_verdict = tr_dom_data[col_verdict];
        let fn = function () {
            $('#button-ok-modal').off()
        };
        if (!isEmpty(col_url_index)) {
            let url = tr_dom_data[col_url_index];
            let domain = findDomainOfURL(url); // getting domain
            this._bulk_marks_wbs[col_url_class] = thiz.analysis_session_obj._helper.getFlowsGroupedBy(col_url_str, domain);
            items_menu['fold1']['items']['fold1-key2'] = {
                name: "By Domain (of column:" + col_url_str + ")" +
                "(" + thiz._bulk_marks_wbs[col_url_class].length + ")",
                icon: "fa-paint-brush",
                className: col_url_class,
                callback: function (key, options) {
                    // setBulkVerdict_WORKER(_bulk_verdict, _bulk_marks_wbs[col_url_class]);
                    _m.EventBulkLabelingByDomains(this._bulk_marks_wbs[col_url_class], _bulk_verdict, domain);
                }
            };
            items_submenu_external_query['virus_total_consult']['items']['fold2-key1'] = {
                name: "Looking for domain (of column:" + col_url_str + ")",
                icon: "fa-paper-plane-o",
                callback: function (key, options) {
                    let qn = tr_dom_data[col_url_index];
                    thiz.modals.consultVirusTotal(qn, "domain");

                }
            };
            items_submenu_external_query['whois_consult']['items']['fold2-key1'] = {
                name: "Looking for domain (of column: " + col_url_str + ")",
                icon: "fa-paper-plane-o",
                callback: function (key, options) {
                    let qn = tr_dom_data[col_url_index];
                    thiz.modals.consultWhois(qn, "domain");

                }
            };

            if (thiz.analysis_session_obj.isSaved()) {
                items_menu['fold1']['items']['fold1-key3'] = {
                    name: "Mark all WBs WHOIS related (domain from column:" + col_url_str + ")",
                    icon: "fa-paint-brush",
                    className: col_url_class,
                    callback: function (key, options) {
                        let weblog_id = tr_dom_data[col_dt_id_index].toString();
                        weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
                        thiz.labelWeblogsWhoisRelated(weblog_id, _bulk_verdict)

                        // setBulkVerdict_WORKER(_bulk_verdict, _bulk_marks_wbs[CLASS_MC_HTTP_URL_STR]);
                        // _m.EventBulkLabelingByDomains(_bulk_marks_wbs[CLASS_MC_HTTP_URL_STR],_bulk_verdict, domain);
                    }

                };

                items_submenu_external_query['whois_consult']['items']['fold2-key3'] = {
                    name: "Find WHOIS related domains (from column:" + col_url_str + ")",
                    icon: "fa-search",
                    callback: function (key, option) {
                        let weblog_id = tr_dom_data[col_dt_id_index].toString();
                        weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
                        thiz.modals.getWeblogsWhoisRelated(weblog_id);

                    }
                };



            }

            items_menu['fold7']['items']["fold2-key1"] = {
                name: "Copy URL (of column: " + col_url_str + ")",
                icon: "fa-file-o",
                callback: function (key, options) {
                    copyTextToClipboard(tr_dom_data[col_url_index]);
                }
            }

        }
        if (!isEmpty(col_dist_ip_index)) {
            let ip_value = tr_dom_data[col_dist_ip_index]; // getting dist ip
            this._bulk_marks_wbs[col_dist_ip_class] = thiz.analysis_session_obj._helper.getFlowsGroupedBy(col_dist_ip_str, ip_value);
            items_menu['fold1']['items']['fold1-key1'] = {
                name: "By IP (of column: " + col_dist_ip_str + ")" +
                "(" + this._bulk_marks_wbs[col_dist_ip_class].length + ")",
                icon: "fa-paint-brush",
                className: col_dist_ip_class,
                callback: function (key, options) {
                    thiz.dynamic_table_obj.setBulkVerdict_WORKER(_bulk_verdict, thiz._bulk_marks_wbs[col_dist_ip_class]);
                    //_m.EventBulkLabelingByEndServerIP(this._bulk_marks_wbs[col_dist_ip_class], _bulk_verdict, ip_value);

                }
            };
            items_submenu_external_query['virus_total_consult']['items']['fold2-key2'] = {
                name: "Looking for IP (of column: " + col_dist_ip_str + ")",
                icon: "fa-paper-plane-o",
                callback: function (key, options) {
                    let qn = tr_dom_data[col_dist_ip_index];
                    thiz.modals.consultVirusTotal(qn, "ip");
                }
            };
            items_submenu_external_query['whois_consult']['items']['fold2-key2'] = {
                name: "Looking for IP (of column: " + col_dist_ip_str + ")",
                icon: "fa-paper-plane-o",
                callback: function (key, options) {
                    let qn = tr_dom_data[col_dist_ip_index];
                    thiz.modals.consultWhois(qn, "ip");
                }
            };

            items_menu['fold7']['items']["fold2-key2"] = {
                name: "Copy IP (of column: " + col_dist_ip_str + ")",
                icon: "fa-file-o",
                callback: function (key, options) {
                    copyTextToClipboard(tr_dom_data[col_dist_ip_index]);
                }
            };
        }

        if (thiz.analysis_session_obj.isSaved()) {

            items_menu['fold4'] = {
                name: "Registry History", icon: "fa-search",
                items: {
                    "fold2-key1": {
                        name: "Veredict History",
                        icon: "fa-paper-plane-o",
                        callback: function (key, options) {
                            let weblog_id = tr_dom_data[col_dt_id_index].toString();
                            weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
                            thiz.modals.getWeblogHistory(weblog_id);

                        }
                    },
                    "fold2-key2": {
                        name: "Modules Changes",
                        icon: "fa-paper-plane-o",
                        callback: function (key, options) {
                            let weblog_id = tr_dom_data[col_dt_id_index].toString();
                            weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
                            thiz.modals.getModulesChangesHistory(weblog_id);
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
                            let weblog_id = tr_dom_data[col_dt_id_index].toString();
                            weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
                            thiz.modals.getWeblogHistory(weblog_id);

                        }
                    },
                    "fold2-key2": {
                        name: "Modules Changes",
                        icon: "fa-paper-plane-o",
                        callback: function (key, options) {
                            let weblog_id = tr_dom_data[col_dt_id_index].toString();
                            weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
                            thiz.modals.getModulesChangesHistory(weblog_id);
                        }
                    },
                    "fold2-key3": {
                        name: "IOCs",
                        icon: "fa-paper-plane-o",
                        callback: function (key, options) {
                            let weblog_id = tr_dom_data[col_dt_id_index].toString();
                            weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
                            thiz.modals.getIOCs(weblog_id);
                        }
                    }
                }
            };

            items_menu['sep5'] = "-----------";
            items_menu['fold5'] = {
                name: "Create a comment", icon: "fa-pencil-square-o",
                callback: function (key, options) {
                    let weblog_id = tr_dom_data[col_dt_id_index];
                    thiz.modals.create_weblog_comment(weblog_id,fn)
                }
            };
        }

        items_menu['fold6']['items'] = items_submenu_external_query;
        items_menu['sep7'] = "-----------";
        items_menu['fold8'] = {
            name: "Hotkeys List", icon: "fa-files-o",
            callback: function (key, options) {
                thiz.modals.consultShortcut();
            },
        };


        return items_menu;

    };

    labelWeblogsWhoisRelated(weblog_id, verdict){
        $.notify("One request for the DB was realized, maybe it will take time to process it and" +
                            " show the information in the modal.",
                            "warn", {autoHideDelay: 2000});
        let data = {weblog_id: weblog_id, verdict: verdict};
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


}

export default ContextualMenu;


