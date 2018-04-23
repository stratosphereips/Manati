import {scrollIntoViewIfNeeded} from '../helpers/utils.js';
import {syncDB} from '../../analysis_session_logic.js';

class Shortcuts {
    constructor(analysis_session_obj) {
        this.analysis_session_obj = analysis_session_obj;
        this.dynamic_table_obj = analysis_session_obj.dynamic_table_obj;
        this.modals = analysis_session_obj.modals;
        // this._dt = analysis_session_obj.dynamic_table_obj.dt;

    }

    define_hotkeys(){
        let thiz = this;
        let preventDefault = function (e) {
            if (e.preventDefault) {
                e.preventDefault();
            } else {
                // internet explorer
                e.returnValue = false;
            }
        };
        // active sync button
        Mousetrap.bind(['ctrl+s', 'command+s'], function (e) {
            preventDefault(e);
            if (thiz.analysis_session_obj.isSaved()) syncDB(true);
        });
        // mark malicious
        Mousetrap.bind(['ctrl+m', 'command+m'], function (e) {
            preventDefault(e);
            thiz.dynamic_table_obj.labelingRows('malicious');
        });
        // mark legitimate
        Mousetrap.bind(['ctrl+l', 'command+l'], function (e) {
            preventDefault(e);
            thiz.dynamic_table_obj.labelingRows('legitimate');
        });
        // mark suspicious
        Mousetrap.bind(['ctrl+i', 'command+i'], function (e) {
            preventDefault(e);
            thiz.dynamic_table_obj.labelingRows('suspicious');
        });
        // mark false positive
        Mousetrap.bind(['ctrl+p', 'command+p'], function (e) {
            preventDefault(e);
            thiz.dynamic_table_obj.labelingRows('falsepositive');
        });
        // mark undefined
        Mousetrap.bind(['ctrl+u', 'command+u'], function (e) {
            preventDefault(e);
            thiz.dynamic_table_obj.labelingRows('undefined');
        });
        // unselect selected rows
        Mousetrap.bind(['shift+ctrl+u', 'shift+command+u'], function (e) {
            preventDefault(e);
            $('tr.selected').removeClass('selected');
        });
        // Filter all Malicious
        Mousetrap.bind(['ctrl+1', 'command+1'], function (e) {
            preventDefault(e);
            thiz.analysis_session_obj.executeFilterBtn('malicious');
        });
        // Filter all Legitimate
        Mousetrap.bind(['ctrl+2', 'command+2'], function (e) {
            preventDefault(e);
            thiz.analysis_session_obj.executeFilterBtn('legitimate');
        });
        // Filter all Suspicious
        Mousetrap.bind(['ctrl+3', 'command+3'], function (e) {
            preventDefault(e);
            thiz.analysis_session_obj.executeFilterBtn('suspicious');
        });
        // Filter all False Positive
        Mousetrap.bind(['ctrl+4', 'command+4'], function (e) {
            preventDefault(e);
            thiz.analysis_session_obj.executeFilterBtn('falsepositive');
        });
        // Filter all Undefined
        Mousetrap.bind(['ctrl+5', 'command+5'], function (e) {
            preventDefault(e);
            thiz.analysis_session_obj.executeFilterBtn('undefined');
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
        Mousetrap.bind(['ctrl+shift+v', 'command+shift+v'], function (e) {
            preventDefault(e);
            let qn = thiz.dynamic_table_obj.get_url_data_by_class('.action');
            thiz.modals.consultVirusTotal(qn, "domain");
        });
        // open WHOIS Modal By domain, the first selected weblog
        Mousetrap.bind(['ctrl+shift+p', 'command+shift+p'], function (e) {
            preventDefault(e);
            let qn = thiz.dynamic_table_obj.get_url_data_by_class('.action');
            thiz.modals.consultWhois(qn, "domain");
        });
        // open VirusTotal Modal By IP, the first selected weblog
        Mousetrap.bind(['ctrl+shift+i', 'command+shift+i'], function (e) {
            preventDefault(e);
            let qn = thiz.dynamic_table_obj.get_dist_ip_data_by_class('.action');
            thiz.modals.consultVirusTotal(qn, "ip");
        });
        // open WHOIS Modal By IP, the first selected weblog
        Mousetrap.bind(['ctrl+shift+o', 'command+shift+o'], function (e) {
            // preventDefault(e);
            // let verdict = thiz.dynamic_table_obj.get_verdict_data_by_class('.action');
            // thiz.dynamic_table_obj.setBulkVerdict_WORKER(verdict, _bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR]);
        });
        //show whois similarity modal
        Mousetrap.bind(['ctrl+shift+d', 'command+shift+d'], function (e) {
            preventDefault(e);
            let weblog_id = thiz.dynamic_table_obj.get_dt_id_data_by_class('.action');
            weblog_id = weblog_id.split(":").length <= 1 ? thiz.getAnalysisSessionId() + ":" + weblog_id : weblog_id;
            this.modals.getWeblogsWhoisRelated(weblog_id);
        });

        // VI-Style
        // moving down with J
        Mousetrap.bind(['j'], function (e) {
            preventDefault(e);
            let current_tr = $('#weblogs-datatable tbody tr.action').first();
            let next_tr;
            if (current_tr.length) {
                next_tr = current_tr.next().first();
                if (!next_tr.length) {
                    //move the page if it is possible
                    let current_page = this._dt.page.info().page;
                    if (this._dt.page.info().pages > current_page + 1) {
                        // moving to the next one
                        this._dt.page(current_page + 1).draw('page');
                    } else {
                        // moving to the first page, first row
                        this._dt.page(0).draw('page');
                    }
                    next_tr = $('#weblogs-datatable tbody tr').first();
                    current_tr = null;
                }
            } else {
                next_tr = $('#weblogs-datatable tbody tr').first();
            }

            $('#weblogs-datatable tbody tr.action').removeClass('action');
            next_tr.addClass('action');
            if (current_tr) {
                scrollIntoViewIfNeeded(current_tr[0])
            } else {
                $("html, body").animate({scrollTop: 0}, "slow");
            }

        });

        // moving up with k
        Mousetrap.bind(['k'], function (e) {
            preventDefault(e);
            let scroll_tr;
            let current_tr = $('#weblogs-datatable tbody tr.action').first();
            let prev_tr;
            if (current_tr.length) {
                prev_tr = current_tr.prev().first();
                if (!prev_tr.length) {
                    //move the page if it is possible
                    let current_page = this._dt.page.info().page;
                    if (0 <= current_page - 1) {
                        // moving to the previous page
                        this._dt.page(current_page - 1).draw('page');
                    } else {
                        // moving to the last page, last row
                        let pages = this._dt.page.info().pages;
                        this._dt.page(pages - 1).draw('page');
                    }
                    prev_tr = $('#weblogs-datatable tbody tr').last();
                    scroll_tr = prev_tr;
                    current_tr = null;
                }
            } else {
                prev_tr = $('#weblogs-datatable tbody tr').last();
            }

            $('#weblogs-datatable tbody tr.action').removeClass('action');
            prev_tr.addClass('action');
            scroll_tr = scroll_tr ? scroll_tr : prev_tr.prev();
            if (scroll_tr.length) {
                scrollIntoViewIfNeeded(scroll_tr[0]);
            } else {
                $("html, body").animate({scrollTop: 0}, "slow");
            }

        });
        // select row to be label.
        Mousetrap.bind(['space'], function (e) {
            preventDefault(e);
            let current_tr = $('#weblogs-datatable tbody tr.action').first();
            current_tr.toggleClass('selected');

        });

        Mousetrap.bind(['left'], function (e) {
            preventDefault(e);
            let pages = this._dt.page.info().pages;
            let current_page = this._dt.page.info().page;
            if (current_page - 1 >= 0) {
                this._dt.page(current_page - 1).draw('page');
            } else {
                this._dt.page(pages - 1).draw('page');
            }
        });

        Mousetrap.bind(['right'], function (e) {
            preventDefault(e);
            let pages = this._dt.page.info().pages;
            let current_page = this._dt.page.info().page;
            if (current_page + 1 < pages) {
                thiz.dynamic_table_obj.dt.page(current_page + 1).draw('page');
            } else {
                thiz.dynamic_table_obj.dt.page(0).draw('page');
            }
        });

        //mark all the weblogs in the current session with the same IP
        Mousetrap.bind(['p'], function (e) {
            preventDefault(e);
            let ip_value = thiz.dynamic_table_obj.get_dist_ip_data_by_class('.action');
            let verdict = thiz.dynamic_table_obj.get_verdict_data_by_class('.action');
            thiz.dynamic_table_obj.setBulkVerdict_WORKER(verdict, _helper.getFlowsGroupedBy(COL_END_POINTS_SERVER_STR, ip_value));
        });

        //mark all  the weblogs in the current session with the same domain
        Mousetrap.bind(['d'], function (e) {
            preventDefault(e);
            let url = thiz.dynamic_table_obj.dt.rows('.action').data()[0][COLUMN_HTTP_URL].toString();
            let domain = findDomainOfURL(url); // getting domain
            let verdict = thiz.dynamic_table_obj.dt.rows('.action').data()[0][COLUMN_VERDICT].toString();
            thiz.dynamic_table_obj.setBulkVerdict_WORKER(verdict, _helper.getFlowsGroupedBy(COL_HTTP_URL_STR, domain));
        });


    };


}

export default Shortcuts;

