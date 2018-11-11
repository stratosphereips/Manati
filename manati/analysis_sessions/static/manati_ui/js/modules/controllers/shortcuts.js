import {scrollIntoViewIfNeeded, findDomainOfURL} from '../helpers/utils.js';
import {syncDB} from '../../analysis_session_logic.js';

class Shortcuts {
    constructor(analysis_session_obj) {
        this.analysis_session_obj = analysis_session_obj;
        this.dynamic_table_obj = analysis_session_obj.dynamic_table_obj;
        this.modals = analysis_session_obj.modals;
        // this._dt = analysis_session_obj.dynamic_table.dt;

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
            thiz.analysis_session_obj.dynamic_table.labelingRows('malicious');
        });
        // mark legitimate
        Mousetrap.bind(['ctrl+l', 'command+l'], function (e) {
            preventDefault(e);
            thiz.analysis_session_obj.dynamic_table.labelingRows('legitimate');
        });
        // mark suspicious
        Mousetrap.bind(['ctrl+i', 'command+i'], function (e) {
            preventDefault(e);
            thiz.analysis_session_obj.dynamic_table.labelingRows('suspicious');
        });
        // mark false positive
        Mousetrap.bind(['ctrl+p', 'command+p'], function (e) {
            preventDefault(e);
            thiz.analysis_session_obj.dynamic_table.labelingRows('falsepositive');
        });
        // mark undefined
        Mousetrap.bind(['ctrl+u', 'command+u'], function (e) {
            preventDefault(e);
            thiz.analysis_session_obj.dynamic_table.labelingRows('undefined');
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
        //  // Unfilter everything
        // Mousetrap.bind(['ctrl+5', 'command+0'], function(e) {
        //     preventDefault(e);
        //     // TO-DO
        // });
        //
        //  // Unfilter everything
        // Mousetrap.bind(['space', 'space'], function(e) {
        //     preventDefault(e);
        //     // TO-DO
        // });
        // open VirusTotal Modal By domain, the first selected weblog
        Mousetrap.bind(['ctrl+shift+v', 'command+shift+v'], function (e) {
            preventDefault(e);
            let qn = thiz.analysis_session_obj.dynamic_table.get_url_data_by_class('.action');
            thiz.modals.consultVirusTotal(qn, "domain");
        });
        // open WHOIS Modal By domain, the first selected weblog
        Mousetrap.bind(['ctrl+shift+p', 'command+shift+p'], function (e) {
            preventDefault(e);
            let qn = thiz.analysis_session_obj.dynamic_table.get_url_data_by_class('.action');
            thiz.modals.consultWhois(qn, "domain");
        });
        // open VirusTotal Modal By IP, the first selected weblog
        Mousetrap.bind(['ctrl+shift+i', 'command+shift+i'], function (e) {
            preventDefault(e);
            let qn = thiz.analysis_session_obj.dynamic_table.get_dist_ip_data_by_class('.action');
            thiz.modals.consultVirusTotal(qn, "ip");
        });
        // open WHOIS Modal By IP, the first selected weblog
        Mousetrap.bind(['ctrl+shift+o', 'command+shift+o'], function (e) {
            // preventDefault(e);
            // let verdict = thiz.analysis_session_obj.dynamic_table.get_verdict_data_by_class('.action');
            // thiz.analysis_session_obj.dynamic_table.setBulkVerdict_WORKER(verdict, _bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR]);
        });
        //show whois similarity modal
        Mousetrap.bind(['ctrl+shift+d', 'command+shift+d'], function (e) {
            preventDefault(e);
            let weblog_id = thiz.analysis_session_obj.dynamic_table.get_dt_id_data_by_class('.action');
            let analysis_session_id = thiz.analysis_session_obj.getAnalysisSessionId();
            weblog_id = weblog_id.split(":").length <= 1 ? analysis_session_id + ":" + weblog_id : weblog_id;
            thiz.modals.getWeblogsWhoisRelated(weblog_id);
        });

        // VI-Style
        // moving down with J
        Mousetrap.bind(['j'], function (e) {
            preventDefault(e);
            let _dt = thiz.analysis_session_obj.dynamic_table.dt;
            let current_tr = $('#weblogs-datatable tbody tr.action').first();
            let next_tr;
            if (current_tr.length) {
                next_tr = current_tr.next().first();
                if (!next_tr.length) {
                    //move the page if it is possible
                    let current_page = this._dt.page.info().page;
                    if (_dt.page.info().pages > current_page + 1) {
                        // moving to the next one
                        _dt.page(current_page + 1).draw('page');
                    } else {
                        // moving to the first page, first row
                        _dt.page(0).draw('page');
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
            let _dt = thiz.analysis_session_obj.dynamic_table.dt;
            let scroll_tr;
            let current_tr = $('#weblogs-datatable tbody tr.action').first();
            let prev_tr;
            if (current_tr.length) {
                prev_tr = current_tr.prev().first();
                if (!prev_tr.length) {
                    //move the page if it is possible
                    let current_page = _dt.page.info().page;
                    if (0 <= current_page - 1) {
                        // moving to the previous page
                        this._dt.page(current_page - 1).draw('page');
                    } else {
                        // moving to the last page, last row
                        let pages = _dt.page.info().pages;
                        _dt.page(pages - 1).draw('page');
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
            let _dt = thiz.analysis_session_obj.dynamic_table.dt;
            let pages = _dt.page.info().pages;
            let current_page =_dt.page.info().page;
            if (current_page - 1 >= 0) {
                _dt.page(current_page - 1).draw('page');
            } else {
                _dt.page(pages - 1).draw('page');
            }
        });

        Mousetrap.bind(['right'], function (e) {
            preventDefault(e);
            let _dt = thiz.analysis_session_obj.dynamic_table.dt;
            let pages = _dt.page.info().pages;
            let current_page = _dt.page.info().page;
            if (current_page + 1 < pages) {
                _dt.page(current_page + 1).draw('page');
            } else {
                _dt.page(0).draw('page');
            }
        });

        //mark all the weblogs in the current session with the same IP
        Mousetrap.bind(['p'], function (e) {
            preventDefault(e);
            let dto = thiz.analysis_session_obj.dynamic_table;
            let ip_value = dto.get_dist_ip_data_by_class('.action');
            let verdict = dto.get_verdict_data_by_class('.action');
            dto.setBulkVerdict_WORKER(verdict, thiz.analysis_session_obj.dynamic_table.getHelperFlowsGroupedBy(ip_value));
        });

        //mark all  the weblogs in the current session with the same domain
        Mousetrap.bind(['d'], function (e) {
            preventDefault(e);
            let dto = thiz.analysis_session_obj.dynamic_table;
            let url = dto.get_url_data_by_class('.action');
            let domain = findDomainOfURL(url); // getting domain
            let verdict = dto.get_verdict_data_by_class('.action');
            dto.setBulkVerdict_WORKER(verdict, thiz.analysis_session_obj.dynamic_table.getHelperFlowsGroupedByDomain(domain));
        });


    };


}

export default Shortcuts;

