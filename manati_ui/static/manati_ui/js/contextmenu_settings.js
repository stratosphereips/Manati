/**
 * Created by raulbeniteznetto on 7/3/17.
 */
function refreshingDomainsWhoisRelatedModal(weblog_id){
    var data = {weblog_id: weblog_id};
    $.ajax({
        type:"GET",
        data: data,
        dataType: "json",
        url: "/manati_project/manati_ui/analysis_session/weblog/reload_modal_domains_whois_related",
        success : function(json) {// handle a successful response
            var whois_related_domains = json['whois_related_domains'];
            var was_related = json['was_related'];
            var table = buildTable_WeblogsWhoisRelated(whois_related_domains,was_related);
            updateBodyModal(table);
            if (was_related) {
                closingModal()

            }
        },
        error : function(xhr,errmsg,err) { // handle a non-successful response
            $.notify(xhr.status + ": " + xhr.responseText, "error");
            console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

        }
    });



}
var closingModal = function(){
    clearInterval(refreshIntervalId);
    refreshIntervalId = null;
};
function getWeblogsWhoisRelated(weblog_id){

    updateFooterModal('<a id="search-domain-selected" class="btn btn-info" data-dismiss="modal">Search Selected</a>');
    initModal("Activating WHOIS Similarity Distance Module..." , closingModal);
    var data = {weblog_id: weblog_id};
    $.ajax({
        type:"GET",
        data: data,
        dataType: "json",
        url: "/manati_project/manati_ui/analysis_session/weblog/modules_whois_related",
        success : function(json) {// handle a successful response
           // / var whois_related_domains = json['whois_related_domains'];
            $.notify(json['msg'], "info");
            updateTitleModal("List of domains WHOIS related with: " + json['domain_primary']);
            // var was_whois_related = json['was_whois_related'];
            // if(!was_whois_related){
            //     $.notify("One request for the DB was realized, maybe it will take time to process it and" +
            //             " show the information in the modal.",
            //             "warn", {autoHideDelay: 2000});
            // }
            // var table = buildTable_WeblogsWhoisRelated(whois_related_domains);
            // updateBodyModal(table);
            refreshIntervalId = setInterval(refreshingDomainsWhoisRelatedModal, 3000,weblog_id)


        },
        error : function(xhr,errmsg,err) { // handle a non-successful response
            $.notify(xhr.status + ": " + xhr.responseText, "error");
            console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

        }

    });

}
function labelWeblogsWhoisRelated(weblog_id, verdict){
    $.notify("One request for the DB was realized, maybe it will take time to process it and" +
                        " show the information in the modal.",
                        "warn", {autoHideDelay: 2000});
    var data = {weblog_id: weblog_id, verdict: verdict};
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

var _bulk_marks_wbs = {};
var _bulk_verdict;



function findDomainOfURL(url){
    var matching_domain = null;
    var domain = ( (matching_domain = url.match(REG_EXP_DOMAINS)) != null )|| matching_domain != undefined && matching_domain.length > 0 ? matching_domain[0] : null ;
    domain = (domain == null)  && ((matching_domain = url.match(REG_EXP_IP)) != null) || matching_domain != undefined && matching_domain.length > 0 ? matching_domain[0] : null;
    return domain
}



function ContextMenuSettings(datatable_setting){
    var _datatable_setting = datatable_setting;

    function generateContextMenuItems(tr_dom){
        // var tr_active = $("tr.menucontext-open.context-menu-active");
        // var bigData = _dt.rows(tr_dom).data()[0];
        // var ip_value = bigData[COLUMN_END_POINTS_SERVER]; // gettin end points server ip
        // var url = bigData[COLUMN_HTTP_URL];
        // var domain = findDomainOfURL(url); // getting domain
        var items_menu = {};
        // _bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR] = _helper.getFlowsGroupedBy(COL_END_POINTS_SERVER_STR,ip_value);
        // _bulk_marks_wbs[CLASS_MC_HTTP_URL_STR] = _helper.getFlowsGroupedBy(COL_HTTP_URL_STR,domain);
        // _bulk_verdict = bigData[COLUMN_VERDICT];
        _verdicts.forEach(function(v){
            items_menu[v] = {name: v, icon: "fa-paint-brush " + v }
        });
        items_menu['sep1'] = "-----------";
        // items_menu['fold1'] = {
        //     name: "Mark all WBs with same: ",
        //     icon: "fa-search-plus",
        //     // disabled: function(){ return !this.data('moreDisabled'); },
        //     items: {
        //     "fold1-key1": { name:  "By IP (of column: " + COL_END_POINTS_SERVER_STR+")" +
        //                             "("+_bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR].length+")",
        //                     icon: "fa-paint-brush",
        //                     className: CLASS_MC_END_POINTS_SERVER_STR,
        //                     callback: function(key, options) {
        //                         setBulkVerdict_WORKER(_bulk_verdict, _bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR]);
        //                         _m.EventBulkLabelingByEndServerIP(_bulk_marks_wbs[CLASS_MC_END_POINTS_SERVER_STR],_bulk_verdict, ip_value);
        //
        //                     }
        //                 },
        //     "fold1-key2": { name: "By Domain (of column:" + COL_HTTP_URL_STR +")" +
        //                             "("+_bulk_marks_wbs[CLASS_MC_HTTP_URL_STR].length+")",
        //                     icon: "fa-paint-brush",
        //                     className: CLASS_MC_HTTP_URL_STR,
        //                     callback: function(key, options) {
        //                         setBulkVerdict_WORKER(_bulk_verdict, _bulk_marks_wbs[CLASS_MC_HTTP_URL_STR]);
        //                         _m.EventBulkLabelingByDomains(_bulk_marks_wbs[CLASS_MC_HTTP_URL_STR],_bulk_verdict, domain);
        //                     }
        //             }
        // }};
        items_menu['sep2'] = "-----------";
        // items_submenu_external_query = {};
        // items_submenu_external_query['virus_total_consult'] = {
        //     name: "VirusTotal", icon: "fa-search",
        //     items: {
        //         "fold2-key1": {
        //             name: "Looking for domain (of column:" + COL_HTTP_URL_STR +")",
        //             icon: "fa-paper-plane-o",
        //             callback: function (key, options) {
        //                 var qn = bigData[COLUMN_HTTP_URL];
        //                 consultVirusTotal(qn, "domain");
        //
        //             }
        //         },
        //         "fold2-key2": {
        //             name: "Looking for IP (of column: " + COL_END_POINTS_SERVER_STR+")",
        //             icon: "fa-paper-plane-o",
        //             callback: function (key, options) {
        //                 var qn = bigData[COLUMN_END_POINTS_SERVER];
        //                 consultVirusTotal(qn, "ip");
        //             }
        //         }
        //     }
        // };
        // items_submenu_external_query['whois_consult'] = {
        //     name: "Whois", icon: "fa-search",
        //     items: {
        //         "fold2-key1": {
        //             name: "Looking for domain (of column: " + COL_HTTP_URL_STR +")",
        //             icon: "fa-paper-plane-o",
        //             callback: function (key, options) {
        //                 var qn = bigData[COLUMN_HTTP_URL];
        //                 consultWhois(qn, "domain");
        //
        //             }
        //         },
        //         "fold2-key2": {
        //             name: "Looking for IP (of column: " + COL_END_POINTS_SERVER_STR+")",
        //             icon: "fa-paper-plane-o",
        //             callback: function (key, options) {
        //                 var qn = bigData[COLUMN_END_POINTS_SERVER];
        //                 consultWhois(qn, "ip");
        //             }
        //         }
        //     }
        // };

        // if(thiz.isSaved()) {
        //     items_menu['fold1']['items']['fold1-key3'] = {
        //         name: "Mark all WBs WHOIS related (domain from column:" + COL_HTTP_URL_STR +")",
        //         icon: "fa-paint-brush",
        //         className: CLASS_MC_HTTP_URL_STR,
        //         callback: function(key, options) {
        //             var weblog_id = bigData[COLUMN_DT_ID].toString();
        //             weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
        //             labelWeblogsWhoisRelated(weblog_id,_bulk_verdict)
        //
        //             // setBulkVerdict_WORKER(_bulk_verdict, _bulk_marks_wbs[CLASS_MC_HTTP_URL_STR]);
        //             // _m.EventBulkLabelingByDomains(_bulk_marks_wbs[CLASS_MC_HTTP_URL_STR],_bulk_verdict, domain);
        //         }
        //
        //     };
        //     items_submenu_external_query['whois_consult']['items']['fold2-key3'] = {
        //         name: "Find WHOIS related domains (from column:" + COL_HTTP_URL_STR +")",
        //         icon: "fa-search",
        //         callback: function (key, option) {
        //             var weblog_id = bigData[COLUMN_DT_ID].toString();
        //             weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
        //             getWeblogsWhoisRelated(weblog_id);
        //
        //         }
        //     };
        //
        //
        //     // items_menu['fold4'] = {
        //     //     name: "Registry History", icon: "fa-search",
        //     //     items: {
        //     //         "fold2-key1": {
        //     //             name: "Veredict History",
        //     //             icon: "fa-paper-plane-o",
        //     //             callback: function (key, options) {
        //     //                 var weblog_id = bigData[COLUMN_DT_ID].toString();
        //     //                     weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
        //     //                     getWeblogHistory(weblog_id);
        //     //
        //     //             }
        //     //         },
        //     //         "fold2-key2": {
        //     //             name: "Modules Changes",
        //     //             icon: "fa-paper-plane-o",
        //     //             callback: function (key, options) {
        //     //                 var weblog_id = bigData[COLUMN_DT_ID].toString();
        //     //                 weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
        //     //                 getModulesChangesHistory(weblog_id);
        //     //             }
        //     //         }
        //     //     }
        //     // };
        //     // items_menu['fold4'] = {
        //     //     name: "Registry History", icon: "fa-search",
        //     //     items: {
        //     //         "fold2-key1": {
        //     //             name: "Veredict History",
        //     //             icon: "fa-paper-plane-o",
        //     //             callback: function (key, options) {
        //     //                 var weblog_id = bigData[COLUMN_DT_ID].toString();
        //     //                     weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
        //     //                     getWeblogHistory(weblog_id);
        //     //
        //     //             }
        //     //         },
        //     //         "fold2-key2": {
        //     //             name: "Modules Changes",
        //     //             icon: "fa-paper-plane-o",
        //     //             callback: function (key, options) {
        //     //                 var weblog_id = bigData[COLUMN_DT_ID].toString();
        //     //                 weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
        //     //                 getModulesChangesHistory(weblog_id);
        //     //             }
        //     //         },
        //     //         "fold2-key3": {
        //     //             name: "IOCs",
        //     //             icon: "fa-paper-plane-o",
        //     //             callback: function (key, options) {
        //     //                 var weblog_id = bigData[COLUMN_DT_ID].toString();
        //     //                 weblog_id = weblog_id.split(":").length <= 1 ? _analysis_session_id + ":" + weblog_id : weblog_id;
        //     //                 getIOCs(weblog_id);
        //     //             }
        //     //         }
        //     //     }
        //     // };
        // }

        // items_menu['fold3'] = {
        //     name: "External Intelligence", icon: "fa-search",
        //     items: items_submenu_external_query
        // };
        items_menu['sep3'] = "-----------";
        // items_menu['fold2'] = {
        //     name: "Copy to clipboard", icon: "fa-files-o",
        //     items: {
        //         "fold2-key1": {
        //             name: "Copy URL (of column: " + COL_HTTP_URL_STR +")",
        //             icon: "fa-file-o",
        //             callback: function (key, options) {
        //                 copyTextToClipboard(bigData[COLUMN_HTTP_URL]);
        //             }
        //         },
        //         "fold2-key2": {
        //             name: "Copy IP (of column: " + COL_END_POINTS_SERVER_STR+")",
        //             icon: "fa-file-o",
        //             callback: function (key, options) {
        //                 copyTextToClipboard(bigData[COLUMN_END_POINTS_SERVER]);
        //             }
        //         }
        //     }
        // };
        items_menu['fold2'] = {
            name: "Hotkeys List", icon: "fa-files-o",
            callback: function (key, options){
                initModal("List of Hotkeys");
                $.ajax({url:'/manati_project/manati_ui/hotkeys/list',
                    type:"GET",
                    dataType: "json",
                    success: function (json){
                        var table = buildTableHotkeys(json['hotkeys']);
                        updateBodyModal(table);
                    },
                    error: function (xhr,errmsg,err) {
                        $.notify(xhr.status + ": " + xhr.responseText, "error");
                        console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
                    }
                })

            },
        };



        return items_menu;

    };


    function buildTableHotkeys(hotkeys){
    var table = "<table class='table table-bordered table-striped'>";
    table += "<thead><tr><th style='width: 110px;'>#</th><th>Description</th><th>Command</th></tr></thead>";
    table += "<tbody>";
        var count = 1;
        _.each(hotkeys, function (value){
            table += "<tr>";
            table += "<td>"+count+"</td>";
            table += "<td>"+value['description']+"</td>";
            table += "<td>"+value['command']+"</td>";
            table += "</tr>";
            count++;

        });

    table += "</tbody>";
    table += "</table>";
    return table;

}
    function buildTableInfo_VT(info_report){
        var table = "<table class='table table-bordered table-striped'>";
        table += "<thead><tr><th style='width: 110px;'>List Attributes</th><th> Values</th></tr></thead>";
        table += "<tbody>";
            for(var key in info_report){
                table += "<tr>";
                table += "<th>"+key+"</th>";
                var info = info_report[key];
                if (info instanceof Array){
                    var html_temp = "";
                    for(var index = 0; index < info.length; index++){
                        var data = info[index];
                        if(data instanceof Object){
                             html_temp += buildTableInfo_VT(data, true) ;
                        }else if(typeof(data) === "string") {
                            table += "<td>" + info.join(", ") + "</td>" ;
                            break;
                        }

                    }
                    if(html_temp != "") table += "<td>"+ html_temp+ "</td>"
                }
                else if(info instanceof Object){
                    var html_temp = "";
                    html_temp += buildTableInfo_VT(info, true) ;
                    if(html_temp != "") table += "<td>"+ html_temp+ "</td>"
                }
                else{
                    table += "<td>" + info + "</td>" ;
                }

                table += "</tr>";
            }

        table += "</tbody>";
        table += "</table>";
        return table;

    }
    function buildTableInfo_Whois(info_report, no_title){
        if(no_title == undefined || no_title == null) no_title = false;
        var table = "<table class='table table-bordered table-striped'>";
        if(!no_title) table += "<thead><tr><th style='width: 110px;'>List Attributes</th><th> Values</th></tr></thead>";
        table += "<tbody>";
            for(var key in info_report){
                table += "<tr>";
                table += "<th>"+key+"</th>";
                var info = info_report[key];
                if (info instanceof Array) {
                    var html_temp = "";
                    for (var index = 0; index < info.length; index++) {
                        var data = info[index];
                        if (data instanceof Object) {
                            html_temp += buildTableInfo_Whois(data, true);
                        } else if (typeof(data) == "string") {
                            table += "<td>" + info.join(", ") + "</td>";
                            break;
                        }
                    }
                    if (html_temp != "") table += "<td>" + html_temp + "</td>";
                }else if(info instanceof Object){
                    var html_temp = "";
                    html_temp += buildTableInfo_Whois(info, false) ;
                    if(html_temp != "") table += "<td>"+ html_temp+ "</td>"
                }else{
                    table += "<td>" + info + "</td>" ;
                }

                table += "</tr>";
            }

        table += "</tbody>";
        table += "</table>";
        return table;

    }
    function initModal(title, after_hidden_function){
        $('#vt_consult_screen #vt_modal_title').html(title);
        $('#vt_consult_screen').modal('show');
        $('#vt_consult_screen').on('hidden.bs.modal', function (e) {
            $(this).find(".table-section").html('').hide();
            $(this).find(".loading").show();
            $(this).find("#vt_modal_title").html('');
            $(this).find(".append").html('');
            if(after_hidden_function !== undefined && after_hidden_function !== null){
                after_hidden_function();
            }

        });
    }
    function updateTitleModal(title){
        $('#vt_consult_screen #vt_modal_title').html(title);

    }
    function updateBodyModal(table) {
        var modal_body = $('#vt_consult_screen .modal-body');
        if (table != null) {
            modal_body.find('.table-section').html(table).show();
            modal_body.find(".loading").hide();
        }
    }
    function updateFooterModal(html_append){
        var modal_footer = $('#vt_consult_screen .modal-footer .append');
        modal_footer.html(html_append)
    }
    function consultVirusTotal(query_node, query_type){
        if(query_type == "domain") _m.EventVirusTotalConsultationByDomian(query_type);
        else if(query_type == "ip") _m.EventVirusTotalConsultationByIp(query_type);
        else{
            console.error("Error query_type for ConsultVirusTotal is incorrect")
        }
        initModal("Virus Total Query: <span>?????</span>");
        var data = {query_node: query_node, query_type: query_type};
        $.ajax({
            type:"GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/consult_virus_total",
            success : function(json) {// handle a successful response
                var info_report = JSON.parse(json['info_report']);
                var node = json['query_node'];
                var table = buildTableInfo_VT(info_report);
                if(query_type === 'ip'){
                    query_node = "<a target='_blank' href='https://virustotal" +
                        ".com/en/ip-address/"+node+"/information/'>"+node+"</a>"
                }
                else if(query_type === 'domain'){
                    query_node = "<a target='_blank' href='https://virustotal" +
                        ".com/en/domain/"+node+"/information/'>"+node+"</a>"
                }
                initModal("Virus Total Query: <span>"+query_node+"</span>");
                updateBodyModal(table);
            },
            error : function(xhr,errmsg,err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }

        })
    }
    function consultWhois(query_node, query_type){
        if(query_type == "domain") _m.EventWhoisConsultationByDomian(query_type);
        else if(query_type == "ip") _m.EventWhoisConsultationByIp(query_type);
        else{
            console.error("Error query_type for WhoisConsultation is incorrect")
        }
        initModal("Whois Query: <span>????</span>");
        var data = {query_node: query_node, query_type: query_type};
        $.ajax({
            type:"GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/consult_whois",
            success : function(json) {// handle a successful response
                var info_report = json['info_report'];
                var query_node = json['query_node'];
                var table = buildTableInfo_Whois(info_report);
                initModal("Whois Query: <span>"+query_node+"</span>");
                updateBodyModal(table);
            },
            error : function(xhr,errmsg,err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }

        })
    }

    function buildTableInfo_Wbl_History(weblog_history){
        var table = "<table class='table table-bordered table-striped'>";
        table += "<thead><tr><th>User/Module</th><th>Previous Verdict</th><th>Verdict</th><th>When?</th></tr></thead>";
        table += "<tbody>";
            _.each(weblog_history, function (value, index) {
                table += "<tr>";
                // for(var key in value){
                //     table += "<td>" + value[key]+ "</td>" ;
                // }
                table += "<td>" + value.author_name + "</td>";
                table += "<td>" + value.old_verdict + "</td>" ;
                table += "<td>" + value.verdict + "</td>" ;
                table += "<td>" + moment(value.created_at).format('llll') + "</td>" ;
                table += "</tr>";
            });


        table += "</tbody>";
        table += "</table>";
        return table;

    }
    function buildTableIOCs(iocs) {
        var table = "<table class='table table-bordered'>";
        table += "<thead><tr><th>#</th><th>IOCs</th><th>Value</th></tr></thead>";
        table += "<tbody>";
        var count = 1;
        _.each(iocs, function (ioc) {
            var tr = "<tr>";
            tr += "<td>" + count + "</td>";
            tr += "<td>" + ioc['ioc_type'] + "</td>";
            tr += "<td>" + ioc['value'] + "</td>";
            tr += "</tr>";
            count++;
            table += tr;
        });
        return table;
    }
    function buildTableInfo_Mod_attributes(mod_attributes) {
        var table = "<table class='table table-bordered'>";
        table += "<thead><tr><th>Module Name</th><th>Attributes</th><th>Values</th></tr></thead>";
        table += "<tbody>";
        console.log(mod_attributes);
        _.each(mod_attributes, function (value, mod_name) {
            var length = _.keys(value).length
            var tr = "<tr>";
            tr += "<td  rowspan='" + length + "'>" + mod_name + "</td>";
            _.each(value, function (parameter_value, key) {
                if (tr == null) tr = "<tr>";
                tr += "<td>" + key + "</td>";
                if (key == 'created_at') {
                    tr += "<td>" + moment(parameter_value).format('llll') + "</td>";
                } else {
                    tr += "<td>" + parameter_value + "</td>";
                }
                tr += "</tr>";
                table += tr;
                tr = null;
            });
        });
        return table;
    }
    function buildTable_WeblogsWhoisRelated(mod_attributes,was_related){
        if(was_related == undefined || was_related == null) was_related = false;
        if(isEmpty(mod_attributes) && !was_related) return null;
        var table = "<table class='table table-bordered'>";
        table += "<thead><tr><th>#</th><th>Domain Name</th><th>Select?</th></tr></thead>";
        table += "<tbody>";
        console.log(mod_attributes);
        var count = 1;
        if(isEmpty(mod_attributes) && was_related){
            var tr = "<tr>";
            tr += "<td colspan='3' style='text-align: center;'> NO WHOIS RELATED DOMAINS in this analysis session </td>";
            table+=tr;
        }else{
            _.each(mod_attributes, function (domain) {
                var tr = "<tr>";
                tr += "<td>"+count+"</td>";
                tr += "<td>"+domain+"</td>";
                tr += "<td><input type='checkbox' name='search_domain_table[]' value='"+domain+"' checked='True'/></td>";
                tr += "</tr>";
                table+=tr;
                count++;
            });

        }

        table += "</tbody>";
        table += "</table>";
        return table;

    }
    function getIOCs(weblog_id){
        initModal("IOCs Selected:" + weblog_id);
        var data = {weblog_id:weblog_id}
        $.ajax({
            type:"GET",
            dataType: "json",
            data:data,
            url: "/manati_project/manati_ui/analysis_session/weblog/iocs",
            success : function(json) {// handle a successful response
                var iocs = json['iocs'];
                var table = buildTableIOCs(iocs);
                updateBodyModal(table);
            },
            error : function(xhr,errmsg,err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }

        })

    }
    function getModulesChangesHistory(weblog_id){
        initModal("Modules Changes History of Weblog ID:" + weblog_id);
        var data = {weblog_id: weblog_id};
        $.ajax({
            type:"GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/analysis_session/weblog/modules_changes_attributes",
            success : function(json) {// handle a successful response
                var mod_attributes = JSON.parse(json['data']);
                var table = buildTableInfo_Mod_attributes(mod_attributes);
                updateBodyModal(table);
                // var info_report = JSON.parse(json['info_report']);
                // var query_node = json['query_node'];
                // var table = buildTableInfo_VT(info_report);
                // updateBodyModal(table);
            },
            error : function(xhr,errmsg,err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }

        })

    }
    function getWeblogHistory(weblog_id){
        initModal("Weblog History ID:" + weblog_id);
        var data = {weblog_id: weblog_id};
        $.ajax({
            type:"GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/analysis_session/weblog/history",
            success : function(json) {// handle a successful response
                var weblog_history = JSON.parse(json['data']);
                var table = buildTableInfo_Wbl_History(weblog_history);
                updateBodyModal(table);
            },
            error : function(xhr,errmsg,err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
            }

        })

    }
    var labelingRows = function (verdict){
        var rows_affected = _datatable_setting.markVerdict(verdict);
    };


    // public events
    this.labelingRows = function (verdict){
        labelingRows(verdict);
    };

    this.eventContextMenu = function (){
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
                            labelingRows(verdict);
                            return true;
                        },
                        items: generateContextMenuItems($trigger)

                    }
                }


            });
    }
}