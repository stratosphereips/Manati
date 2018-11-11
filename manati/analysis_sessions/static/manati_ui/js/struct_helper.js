/**
 * Created by raulbeniteznetto on 9/27/16.
 */

function FlowsProcessed(col_host_str,co_ip_str){
    var thiz = this;
    var COL_HOST_STR = col_host_str;
    var COL_IP_STR = co_ip_str;
    var _int_flows_grouped = {};
    var REG_EXP_DOMAINS = /[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+/;
    var REG_EXP_IP = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))/;
    var NAMES_HTTP_URL = ["http.url", "http_url", "host"];
    var NAMES_END_POINTS_SERVER = ["endpoints.server", "endpoints_server", "id.resp_h", "id_resp_h", "DstAddr"];

    function groupingFlow(key_flow, key_group, value){
        if(key_flow === null || key_group === null || value === null) return false;
        if(!(_int_flows_grouped[key_flow] instanceof Object))_int_flows_grouped[key_flow] = {};
        if(!(_int_flows_grouped[key_flow][key_group] instanceof Array))_int_flows_grouped[key_flow][key_group] = [];
        _int_flows_grouped[key_flow][key_group].push(value);

        return true;

    }
    function findDomainOfURL(url){
        if (typeof url !== "string") return null;
        var matching_domain = null;
        var domain = ( (matching_domain = url.match(REG_EXP_IP)) != null )|| matching_domain != undefined && matching_domain.length > 0 ? matching_domain[0] : null ;
        domain = (domain == null)  && ((matching_domain = url.match(REG_EXP_DOMAINS)) != null) || matching_domain != undefined && matching_domain.length > 0 ? matching_domain[0] : null;
        return domain
    }
    function findIP(url){
        if (typeof url !== "string") return null;
        var matching_domain = null;
        var ip = ((matching_domain = url.match(REG_EXP_IP)) != null) || matching_domain != undefined && matching_domain.length > 0 ? matching_domain[0] : null;
        return ip;
    }
    this.getFlowsGrouped = function(){
        return _int_flows_grouped;
    };
    this.setFlowsGrouped = function (flows_grouped) {
        _int_flows_grouped = flows_grouped;
    };
    this.getFlowsGroupedBy = function (key_group, key_flow) {
        if(key_flow === null || key_group === null) return [];
        if((_int_flows_grouped[key_group] instanceof Object)){
            if((_int_flows_grouped[key_group][key_flow] instanceof Array)){
                return _int_flows_grouped[key_group][key_flow];
            }
            else return [];
        }
        else return [];
    };

    this.addFlows = function(flow){
        _.each(flow, function (v,k){
            if(k === COL_HOST_STR || k === COL_IP_STR){
                let d;
                if((d = findDomainOfURL(v)) !== null){
                    groupingFlow(k,d,flow);
                }
            }

            // if((d = findIP(v)) != null) groupingFlow(k,d,flow); d == null;
        });

    };
    this.addBulkFlows = function (flows){
        if (COL_HOST_STR === null && COL_IP_STR === null) return;

        for(let i = 0; i< flows.length; i++) {
            thiz.addFlows(flows[i]);
        }
    };

    this.sendIoCsToServer = function (iocs, dynamic_table) {
        $.ajax({
            type: "POST",
            data: {
                "iocs[]": JSON.stringify(iocs),
            },
            dataType: "json",
            url: "/manati_project/manati_ui/analysis_session/sync_iocs",
            // handle a successful response
            success: function (json) {
                var ioc_grouped_via_labels = json.ioc_grouped_via_labels;
                for (var verdict in ioc_grouped_via_labels){
                    if(verdict !== 'undefined'){
                        var iocs = ioc_grouped_via_labels[verdict];
                        for (var index in iocs){
                            dynamic_table.dt.search(iocs[index]).draw();
                            dynamic_table.dt.rows({search:'applied'}).nodes().to$().addClass('selected');
                        }
                        dynamic_table.mark_verdict(verdict);
                        dynamic_table.dt.search('').draw();
                        dynamic_table.dt.draw(false);
                    }

                }
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
            }

        });
    };

    this.makeStaticalSection= function (flows_grouped) {
        if(flows_grouped!==undefined){
            _int_flows_grouped=flows_grouped;
        }
        let table = document.createElement('table');
        table.setAttribute("id", "statistics_table");
        table.classList = ["table"];
        let thead = document.createElement('thead');
        let tr = document.createElement('tr');
        let th1 = document.createElement('th');
        let th2 = document.createElement('th');
        let th3 = document.createElement('th');
        let text_h1 = document.createTextNode('Key Group');
        let text_h2 = document.createTextNode('Key Flow');
        let text_h3 = document.createTextNode('Amount');
        th1.appendChild(text_h1);
        th2.appendChild(text_h2); th3.appendChild(text_h3);
        tr.appendChild(th2); tr.appendChild(th3);
        tr.appendChild(th1);
        thead.appendChild(tr);
        table.appendChild(thead);
        let tbody = document.createElement('tbody');
        let iocs = {};
        $.each(_.keys(_int_flows_grouped),function (index, key_group) {
            // let tr = document.createElement('tr');
            let key_flows = _.keys(_int_flows_grouped[key_group]);
            // let td1 = document.createElement('td');
            // let text = document.createTextNode(key_group);
            // td1.rowSpan = key_flows.length;
            // td1.appendChild(text);
            // tr.appendChild(td1);
            var type_ioc = 'undefined';
            if(_.contains(NAMES_HTTP_URL, key_group)){
                type_ioc = 'domain';
            } else if(_.contains(NAMES_END_POINTS_SERVER, key_group)) {
                type_ioc = 'ip';
            } else {
                console.error('unknown attribute')
            }

            iocs[type_ioc] = [];
            $.each(key_flows, function (i,key_flow) {
                let tr = document.createElement('tr');
                let td1 = document.createElement('td');
                let text = document.createTextNode(key_group);
                td1.appendChild(text);
                iocs[type_ioc].push(key_flow);

                // if(tr==null) {
                //     tr=document.createElement('tr');
                //     // let td1 = document.createElement('td');
                //     // let text = document.createTextNode(key_group);
                //     // td1.appendChild(text);
                //     // tr.appendChild(td1);
                // }
                let td2 = document.createElement('td');
                let text1 = document.createTextNode(key_flow);
                td2.appendChild(text1);
                tr.appendChild(td2);
                let size = thiz.getFlowsGroupedBy(key_group, key_flow).length;
                let td3 = document.createElement('td');
                let text3 = document.createTextNode(size.toString());
                td3.appendChild(text3);
                tr.appendChild(td3);
                tr.appendChild(td1);
                tbody.appendChild(tr);
                tr = null;
            });
            table.appendChild(tbody);
        });
        $("#statical-section").append("<br/>");
        $("#statical-section").append(table);
        $(table).DataTable();
        $("li#statical-nav").show();
        return iocs
    };
}
