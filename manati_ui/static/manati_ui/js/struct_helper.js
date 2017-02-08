/**
 * Created by raulbeniteznetto on 9/27/16.
 */

function FlowsProcessed(flows_grouped){
    var thiz = this;
    var flows_grouped = flows_grouped;
    var REG_EXP_DOMAINS = /[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+/;
    var REG_EXP_IP = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/;
    function groupingFlow(key_flow, key_group, value){
        if(key_flow == null || key_group == null || value == null) return false;
        if(!(flows_grouped[key_flow] instanceof Object))flows_grouped[key_flow] = {};
        if(!(flows_grouped[key_flow][key_group] instanceof Array))flows_grouped[key_flow][key_group] = [];
        flows_grouped[key_flow][key_group].push(value);
        return true;

    }
    function findDomainOfURL(url){
        if (typeof url !== "string") return null;
        var matching_domain = null;
        var domain = ( (matching_domain = url.match(REG_EXP_DOMAINS)) != null )|| matching_domain != undefined && matching_domain.length > 0 ? matching_domain[0] : null ;
        domain = (domain == null)  && ((matching_domain = url.match(REG_EXP_IP)) != null) || matching_domain != undefined && matching_domain.length > 0 ? matching_domain[0] : null;
        return domain
    }
    function findIP(url){
        if (typeof url !== "string") return null;
        var matching_domain = null;
        var ip = ((matching_domain = url.match(REG_EXP_IP)) != null) || matching_domain != undefined && matching_domain.length > 0 ? matching_domain[0] : null;
        return ip;
    }
    this.getFlowsGrouped = function(){
        return flows_grouped;
    };
    this.getFlowsGroupedBy = function (key_group, key_flow) {
        if(key_flow == null || key_group == null) return [];
        if((flows_grouped[key_group] instanceof Object)){
            if((flows_grouped[key_group][key_flow] instanceof Array)){
                return flows_grouped[key_group][key_flow];
            }
            else return [];
        }
        else return [];
    };

    this.addFlows = function(flow){
        _.each(flow, function (v,k){
            var d;
            if((d = findDomainOfURL(v)) != null){
                groupingFlow(k,d,flow);
            }
            // if((d = findIP(v)) != null) groupingFlow(k,d,flow); d == null;
        });

    };

    this.makeStaticalSection= function () {
        var table = document.createElement('table');
        table.setAttribute("id", "statistics_table");
        table.classList = ["table"];
        var thead = document.createElement('thead');
        var tr = document.createElement('tr');
        var th1 = document.createElement('th');
        var th2 = document.createElement('th');
        var th3 = document.createElement('th');
        var text_h1 = document.createTextNode('Key Group');
        var text_h2 = document.createTextNode('Key Flow');
        var text_h3 = document.createTextNode('Amount');
        th1.appendChild(text_h1);
        th2.appendChild(text_h2); th3.appendChild(text_h3);
        tr.appendChild(th2); tr.appendChild(th3);
        tr.appendChild(th1);
        thead.appendChild(tr);
        table.appendChild(thead);
        var tbody = document.createElement('tbody');
        $.each(_.keys(flows_grouped),function (index,key_group) {
            // var tr = document.createElement('tr');
            var key_flows = _.keys(flows_grouped[key_group]);
            // var td1 = document.createElement('td');
            // var text = document.createTextNode(key_group);
            // td1.rowSpan = key_flows.length;
            // td1.appendChild(text);
            // tr.appendChild(td1);
            $.each(key_flows, function (i,key_flow) {
                var tr = document.createElement('tr');
                var td1 = document.createElement('td');
                var text = document.createTextNode(key_group);
                td1.appendChild(text);

                // if(tr==null) {
                //     tr=document.createElement('tr');
                //     // var td1 = document.createElement('td');
                //     // var text = document.createTextNode(key_group);
                //     // td1.appendChild(text);
                //     // tr.appendChild(td1);
                // }
                var td2 = document.createElement('td');
                var text1 = document.createTextNode(key_flow);
                td2.appendChild(text1);
                tr.appendChild(td2);
                var size = thiz.getFlowsGroupedBy(key_group, key_flow).length;
                var td3 = document.createElement('td');
                var text3 = document.createTextNode(size.toString());
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
    };
}