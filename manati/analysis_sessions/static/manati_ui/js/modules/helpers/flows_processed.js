import {findDomainOfURL, findIP, isEmpty} from '../helpers/utils.js';
/**
 * Created by raulbeniteznetto on 9/27/16.
 */

class FlowsProcessed{
    constructor(col_host_str, co_ip_str) {
        this.COL_HOST_STR = col_host_str;
        this.COL_IP_STR = co_ip_str;
        this._int_flows_grouped = {};

    }

   groupingFlow(key_flow, key_group, value){
        if(key_flow === null || key_group === null || value === null) return false;
        if(!(this._int_flows_grouped[key_flow] instanceof Object)) this._int_flows_grouped[key_flow] = {};
        if(!(this._int_flows_grouped[key_flow][key_group] instanceof Array)) this._int_flows_grouped[key_flow][key_group] = [];
        this._int_flows_grouped[key_flow][key_group].push(value);

        return true;

    }

    getFlowsGrouped(){
        return this._int_flows_grouped;
    };
    setFlowsGrouped(flows_grouped) {
        this._int_flows_grouped = flows_grouped;
    };
    getFlowsGroupedBy(key_group, key_flow) {
        if(key_flow === null || key_group === null) return [];
        if((this._int_flows_grouped[key_group] instanceof Object)){
            if((this._int_flows_grouped[key_group][key_flow] instanceof Array)){
                return this._int_flows_grouped[key_group][key_flow];
            }
            else return [];
        }
        else return [];
    };

    addFlows (flow){
        let thiz = this;
        _.each(flow, function (v,k){
            if(k === thiz.COL_HOST_STR || k === thiz.COL_IP_STR){
                let d;
                if((d = findDomainOfURL(v)) !== null){
                    thiz.groupingFlow(k,d,flow);
                }
            }

            // if((d = findIP(v)) != null) groupingFlow(k,d,flow); d == null;
        });

    };
    addBulkFlows  (flows){
        if (isEmpty(thiz.COL_HOST_STR ) && isEmpty(thiz.COL_IP_STR)) return;
        for(let i = 0; i< flows.length; i++) {
            this.addFlows(flows[i]);
        }
    };

    makeStaticalSection (flows_grouped) {
        let thiz = this;
        if(flows_grouped !== undefined){
            this._int_flows_grouped=flows_grouped;
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
        $.each(_.keys(this._int_flows_grouped),function (index, key_group) {
            // let tr = document.createElement('tr');
            let key_flows = _.keys(thiz._int_flows_grouped[key_group]);
            // let td1 = document.createElement('td');
            // let text = document.createTextNode(key_group);
            // td1.rowSpan = key_flows.length;
            // td1.appendChild(text);
            // tr.appendChild(td1);
            $.each(key_flows, function (i,key_flow) {
                let tr = document.createElement('tr');
                let td1 = document.createElement('td');
                let text = document.createTextNode(key_group);
                td1.appendChild(text);

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
    };
}

export default FlowsProcessed;
