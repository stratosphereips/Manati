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
        var matching_domain;
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
            if((d = findDomainOfURL(v)) != null) groupingFlow(k,d,flow);
            if((d = findIP(v)) != null) groupingFlow(k,d,flow);
        });

    }
}