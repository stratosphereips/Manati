var REG_EXP_DOMAINS = /[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+/;
var REG_EXP_IP = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/;
function findDomainOfURL(url){
    if (typeof url !== "string") return null;
    var matching_domain = null;
    var domain = ( (matching_domain = url.match(REG_EXP_DOMAINS)) !== null )|| matching_domain !== undefined && matching_domain.length > 0 ? matching_domain[0] : null ;
    domain = (domain === null)  && ((matching_domain = url.match(REG_EXP_IP)) !== null) || matching_domain !== undefined && matching_domain.length > 0 ? matching_domain[0] : null;
    return domain
}

// Speed up calls to hasOwnProperty
var hasOwnProperty = Object.prototype.hasOwnProperty;

function is_boolean(obj){
    return typeof(obj) === "boolean";
}

function is_number(obj){
    return typeof(obj) === 'number';
}

function is_function(functionToCheck) {
 return functionToCheck && {}.toString.call(functionToCheck) === '[object Function]';
}

function isEmpty(obj) {

    if(is_function(obj)) return false;

    if(is_boolean(obj)) return false;

    if(is_number(obj)) return false;

    // if(isString(obj) && obj === '') return false;

    // null and undefined are "empty"
    if (obj === null || obj === undefined) return true;

    // Assume if it has a length property with a non-zero value
    // that that property is correct.
    if (obj.length > 0)    return false;
    if (obj.length === 0)  return true;

    // If it isn't an object at this point
    // it is empty, but it can't be anything *but* empty
    // Is it empty?  Depends on your application.
    if (typeof obj !== "object") return true;

    // Otherwise, does it have any properties of its own?
    // Note that this doesn't handle
    // toString and valueOf enumeration bugs in IE < 9
    for (var key in obj) {
        if (hasOwnProperty.call(obj, key)) return false;
    }

    return true;
}

function set_default(obj,default_obj){
    if(isEmpty(obj)){
        return default_obj;
    }else{
        return obj;
    }

}
