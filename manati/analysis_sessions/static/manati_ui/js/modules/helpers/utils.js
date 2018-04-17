
import {REG_EXP_DOMAINS, REG_EXP_IP, VERDICTS_MERGED_AVAILABLE} from './constants.js'

export function isMac (){
    return navigator.platform.toUpperCase().indexOf('MAC') >= 0;
}


export function findDomainOfURL(url){
    if (typeof url !== "string") return null;
    let matching_domain = null;
    let domain = ( (matching_domain = url.match(REG_EXP_DOMAINS)) !== null )|| matching_domain !== undefined && matching_domain.length > 0 ? matching_domain[0] : null ;
    domain = (domain === null)  && ((matching_domain = url.match(REG_EXP_IP)) !== null) || matching_domain !== undefined && matching_domain.length > 0 ? matching_domain[0] : null;
    return domain
}

export function findIP(url) {
    if (typeof url !== "string") return null;
    let matching_domain = null;
    let ip = ((matching_domain = url.match(REG_EXP_IP)) !== null) || matching_domain !== undefined && matching_domain.length > 0 ? matching_domain[0] : null;
    return ip;
}

// Speed up calls to hasOwnProperty
var hasOwnProperty = Object.prototype.hasOwnProperty;

export function is_boolean(obj){
    return typeof(obj) === "boolean";
}

export function is_number(obj){
    return typeof(obj) === 'number';
}

function is_function(functionToCheck) {
 return functionToCheck && {}.toString.call(functionToCheck) === '[object Function]';
}

export function isEmpty(obj) {

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
    for (let key in obj) {
        if (hasOwnProperty.call(obj, key)) return false;
    }

    return true;
}

export function set_default(obj,default_obj){
    if(isEmpty(obj)){
        return default_obj;
    }else{
        return obj;
    }

}

export function copyTextToClipboard(text) {
      let textArea = document.createElement("textarea");

      //
      // *** This styling is an extra step which is likely not required. ***
      //
      // Why is it here? To ensure:
      // 1. the element is able to have focus and selection.
      // 2. if element was to flash render it has minimal visual impact.
      // 3. less flakyness with selection and copying which **might** occur if
      //    the textarea element is not visible.
      //
      // The likelihood is the element won't even render, not even a flash,
      // so some of these are just precautions. However in IE the element
      // is visible whilst the popup box asking the user for permission for
      // the web page to copy to the clipboard.
      //

      // Place in top-left corner of screen regardless of scroll position.
      textArea.style.position = 'fixed';
      textArea.style.top = 0;
      textArea.style.left = 0;

      // Ensure it has a small width and height. Setting to 1px / 1em
      // doesn't work as this gives a negative w/h on some browsers.
      textArea.style.width = '2em';
      textArea.style.height = '2em';

      // We don't need padding, reducing the size if it does flash render.
      textArea.style.padding = 0;

      // Clean up any borders.
      textArea.style.border = 'none';
      textArea.style.outline = 'none';
      textArea.style.boxShadow = 'none';

      // Avoid flash of white box if rendered for any reason.
      textArea.style.background = 'transparent';


      textArea.value = text;

      document.body.appendChild(textArea);

      textArea.select();

      try {
        let successful = document.execCommand('copy');
        let msg = successful ? 'successful' : 'unsuccessful';
        console.log('Copying text command was ' + msg);
      } catch (err) {
        console.log('Oops, unable to copy');
      }

      document.body.removeChild(textArea);
    }




export function scrollIntoViewIfNeeded(target) {
    let rect = target.getBoundingClientRect();
    if (rect.bottom > window.innerHeight) {
        target.scrollIntoView(false);
    }
    if (rect.top < 0) {
        target.scrollIntoView();
    }
}

export function check_verdict(verdicts_merged, verdict) {
    if (verdict === undefined || verdict === null) return verdict;
    let merged = verdict.split('_');

    if (merged.length > 1) {
        let user_verdict = merged[0];
        let module_verdict = merged[1];
        let verdict_merge1 = user_verdict + "_" + module_verdict;
        let verdict_merge2 = module_verdict + "_" + user_verdict;
        if (verdicts_merged.indexOf(verdict_merge1) > -1) {
            return verdict_merge1;
        } else if (verdicts_merged.indexOf(verdict_merge2) > -1) {
            return verdict_merge2;
        } else {
            console.error("Error adding Verdict, Merged verdict is not known : " + verdict)
        }
    } else if (verdicts_merged.indexOf(verdict) > -1) {
        return verdict;
    } else {
        return null;
    }
}

export function check_verdict_merged(verdict) {
    return check_verdict(VERDICTS_MERGED_AVAILABLE, verdict);
}

export function showLoading() {
    $("#loading-img").show();
}

export function hideLoading() {
    $("#loading-img").hide();
}


