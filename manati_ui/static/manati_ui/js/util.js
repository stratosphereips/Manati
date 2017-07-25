/**
 * Created by raulbeniteznetto on 7/25/17.
 */
var hashids = new Hashids("this is my salt", 8, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890");
function createSecureRandomNumber() {
  var number;

  try {

    // If the client supports the more secure crypto lib
    if (Uint32Array && window.crypto && window.crypto.getRandomValues) {

      var numbers = new Uint32Array(1);
      window.crypto.getRandomValues(numbers);
      number = numbers.length ? (numbers[0] + '') : null;
    }
  } catch(e) {

    // If the browser fucks up ...

  } finally {

    // The fallback
    if (!number) {
      number = Math.floor( Math.random() * 1e9 ).toString() + (new Date().getTime());
    }
  }

  return parseInt(number);
}
function getRowShortId(analysis_session_id){
    var enc = [analysis_session_id > 0 ? analysis_session_id : 0 ,createSecureRandomNumber()];
    return hashids.encode(enc)
}