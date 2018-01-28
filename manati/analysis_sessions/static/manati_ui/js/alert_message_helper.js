var updateAlertBox = function(html){
    var container = $("#flash-messages-container");
    (html != "") ? container.html(html).show().delay(5000).fadeOut(3000) : container.html(html).hide();
}
var eventAlertBox = function (){
    var container = $("#flash-messages-container");
    if(container.html().length > 0){
        container.show().delay(5000).fadeOut(3000);
    }else{
        container.hide();
    }
}
var updateAlertBoxText = function (msg, state){
    var temp_html = "<div class='alert alert-"+state+"' >";
        temp_html += msg;
        temp_html += "<button type='button' class='close' data-dismiss='alert' aria-hidden='true'>&times;</button>"
        temp_html += "</div>";
    updateAlertBox(temp_html);
};