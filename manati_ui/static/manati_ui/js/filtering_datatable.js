/**
 * Created by raulbeniteznetto on 10/2/16.
 */
function FilterDataTable(column_verdict, verdicts){
    var thiz = this;
    var _list_options = {};
    var _verdicts = verdicts;
    var _dt;
    var _column_verdict = column_verdict;

    function init(){
        $.each(_verdicts,function (index, values) {
            _list_options[values] = true;
        });
        pushingDataTable();
    }
    init();
    var setDt = function (dt) {
        _dt = dt;
    };
    var getDt = function () {
        return _dt;
    };
    function pushingDataTable(){
        $.fn.dataTable.ext.search.push(
            function( settings, data, dataIndex ) {
                var verdict = data[_column_verdict]; // use data for the age column
                return _list_options[verdict];
            }
        );
    }

    function generatePopIn (offset_pos){
        var html;
        var dt = getDt();
        var ul = "<ul class='dt-button-collection dropdown-menu filtering' style='top: "+(offset_pos.top+34)+"px; left: "+offset_pos.left+"px; display: block;'>";
        $.each(_.keys(_list_options),function (index, value) {
            var klass =  _list_options[value] ? "active" : "" ;
            var li = "<li class='dt-button buttons-columnVisibility "+klass+"' tabindex='0' aria-controls='weblogs-datatable'>";
            li += "<a href='#'>"+value+"</a>";
            li += "</li>";
            ul += li;
        });
        ul += "</ul>";

        $('body').append(ul);
        $('ul.filtering').hide();
        $('ul.filtering').on('click', 'li',function (ev) {
            ev.preventDefault();
            var elem = $(this);
            var text = elem.text();
            if(elem.hasClass('active')){
                _list_options[text] = false;
                elem.removeClass('active');
            }else{
                _list_options[text] = true;
                elem.addClass('active');
            }
            dt.draw();
        });
        $('body').click(function(event) {
            if(!$(event.target).closest('ul.filtering').length) {
                if($('ul.filtering').is(":visible")) {
                    $('ul.filtering').remove();
                    $('body').off('click');
                }else{
                    $('ul.filtering').show();
                }
            }
        });
    }
    this.showMenuContext = function (dt,offset_pos){
        setDt(dt);
        generatePopIn(offset_pos);
    }


};