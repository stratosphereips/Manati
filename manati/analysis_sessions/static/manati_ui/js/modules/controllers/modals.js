import {set_default, isEmpty} from "../helpers/utils.js";
var _m = null;
var refreshIntervalId = null;
class Modals {

    constructor() {

    }

    refreshingDomainsWhoisRelatedModal(weblog_id) {
        var thiz = this;
        let data = {weblog_id: weblog_id};
        $.ajax({
            type: "GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/analysis_session/weblog/reload_modal_domains_whois_related",
            success: function (json) {// handle a successful response
                let whois_related_domains = json['whois_related_domains'];
                let root_whois_features = json['root_whois_features'];
                let was_related = json['was_related'];
                let table = Modals.buildTable_WeblogsWhoisRelated(whois_related_domains, was_related, root_whois_features);
                Modals.updateBodyModal(table);
                if (was_related) {
                    Modals.closingModal();
                }
            },
            error: function (xhr, errmsg, err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }
        });


    }

    static closingModal() {
        clearInterval(refreshIntervalId);
        refreshIntervalId = null;
    };

    getWeblogsWhoisRelated(weblog_id) {
        var thiz = this;
        Modals.updateFooterModal('<a id="search-domain-selected" class="btn btn-info" data-dismiss="modal">Search Selected</a>');
        this.initModal("Activating WHOIS Similarity Distance Module...", this.closingModal);
        let data = {weblog_id: weblog_id};
        $.ajax({
            type: "GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/analysis_session/weblog/modules_whois_related",
            success: function (json) {// handle a successful response
                // / let whois_related_domains = json['whois_related_domains'];
                $.notify(json['msg'], "info");
                Modals.updateTitleModal("List of domains WHOIS related with: " + json['domain_primary']);
                // let was_whois_related = json['was_whois_related'];
                // if(!was_whois_related){
                //     $.notify("One request for the DB was realized, maybe it will take time to process it and" +
                //             " show the information in the modal.",
                //             "warn", {autoHideDelay: 2000});
                // }
                // let table = buildTable_WeblogsWhoisRelated(whois_related_domains);
                // updateBodyModal(table);
                refreshIntervalId = setInterval(thiz.refreshingDomainsWhoisRelatedModal, 3000, weblog_id)


            },
            error: function (xhr, errmsg, err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }

        });

    }

    buildTableHotkeys(hotkeys) {
        let table = "<table class='table table-bordered table-striped'>";
        table += "<thead><tr><th style='width: 110px;'>#</th><th>Description</th><th>Command</th></tr></thead>";
        table += "<tbody>";
        let count = 1;
        _.each(hotkeys, function (value) {
            table += "<tr>";
            table += "<td>" + count + "</td>";
            table += "<td>" + value['description'] + "</td>";
            table += "<td>" + value['command'] + "</td>";
            table += "</tr>";
            count++;

        });

        table += "</tbody>";
        table += "</table>";
        return table;

    }

    buildTableInfo_VT(info_report) {
        var thiz = this;
        let table = "<table class='table table-bordered table-striped'>";
        table += "<thead><tr><th style='width: 110px;'>List Attributes</th><th> Values</th></tr></thead>";
        table += "<tbody>";
        Object.keys(info_report).forEach(key => {
            table += "<tr>";
            table += "<th>" + key + "</th>";
            let info = info_report[key];
            if (info instanceof Array) {
                let html_temp = "";
                for (let index = 0; index < info.length; index++) {
                    let data = info[index];
                    if (data instanceof Object) {
                        html_temp += thiz.buildTableInfo_VT(data, true);
                    } else if (typeof(data) === "string") {
                        table += "<td>" + info.join(", ") + "</td>";
                        break;
                    }

                }
                if (html_temp !== "") table += "<td>" + html_temp + "</td>"
            }
            else if (info instanceof Object) {
                let html_temp = "";
                html_temp += thiz.buildTableInfo_VT(info, true);
                if (html_temp !== "") table += "<td>" + html_temp + "</td>"
            }
            else {
                table += "<td>" + info + "</td>";
            }

            table += "</tr>";
        });

        table += "</tbody>";
        table += "</table>";
        return table;

    }

    buildTableInfo_Whois(info_report, no_title) {
        if (no_title === undefined || no_title === null) no_title = false;
        let table = "<table class='table table-bordered table-striped'>";
        if (!no_title) table += "<thead><tr><th style='width: 110px;'>List Attributes</th><th> Values</th></tr></thead>";
        table += "<tbody>";
        for (let key in info_report) {
            table += "<tr>";
            table += "<th>" + key + "</th>";
            let info = info_report[key];
            if (info instanceof Array) {
                let html_temp = "";
                for (let index = 0; index < info.length; index++) {
                    let data = info[index];
                    if (data instanceof Object) {
                        html_temp += this.buildTableInfo_Whois(data, true);
                    } else if (typeof(data) === "string") {
                        table += "<td>" + info.join(", ") + "</td>";
                        break;
                    }
                }
                if (html_temp !== "") table += "<td>" + html_temp + "</td>";
            } else if (info instanceof Object) {
                let html_temp = "";
                html_temp += this.buildTableInfo_Whois(info, false);
                if (html_temp !== "") table += "<td>" + html_temp + "</td>"
            } else {
                table += "<td>" + info + "</td>";
            }

            table += "</tr>";
        }

        table += "</tbody>";
        table += "</table>";
        return table;

    }

    initModal(title, after_hidden_function, before_hidden_function) {
        after_hidden_function = set_default(after_hidden_function, null);
        before_hidden_function = set_default(before_hidden_function, null);
        $('#vt_consult_screen #vt_modal_title').html(title);
        $('#vt_consult_screen').modal('show');
        $('#vt_consult_screen').on('hidden.bs.modal', function (e) {
            if (before_hidden_function !== null) {
                before_hidden_function();
            }
            $(this).find(".table-section").html('').hide();
            $(this).find(".loading").show();
            $(this).find("#vt_modal_title").html('');
            $(this).find(".append").html('');
            if (after_hidden_function !== undefined && after_hidden_function !== null) {
                after_hidden_function();
            }

        });
    }

    static updateTitleModal(title) {
        $('#vt_consult_screen #vt_modal_title').html(title);

    }


    static updateBodyModal(table) {
        let modal_body = $('#vt_consult_screen .modal-body');
        if (table !== null) {
            modal_body.find('.table-section').html(table).show();
            modal_body.find(".loading").hide();
        }
    }

    static updateFooterModal(html_append) {
        let modal_footer = $('#vt_consult_screen .modal-footer .append');
        modal_footer.html(html_append)
    }


    buildTableInfo_Wbl_History(weblog_history) {
        let table = "<table class='table table-bordered table-striped'>";
        table += "<thead><tr><th>User/Module</th><th>Previous Verdict</th><th>Verdict</th><th>When?</th></tr></thead>";
        table += "<tbody>";
        _.each(weblog_history, function (value, index) {
            table += "<tr>";
            // for(let key in value){
            //     table += "<td>" + value[key]+ "</td>" ;
            // }
            table += "<td>" + value.author_name + "</td>";
            table += "<td>" + value.old_verdict + "</td>";
            table += "<td>" + value.verdict + "</td>";
            table += "<td>" + moment(value.created_at).format('llll') + "</td>";
            table += "</tr>";
        });


        table += "</tbody>";
        table += "</table>";
        return table;

    }

    buildTableIOCs(iocs) {
        let table = "<table class='table table-bordered'>";
        table += "<thead><tr><th>#</th><th>IOCs</th><th>Value</th></tr></thead>";
        table += "<tbody>";
        let count = 1;
        _.each(iocs, function (ioc) {
            let tr = "<tr>";
            tr += "<td>" + count + "</td>";
            tr += "<td>" + ioc['ioc_type'] + "</td>";
            tr += "<td>" + ioc['value'] + "</td>";
            tr += "</tr>";
            count++;
            table += tr;
        });
        return table;
    }

    buildTableInfo_Mod_attributes(mod_attributes) {
        let table = "<table class='table table-bordered'>";
        table += "<thead><tr><th>Module Name</th><th>Attributes</th><th>Values</th></tr></thead>";
        table += "<tbody>";
        _.each(mod_attributes, function (value, mod_name) {
            let length = _.keys(value).length;
            let tr = "<tr>";
            tr += "<td  rowspan='" + length + "'>" + mod_name + "</td>";
            _.each(value, function (parameter_value, key) {
                if (tr === null) tr = "<tr>";
                tr += "<td>" + key + "</td>";
                if (key === 'created_at') {
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

    static buildTable_WeblogsWhoisRelated(mod_attributes, was_related, root_whois_features) {
        if (was_related === undefined || was_related === null) was_related = false;
        if (isEmpty(mod_attributes) && !was_related) return null;
        let threshold_default = 75;
        let count = 1;
        let feature_names_ref = {
            'emails': 'diff_emails', 'domain_name': 'dist_domain_name', 'name_servers': 'diff_name_servers',
            'registrar': 'dist_registrar', 'name': 'dist_name', 'duration': 'dist_duration', 'zipcode': 'dist_zipcode',
            'org': 'dist_org'
        };
        let html = '';
        html += "<span id='slider-range-span' class='example-val'></span>";
        html += "<div id='slider-range'></div>";

        html += "<br/>";
        html += '<div class="panel-group" id="accordion" role="tablist" aria-multiselectable="true">';
        if (isEmpty(mod_attributes) && was_related) {
            html += "<div> NO WHOIS RELATED DOMAINS in this analysis session </div>";
        } else {
            _.each(mod_attributes, function (features, domain) {


                let table = "<table class='table table-bordered'>";
                table += "<thead><tr><th>Feature Name</th><th>WHOIS info A</th><th>WHOIS info B</th><th>Distance</th></tr></thead>";
                table += "<tbody>";
                let tmp_count = 0;
                let total_dist = 0;
                _.each(features[0], function (whois_info, feature_name) {
                    let local_dist = parseFloat(features[1][feature_names_ref[feature_name]]);
                    let tr = "<tr>";
                    tr += "<td>" + feature_name + "</td>";
                    tr += "<td>" + root_whois_features[feature_name] + "</td>";
                    tr += "<td>" + whois_info + "</td>";
                    tr += "<td>" + local_dist.toString() + "</td>";
                    tr += "</tr>";
                    table += tr;
                    total_dist += local_dist;
                });
                let tr = "<tr>";
                tr += "<td colspan='3'>Total Distance</td>";
                tr += "<td>" + total_dist.toString() + "</td>";
                tr += "</tr>";
                table += tr;
                table += "</tbody>";
                table += "</table>";
                let style = total_dist <= threshold_default ? "" : "display:none;";
                html += '<div class="panel panel-default panel-comparison" style="' + style + '" data-totaldist="' + total_dist + '">';
                html += '<div class="panel-heading" role="tab" id="heading' + count + '">';
                html += '<h4 class="panel-title" style="display: inline; margin-right: 10px">';
                html += '<a role="button" data-toggle="collapse" data-parent="#accordion" href="#collapse' + count + '" aria-expanded="true" aria-controls="collapse' + count + '" >';
                html += domain;
                html += '</a></h4>';
                html += "<input type='checkbox' name='search_domain_table[]' value='" + domain + "' checked='True'/>";
                html += '</div>';
                html += '<div id="collapse' + count + '"  class="panel-collapse collapse" role="tabpanel" aria-labelledby="heading' + count + '" >';
                html += '<div class="panel-body">';
                html += table;
                html += '</div>';
                html += '</div>';
                html += '</div>';
                count++;
            });

        }
        html += '</div>';
        html += '<script type="application/javascript">';
        html += "let slider1 = document.getElementById('slider-range');";
        html += "let slider1Value = document.getElementById('slider-range-span');";
        html += "noUiSlider.create(slider1, {start: " + threshold_default + ", animate: true, range: { min: 5, max: 200}});";
        html += "slider1.noUiSlider.on('update', function( values, handle ){ " +
            "let new_threshold = values[handle];" +
            "slider1Value.innerHTML = new_threshold;" +
            "$('.panel-comparison').each(function (){" +
            "let elem = $(this);" +
            "if(parseFloat(elem.data('totaldist')) <= new_threshold){" +
            "elem.show();" +
            "}else{" +
            "elem.hide();" +
            "}" +
            "});" +
            "});";
        html += '</script>';
        return html;


    }

    getIOCs(weblog_id) {
        var thiz = this;
        this.initModal("IOCs Selected:" + weblog_id);
        let data = {weblog_id: weblog_id};
        $.ajax({
            type: "GET",
            dataType: "json",
            data: data,
            url: "/manati_project/manati_ui/analysis_session/weblog/iocs",
            success: function (json) {// handle a successful response
                let iocs = json['iocs'];
                let table = thiz.buildTableIOCs(iocs);
                Modals.updateBodyModal(table);
            },
            error: function (xhr, errmsg, err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }

        })

    }

    getModulesChangesHistory(weblog_id) {
        var thiz = this;
        this.initModal("Modules Changes History of Weblog ID:" + weblog_id);
        let data = {weblog_id: weblog_id};
        $.ajax({
            type: "GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/analysis_session/weblog/modules_changes_attributes",
            success: function (json) {// handle a successful response
                let mod_attributes = JSON.parse(json['data']);
                let table = thiz.buildTableInfo_Mod_attributes(mod_attributes);
                Modals.updateBodyModal(table);
                // let info_report = JSON.parse(json['info_report']);
                // let query_node = json['query_node'];
                // let table = buildTableInfo_VT(info_report);
                // updateBodyModal(table);
            },
            error: function (xhr, errmsg, err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }

        })

    }

    getWeblogHistory(weblog_id) {
        var thiz = this;
        this.initModal("Weblog History ID:" + weblog_id);
        let data = {weblog_id: weblog_id};
        $.ajax({
            type: "GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/analysis_session/weblog/history",
            success: function (json) {// handle a successful response
                let weblog_history = JSON.parse(json['data']);
                let table = thiz.buildTableInfo_Wbl_History(weblog_history);
                Modals.updateBodyModal(table);
            },
            error: function (xhr, errmsg, err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
            }

        })

    }

    consultVirusTotal(query_node, query_type) {
        var thiz = this;
//         if (query_type === "domain") _m.EventVirusTotalConsultationByDomian(query_type);
//         else if (query_type === "ip") _m.EventVirusTotalConsultationByIp(query_type);
//         else {
//             console.error("Error query_type for ConsultVirusTotal is incorrect")
//         }
        this.initModal("Virus Total Query: <span>?????</span>");
        let data = {query_node: query_node, query_type: query_type};
        $.ajax({
            type: "GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/consult_virus_total",
            success: function (json) {// handle a successful response
                let info_report = JSON.parse(json['info_report']);
                let node = json['query_node'];
                let table = thiz.buildTableInfo_VT(info_report);
                if (query_type === 'ip') {
                    query_node = "<a target='_blank' href='https://virustotal" +
                        ".com/en/ip-address/" + node + "/information/'>" + node + "</a>"
                }
                else if (query_type === 'domain') {
                    query_node = "<a target='_blank' href='https://virustotal" +
                        ".com/en/domain/" + node + "/information/'>" + node + "</a>"
                }
                thiz.initModal("VirusTotal Query: <span>" + query_node + "</span>");
                Modals.updateBodyModal(table);
            },
            error: function (xhr, errmsg, err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }

        })
    }

    showModalCheckingTypeFile(filename, header, data) {
        var thiz = this;
        let before_hidden_func = function () {
            let headers = $('#list-column select').map(function () {
                return this.value;
            }).toArray();
            thiz.settingsForInitData(headers, data);
        };
        this.initModal("Pre-visualize: <span>" + filename + "</span>", null, before_hidden_func);
        Modals.updateBodyModal(build_FilePreviewer(header, data));

    }

    create_weblog_comment(weblog_id, fn){
        let thiz = this;
        this.initModal("Add a comment", fn);
        $('#button-ok-modal').on('click', function (ev) {
            let comment_data = $("#textarea-comment").val();
            $.ajax({
                url: '/manati_project/manati_ui/weblog/comment/create',
                type: "POST",
                dataType: "json",
                data: {text: comment_data, weblog_id: weblog_id},
                success: function (json) {
                    $.notify(json['msg'], "info");
                },
                error: function (xhr, errmsg, err) {
                    $.notify(xhr.status + ": " + xhr.responseText, "error");
                    console.log(xhr.status + ": " + xhr.responseText);
                    // provide a bit more info about the
                    // error to the console
                }
            })

        });
        $.ajax({
            url: '/manati_project/manati_ui/weblog/comment/get',
            type: "GET",
            dataType: "json",
            data: {weblog_id: weblog_id},
            success: function (json) {
                let comment = json['text'];
                let str_data = "<textarea id='textarea-comment' maxlength='250' " +
                    "class='form-control' " +
                    "row='5'></textarea>";
                Modals.updateBodyModal(str_data);
                $("#textarea-comment").val(comment);
            },
            error: function (xhr, errmsg, err) {
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText);
                // provide a bit more info about the
                // error to the console
            }
        });
    }

    consultShortcut() {
        var thiz = this;
        thiz.initModal("List of Hotkeys");
        $.ajax({
            url: '/manati_project/manati_ui/hotkeys/list',
            type: "GET",
            dataType: "json",
            success: function (json) {
                let table = thiz.buildTableHotkeys(json['hotkeys']);
                Modals.updateBodyModal(table);
            },
            error: function (xhr, errmsg, err) {
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console
            }
        })
    }

    consultWhois(query_node, query_type) {
        var thiz = this;
//         if (query_type === "domain") _m.EventWhoisConsultationByDomian(query_type);
//         else if (query_type === "ip") _m.EventWhoisConsultationByIp(query_type);
//         else {
//             console.error("Error query_type for WhoisConsultation is incorrect")
//         }
        this.initModal("Whois Query: <span>????</span>");
        let data = {query_node: query_node, query_type: query_type};
        $.ajax({
            type: "GET",
            data: data,
            dataType: "json",
            url: "/manati_project/manati_ui/consult_whois",
            success: function (json) {// handle a successful response
                let info_report = json['info_report'];
                let query_node = json['query_node'];
                let table = thiz.buildTableInfo_Whois(info_report);
                thiz.initModal("WHOIS Query: <span>" + query_node + "</span>");
                Modals.updateBodyModal(table);
            },
            error: function (xhr, errmsg, err) { // handle a non-successful response
                $.notify(xhr.status + ": " + xhr.responseText, "error");
                console.log(xhr.status + ": " + xhr.responseText); // provide a bit more info about the error to the console

            }

        })
    }
}

export default Modals;

