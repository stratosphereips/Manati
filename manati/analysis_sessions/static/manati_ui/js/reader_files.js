/**
* Created by raulbeniteznetto on 2/8/17.
*/
const FILES_TYPES_AVAILABLE = ['log', 'csv'];

function ReaderFile(analysis_session_logic_obj){
    var reader;
    var _progress;
    var _aslo = analysis_session_logic_obj;

    function abortRead() {
        reader.abort();
    }

    function errorHandler(evt) {
        switch(evt.target.error.code) {
          case evt.target.error.NOT_FOUND_ERR:
            alert('File Not Found!');
            break;
          case evt.target.error.NOT_READABLE_ERR:
            alert('File is not readable');
            break;
          case evt.target.error.ABORT_ERR:
            break; // noop
          default:
            alert('An error occurred reading this file.');
        };
    }

    function updateProgress(evt) {
    // evt is an ProgressEvent.
        if (evt.lengthComputable) {
          var percentLoaded = Math.round((evt.loaded / evt.total) * 100);
          // Increase the progress bar length.
          if (percentLoaded < 100) {
            _progress.style.width = percentLoaded + '%';
            _progress.textContent = percentLoaded + '%';
          }
        }
    }
    function choiceHeaders(possible_headers){
        var goal = "#fields";
        for(var i=0; i<possible_headers.length; i++) {
            var index = possible_headers[i].indexOf(goal);
            if (index >= 0) {
                var text = possible_headers[i].substring(goal.length + 1);
                return text.trim()
            }
        }
    }
    let _type_file = '';
    function handleFileSelect(evt) {
        reader = new FileReader();
        reader.onloadend = function(evt) {
            let file_rows;
            if (evt.target.readyState === FileReader.DONE) {
                var rows = evt.target.result.split('\n');
                let header = true;
                let delimiter = "";
                if(rows[0][0]==='#'){
                    var i=0;
                    var possible_headers = [];
                    for(; i<rows.length; i++){
                        var row = rows[i];
                        if(row[0] === '#') possible_headers.push(row);
                        else break;
                      }
                    var header_text = choiceHeaders(possible_headers);
                    rows = rows.slice(i,rows.length-2); // removing the headers and the last #close comment.
                    // in the end of the BRO files
                    _type_file = 'bro_http_log';
                    rows.unshift(header_text);
                    file_rows = rows.join('\n');
                }else if((_type_file === null || _type_file === '')){
                    _type_file = 'apache_http_log';
                    header = false;
                    delimiter = " ";
                    file_rows = rows.join('\n');
                    var find = /\[|\]/;
                    var re = new RegExp(find, 'g');
                    file_rows = file_rows.replace(re, '\"');
                }else{
                    file_rows = rows.join('\n');
                }
                _aslo.parseData(file_rows, header,_type_file,delimiter);

            }
        };

        // Read in the image file as a binary string.
        let file = evt.target.files[0];
        let extension = file.name.split('.').pop().toLowerCase();
        if(FILES_TYPES_AVAILABLE.indexOf(extension) > -1){
            if (extension === 'csv'){
                _type_file = 'cisco_file';
            }
            thiz.eventBeforeParing(file);
            reader.readAsBinaryString(file);
        }else{
            $.notify('Incorrect Extension file');
        }


    }
    var funcOnReady = function (){
        // _progress = document.querySelector('.percent');
        $(document).on('change','#visualize_weblogs',handleFileSelect);
        // document.getElementById('visualize_weblogs').addEventListener('change', handleFileSelect, false);
        $(':file').on('fileselect', function(event, numFiles, label) {
              var input = $(this).parents('.input-group').find(':text'),
                  log = numFiles > 1 ? numFiles + ' files selected' : label;
              if( input.length ) {
                  input.val(log);
              } else {
                  if( log ) alert(log);
              }
        });
        $(document).on('change', ':file', function() {
            var input = $(this),
                numFiles = input.get(0).files ? input.get(0).files.length : 1,
                label = input.val().replace(/\\/g, '/').replace(/.*\//, '');
            input.trigger('fileselect', [numFiles, label]);
        });

    };

    $(document).ready(function() {
        funcOnReady();
    });

}

