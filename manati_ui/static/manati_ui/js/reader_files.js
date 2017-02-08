/**
* Created by raulbeniteznetto on 2/8/17.
*/
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
    function handleFileSelect(evt) {
        // Reset progress indicator on new file selection.
        // _progress.style.width = '0%';
        // _progress.textContent = '0%';

        reader = new FileReader();
        // reader.onerror = errorHandler;
        // reader.onprogress = updateProgress;
        // reader.onabort = function(e) {
        //       alert('File read cancelled');
        // };
        // reader.onloadstart = function(e) {
        //   document.getElementById('progress_bar').className = 'loading';
        // };
        // reader.onload = function(e) {
        //   // Ensure that the progress bar displays 100% at the end.
        //   _progress.style.width = '100%';
        //   _progress.textContent = '100%';
        //   setTimeout("document.getElementById('progress_bar').className='';", 2000);
        // };
        reader.onloadend = function(evt) {
          if (evt.target.readyState == FileReader.DONE) {
              var rows = evt.target.result.split('\n');
              if(rows[0][0]=='#'){
                  var i=0;
                  var possible_headers = [];
                  for(; i<rows.length; i++){
                      var row = rows[i];
                      if(row[0] == '#') possible_headers.push(row);
                      else break;
                  }
                  var header = choiceHeaders(possible_headers);
                  rows = rows.slice(i,rows.length+1);
                  rows.unshift(header);
              }
              var file_rows = rows.join('\n');
              _aslo.parseData(file_rows);

          }
        };

        // Read in the image file as a binary string.
        var file = evt.target.files[0];
        thiz.eventBeforeParing(file);
        reader.readAsBinaryString(file);

    }
    var funcOnReady = function (){
        // _progress = document.querySelector('.percent');
        document.getElementById('visualize_weblogs').addEventListener('change', handleFileSelect, false);
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

