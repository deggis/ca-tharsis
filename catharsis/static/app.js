
var x;
var t;

(() => {
    //var toBeMinified = document.getElementsByClassName('colgroup-min');

    function prepare() {
        document.querySelectorAll('.colgroup-min').forEach(function(e) {
            console.log(e);

            var table = e.parentElement.parentElement;

            var colname = e.getAttribute('columnname');
            var colMinified = table.querySelector('col.colgroup-min.'+colname);
            var colLarge = table.querySelector('col.colgroup-large.'+colname);
            x = e;
            t=table;

            table.querySelectorAll('a.col-closeaction.'+colname).forEach(function(closeLink) {
                
                var closeAction = function() {
                    colMinified.style.visibility = '';
                    colLarge.style.visibility = 'collapse';
                };
                closeLink.onclick = closeAction;
                closeLink.parentElement.onclick = closeAction;
            });
            table.querySelectorAll('a.col-openaction.'+colname).forEach(function(openLink) {
                var openAction = function() {
                    colLarge.style.visibility = '';
                    colMinified.style.visibility = 'collapse';
                };
                openLink.onclick = openAction;
                openLink.parentElement.onclick = openAction;
            });
   
            if (colname != 'basicinfo' && colname != 'ugs') {
                colMinified.style.visibility = '';
                colLarge.style.visibility = 'collapse';                
            } else {
                e.style.visibility = 'collapse';
            }
        });

    }
    document.addEventListener("DOMContentLoaded", prepare);
})();