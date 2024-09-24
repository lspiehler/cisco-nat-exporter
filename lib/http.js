const { http, https} = require('follow-redirects');

var httpRequest = function(params, callback) {
    //console.log(params);
    const req = https.request(params.options, res => {
        var resp = [];

        res.on('data', function(data) {
            resp.push(data);
        });

        res.on('end', function() {
            callback(false, {statusCode: res.statusCode, options: params.options, headers: res.headers, body: Buffer.concat(resp).toString()});
        });
    })

    req.on('error', function(err) {
        console.log(err.toString());
        callback(false, {statusCode: false, options: params.options, headers: false, body: JSON.stringify({ error: err.toString()})});
    })

    if(params.options.method=='POST') {
        req.write(JSON.stringify(params.body));
    }

    req.end()
}

module.exports = {
    request: function(params, callback) {
        //console.log(params);
        httpRequest(params, function(err, resp) {
            if(err) {
                callback(err, resp);
            } else {
                callback(false, resp);
            }
        });
    }
}