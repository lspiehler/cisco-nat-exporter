const { Client } = require('ssh2');
const ssh2s = require("ssh2-streams");
const promclient = require('prom-client');
const express = require('express');
const router = express.Router();
const url = require("url");
const https = require('../lib/http');
var credentialcache = {}

router.get('/', function(req, res, next) {
    if (!req.headers.authorization || req.headers.authorization.indexOf('Basic ') === -1) {
        res.setHeader("WWW-Authenticate", "Basic realm=\"cisco-nat-exporter\"");
        //res.setHeader("HTTP/1.0 401 Unauthorized");
        res.status(401).json({
            error: {
                code: 401,
                message: 'Missing Authorization Header'
            }
        });
        return;
    }
    let parsecreds = Buffer.from(req.headers.authorization.substring(6), 'base64').toString().split(':')
    let creds = {
        username: parsecreds[0],
        password: parsecreds[1]
    }
    //let bufferObj = Buffer.from(req.headers.authorization.substring(6), "utf8");
    //console.log(creds);
    /*let labels = [];
    if(req.query.hasOwnProperty('labels')) {
        labels = req.query.labels.split(',');
    }
    let maintanancemode = 'any';
    if(req.query.hasOwnProperty('maintanancemode')) {
        maintanancemode = req.query.maintanancemode;
    }*/
    if(req.query.hasOwnProperty('target') === false) {
        res.status(400).json({
            error: {
                code: 400,
                message: 'A target must be specified'
            }
        });
        return;
    }
    /*let application = false;
    if(req.query.hasOwnProperty('application')) {
        application = req.query.application;
    }
    let groupId = false;
    if(req.query.hasOwnProperty('groupId')) {
        groupId = req.query.groupId;
    }*/
    //console.log(creds);
    //console.log(req.query.target);

    const reg = new promclient.Registry();
    //const collectDefaultMetrics = client.collectDefaultMetrics;

    //collectDefaultMetrics({ register: reg });

    const success_gauge = new promclient.Gauge({
        name: 'probe_success',
        help: 'Displays whether or not the probe was a success',
        registers: [reg]
    });

    SSHCommand({
        username: creds.username,
        password: creds.password,
        target: req.query.target,
        command: "show ip nat translations tcp total\n"
    }, function(err, result) {
        if(err) {
            success_gauge.set(0);
            reg.metrics().then(function(resp) {
                //callback(false, resp);
                res.send(resp);
                //register.clear();
            })
            return;
        } else {
            let tcp = result.stdout.split(":")[1].trim();
            SSHCommand({
                username: creds.username,
                password: creds.password,
                target: req.query.target,
                command: "show ip nat translations udp total\n"
            }, function(err, result) {
                if(err) {
                    success_gauge.set(0);
                    reg.metrics().then(function(resp) {
                        //callback(false, resp);
                        res.send(resp);
                        //register.clear();
                    })
                    return;
                } else {
                    let udp = result.stdout.split(":")[1].trim();
                    const pat_gauge = new promclient.Gauge({
                        name: 'nat_translations',
                        help: 'allocated pat translations',
                        labelNames: ['protocol'],
                        registers: [reg]
                    });
    
                    pat_gauge.set({ protocol: 'tcp' }, parseInt(tcp));
                    pat_gauge.set({ protocol: 'udp' }, parseInt(udp));
                    /*reg.getMetricsAsJSON().then(function(resp) {
                        console.log(resp);
                    })*/
                    success_gauge.set(1);
                    reg.metrics().then(function(resp) {
                        //callback(false, resp);
                        res.send(resp);
                        //register.clear();
                    })
                }
            });
        }
    });
});

var SSHCommand = function(params, callback) {
    let username = params.username;
    let password = params.password;
    let handshake;
    var timeout;

    let finished = false;

    const conn = new Client();
    conn.on('ready', () => {
        timeout = setTimeout(function() {
            //conn.end();
            conn.end();
            callback('ssh session timed out', {
                error: 'ssh session timed out'
            });
            timeout = null;
            finished = true;
            return;
        }, 20000);
        /*if(timeout) {
            clearTimeout(timeout);
        }
        conn.end();

        callback(false, {
            error: false,
            handshake: handshake,
            username: username
        });*/
        conn.exec(params.command + '\n', (err, stream) => {
            //stream.write
            const stdoutbuff = [];
            const stderrbuff = [];
            if (err) throw err;
            stream.on('close', (code, signal) => {
                //console.log('Stream :: close :: code: ' + code + ', signal: ' + signal);
                if(timeout) {
                    clearTimeout(timeout);
                }
                if(finished==false) {
                    finished = true;
                    conn.end();
                    callback(false, {
                        error: false,
                        handshake: handshake,
                        stdout: Buffer.concat(stdoutbuff).toString(),
                        stderr: Buffer.concat(stderrbuff).toString()
                    });
                }
            }).on('end', () => {
                //console.log('END');
            }).on('drain', () => {
                //console.log('DRAIN');
            }).on('data', (data) => {
                //console.log(tracker);
                let text = data.toString().trim();
                //console.log('STDOUT: ' + text);
                stdoutbuff.push(data);
                stream.close();
            }).stderr.on('data', (data) => {
                //console.log('STDERR: ' + data);
                //stderrbuff.push(data);
            });
        });
    })

    conn.on('error', function(err) {
        if(timeout) {
            clearTimeout(timeout);
        }
        if(finished==false) {
            finished = true;
            conn.destroy();
            callback(err, {
                error: {
                    err: err,
                    message: err.toString()
                }
            });
        }
    })

    //adding key exchanges for crappy hardware
    //let customkex = ssh2s.constants.ALGORITHMS.SUPPORTED_KEX;
    //customkex.push('diffie-hellman-group1-sha1');

    let connection = conn.connect({
        host: params.target,
        port: 22,
        username: username,
        password: password,
        algorithms: {
            kex: ssh2s.constants.ALGORITHMS.SUPPORTED_KEX,
            cipher: [
                'aes128-ctr',
                'aes192-ctr',
                'aes256-ctr',
                'aes128-gcm@openssh.com',
                'aes256-gcm@openssh.com',
                'aes256-cbc',
                'aes192-cbc',
                'aes128-cbc',
                '3des-cbc'
            ],
            serverHostKey: ssh2s.constants.ALGORITHMS.SERVER_HOST_KEY_BUF, 
            hmac: ssh2s.constants.ALGORITHMS.SUPPORTED_HMAC,
            compress: ssh2s.constants.ALGORITHMS.SUPPORTED_COMPRESS
        }
    });

    connection.on('handshake', function(data) {
        handshake = data;
    });
}

var getNATTranslations = function(params, callback) {
    let username = params.username;
    let password = params.password;
    let handshake;
    var timeout;

    let steps = [
        'enable',
        'terminal',
        'show',
        'exit'
    ]

    let tracker = 0;
    let finished = false;

    const conn = new Client();
    conn.on('ready', () => {
        timeout = setTimeout(function() {
            //conn.end();
            conn.end();
            callback('ssh session timed out', {
                error: 'ssh session timed out'
            });
            timeout = null;
            finished = true;
            return;
        }, 20000);
        /*if(timeout) {
            clearTimeout(timeout);
        }
        conn.end();

        callback(false, {
            error: false,
            handshake: handshake,
            username: username
        });*/
        conn.exec('terminal pager 0\n', (err, stream) => {
            //stream.write
            const stdoutbuff = [];
            const stderrbuff = [];
            if (err) throw err;
            stream.on('close', (code, signal) => {
                console.log('Stream :: close :: code: ' + code + ', signal: ' + signal);
                if(timeout) {
                    clearTimeout(timeout);
                }
                if(finished==false) {
                    finished = true;
                    conn.end();
                    callback(false, {
                        error: false,
                        handshake: handshake,
                        stdout: Buffer.concat(stdoutbuff).toString(),
                        stderr: Buffer.concat(stderrbuff).toString()
                    });
                }
            }).on('end', () => {
                console.log('END');
            }).on('drain', () => {
                console.log('DRAIN');
            }).on('data', (data) => {
                console.log(tracker);
                let text = data.toString().trim();
                console.log('STDOUT: ' + text);
                if(tracker==0) {
                    tracker++;
                    console.log('running second command');
                    stream.write('show ip nat translations tcp total\n');
                    /*if(text=="Password:") {
                        tracker++;
                        //console.log('entering password');
                        stream.write(configs.configs[params.config].enable + '\n');
                    } else if(text.substring(text.length - 1) == "#") {
                        tracker++;
                        //console.log('entering password');
                        stream.write('\n');
                    }*/
                } else if(tracker==1) {
                    tracker++;
                    console.log('running third command');
                    stream.write('show ip nat translations udp total\n');
                    //console.log("data" + data + "data")
                    /*if(text.substring(text.length - 1) == "#") {
                        stream.write('terminal pager 0\n')
                        tracker++;
                    }*/
                } else if(tracker==2) {
                    //console.log("data" + data + "data")
                    stream.close();
                }/* else if(tracker==3) {
                    if(text.substring(text.length - 1) == "#") {
                        stream.close();
                    } else {
                        //console.log(data.toString());
                        stdoutbuff.push(data);
                    }
                }*/
                //stdoutbuff.push(data);
            }).stderr.on('data', (data) => {
                console.log('STDERR: ' + data);
                //stderrbuff.push(data);
            });
        });
    })

    conn.on('error', function(err) {
        if(timeout) {
            clearTimeout(timeout);
        }
        if(finished==false) {
            finished = true;
            conn.destroy();
            callback(err, {
                error: {
                    err: err,
                    message: err.toString()
                }
            });
        }
    })

    //adding key exchanges for crappy hardware
    //let customkex = ssh2s.constants.ALGORITHMS.SUPPORTED_KEX;
    //customkex.push('diffie-hellman-group1-sha1');

    let connection = conn.connect({
        host: params.target,
        port: 22,
        username: username,
        password: password,
        algorithms: {
            kex: ssh2s.constants.ALGORITHMS.SUPPORTED_KEX,
            cipher: [
                'aes128-ctr',
                'aes192-ctr',
                'aes256-ctr',
                'aes128-gcm@openssh.com',
                'aes256-gcm@openssh.com',
                'aes256-cbc',
                'aes192-cbc',
                'aes128-cbc',
                '3des-cbc'
            ],
            serverHostKey: ssh2s.constants.ALGORITHMS.SERVER_HOST_KEY_BUF, 
            hmac: ssh2s.constants.ALGORITHMS.SUPPORTED_HMAC,
            compress: ssh2s.constants.ALGORITHMS.SUPPORTED_COMPRESS
        }
    });

    connection.on('handshake', function(data) {
        handshake = data;
    });
}

module.exports = router;