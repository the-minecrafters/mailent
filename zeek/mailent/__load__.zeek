@load base/protocols/conn
@load base/protocols/smtp
@load base/protocols/ssl
@load base/files/x509
@load policy/protocols/ssl/ssl-log-ext
@load policy/frameworks/files/hash-all-files
@load-sigs ./dpd.sig

module Mailent;

export {
    redef enum Log::ID += { LOG };
    type Info: record {
        ts: time &log;
        uid: string &log;
        protocol: string &log;
        kind: string &log;
        cipher_id: count &log &optional;
    };
}
redef LogAscii::use_json = T;
redef record connection += {
    mailent_ehlo: bool &default=F;
    mailent_advertised: bool &default=F;
    mailent_pending: bool &default=F;
    mailent_rejected: bool &default=F;
    mailent_capa: bool &default=F;
};

function emit(c: connection, protocol: string, kind: string) {
    Log::write(LOG, [$ts=network_time(), $uid=c$uid, $protocol=protocol, $kind=kind]);
}

event zeek_init() {
    Log::create_stream(LOG, [$columns=Info, $path="mailent"]);
    Analyzer::register_for_ports(Analyzer::ANALYZER_IMAP, set(143/tcp));
    Analyzer::register_for_ports(Analyzer::ANALYZER_POP3, set(110/tcp));
    # Default SMTP logs contain envelope/header data that posture does not need.
    Log::disable_stream(SMTP::LOG);
}

event connection_established(c: connection) { emit(c, "", "tcp_connected"); }

event smtp_request(c: connection, is_orig: bool, command: string, arg: string) {
    if ( ! is_orig ) return;
    local cmd = to_upper(command);
    emit(c, "smtp", "protocol_identified");
    if ( cmd == "EHLO" ) {
        c$mailent_ehlo = T;
        c$mailent_advertised = F;
        emit(c, "smtp", "ehlo");
    }
    if ( cmd == "STARTTLS" || cmd == "X-ANONYMOUSTLS" ) {
        c$mailent_pending = T;
        emit(c, "smtp", "starttls_requested");
    }
    else if ( c$mailent_rejected && cmd != "QUIT" )
        emit(c, "smtp", "plaintext_continuation");
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool) {
    if ( is_orig ) return;
    if ( code == 220 && ! c$mailent_pending ) emit(c, "smtp", "smtp_greeting");
    if ( to_upper(cmd) == "EHLO" && code == 250 && c$mailent_ehlo ) {
        if ( /^STARTTLS([ \t]|$)/ in to_upper(msg) ) {
            c$mailent_advertised = T;
            emit(c, "smtp", "starttls_advertised");
        }
        if ( ! cont_resp ) {
            if ( ! c$mailent_advertised ) emit(c, "smtp", "starttls_not_advertised");
            c$mailent_ehlo = F;
        }
    }
    if ( c$mailent_pending && (code >= 400) ) {
        emit(c, "smtp", "starttls_rejected");
        c$mailent_pending = F;
        c$mailent_rejected = T;
    }
}

event smtp_starttls(c: connection) { emit(c, "smtp", "starttls_accepted"); }
event imap_capabilities(c: connection, capabilities: string_vec) {
    local advertised = F;
    for ( i in capabilities ) if ( to_upper(capabilities[i]) == "STARTTLS" ) advertised = T;
    emit(c, "imap", advertised ? "starttls_advertised" : "starttls_not_advertised");
}
event imap_starttls(c: connection) { emit(c, "imap", "starttls_accepted"); }

event pop3_request(c: connection, is_orig: bool, command: string, arg: string) {
    if ( ! is_orig ) return;
    local cmd = to_upper(command);
    emit(c, "pop3", "protocol_identified");
    c$mailent_capa = cmd == "CAPA";
    if ( cmd == "STLS" ) {
        c$mailent_pending = T;
        emit(c, "pop3", "starttls_requested");
    }
    else if ( c$mailent_rejected && cmd != "QUIT" ) emit(c, "pop3", "plaintext_continuation");
}
event pop3_data(c: connection, is_orig: bool, data: string) {
    # Examine only CAPA metadata. Never log message content or credentials.
    if ( ! is_orig && c$mailent_capa && to_upper(data) == "STLS" )
        emit(c, "pop3", "starttls_advertised");
}
event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string) {
    if ( ! is_orig && c$mailent_pending && (to_upper(cmd) == "ERR" || to_upper(cmd) == "-ERR") ) {
        emit(c, "pop3", "starttls_rejected");
        c$mailent_rejected = T;
        c$mailent_pending = F;
    }
}
event pop3_starttls(c: connection) { emit(c, "pop3", "starttls_accepted"); }

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) {
    emit(c, "", "tls_client_hello");
}
event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) {
    Log::write(LOG, [$ts=network_time(), $uid=c$uid, $protocol="", $kind="tls_server_hello", $cipher_id=cipher]);
}
event ssl_established(c: connection) { emit(c, "", "tls_established"); }
event ssl_alert(c: connection, is_orig: bool, level: count, desc: count) {
    if ( level == 2 ) emit(c, "", "tls_fatal_alert");
}

event ssl_ecdh_server_params(c: connection, curve: count, point: string) { emit(c, "", "key_exchange_ecdhe"); }
event ssl_dh_server_params(c: connection, p: string, q: string, Ys: string) { emit(c, "", "key_exchange_dhe"); }
event ssl_rsa_client_pms(c: connection, pms: string) { emit(c, "", "key_exchange_rsa_static"); }
event ssl_extension_key_share(c: connection, is_client: bool, curves: index_vec) {
    if ( is_client ) return;
    for ( i in curves ) {
        if ( curves[i] in set(23, 24, 25, 29, 30) ) emit(c, "", "key_exchange_ecdhe");
        else if ( curves[i] >= 256 && curves[i] <= 260 ) emit(c, "", "key_exchange_dhe");
    }
}
event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) {
    if ( f?$conns && f?$is_orig && ! f$is_orig )
        for ( _, c in f$conns ) emit(c, "", "certificate_observed");
}
event conn_weird(name: string, c: connection, addl: string, source: string) {
    if ( name == "IMAP: server refused StartTLS" ) emit(c, "imap", "starttls_rejected");
}
