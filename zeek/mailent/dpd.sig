# Delegate stream handling to native Zeek analyzers, including nonstandard ports.
signature mailent-pop3 {
    ip-proto == tcp
    payload /^[+][Oo][Kk][ \t]/
    tcp-state responder
    enable "pop3"
}
signature mailent-imap {
    ip-proto == tcp
    payload /^[*][ \t]+[Oo][Kk][ \t]/
    tcp-state responder
    enable "imap"
}
