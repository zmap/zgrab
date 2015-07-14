from zchema import *

zgrab_subj_issuer = SubRecord({
    "serial_number":String(),
    "country":String(),
    "locality":String(),
    "province":String(),
    "street_address":String(),
    "organization":String(),
    "organizational_unit":String(),
    "postal_code":String(),
})

zgrab_parsed_certificate = SubRecord({
    "subject":zgrab_subj_issuer,
    "issuer":zgrab_subj_issuer,
    "version":Integer,
    "serial_number":String(),
    "validity":SubRecord({
        "start":DateTime(),
        "end":DateTime()
    })
})

zgrab_certificate = SubRecord({
    "raw":Binary(),
    "parsed":zgrab_parsed_certificate,
    "signature":SubRecord({})
})

zgrab_tls = SubRecord({
    "client_hello":SubRecord({
        "random":Binary()
    }),
    "server_hello":SubRecord({
    
    }),
    "server_certificates":SubRecord({
        "certificate":zgrab_certificate,
        "chain":ListOf(zgrab_certificate)
    })
})

zgrab_base = Record({
    "host":IPv4Address(required=True),
    "timestamp":DateTime(required=True),
    "domain":String(),
    "data":SubRecord({}),
    "error":String(),
    "error_component":String()
})

zgrab_banner = Record({
    "data":SubRecord({
        "banner":String()
    })
}, extends=zgrab_base)

register_schema("zgrab-ftp", zgrab_banner)

zgrab_smtp = Record({
    "data":SubRecord({
        "ehlo":String(),
        "starttls":String(),
        "tls":zgrab_tls
    })
}, extends=zgrab_banner)
register_schema("zgrab-smtp", zgrab_smtp)

zgrab_starttls = Record({
    "data":SubRecord({
        "starttls":String(),
        "tls":zgrab_tls
    })
}, extends=zgrab_banner)

register_schema("zgrab-imap", zgrab_starttls)
register_schema("zgrab-pop3", zgrab_starttls)

zgrab_https = Record({
    "data":SubRecord({
        "tls":zgrab_tls
    })
})

register_schema("zgrab-https", zgrab_https)

