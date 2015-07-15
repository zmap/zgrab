from zschema import *

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
    }),
    "subject_key_info":SubRecord({
        "key_algorithm":String()
    }),
    "extensions":SubRecord({
        "certificate_policies":ListOf(String()),
        "key_usage":SubRecord({
            "digital_signature":Boolean(),
            "key_encipherment":Boolean(),
            "value":Integer()
        }),
        "basic_constraints":SubField({
            "is_ca":Boolean()
        }),
        "subject_alt_names":SubRecord({
            "dns_names":ListOf(String())
        })
        "crl_distribution_points":ListOf(String()),
        "authority_key_id":String(), # is this actdually binary?
        "extended_key_usage":ListOf(Integer()),
        "certificate_policies":ListOf(String()),
        "authority_info_access":SubRecord({
            "ocsp_urls":ListOf(String()),
            "issuer_urls":ListOf(String())
        })        
    })
})

zgrab_certificate = SubRecord({
    "raw":Binary(),
    "parsed":zgrab_parsed_certificate,
    "signature":SubRecord({
        "algorithm":String(),
        "value":Binary(),
        "valid":Boolean(),
        "validation_error":String(),
        "matches_domain":Boolean(),
        "self_signed":Boolean()
    })
})

zgrab_tls = SubRecord({
    "client_hello":SubRecord({
        "random":Binary()
    }),
    "server_hello":SubRecord({
        "version":SubRecord({
            "name":String(),
            "value":Integer()
        }),
        "random":Binary(),
        "cipher_suite":SubRecord({
            "hex":String(),
            "name":String(),
            "value":Integer(),
        }),
        "compresssion_method":Integer(),
        "ocsp_stapling":Boolean(),
        "ticket":Boolean(),
        "secure_renegotiation":Boolean(),
        "heartbeat":Boolean(),
    }),
    "server_certificates":SubRecord({
        "certificate":zgrab_certificate,
        "chain":ListOf(zgrab_certificate)
    }),
    "server_finished":SubRecord({
        "verify_data":Binary()
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

