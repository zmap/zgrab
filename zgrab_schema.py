from zschema import *

zgrab_subj_issuer = SubRecord({
    "serial_number":ListOf(String()),
    "common_name":ListOf(String()),
    "country":ListOf(String()),
    "locality":ListOf(String()),
    "province":ListOf(String()),
    "street_address":ListOf(String()),
    "organization":ListOf(String()),
    "organizational_unit":ListOf(String()),
    "postal_code":ListOf(String()),
})

unknown_extension = SubRecord({
    "id":String(),
    "critical":Boolean(),
    "value":Binary(),
})

zgrab_parsed_certificate = SubRecord({
    "subject":zgrab_subj_issuer,
    "issuer":zgrab_subj_issuer,
    "version":Integer(),
    "serial_number":String(doc="Serial number as an unsigned decimal integer. Stored as string to support >uint lengths. Negative values are allowed."),
    "validity":SubRecord({
        "start":DateTime(doc="Timestamp of when certificate is first valid. Timezone is UTC."),
        "end":DateTime(doc="Timestamp of when certificate expires. Timezone is UTC.")
    }),
    "signature_algorithm":SubRecord({
        "name":String(),
        "oid":String(),
    }),
    "subject_key_info":SubRecord({
        "key_algorithm":SubRecord({
            "name":String(doc="Name of public key type, e.g., RSA or ECDSA. More information is available the named SubRecord (e.g., rsa_public_key)."),
            "oid":String(doc="OID of the public key on the certificate. This is helpful when an unknown type is present. This field is reserved and not current populated.")
         }),
        "rsa_public_key":SubRecord({
            "exponent":Long(),
            "modulus":Binary(),
            "length":Integer(doc="Bit-length of modulus.")
         }),
        "dsa_public_key":SubRecord({
            "p":Binary(),
            "q":Binary(),
            "g":Binary(),
            "y":Binary(),
        }),
        "ecdsa_public_key":SubRecord({
            "b":Binary(),
            "gx":Binary(),
            "gy":Binary(),
            "n":Binary(),
            "p":Binary(),
            "x":Binary(),
            "y":Binary(),
        })
    }),
    "extensions":SubRecord({
        "key_usage":SubRecord({
            "digital_signature":Boolean(),
            "certificate_sign":Boolean(),
            "crl_sign":Boolean(),
            "content_commitment":Boolean(),
            "key_encipherment":Boolean(),
            "value":Integer(),
            "data_encipherment":Boolean(),
            "key_agreement":Boolean(),
            "decipher_only":Boolean(),
            "encipher_only":Boolean(),
        }),
        "basic_constraints":SubRecord({
            "is_ca":Boolean(),
            "max_path_len":Integer(),
        }),
        "subject_alt_name":SubRecord({
            "dns_names":ListOf(String()),
            "email_addresses":ListOf(String()),
            "ip_addresses":ListOf(String()),
        }),
        "crl_distribution_points":ListOf(String()),
        "authority_key_id":String(), # is this actdually binary?
        "extended_key_usage":ListOf(Integer()),
        "certificate_policies":ListOf(String()),
        "authority_info_access":SubRecord({
            "ocsp_urls":ListOf(String()),
            "issuer_urls":ListOf(String())
        }),
        "name_constraints":SubRecord({
            "critical":Boolean(),
            "permitted_names":ListOf(String()),
        }),
    }),
    "unknown_extensions":ListOf(unknown_extension),
    "signature":SubRecord({
        "signature_algorithm":SubRecord({
            "name":String(),
            "oid":String(),
        }),
        "value":Binary(),
        "valid":Boolean(),
        "self_signed":Boolean(),
    }),
    "fingerprint_md5":Binary(),
    "fingerprint_sha1":Binary(),
    "fingerprint_sha256":Binary(),
})

zgrab_certificate = SubRecord({
    "raw":Binary(),
    "parsed":zgrab_parsed_certificate,
})

zgrab_tls = SubRecord({
    "client_hello":SubRecord({
        "random":Binary(),
        "extended_random":Binary(),
    }),
    "server_hello":SubRecord({
        "version":SubRecord({
            "name":String(),
            "value":Integer()
        }),
        "random":Binary(),
        "session_id": Binary(),
        "cipher_suite":SubRecord({
            "hex":String(),
            "name":String(),
            "value":Integer(),
        }),
        "compression_method":Integer(),
        "ocsp_stapling":Boolean(),
        "ticket":Boolean(),
        "secure_renegotiation":Boolean(),
        "heartbeat":Boolean(),
        "extended_random":Binary(),
    }),
    "server_certificates":SubRecord({
        "certificate":zgrab_certificate,
        "chain":ListOf(zgrab_certificate),
        "validation":SubRecord({
            "browser_trusted":Boolean(),
            "browser_error":String(),
            "matches_domain":Boolean(),
        }),
    }),
    "server_key_exchange":SubRecord({
        "ecdh_params":SubRecord({
            "curve_id":SubRecord({
                "name":String(),
                "id":Integer(),
            }),
            "server_public":SubRecord({
                "x":SubRecord({
                    "value":Binary(),
                    "length":Integer(),
                }),
                "y":SubRecord({
                    "value":Binary(),
                    "length":Integer(),
                }),
            }),
        }),
        "rsa_params":SubRecord({
            "exponent":Long(),
            "modulus":Binary(),
            "length":Integer(),
        }),
        "dh_params":SubRecord({
            "prime":SubRecord({
                "value":Binary(),
                "length":Integer(),
            }),
            "generator":SubRecord({
                "value":Binary(),
                "length":Integer(),
            }),
            "server_public":SubRecord({
                "value":Binary(),
                "length":Integer(),
           }),
        }),
        "signature":SubRecord({
            "raw":Binary(),
            "type":String(),
            "valid":Boolean(),
            "signature_and_hash_type":SubRecord({
                "signature_algorithm":String(),
                "hash_algorithm":String(),
            }),
            "tls_version":SubRecord({
                "name":String(),
                "value":Integer()
            }),
        }),
        "signature_error":String(),
    }),
    "server_finished":SubRecord({
        "verify_data":Binary()
    })
})

zgrab_base = Record({
    "ip":IPv4Address(required=True),
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

zgrab_tls_banner=Record({
    "data":SubRecord({
        "tls":zgrab_tls,
    })
}, extends=zgrab_banner)
register_schema("zgrab-imaps", zgrab_tls_banner)
register_schema("zgrab-pop3s", zgrab_tls_banner)

zgrab_starttls = Record({
    "data":SubRecord({
        "starttls":String(),
    })
}, extends=zgrab_tls_banner)
register_schema("zgrab-imap", zgrab_starttls)
register_schema("zgrab-pop3", zgrab_starttls)

zgrab_smtp = Record({
    "data":SubRecord({
        "ehlo":String(),
    })
}, extends=zgrab_starttls)
register_schema("zgrab-smtp", zgrab_smtp)


zgrab_https = Record({
    "data":SubRecord({
        "tls":zgrab_tls
    })
}, extends=zgrab_base)

register_schema("zgrab-https", zgrab_https)

zgrab_heartbleed = SubRecord({
    "heartbeat_enabled":Boolean(),
    "heartbleed_vulnerable":Boolean()
})

zgrab_https_heartbleed = Record({
    "data":SubRecord({
        "heartbleed":zgrab_heartbleed
    })
}, extends=zgrab_https)

register_schema("zgrab-https-heartbleed", zgrab_https_heartbleed)

zgrab_unknown_http_header = SubRecord({
    "key":String(),
    "value":String()
})

zgrab_http_headers = SubRecord({
    "access_control_allow_origin":String(),
    "accept_patch":String(),
    "accept_ranges":String(),
    "age":String(),
    "allow":String(),
    "cache_control":String(),
    "connection":String(),
    "content_disposition":String(),
    "content_encoding":String(),
    "content_language":String(),
    "content_length":String(),
    "content_location":String(),
    "content_md5":String(),
    "content_range":String(),
    "content_type":String(),
    "date":String(),
    "etag":String(),
    "expires":String(),
    "last_modified":String(),
    "link":String(),
    "location":String(),
    "p3p":String(),
    "pragma":String(),
    "proxy_authenticate":String(),
    "public_key_pins":String(),
    "refresh":String(),
    "retry_after":String(),
    "server":AnalyzedString(),
    "set_cookie":String(),
    "status":String(),
    "strict_transport_security":String(),
    "trailer":String(),
    "transfer_encoding":String(),
    "upgrade":String(),
    "vary":String(),
    "via":String(),
    "warning":String(),
    "www_authenticate":String(),
    "x_frame_options":String(),
    "x_xss_protection":String(),
    "content_security_policy":String(),
    "x_content_security_policy":String(),
    "x_webkit_csp":String(),
    "x_content_type_options":String(),
    "x_powered_by":String(),
    "x_ua_compatible":String(),
    "x_content_duration":String(),
    "proxy_agent":String(),
    "unknown":ListOf(zgrab_unknown_http_header)
})

zgrab_http_request = SubRecord({
    "method":String(),
    "endpoint":String(),
    "user_agent":String()
})

zgrab_http_response = SubRecord({
    "status_code":Integer(),
    "status_line":AnalyzedString(),
    "body":HTML(),
    "body_sha256": Binary(),
    "headers":zgrab_http_headers
})

zgrab_http = Record({
    "data":SubRecord({
      "http":SubRecord({
        "request":zgrab_http_request,
        "response":zgrab_http_response
      })
    })
}, extends=zgrab_base)

register_schema("zgrab-http", zgrab_http)

zgrab_http_proxy = Record({
    "data":SubRecord({
      "http":SubRecord({
        "connect_request":zgrab_http_request,
        "connect_response":zgrab_http_response
      })
    })
}, extends=zgrab_http)
register_schema("zgrab-proxy", zgrab_http_proxy)

zgrab_old_http = Record({
    "data":SubRecord({
        "write":String(),
        "read":String(),
    })
}, extends=zgrab_base)

register_schema("zgrab-old-http", zgrab_old_http)

zgrab_modbus = Record({
    "data":SubRecord({
        "modbus":SubRecord({
            "length":Integer(),
            "unit_id":Integer(),
            "function_code":Integer(),
            "raw_response":String(),
            "mei_response":SubRecord({
                "conformity_level":Integer(),
                "more_follows":Boolean(),
                "object_count":Integer(),
                "objects":SubRecord({
                    "product_code":String(),
                    "revision":String(),
                    "vendor":String(),
                    "oid.255":String(),
                    "vendor_url":String(),
                    "product_name":String(),
                    "model_name":String(),
                    "user_application_name":String(),
                }),
            }),
            "exception_response":SubRecord({
                "exception_function":Integer(),
                "exception_type":Integer(),
            }),
        }),
    }),
}, extends=zgrab_base)

register_schema("zgrab-modbus", zgrab_modbus)
