from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

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
    "domain_component":ListOf(String()),
})

unknown_extension = SubRecord({
    "id":String(),
    "critical":Boolean(),
    "value":Binary(),
})

alternate_name = SubRecord({
    "dns_names":ListOf(String()),
    "email_addresses":ListOf(String()),
    "ip_addresses":ListOf(String()),
    "directory_names":ListOf(zgrab_subj_issuer),
    "edi_party_names":ListOf(SubRecord({
        "name_assigner":AnalyzedString(es_include_raw=True),
        "party_name":AnalyzedString(es_include_raw=True),
    })),
    "other_names":ListOf(SubRecord({
        "id":String(),
        "value":Binary(),
    })),
    "registered_ids":ListOf(String()),
    "uniform_resource_identifiers":ListOf(AnalyzedString(es_include_raw=True)),
})

rsa_public_key = SubRecord({
    "exponent":Long(),
    "modulus":Binary(),
    "length":Integer(doc="Bit-length of modulus."),
})

dsa_public_key = SubRecord({
    "p":Binary(),
    "q":Binary(),
    "g":Binary(),
    "y":Binary(),
})

ecdsa_public_key = SubRecord({
    "pub":Binary(),
    "b":Binary(),
    "gx":Binary(),
    "gy":Binary(),
    "n":Binary(),
    "p":Binary(),
    "x":Binary(),
    "y":Binary(),
    "curve":String(),
    "length":Unsigned16BitInteger(),
    "asn1_oid":String(),
})

zgrab_parsed_certificate = SubRecord({
    "subject":zgrab_subj_issuer,
    "issuer":zgrab_subj_issuer,
    "version":Integer(),
    "serial_number":String(doc="Serial number as an unsigned decimal integer. Stored as string to support >uint lengths. Negative values are allowed."),
    "validity":SubRecord({
        "start":DateTime(doc="Timestamp of when certificate is first valid. Timezone is UTC."),
        "end":DateTime(doc="Timestamp of when certificate expires. Timezone is UTC."),
        "length":Integer(),
    }),
    "signature_algorithm":SubRecord({
        "name":String(),
        "oid":String(),
    }),
    "subject_key_info":SubRecord({
        "fingerprint_sha256":Binary(),
        "key_algorithm":SubRecord({
            "name":String(doc="Name of public key type, e.g., RSA or ECDSA. More information is available the named SubRecord (e.g., rsa_public_key)."),
         }),
        "rsa_public_key":rsa_public_key,
        "dsa_public_key":dsa_public_key,
        "ecdsa_public_key":ecdsa_public_key,
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
        "subject_alt_name": alternate_name,
        "issuer_alt_name": alternate_name,
        "crl_distribution_points":ListOf(String()),
        "authority_key_id":Binary(), # is this actdually binary?
        "subject_key_id":Binary(),
        "extended_key_usage":ListOf(Integer()),
        "certificate_policies":ListOf(String()),
        "authority_info_access":SubRecord({
            "ocsp_urls":ListOf(String()),
            "issuer_urls":ListOf(String())
        }),
        "name_constraints":SubRecord({
            "critical":Boolean(),
            "permitted_names":ListOf(String()),
            "permitted_email_addresses":ListOf(String()),
            "permitted_ip_addresses":ListOf(String()),
            "permitted_directory_names":ListOf(zgrab_subj_issuer),
            "excluded_names":ListOf(String()),
            "excluded_email_addresses":ListOf(String()),
            "excluded_ip_addresses":ListOf(String()),
            "excluded_directory_names":ListOf(zgrab_subj_issuer)
        }),
        "signed_certificate_timestamps":ListOf(SubRecord({
            "version":Integer(),
            "log_id":Binary(es_index=True),
            "timestamp":DateTime(),
            "extensions":Binary(),
            "signature":Binary()
        })),
        "ct_poison":Boolean()
    }),
    "unknown_extensions":ListOf(unknown_extension),
    "signature":SubRecord({
        "signature_algorithm":SubRecord({
            "name":String(),
            "oid":String(),
        }),
        "value":Binary(),
        #"valid":Boolean(),
        "self_signed":Boolean(),
    }),
    "fingerprint_md5":Binary(),
    "fingerprint_sha1":Binary(),
    "fingerprint_sha256":Binary(),
    "spki_subject_fingerprint":Binary(),
    "tbs_fingerprint":Binary(),
    "validation_level": String(),
    "redacted": Boolean(),
    "names":ListOf(String()),
})

zgrab_certificate_trust = SubRecord({
    "type":String(doc="root, intermediate, or leaf certificate"),
    "trusted_path":Boolean(doc="Does certificate chain up to browser root store"),
    "valid":Boolean(doc="is this certificate currently valid in this browser"),
    "was_valid":Boolean(doc="was this certificate ever valid in this browser")
})

zgrab_lint_result = SubRecord({

})

zgrab_lint = SubRecord({})

zgrab_certificate = SubRecord({
    "raw":Binary(),
    "parsed":zgrab_parsed_certificate,
    "validation":SubRecord({
        "nss":zgrab_certificate_trust,
        "apple":zgrab_certificate_trust,
        "microsoft":zgrab_certificate_trust,
        "android":zgrab_certificate_trust,
        "java":zgrab_certificate_trust,
    }),
    "lint":zgrab_lint
})


zgrab_server_certificate_valid = SubRecord({
    "complete_chain":Boolean(doc="does server provide a chain up to a root"),
    "valid":Boolean(doc="is this certificate currently valid in this browser"),
    "error":String()
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
        "extended_master_secret": Boolean(),
        "scts":ListOf(SubRecord({
                "parsed":SubRecord({
                    "version":Unsigned16BitInteger(),
                    "log_id":IndexedBinary(),
                    "timestamp":Signed64BitInteger(),
                    "signature":Binary(),
                 }),
                "raw":Binary()
            })),
    }),
    "server_certificates":SubRecord({
        "certificate":zgrab_certificate,
        "chain":ListOf(zgrab_certificate),
        "validation":SubRecord({
            "matches_domain":Boolean(),
            "stores":SubRecord({
                "nss":zgrab_server_certificate_valid,
                "microsoft":zgrab_server_certificate_valid,
                "apple":zgrab_server_certificate_valid,
                "java":zgrab_server_certificate_valid,
                "android":zgrab_server_certificate_valid,
            })
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
    }),
    "session_ticket":SubRecord({
        "value":Binary(),
        "length":Integer(),
        "lifetime_hint":Long()
    }),
    "key_material":SubRecord({
        "pre_master_secret":SubRecord({
            "value":Binary(),
            "length":Integer()
        }),
        "master_secret":SubRecord({
            "value":Binary(),
            "length":Integer()
        }),
    }),
    "client_finished":SubRecord({
        "verify_data":Binary()
    }),
    "client_key_exchange":SubRecord({
        "dh_params":SubRecord({
            "prime":SubRecord({
                "value":Binary(),
                "length":Integer()
            }),
            "generator":SubRecord({
                "value":Binary(),
                "length":Integer()
            }),
            "client_public":SubRecord({
                "value":Binary(),
                "length":Integer()
            }),
            "client_private":SubRecord({
                "value":Binary(),
                "length":Integer()
            }),
        }),
        "ecdh_params":SubRecord({
            "curve_id":SubRecord({
                "name":String(),
                "id":Integer()
            }),
            "client_public":SubRecord({
                "x":SubRecord({
                    "value":Binary(),
                    "length":Integer()
                }),
                "y":SubRecord({
                    "value":Binary(),
                    "length":Integer()
                }),
            }),
            "client_private":SubRecord({
                "value":Binary(),
                "length":Integer()
            }),
        }),
        "rsa_params":SubRecord({
            "length":Integer(),
            "encrypted_pre_master_secret":Binary()
        }),
    }),
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

zschema.registry.register_schema("zgrab-ftp", zgrab_banner)

caps_list = ListOf(SubRecord({
    "name":String(),
    "value":Integer()
}))

zgrab_telnet = Record({
    "data":SubRecord({
        "telnet":SubRecord({
            "banner":AnalyzedString(),
            "will":caps_list,
            "wont":caps_list,
            "do":caps_list,
            "dont":caps_list,
        })
    })
}, extends=zgrab_base)

zschema.registry.register_schema("zgrab-telnet", zgrab_telnet)

zgrab_tls_banner = Record({
    "data":SubRecord({
        "tls":zgrab_tls,
    })
}, extends=zgrab_banner)
zschema.registry.register_schema("zgrab-imaps", zgrab_tls_banner)
zschema.registry.register_schema("zgrab-pop3s", zgrab_tls_banner)

zgrab_starttls = Record({
    "data":SubRecord({
        "starttls":String(),
    })
}, extends=zgrab_tls_banner)
zschema.registry.register_schema("zgrab-imap", zgrab_starttls)
zschema.registry.register_schema("zgrab-pop3", zgrab_starttls)

zgrab_smtp = Record({
    "data":SubRecord({
        "ehlo":String(),
    })
}, extends=zgrab_starttls)
zschema.registry.register_schema("zgrab-smtp", zgrab_smtp)


zgrab_https = Record({
    "data":SubRecord({
        "tls":zgrab_tls
    })
}, extends=zgrab_base)

zschema.registry.register_schema("zgrab-https", zgrab_https)

zgrab_heartbleed = SubRecord({
    "heartbeat_enabled":Boolean(),
    "heartbleed_vulnerable":Boolean()
})

zgrab_https_heartbleed = Record({
    "data":SubRecord({
        "heartbleed":zgrab_heartbleed
    })
}, extends=zgrab_https)

zschema.registry.register_schema("zgrab-https-heartbleed", zgrab_https_heartbleed)

zgrab_unknown_http_header = SubRecord({
    "key":String(),
    "value":ListOf(String())
})

zgrab_http_headers = SubRecord({
    "access_control_allow_origin":ListOf(String()),
    "accept_patch":ListOf(String()),
    "accept_ranges":ListOf(String()),
    "age":ListOf(String()),
    "allow":ListOf(String()),
    "alt_svc":ListOf(String()),
    "alternate_protocol":ListOf(String()),
    "cache_control":ListOf(String()),
    "connection":ListOf(String()),
    "content_disposition":ListOf(String()),
    "content_encoding":ListOf(String()),
    "content_language":ListOf(String()),
    "content_length":ListOf(String()),
    "content_location":ListOf(String()),
    "content_md5":ListOf(String()),
    "content_range":ListOf(String()),
    "content_type":ListOf(String()),
    "date":ListOf(String()),
    "etag":ListOf(String()),
    "expires":ListOf(String()),
    "last_modified":ListOf(String()),
    "link":ListOf(String()),
    "location":ListOf(String()),
    "p3p":ListOf(String()),
    "pragma":ListOf(String()),
    "proxy_authenticate":ListOf(String()),
    "public_key_pins":ListOf(String()),
    "referer":ListOf(String()),
    "refresh":ListOf(String()),
    "retry_after":ListOf(String()),
    "server":ListOf(String()),
    "set_cookie":ListOf(String()),
    "status":ListOf(String()),
    "strict_transport_security":ListOf(String()),
    "trailer":ListOf(String()),
    "transfer_encoding":ListOf(String()),
    "upgrade":ListOf(String()),
    "vary":ListOf(String()),
    "via":ListOf(String()),
    "warning":ListOf(String()),
    "www_authenticate":ListOf(String()),
    "x_frame_options":ListOf(String()),
    "x_xss_protection":ListOf(String()),
    "content_security_policy":ListOf(String()),
    "x_content_security_policy":ListOf(String()),
    "x_webkit_csp":ListOf(String()),
    "x_content_type_options":ListOf(String()),
    "x_powered_by":ListOf(String()),
    "x_ua_compatible":ListOf(String()),
    "x_content_duration":ListOf(String()),
    "x_real_ip":ListOf(String()),
    "x_forwarded_for": ListOf(String()),
    "proxy_agent":ListOf(String()),
    "unknown":ListOf(zgrab_unknown_http_header),
})

zgrab_url = SubRecord({
    "scheme":String(),
    "host":String(),
    "path":String()
})

zgrab_http_request = SubRecord({
    "url":zgrab_url,
    "method":String(),
    "headers":zgrab_http_headers
})

zgrab_http_protocol = SubRecord({
    "name":String(),
    "major":Integer(),
    "minor":Integer()
})

zgrab_http_response = SubRecord({
    "protocol":zgrab_http_protocol,
    "status_line":AnalyzedString(),
    "status_code":Integer(),
    "body":HTML(),
    "body_sha256": Binary(),
    "headers":zgrab_http_headers,
    "content_length":Integer(),
    "request":zgrab_http_request
})

zgrab_http = Record({
    "data":SubRecord({
      "http":SubRecord({
        "response":zgrab_http_response,
        "redirect_response_chain":ListOf(zgrab_http_response)
      })
    })
}, extends=zgrab_base)

zschema.registry.register_schema("zgrab-http", zgrab_http)

zgrab_http_proxy = Record({
    "data":SubRecord({
      "http":SubRecord({
        "connect_request":zgrab_http_request,
        "connect_response":zgrab_http_response
      })
    })
}, extends=zgrab_http)
zschema.registry.register_schema("zgrab-proxy", zgrab_http_proxy)

zgrab_old_http = Record({
    "data":SubRecord({
        "write":String(),
        "read":String(),
    })
}, extends=zgrab_base)

zschema.registry.register_schema("zgrab-old-http", zgrab_old_http)

zgrab_bacnet = Record({
    "data": SubRecord({
        "bacnet": SubRecord({
            "is_bacnet": Boolean(),
            "instance_number": Integer(),
            "vendor_id": Integer(),
            "vendor_name": AnalyzedString(es_include_raw=True),
            "firmware_revision": String(),
            "application_software_revision": String(),
            "object_name": AnalyzedString(es_include_raw=True),
            "model_name": AnalyzedString(es_include_raw=True),
            "description": AnalyzedString(es_include_raw=True),
            "location": AnalyzedString(es_include_raw=True),
        }),
    }),
}, extends=zgrab_base)

zschema.registry.register_schema("zgrab-bacnet", zgrab_bacnet)

zgrab_fox = Record({
    "data": SubRecord({
        "fox": SubRecord({
            "is_fox": Boolean(),
            "version": AnalyzedString(es_include_raw=True),
            "id": Integer(),
            "hostname": String(),
            "host_address": String(),
            "app_name": AnalyzedString(es_include_raw=True),
            "app_version": String(),
            "vm_name": AnalyzedString(es_include_raw=True),
            "vm_version": String(),
            "os_name": AnalyzedString(es_include_raw=True),
            "os_version": String(),
            "station_name": String(),
            "language": AnalyzedString(es_include_raw=True),
            "time_zone": AnalyzedString(es_include_raw=True),
            "host_id": AnalyzedString(es_include_raw=True),
            "vm_uuid": String(),
            "brand_id": AnalyzedString(es_include_raw=True),
            "sys_info": AnalyzedString(es_include_raw=True),
            "auth_agent_type": String()
        }),
    }),
}, extends=zgrab_base)

zschema.registry.register_schema("zgrab-fox", zgrab_fox)

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

zschema.registry.register_schema("zgrab-modbus", zgrab_modbus)

zgrab_dnp3 = Record({
    "data":SubRecord({
        "dnp3":SubRecord({
            "is_dnp3":Boolean(),
            "raw_response":Binary(),
        }),
    }),
}, extends=zgrab_base)

zschema.registry.register_schema("zgrab-dnp3", zgrab_dnp3)

zgrab_s7 = Record({
    "data":SubRecord({
        "s7":SubRecord({
            "is_s7":Boolean(),
            "system":String(),
            "module":String(),
            "plant_id":String(),
            "copyright":String(),
            "serial_number":String(),
            "reserved_for_os":String(),
            "module_type":String(),
            "memory_serial_number":String(),
            "cpu_profile":String(),
            "oem_id":String(),
            "location":String(),
            "module_id":String(),
            "hardware":String(),
            "firmware":String(),
        }),
    }),
}, extends=zgrab_base)

zschema.registry.register_schema("zgrab-s7", zgrab_s7)

zgrab_ssh_protocol_agreement = SubRecord({
    "raw_banner": AnalyzedString(),
    "protocol_version": String(),
    "software_version": String(),
    "comments": String(),
})

zgrab_ssh_key_exchange_init = SubRecord({
    "cookie": Binary(),
    "key_exchange_algorithms": ListOf(String()),
    "host_key_algorithms": ListOf(String()),
    "encryption_client_to_server": ListOf(String()),
    "encryption_server_to_client": ListOf(String()),
    "mac_client_to_server": ListOf(String()),
    "mac_server_to_client": ListOf(String()),
    "compression_client_to_server": ListOf(String()),
    "compression_server_to_client": ListOf(String()),
    "language_client_to_server": ListOf(String()),
    "language_server_to_client": ListOf(String()),
    "first_kex_packet_follows": Boolean(),
    "zero": Integer(),
})

zgrab_ssh_algorithms = SubRecord({
    "key_exchange_algorithm": String(),
    "host_key_algorithm": String(),
})

zgrab_ssh_dh_group_request = SubRecord({
    "min": Integer(),
    "preferred": Integer(),
    "max": Integer(),
})

zgrab_ssh_dh_group_params = SubRecord({
    "prime": Binary(),
    "generator": Binary(),
})

zgrab_ssh_dh_init = SubRecord({
    "e": Binary(),
})

zgrab_ssh_dh_reply = SubRecord({
    "k_s": Binary(),
    "f": Binary(),
    "signature": Binary(),
})

zgrab_ssh = Record({
    "data": SubRecord({
        "ssh": SubRecord({
            "client_protocol": zgrab_ssh_protocol_agreement,
            "server_protocol": zgrab_ssh_protocol_agreement,
            "client_key_exchange_init": zgrab_ssh_key_exchange_init,
            "server_key_exchange_init": zgrab_ssh_key_exchange_init,
            "algorithms": zgrab_ssh_algorithms,
            "key_exchange_dh_group_request": zgrab_ssh_dh_group_request,
            "key_exchange_dh_group_params": zgrab_ssh_dh_group_params,
            "key_exchange_dh_group_init": zgrab_ssh_dh_init,
            "key_exchange_dh_group_reply": zgrab_ssh_dh_reply,
            "key_exchange_dh_init": zgrab_ssh_dh_init,
            "key_exchange_dh_reply": zgrab_ssh_dh_reply,
        }),
    }),
}, extends=zgrab_base)

zschema.registry.register_schema("zgrab-ssh", zgrab_ssh)

ed25519_public_key = SubRecord({
    "public_bytes":Binary(),
})

zgrab_xssh = Record({
    "data":SubRecord({
        "xssh":SubRecord({
            "server_id":SubRecord({
                "raw":AnalyzedString(),
                "version":String(),
                "software":AnalyzedString(),
                "comment":AnalyzedString(),
            }),
            "server_key_exchange":SubRecord({
                "cookie": Binary(),
                "kex_algorithms":ListOf(String()),
                "host_key_algorithms":ListOf(String()),
                "client_to_server_ciphers":ListOf(String()),
                "server_to_client_ciphers":ListOf(String()),
                "client_to_server_macs":ListOf(String()),
                "server_to_client_macs":ListOf(String()),
                "client_to_server_compression":ListOf(String()),
                "server_to_client_compression":ListOf(String()),
                "client_to_server_languages":ListOf(String()),
                "server_to_client_languages":ListOf(String()),
                "first_kex_follows":Boolean(),
                "reserved":Short(),
            }),
            "userauth":ListOf(String()),
            "algorithm_selection":SubRecord({
                "dh_kex_algorithm":String(),
                "host_key_algorithm":String(),
                "client_to_server_alg_group": SubRecord({
                    "cipher":String(),
                    "mac":String(),
                    "compression":String(),
                }),
                "server_to_client_alg_group": SubRecord({
                    "cipher":String(),
                    "mac":String(),
                    "compression":String(),
                }),
            }),
            "dh_key_exchange": SubRecord({
                "parameters": SubRecord({
                    "client_public":Binary(),
                    "client_private":Binary(),
                    "server_public":Binary(),
                    "prime":Binary(),
                    "generator":Binary(),
                }),
                "server_signature":Binary(),
                "server_host_key":SubRecord({
                    "raw":Binary(),
                    "algorithm":String(),
                    "fingerprint_sha256":String(),
                    "rsa_public_key":rsa_public_key,
                    "dsa_public_key":dsa_public_key,
                    "ecdsa_public_key":ecdsa_public_key,
                    "ed25519_public_key":ed25519_public_key,
                    "certkey_public_key":SubRecord({
                        "nonce":Binary(),
                        "key":SubRecord({
                            "raw":Binary(),
                            "fingerprint_sha256":String(),
                            "algorithm":String(),
                            "rsa_public_key":rsa_public_key,
                            "dsa_public_key":dsa_public_key,
                            "ecdsa_public_key":ecdsa_public_key,
                            "ed25519_public_key":ed25519_public_key,
                        }),
                        "serial":String(),
                        "cert_type":SubRecord({
                            "id":Integer(),
                            "name":String(),
                        }),
                        "key_id":String(),
                        "valid_principals":ListOf(String()),
                        "validity":SubRecord({
                            "valid_after":DateTime(doc="Timestamp of when certificate is first valid. Timezone is UTC."),
                            "valid_before":DateTime(doc="Timestamp of when certificate expires. Timezone is UTC."),
                            "length":Integer(),
                        }),
                        "reserved":Binary(),
                        "signature_key":SubRecord({
                            "raw":Binary(),
                            "fingerprint_sha256":String(),
                            "algorithm":String(),
                            "rsa_public_key":rsa_public_key,
                            "dsa_public_key":dsa_public_key,
                            "ecdsa_public_key":ecdsa_public_key,
                            "ed25519_public_key":ed25519_public_key,
                        }),
                        "signature":SubRecord({
                            "algorithm":String(),
                            "value":Binary(),
                        }),
                        "parse_error":String(),
                        "extensions":SubRecord({
                            "known":SubRecord({
                                "permit-X11-forwarding":String(),
                                "permit-agent-forwarding":String(),
                                "permit-port-forwarding":String(),
                                "permit-pty":String(),
                                "permit-user-rc":String(),
                            }),
                            "unknown":ListOf(String()),
                        }),
                        "critical_options":SubRecord({
                            "known":SubRecord({
                                "force-command":String(),
                                "source-address":String(),
                            }),
                            "unknown":ListOf(String()),
                        })
                    }),
                }),
            }),
        }),
    }),
}, extends=zgrab_base)

zschema.registry.register_schema("zgrab-xssh", zgrab_xssh)
