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
    "exponent":Signed64BitInteger(),
    "modulus":Binary(),
    "length":Unsigned32BitInteger(doc="Bit-length of modulus."),
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
    "version":Signed32BitInteger(),
    "serial_number":String(doc="Serial number as an unsigned decimal integer. Stored as string to support >uint lengths. Negative values are allowed."),
    "validity":SubRecord({
        "start":DateTime(doc="Timestamp of when certificate is first valid. Timezone is UTC."),
        "end":DateTime(doc="Timestamp of when certificate expires. Timezone is UTC."),
        "length":Signed32BitInteger(),
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
            "value":Signed32BitInteger(),
            "data_encipherment":Boolean(),
            "key_agreement":Boolean(),
            "decipher_only":Boolean(),
            "encipher_only":Boolean(),
        }),
        "basic_constraints":SubRecord({
            "is_ca":Boolean(),
            "max_path_len":Signed32BitInteger(),
        }),
        "subject_alt_name": alternate_name,
        "issuer_alt_name": alternate_name,
        "crl_distribution_points":ListOf(String()),
        "authority_key_id":Binary(), # is this actdually binary?
        "subject_key_id":Binary(),
        "extended_key_usage":ListOf(Signed32BitInteger()),
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
            "version":Signed32BitInteger(),
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
            "value":Signed32BitInteger()
        }),
        "random":Binary(),
        "session_id": Binary(),
        "cipher_suite":SubRecord({
            "hex":String(),
            "name":String(),
            "value":Signed32BitInteger(),
        }),
        "compression_method":Signed32BitInteger(),
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
                "id":Signed32BitInteger(),
            }),
            "server_public":SubRecord({
                "x":SubRecord({
                    "value":Binary(),
                    "length":Signed32BitInteger(),
                }),
                "y":SubRecord({
                    "value":Binary(),
                    "length":Signed32BitInteger(),
                }),
            }),
        }),
        "rsa_params":SubRecord({
            "exponent":Signed64BitInteger(),
            "modulus":Binary(),
            "length":Signed32BitInteger(),
        }),
        "dh_params":SubRecord({
            "prime":SubRecord({
                "value":Binary(),
                "length":Signed32BitInteger(),
            }),
            "generator":SubRecord({
                "value":Binary(),
                "length":Signed32BitInteger(),
            }),
            "server_public":SubRecord({
                "value":Binary(),
                "length":Signed32BitInteger(),
           }),
        }),
        "digest": Binary(),
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
                "value":Signed32BitInteger()
            }),
        }),
        "signature_error":String(),
    }),
    "server_finished":SubRecord({
        "verify_data":Binary()
    }),
    "session_ticket":SubRecord({
        "value":Binary(),
        "length":Signed32BitInteger(),
        "lifetime_hint":Signed64BitInteger()
    }),
    "key_material":SubRecord({
        "pre_master_secret":SubRecord({
            "value":Binary(),
            "length":Signed32BitInteger()
        }),
        "master_secret":SubRecord({
            "value":Binary(),
            "length":Signed32BitInteger()
        }),
    }),
    "client_finished":SubRecord({
        "verify_data":Binary()
    }),
    "client_key_exchange":SubRecord({
        "dh_params":SubRecord({
            "prime":SubRecord({
                "value":Binary(),
                "length":Signed32BitInteger()
            }),
            "generator":SubRecord({
                "value":Binary(),
                "length":Signed32BitInteger()
            }),
            "client_public":SubRecord({
                "value":Binary(),
                "length":Signed32BitInteger()
            }),
            "client_private":SubRecord({
                "value":Binary(),
                "length":Signed32BitInteger()
            }),
        }),
        "ecdh_params":SubRecord({
            "curve_id":SubRecord({
                "name":String(),
                "id":Signed32BitInteger()
            }),
            "client_public":SubRecord({
                "x":SubRecord({
                    "value":Binary(),
                    "length":Signed32BitInteger()
                }),
                "y":SubRecord({
                    "value":Binary(),
                    "length":Signed32BitInteger()
                }),
            }),
            "client_private":SubRecord({
                "value":Binary(),
                "length":Signed32BitInteger()
            }),
        }),
        "rsa_params":SubRecord({
            "length":Signed32BitInteger(),
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
    "value":Signed32BitInteger()
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
    "major":Signed32BitInteger(),
    "minor":Signed32BitInteger()
})

zgrab_http_response = SubRecord({
    "protocol":zgrab_http_protocol,
    "status_line":AnalyzedString(),
    "status_code":Signed32BitInteger(),
    "body":HTML(),
    "body_sha256":HexString(),
    "headers":zgrab_http_headers,
    "content_length":Signed32BitInteger(),
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
            "instance_number": Signed32BitInteger(),
            "vendor_id": Signed32BitInteger(),
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
            "id": Signed32BitInteger(),
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
            "length":Signed32BitInteger(),
            "unit_id":Signed32BitInteger(),
            "function_code":Signed32BitInteger(),
            "raw_response":String(),
            "mei_response":SubRecord({
                "conformity_level":Signed32BitInteger(),
                "more_follows":Boolean(),
                "object_count":Signed32BitInteger(),
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
                "exception_function":Signed32BitInteger(),
                "exception_type":Signed32BitInteger(),
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

zgrab_smb = Record({
    "data":SubRecord({
        "smb":SubRecord({
           "smbv1_support":Boolean(),
        }),
    }),
}, extends=zgrab_base)

zschema.registry.register_schema("zgrab-smb", zgrab_smb)

ed25519_public_key = SubRecord({
    "public_bytes":Binary(),
})

xssh_signature = SubRecord({
    "parsed":SubRecord({
        "algorithm":String(),
        "value":Binary(),
    }),
    "raw":Binary(),
    "h":Binary(),
})

golang_crypto_param = SubRecord({
    "value":Binary(),
    "length":Unsigned32BitInteger()
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
                "reserved":Unsigned32BitInteger(),
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
            "key_exchange": SubRecord({
                "curve25519_sha256_params": SubRecord({
                    "server_public": Binary(),
                }),
                "ecdh_params": SubRecord({
                    "server_public": SubRecord({
                        "x": golang_crypto_param,
                        "y": golang_crypto_param,
                    }),
                }),
                "dh_params": SubRecord({
                    "prime": golang_crypto_param,
                    "generator": golang_crypto_param,
                    "server_public": golang_crypto_param,
                }),
                "server_signature":xssh_signature,
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
                            "id":Unsigned32BitInteger(),
                            "name":String(),
                        }),
                        "key_id":String(),
                        "valid_principals":ListOf(String()),
                        "validity":SubRecord({
                            "valid_after":DateTime(doc="Timestamp of when certificate is first valid. Timezone is UTC."),
                            "valid_before":DateTime(doc="Timestamp of when certificate expires. Timezone is UTC."),
                            "length":Signed64BitInteger(),
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
                        "signature":xssh_signature,
                        "parse_error":String(),
                        "extensions":SubRecord({
                            "known":SubRecord({
                                "permit_X11_forwarding":String(),
                                "permit_agent_forwarding":String(),
                                "permit_port_forwarding":String(),
                                "permit_pty":String(),
                                "permit_user_rc":String(),
                            }),
                            "unknown":ListOf(String()),
                        }),
                        "critical_options":SubRecord({
                            "known":SubRecord({
                                "force_command":String(),
                                "source_address":String(),
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

if __name__ == '__main__':
    from subprocess import call
    schema_types = ['bigquery', 'elasticsearch', 'json', 'text', 'flat']
    for name in zschema.registry.all_schemas():
        for schema_type in schema_types:
            cmd = ["zschema", schema_type, __file__ + ":" + name]
            call(cmd)
