import datetime
import pytest
import json

from .....storage.vc_holder.vc_record import VCRecord
from .....resolver.did_resolver_registry import DIDResolverRegistry
from .....resolver.did_resolver import DIDResolver

from ..pres_exch import PresentationDefinition
from ..pres_exch_handler import PresentationExchError

from .....core.in_memory import InMemoryProfile
from .....did.did_key import DIDKey
from .....vc.vc_ld.issue import issue
from .....vc.ld_proofs.document_loader import DocumentLoader
from .....vc.tests.document_loader import custom_document_loader
from .....vc.ld_proofs import (
    BbsBlsSignatureProof2020,
    BbsBlsSignature2020,
    Ed25519Signature2018,
    WalletKeyPair,
)
from .....wallet.base import BaseWallet
from .....wallet.crypto import KeyType
from .....wallet.util import b58_to_bytes
from .....wallet.in_memory import InMemoryWallet


cred_json_1 = """
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/bbs/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "http://example.edu/credentials/1872",
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "issuer": {
      "id": "did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa"
  },
  "issuanceDate": "2010-01-01T19:53:24Z",
  "credentialSubject": {
    "id": "did:example:123",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
  }
}
"""

cred_json_2 = """
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/bbs/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "http://example.edu/credentials/1873",
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "issuer": {
      "id": "did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa"
  },
  "issuanceDate": "2010-01-01T19:53:24Z",
  "credentialSubject": {
    "id": "did:example:456",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
  }
}
"""

cred_json_3 = """
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/bbs/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "http://example.edu/credentials/1874",
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "issuer": {
      "id": "did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa"
  },
  "issuanceDate": "2010-01-01T19:53:24Z",
  "credentialSubject": {
    "id": "did:example:789",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
  }
}
"""
cred_json_4 = """
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/bbs/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.edu/credentials/1875",
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "issuer": {
          "id": "did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa"
      },
      "issuanceDate": "2010-01-01T19:53:24Z",
      "credentialSubject": {
        "id": "did:example:321",
        "degree": {
          "type": "BachelorDegree",
          "name": "Bachelor of Science and Arts"
        }
      }
    }
"""

cred_json_5 = """
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/bbs/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.edu/credentials/1876",
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "issuer": {
          "id": "did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa"
      },      
      "issuanceDate": "2010-01-01T19:53:24Z",
      "credentialSubject": {
        "id": "did:example:654",
        "degree": {
          "type": "BachelorDegree",
          "name": "Bachelor of Science and Arts"
        }
      }
    }
"""
cred_json_6 = """
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/bbs/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.edu/credentials/1877",
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "issuer": {
          "id": "did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa"
      },      
      "issuanceDate": "2010-01-01T19:53:24Z",
      "credentialSubject": {
        "id": "did:example:987",
        "degree": {
          "type": "BachelorDegree",
          "name": "Bachelor of Science and Arts"
        }
      }
    }
"""

pres_exch_nested_srs_a = """
{
  "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
  "submission_requirements":[
    {
      "name": "Citizenship Information",
      "rule": "pick",
      "count": 1,
      "from_nested": [
        {
          "name": "United States Citizenship Proofs",
          "purpose": "We need you to prove you are a US citizen.",
          "rule": "all",
          "from": "A"
        },
        {
          "name": "European Union Citizenship Proofs",
          "purpose": "We need you to prove you are a citizen of a EU country.",
          "rule": "all",
          "from": "B"
        }
      ]
    }
  ],
  "input_descriptors":[
    {
      "id":"citizenship_input_1",
      "name":"EU Driver's License",
      "group":[
        "A"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuer.id",
              "$.vc.issuer.id"
            ],
            "purpose":"The claim must be from one of the specified issuers",
            "filter":{
              "type":"string",
              "enum": ["did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa"]
            }
          }
        ]
      }
    },
    {
      "id":"citizenship_input_2",
      "name":"US Passport",
      "group":[
        "B"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuanceDate",
              "$.vc.issuanceDate"
            ],
            "filter":{
              "type":"string",
              "format":"date",
              "maximum":"2009-5-16"
            }
          }
        ]
      }
    }
  ]
}
"""

pres_exch_nested_srs_b = """
{
  "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
  "submission_requirements":[
    {
      "name": "Citizenship Information",
      "rule": "pick",
      "count": 1,
      "from_nested": [
        {
          "name": "United States Citizenship Proofs",
          "purpose": "We need you to prove you are a US citizen.",
          "rule": "all",
          "from": "A"
        },
        {
          "name": "European Union Citizenship Proofs",
          "purpose": "We need you to prove you are a citizen of a EU country.",
          "rule": "all",
          "from": "B"
        }
      ]
    }
  ],
  "input_descriptors":[
    {
      "id":"citizenship_input_1",
      "name":"EU Driver's License",
      "group":[
        "A"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuer.id",
              "$.vc.issuer.id"
            ],
            "purpose":"The claim must be from one of the specified issuers",
            "filter":{
              "type":"string",
              "enum": ["did:key:test"]
            }
          }
        ]
      }
    },
    {
      "id":"citizenship_input_2",
      "name":"US Passport",
      "group":[
        "B"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuanceDate",
              "$.vc.issuanceDate"
            ],
            "filter":{
              "type":"string",
              "format":"date",
              "maximum":"2012-5-16"
            }
          }
        ]
      }
    }
  ]
}
"""

pres_exch_multiple_srs_not_met = """
{
  "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
  "submission_requirements":[
    {
      "name": "Citizenship Information",
      "rule": "pick",
      "count": 2,
      "from": "A"
    },
    {
      "name": "European Union Citizenship Proofs",
      "purpose": "We need you to prove you are a citizen of a EU country.",
      "rule": "all",
      "from": "B"
    }
  ],
  "input_descriptors":[
    {
      "id":"citizenship_input_1",
      "name":"EU Driver's License",
      "group":[
        "A"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuer.id",
              "$.vc.issuer.id"
            ],
            "purpose":"The claim must be from one of the specified issuers",
            "filter":{
              "type":"string",
              "enum": ["did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa"]
            }
          }
        ]
      }
    },
    {
      "id":"citizenship_input_2",
      "name":"US Passport",
      "group":[
        "B"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuanceDate",
              "$.vc.issuanceDate"
            ],
            "filter":{
              "type":"string",
              "format":"date",
              "exclusiveMax":"2009-5-16"
            }
          }
        ]
      }
    }
  ]
}
"""

pres_exch_multiple_srs_met = """
{
  "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
  "submission_requirements":[
    {
      "name": "Citizenship Information",
      "rule": "pick",
      "min": 1,
      "from": "A"
    },
    {
      "name": "European Union Citizenship Proofs",
      "rule": "all",
      "from": "B"
    }
  ],
  "input_descriptors":[
    {
      "id":"citizenship_input_1",
      "name":"EU Driver's License",
      "group":[
        "A"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuer.id",
              "$.vc.issuer.id"
            ],
            "filter":{
              "type":"string",
              "enum": ["did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa"]
            }
          }
        ]
      }
    },
    {
      "id":"citizenship_input_2",
      "name":"US Passport",
      "group":[
        "B"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuanceDate",
              "$.vc.issuanceDate"
            ],
            "filter":{
              "type":"string",
              "format":"date",
              "maximum":"2012-5-16"
            }
          }
        ]
      }
    }
  ]
}
"""

pres_exch_datetime_minimum_met = """
{
  "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
  "submission_requirements":[
    {
      "name": "European Union Citizenship Proofs",
      "rule": "pick",
      "max": 6,
      "from": "B"
    }
  ],
  "input_descriptors":[
    {
      "id":"citizenship_input_1",
      "name":"EU Driver's License",
      "group":[
        "A"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuer.id",
              "$.vc.issuer.id"
            ],
            "purpose":"The claim must be from one of the specified issuers",
            "filter":{
              "type":"string",
              "enum": ["did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa", "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"]
            }
          }
        ]
      }
    },
    {
      "id":"citizenship_input_2",
      "name":"US Passport",
      "group":[
        "B"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.issuanceDate",
              "$.vc.issuanceDate"
            ],
            "filter":{
              "type":"string",
              "format":"date",
              "minimum":"1999-5-16"
            }
          }
        ]
      }
    }
  ]
}
"""

pres_exch_number_const_met = """
{
  "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
  "submission_requirements":[
    {
      "name": "European Union Citizenship Proofs",
      "rule": "pick",
      "min": 1,
      "from": "A"
    }
  ],
  "format": {
    "jwt": {
      "alg": ["EdDSA", "ES256K", "ES384"]
    },
    "jwt_vc": {
      "alg": ["ES256K", "ES384"]
    },
    "jwt_vp": {
      "alg": ["EdDSA", "ES256K"]
    },
    "ldp_vc": {
      "proof_type": [
        "JsonWebSignature2020",
        "Ed25519Signature2018",
        "EcdsaSecp256k1Signature2019",
        "RsaSignature2018"
      ]
    },
    "ldp_vp": {
      "proof_type": ["Ed25519Signature2018"]
    },
    "ldp": {
      "proof_type": ["RsaSignature2018"]
    }
  },
  "input_descriptors":[
    {
      "id":"citizenship_input_1",
      "name":"EU Driver's License",
      "group":[
        "A"
      ],
      "schema":[
        {
          "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        }
      ],
      "constraints":{
        "fields":[
          {
            "path":[
              "$.credentialSubject.degree.test",
              "$.vc.credentialSubject.degree.test",
              "$.test"
            ],
            "purpose":"The claim must be from one of the specified issuers",
            "filter":{
              "enum": [2, 2.1, 2.2]
            }
          }
        ]
      }
    }
  ]
}
"""

def make_profile():
    profile = InMemoryProfile.test_profile()
    context = profile.context
    did_resolver_registry = DIDResolverRegistry()
    context.injector.bind_instance(DIDResolverRegistry, did_resolver_registry)
    context.injector.bind_instance(DIDResolver, DIDResolver(did_resolver_registry))
    context.injector.bind_instance(DocumentLoader, custom_document_loader)
    return profile

@pytest.mark.asyncio
@pytest.mark.ursa_bbs_signatures
async def get_test_data():
    profile = make_profile()
    wallet = InMemoryWallet(profile)

    ed25519_key_info = await wallet.create_signing_key(
        key_type=KeyType.ED25519, seed="testseed000000000000000000000002"
    )
    ed25519_verification_method = DIDKey.from_public_key_b58(
        ed25519_key_info.verkey, KeyType.ED25519
    ).key_id
    bls12381g2_key_info = await wallet.create_signing_key(
      key_type=KeyType.BLS12381G2, seed="testseed000000000000000000000001"
    )
    bls12381g2_verification_method = DIDKey.from_public_key_b58(
        bls12381g2_key_info.verkey, KeyType.BLS12381G2
    ).key_id

    bls_issuer_suite = BbsBlsSignature2020(
        verification_method=bls12381g2_verification_method,
        key_pair=WalletKeyPair(
            wallet=wallet,
            key_type=KeyType.BLS12381G2,
            public_key_base58=bls12381g2_key_info.verkey,
        )
    )
    edd_issuer_suite = Ed25519Signature2018(
        verification_method=ed25519_verification_method,
        key_pair=WalletKeyPair(
            wallet=wallet,
            key_type=KeyType.ED25519,
            public_key_base58=ed25519_key_info.verkey,
        )
    )
    bls_proof_suite = BbsBlsSignatureProof2020(
        key_pair=WalletKeyPair(
            wallet=wallet,
            key_type=KeyType.BLS12381G2,
            public_key_base58=bls12381g2_key_info.verkey,
        ),
    )

    creds_json_list = [
        json.dumps(await issue(credential=json.loads(cred_json_1), 
                    suite=bls_issuer_suite, 
                    document_loader=custom_document_loader
              )),
        json.dumps(await issue(credential=json.loads(cred_json_2), 
                    suite=bls_issuer_suite, 
                    document_loader=custom_document_loader
              )),
        json.dumps(await issue(credential=json.loads(cred_json_3), 
                    suite=bls_issuer_suite, 
                    document_loader=custom_document_loader
              )),
        json.dumps(await issue(credential=json.loads(cred_json_4), 
                    suite=bls_issuer_suite, 
                    document_loader=custom_document_loader
              )),
        json.dumps(await issue(credential=json.loads(cred_json_5), 
                    suite=bls_issuer_suite, 
                    document_loader=custom_document_loader
              )),
        json.dumps(await issue(credential=json.loads(cred_json_6), 
                    suite=bls_issuer_suite, 
                    document_loader=custom_document_loader
              )),
    ]

    vc_record_list = []
    for cred in creds_json_list:
        vc_record_list.append(VCRecord.deserialize_jsonld_cred(cred))
    pd_json_list = [
        (pres_exch_multiple_srs_not_met, 0),
        (pres_exch_multiple_srs_met, 6),
        (pres_exch_datetime_minimum_met, 6),
        (pres_exch_number_const_met, 0),
        (pres_exch_nested_srs_a, 6),
        (pres_exch_nested_srs_b, 6),
    ]

    pd_list = []
    for pd in pd_json_list:
        pd_list.append(
            (
                PresentationDefinition.deserialize(json.loads(pd[0])),
                pd[1],
            )
        )
    # Returns VCRecords, PDsList, profile and suites for PresExch Tests
    return (vc_record_list, pd_list, profile, edd_issuer_suite, bls_proof_suite)
