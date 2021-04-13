import datetime
import pytest
import json

from .....storage.vc_holder.vc_record import VCRecord

from ..pres_exch import PresentationDefinition
from ..pres_exch_handler import PresentationExchError


cred_1 = """
  {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/security/bbs/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "id": "http://example.edu/credentials/1872",
    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
    "issuer": {"id": "did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa"},
    "issuanceDate": "2010-01-01T19:53:24Z",
    "credentialSubject": {"id": "did:example:123", "degree": {"type": "BachelorDegree", "name": "Bachelor of Science and Arts"}},
    "proof": {
      "type": "BbsBlsSignature2020",
      "verificationMethod": "did:key:zUC75YSsU8xpRgqZaERxSeLjqXiUfxpHAHQvKMTQbLwL8AHujx1dPyxQiqvRz9XzeJgt6MM17eze1k6UPsKS4C6GFe8xG28Ux55MVAURZ7VXwEnoWq8uPXfFxBcUDWiqeHJr45g#zUC75YSsU8xpRgqZaERxSeLjqXiUfxpHAHQvKMTQbLwL8AHujx1dPyxQiqvRz9XzeJgt6MM17eze1k6UPsKS4C6GFe8xG28Ux55MVAURZ7VXwEnoWq8uPXfFxBcUDWiqeHJr45g",
      "created": "2021-04-13T12:58:33.070775",
      "proofPurpose": "assertionMethod",
      "proofValue": "tafRIR7raM2Gd8SqslSBs+OFICg4bYsU1sso3oMPOm5phbIqsPWxMNRQBjHwZh9FYRCOnl/Jto8ZoIKfr3VGwXdMVkzFUywD2GxBroxVBN4KfjPayh+M52wSgEsEEsQBB1UT2AWFfoiNZqnIFZaV9g=="
      }
    }
"""

cred_2 = """
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
      "degree": {"type": "BachelorDegree", "name": "Bachelor of Science and Arts"}
    },
    "proof": {
      "type": "BbsBlsSignature2020",
      "verificationMethod": "did:key:zUC75YSsU8xpRgqZaERxSeLjqXiUfxpHAHQvKMTQbLwL8AHujx1dPyxQiqvRz9XzeJgt6MM17eze1k6UPsKS4C6GFe8xG28Ux55MVAURZ7VXwEnoWq8uPXfFxBcUDWiqeHJr45g#zUC75YSsU8xpRgqZaERxSeLjqXiUfxpHAHQvKMTQbLwL8AHujx1dPyxQiqvRz9XzeJgt6MM17eze1k6UPsKS4C6GFe8xG28Ux55MVAURZ7VXwEnoWq8uPXfFxBcUDWiqeHJr45g",
      "created": "2021-04-13T15:02:42.625340",
      "proofPurpose": "assertionMethod",
      "proofValue": "rvDzAELSMw1QGjokFZsSu9utAM9HZKzW0xo7nl0CfFWmAWFuRcnmeBicJSScT3h3NKGqv+sBAJRMU9V4Q5heXfqmWZFnsf1cO6vp+Tg9mVsgNFwzKOA3FbJp80cYFPzJGR6VgsrUsOMSINyynup4Dg=="
    }
  }
"""

cred_3 = """
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
      "degree": {"type": "BachelorDegree", "name": "Bachelor of Science and Arts"}
    },
   "proof": {
    "type": "BbsBlsSignature2020", 
    "verificationMethod": "did:key:zUC75YSsU8xpRgqZaERxSeLjqXiUfxpHAHQvKMTQbLwL8AHujx1dPyxQiqvRz9XzeJgt6MM17eze1k6UPsKS4C6GFe8xG28Ux55MVAURZ7VXwEnoWq8uPXfFxBcUDWiqeHJr45g#zUC75YSsU8xpRgqZaERxSeLjqXiUfxpHAHQvKMTQbLwL8AHujx1dPyxQiqvRz9XzeJgt6MM17eze1k6UPsKS4C6GFe8xG28Ux55MVAURZ7VXwEnoWq8uPXfFxBcUDWiqeHJr45g",
    "created": "2021-04-13T15:06:06.860337",
    "proofPurpose": "assertionMethod",
    "proofValue": "tUD/aNULZkGX7e5jv+0n/mIkGbwNRag0WY7yhv9mzFBcEL5TczTbT+b3BY4D9t2oFrPNQUS48ytgdcmGjrBWJSCyupfYH+B6Sii0XGI+3oRG5M2Xvy1emcdUtteq2Q9q3NNRRgy/1kaZBjolDalaPQ=="
    }
  }
"""

cred_4 = """
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
      "degree": {"type": "BachelorDegree", "name": "Bachelor of Science and Arts"}
    },
    "proof": {
      "type": "BbsBlsSignature2020",
      "verificationMethod": "did:key:zUC75YSsU8xpRgqZaERxSeLjqXiUfxpHAHQvKMTQbLwL8AHujx1dPyxQiqvRz9XzeJgt6MM17eze1k6UPsKS4C6GFe8xG28Ux55MVAURZ7VXwEnoWq8uPXfFxBcUDWiqeHJr45g#zUC75YSsU8xpRgqZaERxSeLjqXiUfxpHAHQvKMTQbLwL8AHujx1dPyxQiqvRz9XzeJgt6MM17eze1k6UPsKS4C6GFe8xG28Ux55MVAURZ7VXwEnoWq8uPXfFxBcUDWiqeHJr45g",
      "created": "2021-04-13T15:08:39.678804",
      "proofPurpose": "assertionMethod", 
      "proofValue": "izba7JXCte2lqMkmDgUl+8gSb1lHE6BjQZjDiGuul5CkYT7IzokNeEqUMqIHKs1oCs80fjDyYzeUqA+EIS66tgkpkXR/PLYaZObJmf8uvA5qH7viGVFEp0L9K9SAmiRTM02Rru62nyaRFFmmjFZ7Vw=="
    }
  }
"""

cred_5 = """
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
      "degree": {"type": "BachelorDegree", "name": "Bachelor of Science and Arts"}
    },
    "proof": {
      "type": "BbsBlsSignature2020",
      "verificationMethod": "did:key:zUC75YSsU8xpRgqZaERxSeLjqXiUfxpHAHQvKMTQbLwL8AHujx1dPyxQiqvRz9XzeJgt6MM17eze1k6UPsKS4C6GFe8xG28Ux55MVAURZ7VXwEnoWq8uPXfFxBcUDWiqeHJr45g#zUC75YSsU8xpRgqZaERxSeLjqXiUfxpHAHQvKMTQbLwL8AHujx1dPyxQiqvRz9XzeJgt6MM17eze1k6UPsKS4C6GFe8xG28Ux55MVAURZ7VXwEnoWq8uPXfFxBcUDWiqeHJr45g",
      "created": "2021-04-13T15:39:32.675628",
      "proofPurpose": "assertionMethod",
      "proofValue": "gdkOuDRYerVlr0KQYUdvUBCrt6IqjfKpDE48EjAMpr9UOZn/vrJMjaZBU4/1pxXxL3WANJaTInG8PgOw9Yx6pwAA2DyOZLgwsX009AITzeQtnO6R8H0l4kaSqDceYj/zFXNjSqQLR+TWG8lNrnXG7A=="
    }
  }
"""

cred_6 = """
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
      "degree": {"type": "BachelorDegree", "name": "Bachelor of Science and Arts"}
    },
    "proof": {
      "type": "BbsBlsSignature2020",
      "verificationMethod": "did:key:zUC75YSsU8xpRgqZaERxSeLjqXiUfxpHAHQvKMTQbLwL8AHujx1dPyxQiqvRz9XzeJgt6MM17eze1k6UPsKS4C6GFe8xG28Ux55MVAURZ7VXwEnoWq8uPXfFxBcUDWiqeHJr45g#zUC75YSsU8xpRgqZaERxSeLjqXiUfxpHAHQvKMTQbLwL8AHujx1dPyxQiqvRz9XzeJgt6MM17eze1k6UPsKS4C6GFe8xG28Ux55MVAURZ7VXwEnoWq8uPXfFxBcUDWiqeHJr45g",
      "created": "2021-04-13T15:42:22.553058",
      "proofPurpose": "assertionMethod",
      "proofValue": "hiYBUPCX8m1pocU3PPSUR7TZyXc01U3YPqogcW4Fd6Sah9lShIhXvxtfpCOoYPrhFsmqpqkx7w8zjUIlAYXy8HrqXxLmy8gZU6S5xA7CWeJfLGQV06mvhYd9HT3+bLewVyDRdxSIXY8GyMEjNEj3qw=="
    }
  }
"""

pres_exch_nested_srs = """
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
              "minimum":"2009-5-16"
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
              "exclusiveMax":"2020-5-16"
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
              "pattern": "did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa"
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

def get_test_data():
    creds_json_list = [
        cred_1,
        cred_2,
        cred_3,
        cred_4,
        cred_5,
        cred_6,
    ]

    vc_record_list = []
    for cred in creds_json_list:
        vc_record_list.append(VCRecord.deserialize_jsonld_cred(cred))
    pd_json_list = [
        (pres_exch_multiple_srs_not_met, 0),
        (pres_exch_multiple_srs_met, 6),
        (pres_exch_datetime_minimum_met, 6),
        (pres_exch_number_const_met, 0),
        (pres_exch_nested_srs, 6),
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
    return (vc_record_list, pd_list)
