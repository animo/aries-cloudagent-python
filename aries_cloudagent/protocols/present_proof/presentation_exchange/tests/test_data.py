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
    },
    "proof": {
      "type": "BbsBlsSignature2020", 
      "verificationMethod": "did:key:zUC75YSsU8xpRgqZaERxSeLjqXiUfxpHAHQvKMTQbLwL8AHujx1dPyxQiqvRz9XzeJgt6MM17eze1k6UPsKS4C6GFe8xG28Ux55MVAURZ7VXwEnoWq8uPXfFxBcUDWiqeHJr45g#zUC75YSsU8xpRgqZaERxSeLjqXiUfxpHAHQvKMTQbLwL8AHujx1dPyxQiqvRz9XzeJgt6MM17eze1k6UPsKS4C6GFe8xG28Ux55MVAURZ7VXwEnoWq8uPXfFxBcUDWiqeHJr45g", 
      "created": "2021-04-13T09:44:40.224720", 
      "proofPurpose": "assertionMethod", 
      "proofValue": "jdAXIact43vAPsDl/wX6mSyglmc5hKLrJHxz8F6njpjpIwXuKTGK9SjMpCjUTp0tP+j9OtQaQH14cbvqbk2U0U+HEvzFKvZIVvBYEyqSpVgiXapWiyeucq1Ly3Zzz3kXMxYLux+ZtfQYxRxweTUHig=="
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
      "created": "2021-04-13T09:56:03.315756",
      "proofPurpose": "assertionMethod",
      "proofValue": "gfcwzfXLr5axXbACObQupG3147GeV309nUmX6XtLpkPiDGdAekPwgyYyyyPZSDkILEv92B+3midG+vaw1O4+Tz3EbJRN/FvnoDxLOQD11Ldoi8PAW0apg+JoKSmkc6zq9E53HMXIyQGTevobf9mcig=="
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
      "created": "2021-04-13T10:06:11.794774",
      "proofPurpose": "assertionMethod", 
      "proofValue": "udmjbp7pYPO9cvkpUmE20F4VA38LjPhSo3OHzTKSYWJOQtIkdIoXMW8C5V6l07Z3ac6lZc2adAcyz38mzK0z2Ea+lZYXlZceNvukwRwK3SMKHbDfoBuMzK9VOXRTCuRQbX0T8ee7yit5wZ1ovBnksg=="
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
      "created": "2021-04-13T10:15:06.266977",
      "proofPurpose": "assertionMethod", 
      "proofValue": "kNhBt2CP1zInrOx+kj7WJGLtywzuvFw6+4Bpo5Pn7oZvucuqWiMMTV7VWAFM8xpiD+8xwquP6ptRjPoFps+lXypb4+LTTkbb8a4SrGYpdu9A1wOl00RsIS8eAGHMEZ8talMgSqaMt60O7SYYFHC/Rw=="
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
      "created": "2021-04-13T10:21:43.216057",
      "proofPurpose": "assertionMethod",
      "proofValue": "kqBAdSsgMgz+pTGMRw61QtH679+KaEqTBPUbMcPXpIDb7z1nubb4GBdOHqHxxuQSMph6bJ1VQUCvONmNFVCIhRP1v6bRpCXnfye9NvUld/MU8S8C2Yy1+oAfkPqo0lEEVBdOhYfUDYpwCtw+v0SXDQ=="
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
      "created": "2021-04-13T10:51:17.312259",
      "proofPurpose": "assertionMethod", 
      "proofValue": "sYIg/SGj9C1Z2Vj+av/WJ9zGIVi+SAvF2iEz3I2IXSw5mpYmpjzQOxQ5g9/Af/ebc6T7fZljMV1pFSwZlUE8SQ243x2zKkYYaR5kwrtjwwEz0EPmTSOwfiM3A1qtB5HoGAEJ2OoL41Vly8Qn3GeERw=="
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
