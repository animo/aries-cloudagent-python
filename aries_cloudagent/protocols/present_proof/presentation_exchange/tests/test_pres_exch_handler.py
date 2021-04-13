import asyncio
import pytest

from asynctest import TestCase
from copy import deepcopy

from .....core.in_memory import InMemoryProfile
from .....core.profile import Profile
from .....storage.vc_holder.vc_record import VCRecord

from ..pres_exch import (
    PresentationDefinition,
    Requirement,
    Filter,
    SchemaInputDescriptor,
)
from ..pres_exch_handler import (
    make_requirement,
    is_len_applicable,
    exclusive_maximum_check,
    exclusive_minimum_check,
    minimum_check,
    maximum_check,
    length_check,
    pattern_check,
    subject_is_issuer,
    filter_schema,
    credential_match_schema,
    is_numeric,
    merge_nested_results,
    create_vp,
    PresentationExchError,
)
from .....resolver.did_resolver_registry import DIDResolverRegistry
from .....resolver.did_resolver import DIDResolver

from .test_data import get_test_data


@pytest.yield_fixture(scope='class')
def event_loop(request):
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope='class')
async def setup_tuple():
    creds, pds, profile, issue_suite, proof_suite = await get_test_data()
    return creds, pds, profile, issue_suite, proof_suite


class TestPresExchHandler:
    @pytest.mark.asyncio
    @pytest.mark.ursa_bbs_signatures
    async def test_load_cred_json(self, setup_tuple):
        cred_list, pd_list, profile, issue_suite, proof_suite = setup_tuple
        assert len(cred_list) == 6
        for tmp_pd in pd_list:
            # tmp_pd is tuple of presentation_definition and expected number of VCs
            tmp_vp = await create_vp(
                credentials=cred_list,
                pd=tmp_pd[0],
                profile=profile,
                challenge="1f44d55f-f161-4938-a659-f8026467f126",
                derive_suite=proof_suite,
                issue_suite=issue_suite,
            )
            assert len(tmp_vp["verifiableCredential"]) == tmp_pd[1]

    @pytest.mark.asyncio
    async def test_to_requirement_catch_errors(self):
        test_json_pd = """
            {
                "submission_requirements": [
                    {
                        "name": "Banking Information",
                        "purpose": "We need you to prove you currently hold a bank account older than 12months.",
                        "rule": "pick",
                        "count": 1,
                        "from": "A"
                    }
                ],
                "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "input_descriptors": [
                    {
                        "id": "banking_input_1",
                        "name": "Bank Account Information",
                        "purpose": "We can only remit payment to a currently-valid bank account.",
                        "group": [
                            "B"
                        ],
                        "schema": [
                            {
                                "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
                            }
                        ],
                        "constraints": {
                            "fields": [
                                {
                                    "path": [
                                        "$.issuer.id",
                                        "$.vc.issuer.id"
                                    ],
                                    "purpose": "We can only verify bank accounts if they are attested by a trusted bank, auditor or regulatory authority.",
                                    "filter": {
                                        "type": "string",
                                        "pattern": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
                                    }
                                },
                                {
                                    "path": [
                                        "$.credentialSubject.account[*].route",
                                        "$.vc.credentialSubject.account[*].route",
                                        "$.account[*].route"
                                    ],
                                    "purpose": "We can only remit payment to a currently-valid account at a US, Japanese, or German federally-accredited bank, submitted as an ABA RTN or SWIFT code.",
                                    "filter": {
                                        "type": "string",
                                        "pattern": "^[0-9]{9}|^([a-zA-Z]){4}([a-zA-Z]){2}([0-9a-zA-Z]){2}([0-9a-zA-Z]{3})?$"
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        """

        with pytest.raises(PresentationExchError):
            test_pd = PresentationDefinition.deserialize(test_json_pd)
            await make_requirement(
                srs=test_pd.submission_requirements,
                descriptors=test_pd.input_descriptors,
            )

        test_json_pd_nested_srs = """
            {
                "submission_requirements": [
                    {
                        "name": "Citizenship Information",
                        "rule": "pick",
                        "max": 3,
                        "from_nested": [
                            {
                                "name": "United States Citizenship Proofs",
                                "purpose": "We need you to prove your US citizenship.",
                                "rule": "all",
                                "from": "C"
                            },
                            {
                                "name": "European Union Citizenship Proofs",
                                "purpose": "We need you to prove you are a citizen of an EU member state.",
                                "rule": "all",
                                "from": "D"
                            }
                        ]
                    }
                ],
                "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "input_descriptors": [
                    {
                        "id": "banking_input_1",
                        "name": "Bank Account Information",
                        "purpose": "We can only remit payment to a currently-valid bank account.",
                        "group": [
                            "B"
                        ],
                        "schema": [
                            {
                                "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
                            }
                        ],
                        "constraints": {
                            "fields": [
                                {
                                    "path": [
                                        "$.issuer.id",
                                        "$.vc.issuer.id"
                                    ],
                                    "purpose": "We can only verify bank accounts if they are attested by a trusted bank, auditor or regulatory authority.",
                                    "filter": {
                                        "type": "string",
                                        "pattern": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
                                    }
                                },
                                {
                                    "path": [
                                        "$.credentialSubject.account[*].route",
                                        "$.vc.credentialSubject.account[*].route",
                                        "$.account[*].route"
                                    ],
                                    "purpose": "We can only remit payment to a currently-valid account at a US, Japanese, or German federally-accredited bank, submitted as an ABA RTN or SWIFT code.",
                                    "filter": {
                                        "type": "string",
                                        "pattern": "^[0-9]{9}|^([a-zA-Z]){4}([a-zA-Z]){2}([0-9a-zA-Z]){2}([0-9a-zA-Z]{3})?$"
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        """

        with pytest.raises(PresentationExchError):
            test_pd = PresentationDefinition.deserialize(test_json_pd_nested_srs)
            await make_requirement(
                srs=test_pd.submission_requirements,
                descriptors=test_pd.input_descriptors,
            )

    @pytest.mark.asyncio
    async def test_make_requirement_with_none_params(self):
        test_json_pd_no_sr = """
            {
                "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "input_descriptors": [
                    {
                        "id": "banking_input_1",
                        "name": "Bank Account Information",
                        "purpose": "We can only remit payment to a currently-valid bank account.",
                        "group": [
                            "B"
                        ],
                        "schema": [
                            {
                                "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
                            }
                        ],
                        "constraints": {
                            "fields": [
                                {
                                    "path": [
                                        "$.issuer.id",
                                        "$.vc.issuer.id"
                                    ],
                                    "purpose": "We can only verify bank accounts if they are attested by a trusted bank, auditor or regulatory authority.",
                                    "filter": {
                                        "type": "string",
                                        "pattern": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
                                    }
                                },
                                {
                                    "path": [
                                        "$.credentialSubject.account[*].route",
                                        "$.vc.credentialSubject.account[*].route",
                                        "$.account[*].route"
                                    ],
                                    "purpose": "We can only remit payment to a currently-valid account at a US, Japanese, or German federally-accredited bank, submitted as an ABA RTN or SWIFT code.",
                                    "filter": {
                                        "type": "string",
                                        "pattern": "^[0-9]{9}|^([a-zA-Z]){4}([a-zA-Z]){2}([0-9a-zA-Z]){2}([0-9a-zA-Z]{3})?$"
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        """

        test_pd = PresentationDefinition.deserialize(test_json_pd_no_sr)
        assert test_pd.submission_requirements is None
        await make_requirement(
            srs=test_pd.submission_requirements, descriptors=test_pd.input_descriptors
        )

        test_json_pd_no_input_desc = """
            {
                "submission_requirements": [
                    {
                        "name": "Banking Information",
                        "purpose": "We need you to prove you currently hold a bank account older than 12months.",
                        "rule": "pick",
                        "count": 1,
                        "from": "A"
                    }
                ],
                "id": "32f54163-7166-48f1-93d8-ff217bdb0653"
            }
        """

        with pytest.raises(PresentationExchError):
            test_pd = PresentationDefinition.deserialize(test_json_pd_no_input_desc)
            await make_requirement(
                srs=test_pd.submission_requirements,
                descriptors=test_pd.input_descriptors,
            )

    @pytest.mark.asyncio
    @pytest.mark.ursa_bbs_signatures
    async def test_subject_is_issuer_check(self, setup_tuple):
        cred_list, pd_list, profile, issue_suite, proof_suite = setup_tuple

        test_pd = """
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
                            "subject_is_issuer": "required",
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
                                        "maximum":"2009-5-16"
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        """

        tmp_vp = await create_vp(
            credentials=cred_list,
            pd=PresentationDefinition.deserialize(test_pd),
            profile=profile,
            challenge="1f44d55f-f161-4938-a659-f8026467f126",
            derive_suite=proof_suite,
            issue_suite=issue_suite,
        )

    @pytest.mark.asyncio
    @pytest.mark.ursa_bbs_signatures
    async def test_limit_disclosure_required_check(self, setup_tuple):
        cred_list, pd_list, profile, issue_suite, proof_suite = setup_tuple
        test_pd = """
            {
                "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
                "submission_requirements":[
                    {
                    "name": "Citizenship Information",
                    "rule": "pick",
                    "min": 1,
                    "from": "A"
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
                            "limit_disclosure": "required",
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
                    }
                ]
            }
        """

        tmp_pd = PresentationDefinition.deserialize(test_pd)
        assert tmp_pd.input_descriptors[0].constraint.limit_disclosure
        tmp_vp = await create_vp(
            credentials=cred_list,
            pd=tmp_pd,
            profile=profile,
            challenge="1f44d55f-f161-4938-a659-f8026467f126",
            derive_suite=proof_suite,
            issue_suite=issue_suite,
        )
        assert len(tmp_vp["verifiableCredential"]) == 6
        for cred in tmp_vp["verifiableCredential"]:
            assert cred["issuer"] in [
                "did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa",
                "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
            ]
            assert cred["proof"]["type"] == "BbsBlsSignatureProof2020"

    # @pytest.mark.asyncio
    # async def test_filter_number_type_check(self, profile, cred_list):
        # test_pd_min = """
        #     {
        #         "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
        #         "submission_requirements":[
        #             {
        #                 "name": "European Union Citizenship Proofs",
        #                 "rule": "pick",
        #                 "min": 1,
        #                 "from": "A"
        #             }
        #         ],
        #         "input_descriptors":[
        #             {
        #             "id":"citizenship_input_1",
        #             "name":"EU Driver's License",
        #             "group":[
        #                 "A"
        #             ],
        #             "schema":[
        #                 {
        #                     "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        #                 }
        #             ],
        #             "constraints":{
        #                 "fields":[
        #                     {
        #                         "path":[
        #                             "$.credentialSubject.degree.test",
        #                             "$.vc.credentialSubject.degree.test",
        #                             "$.test"
        #                         ],
        #                         "purpose":"The claim must be from one of the specified issuers",
        #                         "filter":{  
        #                             "type": "number",
        #                             "minimum": 2
        #                         }
        #                     }
        #                 ]
        #             }
        #             }
        #         ]
        #     }
        # """

        # tmp_pd = PresentationDefinition.deserialize(test_pd_min)
        # tmp_vp = await create_vp(
        #     credentials=cred_list,
        #     pd=tmp_pd,
        #     profile=InMemoryProfile.test_profile(),
        #     challenge="1f44d55f-f161-4938-a659-f8026467f126",
        # )
        # assert len(tmp_vp["verifiableCredential"]) == 2
        # test_pd_max = """
        #     {
        #         "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
        #         "submission_requirements":[
        #             {
        #                 "name": "European Union Citizenship Proofs",
        #                 "rule": "pick",
        #                 "min": 1,
        #                 "from": "A"
        #             }
        #         ],
        #         "input_descriptors":[
        #             {
        #             "id":"citizenship_input_1",
        #             "name":"EU Driver's License",
        #             "group":[
        #                 "A"
        #             ],
        #             "schema":[
        #                 {
        #                     "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        #                 }
        #             ],
        #             "constraints":{
        #                 "fields":[
        #                     {
        #                         "path":[
        #                             "$.credentialSubject.degree.test",
        #                             "$.vc.credentialSubject.degree.test",
        #                             "$.test"
        #                         ],
        #                         "purpose":"The claim must be from one of the specified issuers",
        #                         "filter":{  
        #                             "type": "number",
        #                             "maximum": 2
        #                         }
        #                     }
        #                 ]
        #             }
        #             }
        #         ]
        #     }
        # """

        # tmp_pd = PresentationDefinition.deserialize(test_pd_max)
        # tmp_vp = await create_vp(
        #     credentials=cred_list,
        #     pd=tmp_pd,
        #     profile=InMemoryProfile.test_profile(),
        #     challenge="1f44d55f-f161-4938-a659-f8026467f126",
        # )
        # assert len(tmp_vp["verifiableCredential"]) == 2

        # test_pd_excl_min = """
        #     {
        #         "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
        #         "submission_requirements":[
        #             {
        #                 "name": "European Union Citizenship Proofs",
        #                 "rule": "pick",
        #                 "min": 1,
        #                 "from": "A"
        #             }
        #         ],
        #         "input_descriptors":[
        #             {
        #             "id":"citizenship_input_1",
        #             "name":"EU Driver's License",
        #             "group":[
        #                 "A"
        #             ],
        #             "schema":[
        #                 {
        #                     "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        #                 }
        #             ],
        #             "constraints":{
        #                 "fields":[
        #                     {
        #                         "path":[
        #                             "$.credentialSubject.degree.test",
        #                             "$.vc.credentialSubject.degree.test",
        #                             "$.test"
        #                         ],
        #                         "purpose":"The claim must be from one of the specified issuers",
        #                         "filter":{  
        #                             "type": "number",
        #                             "exclusiveMinimum": 1.5
        #                         }
        #                     }
        #                 ]
        #             }
        #             }
        #         ]
        #     }
        # """

        # tmp_pd = PresentationDefinition.deserialize(test_pd_excl_min)
        # tmp_vp = await create_vp(
        #     credentials=cred_list,
        #     pd=tmp_pd,
        #     profile=InMemoryProfile.test_profile(),
        #     challenge="1f44d55f-f161-4938-a659-f8026467f126",
        # )
        # assert len(tmp_vp["verifiableCredential"]) == 2

        # test_pd_excl_max = """
        #     {
        #         "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
        #         "submission_requirements":[
        #             {
        #                 "name": "European Union Citizenship Proofs",
        #                 "rule": "pick",
        #                 "min": 1,
        #                 "from": "A"
        #             }
        #         ],
        #         "input_descriptors":[
        #             {
        #             "id":"citizenship_input_1",
        #             "name":"EU Driver's License",
        #             "group":[
        #                 "A"
        #             ],
        #             "schema":[
        #                 {
        #                     "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        #                 }
        #             ],
        #             "constraints":{
        #                 "fields":[
        #                     {
        #                         "path":[
        #                             "$.credentialSubject.degree.test",
        #                             "$.vc.credentialSubject.degree.test",
        #                             "$.test"
        #                         ],
        #                         "purpose":"The claim must be from one of the specified issuers",
        #                         "filter":{  
        #                             "type": "number",
        #                             "exclusiveMaximum": 2.5
        #                         }
        #                     }
        #                 ]
        #             }
        #             }
        #         ]
        #     }
        # """

        # tmp_pd = PresentationDefinition.deserialize(test_pd_excl_max)
        # tmp_vp = await create_vp(
        #     credentials=cred_list,
        #     pd=tmp_pd,
        #     profile=InMemoryProfile.test_profile(),
        #     challenge="1f44d55f-f161-4938-a659-f8026467f126",
        # )
        # assert len(tmp_vp["verifiableCredential"]) == 2

        # test_pd_const = """
        #     {
        #         "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
        #         "submission_requirements":[
        #             {
        #                 "name": "European Union Citizenship Proofs",
        #                 "rule": "pick",
        #                 "min": 1,
        #                 "from": "A"
        #             }
        #         ],
        #         "input_descriptors":[
        #             {
        #             "id":"citizenship_input_1",
        #             "name":"EU Driver's License",
        #             "group":[
        #                 "A"
        #             ],
        #             "schema":[
        #                 {
        #                     "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        #                 }
        #             ],
        #             "constraints":{
        #                 "fields":[
        #                     {
        #                         "path":[
        #                             "$.credentialSubject.degree.test",
        #                             "$.vc.credentialSubject.degree.test",
        #                             "$.test"
        #                         ],
        #                         "purpose":"The claim must be from one of the specified issuers",
        #                         "filter":{  
        #                             "type": "number",
        #                             "const": 2
        #                         }
        #                     }
        #                 ]
        #             }
        #             }
        #         ]
        #     }
        # """

        # tmp_pd = PresentationDefinition.deserialize(test_pd_const)
        # tmp_vp = await create_vp(
        #     credentials=cred_list,
        #     pd=tmp_pd,
        #     profile=InMemoryProfile.test_profile(),
        #     challenge="1f44d55f-f161-4938-a659-f8026467f126",
        # )
        # assert len(tmp_vp["verifiableCredential"]) == 2

        # test_pd_enum = """
        #     {
        #         "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
        #         "submission_requirements":[
        #             {
        #                 "name": "European Union Citizenship Proofs",
        #                 "rule": "pick",
        #                 "min": 1,
        #                 "from": "A"
        #             }
        #         ],
        #         "input_descriptors":[
        #             {
        #             "id":"citizenship_input_1",
        #             "name":"EU Driver's License",
        #             "group":[
        #                 "A"
        #             ],
        #             "schema":[
        #                 {
        #                     "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        #                 }
        #             ],
        #             "constraints":{
        #                 "fields":[
        #                     {
        #                         "path":[
        #                             "$.credentialSubject.degree.test",
        #                             "$.vc.credentialSubject.degree.test",
        #                             "$.test"
        #                         ],
        #                         "purpose":"The claim must be from one of the specified issuers",
        #                         "filter":{  
        #                             "type": "number",
        #                             "enum": [2, 2.0 , "test"]
        #                         }
        #                     }
        #                 ]
        #             }
        #             }
        #         ]
        #     }
        # """

        # tmp_pd = PresentationDefinition.deserialize(test_pd_enum)
        # tmp_vp = await create_vp(
        #     credentials=cred_list,
        #     pd=tmp_pd,
        #     profile=InMemoryProfile.test_profile(),
        #     challenge="1f44d55f-f161-4938-a659-f8026467f126",
        # )
        # assert len(tmp_vp["verifiableCredential"]) == 2

        # test_pd_missing = """
        #     {
        #         "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
        #         "submission_requirements":[
        #             {
        #                 "name": "European Union Citizenship Proofs",
        #                 "rule": "pick",
        #                 "min": 1,
        #                 "from": "A"
        #             }
        #         ],
        #         "input_descriptors":[
        #             {
        #             "id":"citizenship_input_1",
        #             "name":"EU Driver's License",
        #             "group":[
        #                 "A"
        #             ],
        #             "schema":[
        #                 {
        #                     "uri":"https://www.w3.org/2018/credentials#VerifiableCredential"
        #                 }
        #             ],
        #             "constraints":{
        #                 "fields":[
        #                     {
        #                         "path":[
        #                             "$.credentialSubject.degree.test",
        #                             "$.vc.credentialSubject.degree.test",
        #                             "$.test"
        #                         ],
        #                         "purpose":"The claim must be from one of the specified issuers",
        #                         "filter":{  
        #                             "type": "number"
        #                         }
        #                     }
        #                 ]
        #             }
        #             }
        #         ]
        #     }
        # """

        # tmp_pd = PresentationDefinition.deserialize(test_pd_missing)
        # tmp_vp = await create_vp(
        #     credentials=cred_list,
        #     pd=tmp_pd,
        #     profile=profile,
        #     challenge="1f44d55f-f161-4938-a659-f8026467f126",
        # )
        # assert len(tmp_vp["verifiableCredential"]) == 0

    @pytest.mark.asyncio
    @pytest.mark.ursa_bbs_signatures
    async def test_filter_no_type_check(self, setup_tuple):
        cred_list, pd_list, profile, issue_suite, proof_suite = setup_tuple
        test_pd = """
            {
                "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
                "submission_requirements":[
                    {
                        "name": "European Union Citizenship Proofs",
                        "rule": "all",
                        "from": "A"
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
                                    "$.credentialSubject.degree.type",
                                    "$.vc.credentialSubject.degree.type",
                                    "$.test"
                                ],
                                "purpose":"The claim must be from one of the specified issuers",
                                "filter":{  
                                    "not": {
                                        "const": "MasterDegree"
                                    }
                                }
                            }
                        ]
                    }
                    }
                ]
            }
        """

        tmp_pd = PresentationDefinition.deserialize(test_pd)
        tmp_vp = await create_vp(
            credentials=cred_list,
            pd=tmp_pd,
            profile=profile,
            challenge="1f44d55f-f161-4938-a659-f8026467f126",
            derive_suite=proof_suite,
            issue_suite=issue_suite,
        )
        assert len(tmp_vp["verifiableCredential"]) == 6

    @pytest.mark.asyncio
    @pytest.mark.ursa_bbs_signatures
    async def test_filter_string(self, setup_tuple):
        cred_list, pd_list, profile, issue_suite, proof_suite = setup_tuple
        test_pd_min_length = """
            {
                "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
                "submission_requirements":[
                    {
                        "name": "European Union Citizenship Proofs",
                        "rule": "all",
                        "from": "A"
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
                                        "$.vc.issuer.id",
                                        "$.issuer.id"
                                    ],
                                    "filter":{
                                        "type":"string",
                                        "minLength": 5
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        """

        tmp_pd = PresentationDefinition.deserialize(test_pd_min_length)
        tmp_vp = await create_vp(
            credentials=cred_list,
            pd=tmp_pd,
            profile=profile,
            challenge="1f44d55f-f161-4938-a659-f8026467f126",
            derive_suite=proof_suite,
            issue_suite=issue_suite,
        )
        assert len(tmp_vp["verifiableCredential"]) == 6

        test_pd_max_length = """
            {
                "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
                "submission_requirements":[
                    {
                        "name": "European Union Citizenship Proofs",
                        "rule": "all",
                        "from": "A"
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
                                        "maxLength": 150
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        """

        tmp_pd = PresentationDefinition.deserialize(test_pd_max_length)
        tmp_vp = await create_vp(
            credentials=cred_list,
            pd=tmp_pd,
            profile=profile,
            challenge="1f44d55f-f161-4938-a659-f8026467f126",
            derive_suite=proof_suite,
            issue_suite=issue_suite,
        )
        assert len(tmp_vp["verifiableCredential"]) == 6

        test_pd_pattern_check = """
            {
                "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
                "submission_requirements":[
                    {
                        "name": "European Union Citizenship Proofs",
                        "rule": "all",
                        "from": "A"
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
                                        "$.vc.issuer.id",
                                        "$.issuer.id"
                                    ],
                                    "filter":{
                                        "type":"string",
                                        "pattern": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        """

        tmp_pd = PresentationDefinition.deserialize(test_pd_pattern_check)
        tmp_vp = await create_vp(
            credentials=cred_list,
            pd=tmp_pd,
            profile=profile,
            challenge="1f44d55f-f161-4938-a659-f8026467f126",
            derive_suite=proof_suite,
            issue_suite=issue_suite,
        )
        assert len(tmp_vp["verifiableCredential"]) == 0

        test_pd_datetime_exclmax = """
            {
                "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
                "submission_requirements":[
                    {
                        "name": "European Union Citizenship Proofs",
                        "rule": "all",
                        "from": "A"
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
                                        "$.issuanceDate",
                                        "$.vc.issuanceDate"
                                    ],
                                    "filter":{
                                        "type":"string",
                                        "format":"date",
                                        "exclusiveMaximum":"2011-5-16"
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        """

        tmp_pd = PresentationDefinition.deserialize(test_pd_datetime_exclmax)
        tmp_vp = await create_vp(
            credentials=cred_list,
            pd=tmp_pd,
            profile=profile,
            challenge="1f44d55f-f161-4938-a659-f8026467f126",
            derive_suite=proof_suite,
            issue_suite=issue_suite,
        )
        assert len(tmp_vp["verifiableCredential"]) == 6

        test_pd_datetime_exclmin = """
            {
                "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
                "submission_requirements":[
                    {
                        "name": "European Union Citizenship Proofs",
                        "rule": "all",
                        "from": "A"
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
                                        "$.issuanceDate",
                                        "$.vc.issuanceDate"
                                    ],
                                    "filter":{
                                        "type":"string",
                                        "format":"date",
                                        "exclusiveMinimum":"2008-5-16"
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        """

        tmp_pd = PresentationDefinition.deserialize(test_pd_datetime_exclmin)
        tmp_vp = await create_vp(
            credentials=cred_list,
            pd=tmp_pd,
            profile=profile,
            challenge="1f44d55f-f161-4938-a659-f8026467f126",
            derive_suite=proof_suite,
            issue_suite=issue_suite,
        )
        assert len(tmp_vp["verifiableCredential"]) == 6

        test_pd_const_check = """
            {
                "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
                "submission_requirements":[
                    {
                        "name": "European Union Citizenship Proofs",
                        "rule": "all",
                        "from": "A"
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
                                        "$.vc.issuer.id",
                                        "$.issuer.id"
                                    ],
                                    "filter":{
                                        "type":"string",
                                        "const": "did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa"
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        """

        tmp_pd = PresentationDefinition.deserialize(test_pd_const_check)
        tmp_vp = await create_vp(
            credentials=cred_list,
            pd=tmp_pd,
            profile=profile,
            challenge="1f44d55f-f161-4938-a659-f8026467f126",
            derive_suite=proof_suite,
            issue_suite=issue_suite,
        )
        assert len(tmp_vp["verifiableCredential"]) == 6

    @pytest.mark.asyncio
    async def test_filter_schema(self, setup_tuple):
        cred_list, pd_list, profile, issue_suite, proof_suite = setup_tuple
        tmp_schema_list = [
            SchemaInputDescriptor(
                uri="test123",
                required=True,
            )
        ]
        assert len(await filter_schema(cred_list, tmp_schema_list)) == 0

    @pytest.mark.asyncio
    async def test_cred_schema_match(self, setup_tuple):
        cred_list, pd_list, profile, issue_suite, proof_suite = setup_tuple
        tmp_cred = deepcopy(cred_list[0])
        assert await credential_match_schema(tmp_cred, "https://www.w3.org/2018/credentials#VerifiableCredential") is True

    @pytest.mark.asyncio
    async def test_merge_nested(self, setup_tuple):
        cred_list, pd_list, profile, issue_suite, proof_suite = setup_tuple
        test_nested_result = []
        test_dict_1 = {}
        test_dict_1["citizenship_input_1"] = [
            cred_list[0],
            cred_list[1],
            cred_list[2],
            cred_list[3],
            cred_list[4],
            cred_list[5],
        ]
        test_dict_2 = {}
        test_dict_2["citizenship_input_2"] = [
            cred_list[4],
            cred_list[5],
        ]
        test_dict_3 = {}
        test_dict_3["citizenship_input_2"] = [
            cred_list[3],
            cred_list[2],
        ]
        test_nested_result.append(test_dict_1)
        test_nested_result.append(test_dict_2)
        test_nested_result.append(test_dict_3)

        tmp_result = await merge_nested_results(test_nested_result, {})

    @pytest.mark.asyncio
    async def test_subject_is_issuer(self, setup_tuple):
        cred_list, pd_list, profile, issue_suite, proof_suite = setup_tuple
        tmp_cred = deepcopy(cred_list[0])
        tmp_cred.issuer_id = "4fc82e63-f897-4dad-99cc-f698dff6c425"
        tmp_cred.subject_ids.add("4fc82e63-f897-4dad-99cc-f698dff6c425")
        assert tmp_cred.subject_ids is not None
        assert await subject_is_issuer(tmp_cred) is True
        tmp_cred.issuer_id = "19b823fb-55ef-49f4-8caf-2a26b8b9286f"
        assert await subject_is_issuer(tmp_cred) is False

    @pytest.mark.asyncio
    def test_is_numeric(self):
        assert is_numeric("test") is False
        assert is_numeric(1) is True
        assert is_numeric(2 + 3j) is False

    @pytest.mark.asyncio
    def test_filter_no_match(self):
        tmp_filter_excl_min = Filter(exclusive_min=7)
        assert exclusive_minimum_check("test", tmp_filter_excl_min) is False
        tmp_filter_excl_max = Filter(exclusive_max=10)
        assert exclusive_maximum_check("test", tmp_filter_excl_max) is False
        tmp_filter_min = Filter(minimum=10)
        assert minimum_check("test", tmp_filter_min) is False
        tmp_filter_max = Filter(maximum=10)
        assert maximum_check("test", tmp_filter_max) is False

    @pytest.mark.asyncio
    def test_filter_valueerror(self):
        tmp_filter_excl_min = Filter(exclusive_min=7, fmt="date")
        assert exclusive_minimum_check("test", tmp_filter_excl_min) is False
        tmp_filter_excl_max = Filter(exclusive_max=10, fmt="date")
        assert exclusive_maximum_check("test", tmp_filter_excl_max) is False
        tmp_filter_min = Filter(minimum=10, fmt="date")
        assert minimum_check("test", tmp_filter_min) is False
        tmp_filter_max = Filter(maximum=10, fmt="date")
        assert maximum_check("test", tmp_filter_max) is False

    @pytest.mark.asyncio
    def test_filter_length_check(self):
        tmp_filter_both = Filter(min_length=7, max_length=10)
        assert length_check("test12345", tmp_filter_both) is True
        tmp_filter_min = Filter(min_length=7)
        assert length_check("test123", tmp_filter_min) is True
        tmp_filter_max = Filter(max_length=10)
        assert length_check("test", tmp_filter_max) is True
        assert length_check("test12", tmp_filter_min) is False

    @pytest.mark.asyncio
    def test_filter_pattern_check(self):
        tmp_filter = Filter(pattern="test1|test2")
        assert pattern_check("test3", tmp_filter) is False
        tmp_filter = Filter(const="test3")
        assert pattern_check("test3", tmp_filter) is False

    @pytest.mark.asyncio
    def test_is_len_applicable(self):
        tmp_req_a = Requirement(count=1)
        tmp_req_b = Requirement(minimum=3)
        tmp_req_c = Requirement(maximum=5)

        assert is_len_applicable(tmp_req_a, 2) is False
        assert is_len_applicable(tmp_req_b, 2) is False
        assert is_len_applicable(tmp_req_c, 6) is False
