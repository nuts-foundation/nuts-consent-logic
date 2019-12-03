/*
 *  Nuts consent logic holds the logic for consent creation
 *  Copyright (C) 2019 Nuts community
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package pkg

const template = `
{
  "resourceType": "Consent",
  "meta": {
    "versionId": "{{versionId}}",
    "lastUpdated": "{{lastUpdated}}"
  },
  "scope": {
    "coding": [
      {
        "system": "http://terminology.hl7.org/CodeSystem/consentscope",
        "code": "patient-privacy"
      }
    ]
  },
  "category": [
    {
      "coding": [
        {
          "system": "http://loinc.org",
          "code": "64292-6"
        }
      ]
    }
  ],
  "patient": {
    "identifier": {
      "system": "urn:oid:2.16.840.1.113883.2.4.6.3",
      "value": "{{subjectBsn}}"
    }
  },
  {{#performerId}}
  "performer": [{
    "type": "Organization",
    "identifier": {
      "system": "urn:oid:2.16.840.1.113883.2.4.6.1",
      "value": "{{performerId}}"
    }
  }],
  {{/performerId}}
  "organization": [{
    "identifier": {
      "system": "urn:oid:2.16.840.1.113883.2.4.6.1",
      "value": "{{custodianAgb}}"
    }
  }],
  {{#consentProof}}
  "sourceAttachment": {
{{#ContentType}}
    "contentType": "{{ContentType}}",
{{/ContentType}}
{{#URL}}
    "url": "{{URL}}",
{{/URL}}
{{#Hash}}
    "hash": "{{Hash}}",
{{/Hash}}
    "id": "{{ID}}",
	"title": "{{Title}}"
  },
  {{/consentProof}}
  "verification": [{
    "verified": true,
    "verifiedWith": {
      "type": "Patient",
      "identifier": {
        "system": "urn:oid:2.16.840.1.113883.2.4.6.3",
        "value": "{{subjectBsn}}"
      }
    }
  }],
  "policyRule": {
    "coding": [
      {
        "system": "http://terminology.hl7.org/CodeSystem/v3-ActCode",
        "code": "OPTIN"
      }
    ]
  },
  "provision": {
    "actor": [
      {{#actorAgbs}}
      {
        "role":{
          "coding": [
            {
              "system": "http://terminology.hl7.org/CodeSystem/v3-ParticipationType",
              "code": "PRCP"
            }
          ]
        },
        "reference": {
          "identifier": {
            "system": "urn:oid:2.16.840.1.113883.2.4.6.1",
            "value": "{{.}}"
          }
        }
      },
    {{/actorAgbs}}
    ],
    "period": {
      "start": "{{period.Start}}"
{{#period.End}}
      ,"end": "{{period.End}}"
{{/period.End}}
    },
    "provision": [
      {
        "type": "permit",
        "action": [
          {
            "coding": [
              {
                "system": "http://terminology.hl7.org/CodeSystem/consentaction",
                "code": "access"
              }
            ]
          }
        ],
        "class": [
{{#dataClass}}
          {
			"system": "{{system}}",
			"code": "{{code}}"
          },
{{/dataClass}}
        ]
      }
    ]
  }
}
`
