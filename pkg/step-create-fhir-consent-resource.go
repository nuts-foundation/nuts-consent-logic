/*
 * This file is part of nuts-consent-logic.
 *
 * nuts-consent-logic is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nuts-consent-logic is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with nuts-consent-logic.  If not, see <http://www.gnu.org/licenses/>.
 *
 */



package pkg

import (
	"github.com/cbroglie/mustache"
	"regexp"
	"strings"
	"time"
)

const template = `
{
  "resourceType": "Consent",
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
      "system": "urn:oid:2.16.840.1.113883.2.4.6.1",
      "value": "{{subjectBsn}}"
    }
  },
  {{#performerId}}
  "performer": [{
    "type": "Organization",
    "identifier": {
      "system": "urn:oid:2.16.840.1.113883.2.4.6.3",
      "value": "{{performerId}}"
    }
  }],
  {{/performerId}}
  "organization": [{
    "identifier": {
      "system": "urn:oid:2.16.840.1.113883.2.4.6.3",
      "value": "{{custodianAgb}}"
    }
  }],
  {{#consentProof}}
  "sourceAttachment": {
    "contentType": "{{ContentType}}",
    "data": "{{Data}}"
  },
  {{/consentProof}}
  "verification": [{
    "verified": true,
    "verifiedWith": {
      "type": "Patient",
      "identifier": {
        "system": "urn:oid:2.16.840.1.113883.2.4.6.1",
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
            "system": "urn:oid:2.16.840.1.113883.2.4.6.3",
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
          {
            "system": "http://hl7.org/fhir/resource-types",
            "code": "Observation"
          }
        ]
      }
    ]
  }
}
`

func valueFromUrn(urn string) string {
	segments := strings.Split(urn, ":")
	return segments[len(segments)-1]
}

func CreateFhirConsentResource(request CreateConsentRequest) (string, error) {

	var actorAgbs []string
	for _, actor := range request.Actors {
		actorAgbs = append(actorAgbs, valueFromUrn(string(actor)))
	}

	viewModel := map[string]interface{}{
		"subjectBsn":   valueFromUrn(string(request.Subject)),
		"actorAgbs":    actorAgbs,
		"custodianAgb": valueFromUrn(string(request.Custodian)),
		"period": map[string]string{
			"Start": request.Period.Start.Format(time.RFC3339),
		},
		"consentProof": request.ConsentProof,
		"performerId":  valueFromUrn(string(*request.Performer)),
	}

	periodEnd := request.Period.End
	if periodEnd != nil {
		(viewModel["period"].(map[string]string))["End"] = periodEnd.Format(time.RFC3339)
	}

	var (
		res string
		err error
	)
	if res, err = mustache.Render(template, viewModel); err != nil {
		// uh oh
		return "", err
	}

	// filter out last comma out [{},{},] since mustache templates cannot handle this:
	// https://stackoverflow.com/questions/6114435/in-mustache-templating-is-there-an-elegant-way-of-expressing-a-comma-separated-l
	re := regexp.MustCompile(`\},(\s*)]`)
	res = re.ReplaceAllString(res, `}$1]`)

	return res, nil
}
