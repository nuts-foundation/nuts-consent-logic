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

package steps

import (
	"github.com/cbroglie/mustache"
	"github.com/nuts-foundation/nuts-consent-logic/generated"
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
      "system": "https://nuts.nl/identifiers/bsn",
      "value": "{{subjectBsn}}"
    }
  },
  {{#performerId}}
  "performer": [{
    "type": "Organization",
    "identifier": {
      "system": "https://nuts.nl/identifiers/agb",
      "value": "{{performerId}}"
    }
  }],
  {{/performerId}}
  "organization": [{
    "identifier": {
      "system": "https://nuts.nl/identifiers/agb",
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
        "system": "https://nuts.nl/identifiers/bsn",
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
            "system": "https://nuts.nl/identifiers/agb",
            "value": "{{.}}"
          }
        }
      },
    {{/actorAgbs}}
    ],
    "period": {
      "start": "{{period.Start}}",
      "end": "{{period.End}}"
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

func CreateFhirConsentResource(request generated.CreateConsentRequest) (string, error) {

	var actorAgbs []string
	for _, actor := range request.Actors {
		actorAgbs = append(actorAgbs, strings.Split(string(actor), "#")[1])
	}

	viewModel := map[string]interface{}{
		"subjectBsn":   strings.Split(string(request.Subject), "#")[1],
		"actorAgbs":    actorAgbs,
		"custodianAgb": strings.Split(string(request.Custodian), "#")[1],
		"period": map[string]string{
			"Start": request.Period.Start.Format(time.RFC3339),
			"End":   request.Period.End.Format(time.RFC3339),
		},
		"consentProof": request.ConsentProof,
		"performerId":  strings.Split(string(*request.Performer), "#")[1],
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
