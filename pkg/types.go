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
	"time"
)

type CreateConsentRequest struct {
	Actor     IdentifierURI
	Custodian IdentifierURI
	Subject   IdentifierURI
	Performer *IdentifierURI
	Records   []Record
}

// Record contains derived values from a consent record for a custodian/subject/actor triple.
// There can be multiple records per triple, each with their own proof and details.
// More values can be added to this struct later.
type Record struct {
	// RecordID refers to the current hash of the decoded attachment
	RecordID *string
	// PreviousRecordID refers to a previous record.
	PreviousRecordID *string
	ConsentProof     *EmbeddedData
	Period           *Period
}

// EmbeddedData defines component schema for EmbeddedData.
type EmbeddedData struct {
	ContentType string
	Data        string
}

// Period defines component schema for Period.
type Period struct {
	End   *time.Time
	Start time.Time
}

// IdentifierURI defines component schema for IdentifierURI.
type IdentifierURI string
