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
	// RecordHash refers to the current hash of the decoded fhir record
	RecordHash *string
	// PreviousRecordhash refers to a previous record.
	PreviousRecordhash *string
	ConsentProof       *DocumentReference
	DataClass          []IdentifierURI
	Period             Period
}

// DocumentReference defines component schema for DocumentReference.
type DocumentReference struct {
	ID          string
	Title       string
	ContentType *string
	URL         *string
	Hash        *string
}

// Period defines component schema for Period.
type Period struct {
	End   *time.Time
	Start time.Time
}

// IdentifierURI defines component schema for IdentifierURI.
type IdentifierURI string

// abstraction of time.Now() for testing
type nutsTimeI interface {
	Now() time.Time
}

type realNutsTime struct{}

func (realNutsTime) Now() time.Time { return time.Now() }

var nutsTime nutsTimeI = realNutsTime{}
