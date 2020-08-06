// Package api provides primitives to interact the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen DO NOT EDIT.
package api

import (
	"github.com/labstack/echo/v4"
	"time"
)

// ActorURI defines model for ActorURI.
type ActorURI string

// ConsentRecord defines model for ConsentRecord.
type ConsentRecord struct {
	ConsentProof DocumentReference    `json:"consentProof"`
	DataClass    []DataClassification `json:"dataClass"`
	Period       Period               `json:"period"`

	// Optional parameter. If provided, the previous consentRecord will be replaced by this new ConsentRecord. This is the computed hash of the fhir record.
	PreviousRecordHash *string `json:"previousRecordHash,omitempty"`
}

// CreateConsentRequest defines model for CreateConsentRequest.
type CreateConsentRequest struct {

	// URI defining the actor, usually a practitioner
	Actor ActorURI `json:"actor"`

	// URI defining an organization, usually the custodian or actor
	Custodian CustodianURI `json:"custodian"`

	// URI defining a party such as a person or organization
	Performer *IdentifierURI  `json:"performer,omitempty"`
	Records   []ConsentRecord `json:"records"`

	// URI defining the data subject, usually the patient
	Subject SubjectURI `json:"subject"`
}

// CustodianURI defines model for CustodianURI.
type CustodianURI string

// DataClassification defines model for DataClassification.
type DataClassification string

// DocumentReference defines model for DocumentReference.
type DocumentReference struct {

	// unique identifier useable for retrieving the proof when contacting the care provider (technical or on paper)
	ID string `json:"ID"`

	// location where the proof document can be found, should accept Nuts based authentication
	URL         *string `json:"URL,omitempty"`
	ContentType *string `json:"contentType,omitempty"`

	// base64 encoded sha256 of the document
	Hash *string `json:"hash,omitempty"`

	// human readable identifier for consent proof, eg: document name
	Title string `json:"title"`
}

// IdentifierURI defines model for IdentifierURI.
type IdentifierURI string

// JobCreatedResponse defines model for JobCreatedResponse.
type JobCreatedResponse struct {
	JobId      *string `json:"jobId,omitempty"`
	ResultCode string  `json:"resultCode"`
}

// Period defines model for Period.
type Period struct {
	End   *time.Time `json:"end,omitempty"`
	Start time.Time  `json:"start"`
}

// SubjectURI defines model for SubjectURI.
type SubjectURI string

// CreateOrUpdateConsentJSONBody defines parameters for CreateOrUpdateConsent.
type CreateOrUpdateConsentJSONBody CreateConsentRequest

// CreateOrUpdateConsentRequestBody defines body for CreateOrUpdateConsent for application/json ContentType.
type CreateOrUpdateConsentJSONRequestBody CreateOrUpdateConsentJSONBody

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Create or update a new consent.
	// (POST /api/consent)
	CreateOrUpdateConsent(ctx echo.Context) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// CreateOrUpdateConsent converts echo context to params.
func (w *ServerInterfaceWrapper) CreateOrUpdateConsent(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.CreateOrUpdateConsent(ctx)
	return err
}

// This is a simple interface which specifies echo.Route addition functions which
// are present on both echo.Echo and echo.Group, since we want to allow using
// either of them for path registration
type EchoRouter interface {
	CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
}

// RegisterHandlers adds each server route to the EchoRouter.
func RegisterHandlers(router EchoRouter, si ServerInterface) {

	wrapper := ServerInterfaceWrapper{
		Handler: si,
	}

	router.POST("/api/consent", wrapper.CreateOrUpdateConsent)

}

