// Package api provides primitives to interact the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen DO NOT EDIT.
package api

import (
	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/labstack/echo/v4"
	"time"
)

// ActorURI defines model for ActorURI.
type ActorURI string

// ConsentRecord defines model for ConsentRecord.
type ConsentRecord struct {
	ConsentProof struct {
		// Embedded struct due to allOf(#/components/schemas/EmbeddedData)
		EmbeddedData
	} `json:"consentProof"`
	DataRef *DataIdentifier `json:"dataRef,omitempty"`
	Period  Period          `json:"period"`
}

// ConsentValidationRequest defines model for ConsentValidationRequest.
type ConsentValidationRequest struct {
	ConsentId *string `json:"consentId,omitempty"`
}

// CreateConsentRequest defines model for CreateConsentRequest.
type CreateConsentRequest struct {
	Actor     ActorURI        `json:"actor"`
	Custodian CustodianURI    `json:"custodian"`
	Performer *IdentifierURI  `json:"performer,omitempty"`
	Records   []ConsentRecord `json:"records"`
	Subject   SubjectURI      `json:"subject"`
}

// CustodianURI defines model for CustodianURI.
type CustodianURI string

// DataIdentifier defines model for DataIdentifier.
type DataIdentifier struct {
	DataIdentifier string `json:"dataIdentifier"`
	EndpointType   string `json:"endpointType"`
}

// EmbeddedData defines model for EmbeddedData.
type EmbeddedData struct {
	ContentType string `json:"contentType"`
	Data        string `json:"data"`
}

// IdentifierURI defines model for IdentifierURI.
type IdentifierURI string

// JobCreatedResponse defines model for JobCreatedResponse.
type JobCreatedResponse struct {
	JobId      *string `json:"jobId,omitempty"`
	ResultCode *string `json:"resultCode,omitempty"`
}

// Period defines model for Period.
type Period struct {
	End   *time.Time `json:"end,omitempty"`
	Start time.Time  `json:"start"`
}

// SubjectURI defines model for SubjectURI.
type SubjectURI string

// createConsentJSONBody defines parameters for CreateConsent.
type createConsentJSONBody CreateConsentRequest

// validateConsentJSONBody defines parameters for ValidateConsent.
type validateConsentJSONBody ConsentValidationRequest

// CreateConsentRequestBody defines body for CreateConsent for application/json ContentType.
type CreateConsentJSONRequestBody createConsentJSONBody

// ValidateConsentRequestBody defines body for ValidateConsent for application/json ContentType.
type ValidateConsentJSONRequestBody validateConsentJSONBody

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Create a new consent.// (POST /api/consent)
	CreateConsent(ctx echo.Context) error
	// Create the validity of a consent-request job// (POST /api/consent/validation)
	ValidateConsent(ctx echo.Context) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// CreateConsent converts echo context to params.
func (w *ServerInterfaceWrapper) CreateConsent(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.CreateConsent(ctx)
	return err
}

// ValidateConsent converts echo context to params.
func (w *ServerInterfaceWrapper) ValidateConsent(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.ValidateConsent(ctx)
	return err
}

// RegisterHandlers adds each server route to the EchoRouter.
func RegisterHandlers(router runtime.EchoRouter, si ServerInterface) {

	wrapper := ServerInterfaceWrapper{
		Handler: si,
	}

	router.POST("/api/consent", wrapper.CreateConsent)
	router.POST("/api/consent/validation", wrapper.ValidateConsent)

}

