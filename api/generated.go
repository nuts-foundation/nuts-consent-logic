// Package api provides primitives to interact the openapi HTTP API.
//
// This is an autogenerated file, any edits which you make here will be lost!
package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/labstack/echo/v4"
	"io"
	"net/http"
	"strings"
	"time"
)

// ActorURI defines component schema for ActorURI.
type ActorURI string

// ConsentValidationRequest defines component schema for ConsentValidationRequest.
type ConsentValidationRequest struct {
	ConsentId *string `json:"consentId,omitempty"`
}

// CreateConsentRequest defines component schema for CreateConsentRequest.
type CreateConsentRequest struct {
	Actors       []ActorURI `json:"actors"`
	ConsentProof struct {
		// Embedded struct due to allOf(#/components/schemas/EmbeddedData)
		EmbeddedData
	} `json:"consentProof,omitempty"`
	Custodian CustodianURI   `json:"custodian"`
	Performer *IdentifierURI `json:"performer,omitempty"`
	Period    *Period        `json:"period,omitempty"`
	Subject   SubjectURI     `json:"subject"`
}

// CustodianURI defines component schema for CustodianURI.
type CustodianURI string

// EmbeddedData defines component schema for EmbeddedData.
type EmbeddedData struct {
	ContentType string `json:"contentType"`
	Data        string `json:"data"`
}

// IdentifierURI defines component schema for IdentifierURI.
type IdentifierURI string

// JobCreatedResponse defines component schema for JobCreatedResponse.
type JobCreatedResponse struct {
	JobId      *string `json:"jobId,omitempty"`
	ResultCode *string `json:"resultCode,omitempty"`
}

// Period defines component schema for Period.
type Period struct {
	End   time.Time `json:"end"`
	Start time.Time `json:"start"`
}

// SubjectURI defines component schema for SubjectURI.
type SubjectURI string

// Client which conforms to the OpenAPI3 specification for this service. The
// server should be fully qualified with shema and server, ie,
// https://deepmap.com.
type Client struct {
	Server string
	Client http.Client
}

// NutsConsentLogicCreateConsent request with JSON body
func (c *Client) NutsConsentLogicCreateConsent(ctx context.Context, body CreateConsentRequest) (*http.Response, error) {
	req, err := NewNutsConsentLogicCreateConsentRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	return c.Client.Do(req)
}

// NutsConsentLogicValidateConsent request with JSON body
func (c *Client) NutsConsentLogicValidateConsent(ctx context.Context, body ConsentValidationRequest) (*http.Response, error) {
	req, err := NewNutsConsentLogicValidateConsentRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	return c.Client.Do(req)
}

// NewNutsConsentLogicCreateConsentRequest generates requests for NutsConsentLogicCreateConsent with JSON body
func NewNutsConsentLogicCreateConsentRequest(server string, body CreateConsentRequest) (*http.Request, error) {
	var bodyReader io.Reader

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)

	return NewNutsConsentLogicCreateConsentRequestWithBody(server, "application/json", bodyReader)
}

// NewNutsConsentLogicCreateConsentRequestWithBody generates requests for NutsConsentLogicCreateConsent with non-JSON body
func NewNutsConsentLogicCreateConsentRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	queryURL := fmt.Sprintf("%s/api/consent", server)

	req, err := http.NewRequest("POST", queryURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)
	return req, nil
}

// NewNutsConsentLogicValidateConsentRequest generates requests for NutsConsentLogicValidateConsent with JSON body
func NewNutsConsentLogicValidateConsentRequest(server string, body ConsentValidationRequest) (*http.Request, error) {
	var bodyReader io.Reader

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)

	return NewNutsConsentLogicValidateConsentRequestWithBody(server, "application/json", bodyReader)
}

// NewNutsConsentLogicValidateConsentRequestWithBody generates requests for NutsConsentLogicValidateConsent with non-JSON body
func NewNutsConsentLogicValidateConsentRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	queryURL := fmt.Sprintf("%s/api/consent/validation", server)

	req, err := http.NewRequest("POST", queryURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)
	return req, nil
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Create a new consent. (POST /api/consent)
	NutsConsentLogicCreateConsent(ctx echo.Context) error
	// Create the validity of a consent-request job (POST /api/consent/validation)
	NutsConsentLogicValidateConsent(ctx echo.Context) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// NutsConsentLogicCreateConsent converts echo context to params.
func (w *ServerInterfaceWrapper) NutsConsentLogicCreateConsent(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.NutsConsentLogicCreateConsent(ctx)
	return err
}

// NutsConsentLogicValidateConsent converts echo context to params.
func (w *ServerInterfaceWrapper) NutsConsentLogicValidateConsent(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.NutsConsentLogicValidateConsent(ctx)
	return err
}

// RegisterHandlers adds each server route to the EchoRouter.
func RegisterHandlers(router runtime.EchoRouter, si ServerInterface) {

	wrapper := ServerInterfaceWrapper{
		Handler: si,
	}

	router.POST("/api/consent", wrapper.NutsConsentLogicCreateConsent)
	router.POST("/api/consent/validation", wrapper.NutsConsentLogicValidateConsent)

}

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file.
func GetSwagger() (*openapi3.Swagger, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %s", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}

	swagger, err := openapi3.NewSwaggerLoader().LoadSwaggerFromData(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error loading Swagger: %s", err)
	}
	return swagger, nil
}

