// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/ory/kratos/x"

	"github.com/ory/x/httpx"
	"github.com/ory/x/pagination/keysetpagination"
	"github.com/ory/x/pointerx"

	"github.com/pkg/errors"

	"github.com/gofrs/uuid"

	"github.com/ory/herodot"
	"github.com/ory/kratos/identity"
	"github.com/ory/x/randx"
)

var (
	ErrIdentityDisabled   = herodot.ErrUnauthorized.WithError("identity is disabled").WithReason("This account was disabled.")
	ErrSuspiciousLocation = herodot.ErrForbidden.WithError("invalid location").WithReason("Suspicious session location.")
)

type lifespanProvider interface {
	SessionLifespan(ctx context.Context) time.Duration
}

type refreshWindowProvider interface {
	SessionRefreshMinTimeLeft(ctx context.Context) time.Duration
}

// Location details of a Device
type LocationDetails struct {
	// Country of the IP Address.
	Country *string `json:"country" faker:"-" db:"country"`

	// City of the IP Address.
	City *string `json:"city" faker:"-" db:"city"`

	// Location longitude
	Longitude *string `json:"long" faker:"-" db:"long"`

	// Location latitude
	Latitude *string `json:"lat" faker:"-" db:"lat"`
}

func (m LocationDetails) DistanceTo(other *LocationDetails) (float64, error) {
	if other == nil || m.Latitude == nil || m.Longitude == nil || other.Latitude == nil || other.Longitude == nil {
		return 0, errors.New("invalid location details")
	}

	mLat, err := strconv.ParseFloat(*m.Latitude, 64)
	if err != nil {
		return 0, err
	}
	mLong, err := strconv.ParseFloat(*m.Longitude, 64)
	if err != nil {
		return 0, err
	}

	oLat, err := strconv.ParseFloat(*other.Latitude, 64)
	if err != nil {
		return 0, err
	}
	oLong, err := strconv.ParseFloat(*other.Longitude, 64)
	if err != nil {
		return 0, err
	}

	return x.HaversineDistance(mLat, mLong, oLat, oLong), nil
}

// Device corresponding to a Session
//
// swagger:model sessionDevice
type Device struct {
	// Device record ID
	//
	// required: true
	ID uuid.UUID `json:"id" faker:"-" db:"id"`

	// SessionID is a helper struct field for gobuffalo.pop.
	SessionID uuid.UUID `json:"-" faker:"-" db:"session_id"`

	// IPAddress of the client
	IPAddress *string `json:"ip_address" faker:"ptr_ipv4" db:"ip_address"`

	// UserAgent of the client
	UserAgent *string `json:"user_agent" faker:"-" db:"user_agent"`

	// Geo Location corresponding to the IP Address
	Location *string `json:"location" faker:"ptr_geo_location" db:"location"`

	// Geo Location corresponding to the IP Address
	LocationDetails *string `json:"location_details" faker:"ptr_geo_location_details" db:"location_details"`

	// Time of capture
	CreatedAt time.Time `json:"-" faker:"-" db:"created_at"`

	// Last updated at
	UpdatedAt time.Time `json:"-" faker:"-" db:"updated_at"`

	NID uuid.UUID `json:"-"  faker:"-" db:"nid"`
}

func (m Device) TableName(ctx context.Context) string {
	return "session_devices"
}

func (m *Device) GetLocationDetails() *LocationDetails {
	result := &LocationDetails{}
	v := reflect.ValueOf(result).Elem()

	pairs := strings.Split(*m.LocationDetails, ",")
	for _, pair := range pairs {
		kv := strings.Split(strings.TrimSpace(pair), "=")
		if len(kv) != 2 {
			continue
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		capitalizedKey := strings.ToUpper(key[:1]) + key[1:]
		field := v.FieldByName(capitalizedKey)

		if field.IsValid() {
			if field.Kind() == reflect.String {
				field.SetString(value)
			} else if field.Kind() == reflect.Ptr && field.Type().Elem().Kind() == reflect.String {
				field.Set(reflect.ValueOf(&value))
			}
		}
	}

	return result
}

func (m *Device) SetLocationDetails(ld *LocationDetails) {
	v := reflect.ValueOf(ld).Elem()
	typeOfT := v.Type()

	var pairs []string
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldName := typeOfT.Field(i).Name
		lowercaseKey := strings.ToLower(fieldName[:1]) + fieldName[1:]

		if field.Kind() == reflect.String {
			value := field.String()
			pairs = append(pairs, fmt.Sprintf("%s=%s", lowercaseKey, value))
		} else if field.Kind() == reflect.Ptr && field.Type().Elem().Kind() == reflect.String {
			if !field.IsNil() {
				value := field.Elem().String()
				pairs = append(pairs, fmt.Sprintf("%s=%s", lowercaseKey, value))
			}
		}
	}

	result := strings.Join(pairs, ",")

	m.LocationDetails = &result
}

// A Session
//
// swagger:model session
type Session struct {
	// Session ID
	//
	// required: true
	ID uuid.UUID `json:"id" faker:"-" db:"id"`

	// Active state. If false the session is no longer active.
	Active bool `json:"active" db:"active"`

	// The Session Expiry
	//
	// When this session expires at.
	ExpiresAt time.Time `json:"expires_at" db:"expires_at" faker:"time_type"`

	// The Session Authentication Timestamp
	//
	// When this session was authenticated at. If multi-factor authentication was used this
	// is the time when the last factor was authenticated (e.g. the TOTP code challenge was completed).
	AuthenticatedAt time.Time `json:"authenticated_at" db:"authenticated_at" faker:"time_type"`

	// AuthenticationMethod Assurance Level (AAL)
	//
	// The authenticator assurance level can be one of "aal1", "aal2", or "aal3". A higher number means that it is harder
	// for an attacker to compromise the account.
	//
	// Generally, "aal1" implies that one authentication factor was used while AAL2 implies that two factors (e.g.
	// password + TOTP) have been used.
	//
	// To learn more about these levels please head over to: https://www.ory.sh/kratos/docs/concepts/credentials
	AuthenticatorAssuranceLevel identity.AuthenticatorAssuranceLevel `faker:"len=4" db:"aal" json:"authenticator_assurance_level"`

	// Authentication Method References (AMR)
	//
	// A list of authentication methods (e.g. password, oidc, ...) used to issue this session.
	AMR AuthenticationMethods `db:"authentication_methods" json:"authentication_methods"`

	// The Session Issuance Timestamp
	//
	// When this session was issued at. Usually equal or close to `authenticated_at`.
	IssuedAt time.Time `json:"issued_at" db:"issued_at" faker:"time_type"`

	// The Logout Token
	//
	// Use this token to log out a user.
	LogoutToken string `json:"-" db:"logout_token"`

	// The Session Identity
	//
	// The identity that authenticated this session.
	//
	// If 2FA is required for the user, and the authentication process only solved the first factor, this field will be
	// null until the session has been fully authenticated with the second factor.
	Identity *identity.Identity `json:"identity" faker:"identity" db:"-" belongs_to:"identities" fk_id:"IdentityID"`

	// Devices has history of all endpoints where the session was used
	Devices []Device `json:"devices" faker:"-" has_many:"session_devices" fk_id:"session_id"`

	// IdentityID is a helper struct field for gobuffalo.pop.
	IdentityID uuid.UUID `json:"-" faker:"-" db:"identity_id"`

	// CreatedAt is a helper struct field for gobuffalo.pop.
	CreatedAt time.Time `json:"-" faker:"-" db:"created_at"`

	// UpdatedAt is a helper struct field for gobuffalo.pop.
	UpdatedAt time.Time `json:"-" faker:"-" db:"updated_at"`

	// Tokenized is the tokenized (e.g. JWT) version of the session.
	//
	// It is only set when the `tokenize` query parameter was set to a valid tokenize template during calls to `/session/whoami`.
	Tokenized string `json:"tokenized,omitempty" faker:"-" db:"-"`

	// The Session Token
	//
	// The token of this session.
	Token string    `json:"-" db:"token"`
	NID   uuid.UUID `json:"-"  faker:"-" db:"nid"`
}

func (s Session) PageToken() keysetpagination.PageToken {
	return keysetpagination.MapPageToken{
		"id":         s.ID.String(),
		"created_at": s.CreatedAt.Format(x.MapPaginationDateFormat),
	}
}

func (m Session) DefaultPageToken() keysetpagination.PageToken {
	return keysetpagination.MapPageToken{
		"id":         uuid.Nil.String(),
		"created_at": time.Date(2200, 12, 31, 23, 59, 59, 0, time.UTC).Format(x.MapPaginationDateFormat),
	}
}

func (s Session) TableName(ctx context.Context) string {
	return "sessions"
}

func (s *Session) CompletedLoginForMethod(method AuthenticationMethod) {
	method.CompletedAt = time.Now().UTC()
	s.AMR = append(s.AMR, method)
}

func (s *Session) CompletedLoginFor(method identity.CredentialsType, aal identity.AuthenticatorAssuranceLevel) {
	s.CompletedLoginForMethod(AuthenticationMethod{Method: method, AAL: aal})
}

func (s *Session) CompletedLoginForWithProvider(method identity.CredentialsType, aal identity.AuthenticatorAssuranceLevel, providerID string, organizationID string) {
	s.CompletedLoginForMethod(AuthenticationMethod{
		Method:       method,
		AAL:          aal,
		Provider:     providerID,
		Organization: organizationID,
	})
}

func (s *Session) AuthenticatedVia(method identity.CredentialsType) bool {
	for _, authMethod := range s.AMR {
		if authMethod.Method == method {
			return true
		}
	}
	return false
}

func (s *Session) SetAuthenticatorAssuranceLevel() {
	if len(s.AMR) == 0 {
		// No AMR is set
		s.AuthenticatorAssuranceLevel = identity.NoAuthenticatorAssuranceLevel
	}

	var isAAL1, isAAL2 bool
	for _, amr := range s.AMR {
		switch amr.AAL {
		case identity.AuthenticatorAssuranceLevel1:
			isAAL1 = true
		case identity.AuthenticatorAssuranceLevel2:
			isAAL2 = true
		// The following section is a graceful migration from Ory Kratos v0.9.
		//
		// TODO remove this section, it is already over 2 years old.
		case "":
			// Sessions before Ory Kratos 0.9 did not have the AAL
			// be part of the AMR.
			switch amr.Method {
			case identity.CredentialsTypeRecoveryLink:
			case identity.CredentialsTypeRecoveryCode:
				isAAL1 = true
			case identity.CredentialsTypeOIDC:
				isAAL1 = true
			case "v0.6_legacy_session":
				isAAL1 = true
			case identity.CredentialsTypePassword:
				isAAL1 = true
			case identity.CredentialsTypeWebAuthn:
				isAAL2 = true
			case identity.CredentialsTypeTOTP:
				isAAL2 = true
			case identity.CredentialsTypeLookup:
				isAAL2 = true
			}
		}
	}

	if isAAL1 && isAAL2 {
		s.AuthenticatorAssuranceLevel = identity.AuthenticatorAssuranceLevel2
	} else if isAAL1 {
		s.AuthenticatorAssuranceLevel = identity.AuthenticatorAssuranceLevel1
	} else if len(s.AMR) > 0 {
		// A fallback. If an AMR is set, but we did not satisfy the above, gracefully fall back to level 1.
		s.AuthenticatorAssuranceLevel = identity.AuthenticatorAssuranceLevel1
	}
}

func NewInactiveSession() *Session {
	return &Session{
		ID:                          uuid.Nil,
		Token:                       x.OrySessionToken + randx.MustString(32, randx.AlphaNum),
		LogoutToken:                 x.OryLogoutToken + randx.MustString(32, randx.AlphaNum),
		Active:                      false,
		AuthenticatorAssuranceLevel: identity.NoAuthenticatorAssuranceLevel,
	}
}

func (s *Session) SetSessionDeviceInformation(r *http.Request) {
	device := Device{
		SessionID: s.ID,
		IPAddress: pointerx.Ptr(httpx.ClientIP(r)),
	}

	agent := r.Header["User-Agent"]
	if len(agent) > 0 {
		device.UserAgent = pointerx.Ptr(strings.Join(agent, " "))
	}

	var clientGeoLocation []string
	var clientGeoLocationDetails LocationDetails
	if r.Header.Get("Cf-Ipcity") != "" {
		clientGeoLocation = append(clientGeoLocation, r.Header.Get("Cf-Ipcity"))
		clientGeoLocationDetails.City = pointerx.Ptr(r.Header.Get("Cf-Ipcity"))
	}
	if r.Header.Get("Cf-Ipcountry") != "" {
		clientGeoLocation = append(clientGeoLocation, r.Header.Get("Cf-Ipcountry"))
		clientGeoLocationDetails.Country = pointerx.Ptr(r.Header.Get("Cf-Ipcountry"))
	}
	if r.Header.Get("Cf-Iplongitude") != "" {
		clientGeoLocationDetails.Longitude = pointerx.Ptr(r.Header.Get("Cf-Iplongitude"))
	}
	if r.Header.Get("Cf-Iplatitude") != "" {
		clientGeoLocationDetails.Latitude = pointerx.Ptr(r.Header.Get("Cf-Iplatitude"))
	}
	device.Location = pointerx.Ptr(strings.Join(clientGeoLocation, ", "))

	device.SetLocationDetails(&clientGeoLocationDetails)

	s.Devices = append(s.Devices, device)
}

func (s Session) Declassified() *Session {
	s.Identity = s.Identity.CopyWithoutCredentials()
	return &s
}

func (s *Session) IsActive() bool {
	return s.Active && s.ExpiresAt.After(time.Now()) && (s.Identity == nil || s.Identity.IsActive())
}

func (s *Session) Refresh(ctx context.Context, c lifespanProvider) *Session {
	s.ExpiresAt = time.Now().Add(c.SessionLifespan(ctx)).UTC()
	return s
}

func (s *Session) MarshalJSON() ([]byte, error) {
	type ss Session
	out := ss(*s)
	out.Active = s.IsActive()
	return json.Marshal(out)
}

func (s *Session) CanBeRefreshed(ctx context.Context, c refreshWindowProvider) bool {
	return s.ExpiresAt.Add(-c.SessionRefreshMinTimeLeft(ctx)).Before(time.Now())
}

// List of (Used) AuthenticationMethods
//
// A list of authenticators which were used to authenticate the session.
//
// swagger:model sessionAuthenticationMethods
type AuthenticationMethods []AuthenticationMethod

// AuthenticationMethod identifies an authentication method
//
// A singular authenticator used during authentication / login.
//
// swagger:model sessionAuthenticationMethod
type AuthenticationMethod struct {
	// The method used in this authenticator.
	Method identity.CredentialsType `json:"method"`

	// The AAL this method introduced.
	AAL identity.AuthenticatorAssuranceLevel `json:"aal"`

	// When the authentication challenge was completed.
	CompletedAt time.Time `json:"completed_at"`

	// OIDC or SAML provider id used for authentication
	Provider string `json:"provider,omitempty"`

	// The Organization id used for authentication
	Organization string `json:"organization,omitempty"`
}

// Scan implements the Scanner interface.
func (n *AuthenticationMethod) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	v := fmt.Sprintf("%s", value)
	if len(v) == 0 {
		return nil
	}
	return errors.WithStack(json.Unmarshal([]byte(v), n))
}

// Value implements the driver Valuer interface.
func (n AuthenticationMethod) Value() (driver.Value, error) {
	value, err := json.Marshal(n)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return string(value), nil
}

// Scan implements the Scanner interface.
func (n *AuthenticationMethods) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	v := fmt.Sprintf("%s", value)
	if len(v) == 0 {
		return nil
	}
	return errors.WithStack(json.Unmarshal([]byte(v), n))
}

// Value implements the driver Valuer interface.
func (n AuthenticationMethods) Value() (driver.Value, error) {
	value, err := json.Marshal(n)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return string(value), nil
}
