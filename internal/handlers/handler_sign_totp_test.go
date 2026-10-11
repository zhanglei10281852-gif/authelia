// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/valyala/fasthttp"
	"go.uber.org/mock/gomock"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/regulation"
	"github.com/authelia/authelia/v4/internal/session/memory"
	"github.com/authelia/authelia/v4/internal/storage"
)

type HandlerSignTOTPSuite struct {
	suite.Suite

	mock *mocks.MockAutheliaCtx
}

func (s *HandlerSignTOTPSuite) SetupTest() {
	s.mock = mocks.NewMockAutheliaCtx(s.T())
	userSession, err := s.mock.Ctx.GetSession()
	s.Assert().NoError(err)

	userSession.Username = testUsername
	userSession.AuthenticationMethodRefs.UsernameAndPassword = true
	s.Assert().NoError(s.mock.Ctx.SaveSession(userSession))

	s.mock.Clock.Set(time.Unix(1701295903, 0))
	s.mock.Ctx.Providers.Clock = &s.mock.Clock
	s.mock.Ctx.Configuration.TOTP = schema.DefaultTOTPConfiguration
}

func (s *HandlerSignTOTPSuite) TearDownTest() {
	s.mock.Close()
}

func (s *HandlerSignTOTPSuite) AssertLastLogMessage(message string, err string) {
	AssertLogEntryMessageAndError(s.T(), s.mock.Hook.LastEntry(), message, err)
}

func (s *HandlerSignTOTPSuite) TestShouldRedirectUserToDefaultURL() {
	config := model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}

	gomock.InOrder(
		s.mock.StorageMock.
			EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, gomock.Any()).
			Return(&config, nil),
		s.mock.TOTPMock.
			EXPECT().
			Validate(s.mock.Ctx, gomock.Eq("123456"), gomock.Eq(&config)).
			Return(true, getStepTOTP(s.mock.Ctx, -1), nil),
		s.mock.StorageMock.
			EXPECT().
			ConsumeTOTPHistory(s.mock.Ctx, testUsername, uint64(1701295890)).
			Return(true, nil),
		s.mock.StorageMock.
			EXPECT().
			UpdateTOTPConfigurationSignIn(s.mock.Ctx, gomock.Any(), gomock.Any()).
			Return(nil),
		s.mock.StorageMock.
			EXPECT().
			AppendAuthenticationLog(s.mock.Ctx, gomock.Eq(model.AuthenticationAttempt{
				Username:   testUsername,
				Successful: true,
				Banned:     false,
				Time:       s.mock.Clock.Now(),
				Type:       regulation.AuthTypeTOTP,
				RemoteIP:   model.NewNullIPFromString("0.0.0.0"),
			})).
			Return(nil),
	)

	s.mock.Ctx.Configuration.Session.Cookies[0].DefaultRedirectionURL = testRedirectionURL

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{
		Token: "123456",
	})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert200OK(s.T(), redirectResponse{
		Redirect: testRedirectionURLString,
	})
}

func (s *HandlerSignTOTPSuite) TestShouldNotFailWhenTOTPSignInInfoFailsToUpdate() {
	config := model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}

	gomock.InOrder(
		s.mock.StorageMock.
			EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, gomock.Any()).
			Return(&config, nil),
		s.mock.TOTPMock.
			EXPECT().
			Validate(s.mock.Ctx, gomock.Eq("123456"), gomock.Eq(&config)).
			Return(true, getStepTOTP(s.mock.Ctx, -1), nil),
		s.mock.StorageMock.
			EXPECT().
			ConsumeTOTPHistory(s.mock.Ctx, testUsername, uint64(1701295890)).
			Return(true, nil),
		s.mock.StorageMock.
			EXPECT().
			UpdateTOTPConfigurationSignIn(s.mock.Ctx, gomock.Any(), gomock.Any()).
			Return(errors.New("failed to perform update")),
		s.mock.StorageMock.
			EXPECT().
			AppendAuthenticationLog(s.mock.Ctx, gomock.Eq(model.AuthenticationAttempt{
				Username:   testUsername,
				Successful: true,
				Banned:     false,
				Time:       s.mock.Clock.Now(),
				Type:       regulation.AuthTypeTOTP,
				RemoteIP:   model.NewNullIPFromString("0.0.0.0"),
			})).
			Return(nil),
	)

	s.mock.Ctx.Configuration.Session.Cookies[0].DefaultRedirectionURL = testRedirectionURL

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{
		Token: "123456",
	})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)

	// The two-factor session already exists when the credential last-used update fails, so the authentication
	// remains successful: the code is kept consumed and the failure is only logged.
	s.mock.Assert200OK(s.T(), redirectResponse{
		Redirect: testRedirectionURLString,
	})

	s.AssertLastLogMessage("Failed to update the TOTP credential sign-in information for user 'john'", "failed to perform update")
}

func (s *HandlerSignTOTPSuite) TestShouldNotReturnRedirectURL() {
	config := model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}

	gomock.InOrder(
		s.mock.StorageMock.
			EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, gomock.Any()).
			Return(&config, nil),
		s.mock.TOTPMock.
			EXPECT().
			Validate(s.mock.Ctx, gomock.Eq("123456"), gomock.Eq(&config)).
			Return(true, getStepTOTP(s.mock.Ctx, -1), nil),
		s.mock.StorageMock.
			EXPECT().
			ConsumeTOTPHistory(s.mock.Ctx, testUsername, uint64(1701295890)).
			Return(true, nil),
		s.mock.StorageMock.
			EXPECT().
			UpdateTOTPConfigurationSignIn(s.mock.Ctx, gomock.Any(), gomock.Any()).
			Return(nil),
		s.mock.StorageMock.
			EXPECT().
			AppendAuthenticationLog(s.mock.Ctx, gomock.Eq(model.AuthenticationAttempt{
				Username:   testUsername,
				Successful: true,
				Banned:     false,
				Time:       s.mock.Clock.Now(),
				Type:       regulation.AuthTypeTOTP,
				RemoteIP:   model.NewNullIPFromString("0.0.0.0"),
			})).
			Return(nil),
	)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{
		Token: "123456",
	})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert200OK(s.T(), &redirectResponse{Redirect: "https://www.example.com"})
}

func (s *HandlerSignTOTPSuite) TestShouldRedirectUserToSafeTargetURL() {
	config := model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}
	s.mock.Ctx.Configuration.Session.Cookies = []schema.SessionCookie{
		{
			Domain: "example.com",
		},
		{
			Domain: "mydomain.local",
		},
	}

	gomock.InOrder(
		s.mock.StorageMock.
			EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, gomock.Any()).
			Return(&config, nil),
		s.mock.TOTPMock.
			EXPECT().
			Validate(s.mock.Ctx, gomock.Eq("123456"), gomock.Eq(&config)).
			Return(true, getStepTOTP(s.mock.Ctx, -1), nil),
		s.mock.StorageMock.
			EXPECT().
			ConsumeTOTPHistory(s.mock.Ctx, testUsername, uint64(1701295890)).
			Return(true, nil),
		s.mock.StorageMock.
			EXPECT().
			UpdateTOTPConfigurationSignIn(s.mock.Ctx, gomock.Any(), gomock.Any()).
			Return(nil),
		s.mock.StorageMock.
			EXPECT().
			AppendAuthenticationLog(s.mock.Ctx, gomock.Eq(model.AuthenticationAttempt{
				Username:   testUsername,
				Successful: true,
				Banned:     false,
				Time:       s.mock.Clock.Now(),
				Type:       regulation.AuthTypeTOTP,
				RemoteIP:   model.NewNullIPFromString("0.0.0.0"),
			})).
			Return(nil),
	)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{
		Token:     "123456",
		TargetURL: "https://mydomain.example.com",
	})

	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert200OK(s.T(), redirectResponse{
		Redirect: "https://mydomain.example.com",
	})
}

func (s *HandlerSignTOTPSuite) TestShouldRedirectUserToSafeTargetURLDisableReusePolicy() {
	config := model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}
	s.mock.Ctx.Configuration.Session.Cookies = []schema.SessionCookie{
		{
			Domain: "example.com",
		},
		{
			Domain: "mydomain.local",
		},
	}

	s.mock.Ctx.Configuration.TOTP.DisableReuseSecurityPolicy = true

	gomock.InOrder(
		s.mock.StorageMock.
			EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, gomock.Any()).
			Return(&config, nil),
		s.mock.TOTPMock.
			EXPECT().
			Validate(s.mock.Ctx, gomock.Eq("123456"), gomock.Eq(&config)).
			Return(true, getStepTOTP(s.mock.Ctx, -1), nil),
		s.mock.StorageMock.
			EXPECT().
			ConsumeTOTPHistory(s.mock.Ctx, testUsername, uint64(1701295890)).
			Return(true, nil),
		s.mock.StorageMock.
			EXPECT().
			UpdateTOTPConfigurationSignIn(s.mock.Ctx, gomock.Any(), gomock.Any()).
			Return(nil),
		s.mock.StorageMock.
			EXPECT().
			AppendAuthenticationLog(s.mock.Ctx, gomock.Eq(model.AuthenticationAttempt{
				Username:   testUsername,
				Successful: true,
				Banned:     false,
				Time:       s.mock.Clock.Now(),
				Type:       regulation.AuthTypeTOTP,
				RemoteIP:   model.NewNullIPFromString("0.0.0.0"),
			})).
			Return(nil),
	)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{
		Token:     "123456",
		TargetURL: "https://mydomain.example.com",
	})

	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert200OK(s.T(), redirectResponse{
		Redirect: "https://mydomain.example.com",
	})
}

func (s *HandlerSignTOTPSuite) TestShouldNotRedirectToUnsafeURL() {
	gomock.InOrder(
		s.mock.StorageMock.
			EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, testUsername).
			Return(&model.TOTPConfiguration{Secret: []byte("secret"), Digits: 6, Period: 30}, nil),
		s.mock.TOTPMock.EXPECT().
			Validate(s.mock.Ctx, gomock.Eq("123456"), gomock.Eq(&model.TOTPConfiguration{Secret: []byte("secret"), Digits: 6, Period: 30})).
			Return(true, getStepTOTP(s.mock.Ctx, -1), nil),
		s.mock.StorageMock.
			EXPECT().
			ConsumeTOTPHistory(s.mock.Ctx, testUsername, uint64(1701295890)).
			Return(true, nil),
		s.mock.StorageMock.
			EXPECT().
			UpdateTOTPConfigurationSignIn(s.mock.Ctx, gomock.Any(), gomock.Any()).
			Return(nil),
		s.mock.StorageMock.
			EXPECT().
			AppendAuthenticationLog(s.mock.Ctx, gomock.Eq(model.AuthenticationAttempt{
				Username:   testUsername,
				Successful: true,
				Banned:     false,
				Time:       s.mock.Clock.Now(),
				Type:       regulation.AuthTypeTOTP,
				RemoteIP:   model.NewNullIPFromString("0.0.0.0"),
			})).
			Return(nil),
	)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{
		Token:     "123456",
		TargetURL: "http://mydomain.example.com",
	})

	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert200OK(s.T(), nil)
}

func (s *HandlerSignTOTPSuite) TestShouldRegenerateSessionForPreventingSessionFixation() {
	config := model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}

	gomock.InOrder(
		s.mock.StorageMock.
			EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, gomock.Any()).
			Return(&config, nil),
		s.mock.TOTPMock.
			EXPECT().
			Validate(s.mock.Ctx, gomock.Eq("123456"), gomock.Eq(&config)).
			Return(true, getStepTOTP(s.mock.Ctx, -1), nil),
		s.mock.StorageMock.
			EXPECT().
			ConsumeTOTPHistory(s.mock.Ctx, testUsername, uint64(1701295890)).
			Return(true, nil),
		s.mock.StorageMock.
			EXPECT().
			UpdateTOTPConfigurationSignIn(s.mock.Ctx, gomock.Any(), gomock.Any()).
			Return(nil),
		s.mock.StorageMock.
			EXPECT().
			AppendAuthenticationLog(s.mock.Ctx, gomock.Eq(model.AuthenticationAttempt{
				Username:   testUsername,
				Successful: true,
				Banned:     false,
				Time:       s.mock.Clock.Now(),
				Type:       regulation.AuthTypeTOTP,
				RemoteIP:   model.NewNullIPFromString("0.0.0.0"),
			})).
			Return(nil),
	)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{
		Token: "123456",
	})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	r := regexp.MustCompile("^authelia_session=(.*); path=")
	res := r.FindAllStringSubmatch(string(s.mock.Ctx.Response.Header.PeekCookie("authelia_session")), -1)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert200OK(s.T(), &redirectResponse{Redirect: "https://www.example.com"})

	s.NotEqual(
		res[0][1],
		string(s.mock.Ctx.Request.Header.Cookie("authelia_session")))
}

func (s *HandlerSignTOTPSuite) TestShouldHandleErrorConsumeHistory() {
	config := model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}

	gomock.InOrder(
		s.mock.StorageMock.
			EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, gomock.Any()).
			Return(&config, nil),
		s.mock.TOTPMock.
			EXPECT().
			Validate(s.mock.Ctx, gomock.Eq("123456"), gomock.Eq(&config)).
			Return(true, getStepTOTP(s.mock.Ctx, -1), nil),
		s.mock.StorageMock.
			EXPECT().
			ConsumeTOTPHistory(s.mock.Ctx, testUsername, uint64(1701295890)).
			Return(false, fmt.Errorf("bad stuff")),
	)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{
		Token: "123456",
	})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert403KO(s.T(), "Authentication failed, please retry later.")

	s.AssertLastLogMessage("Error occurred validating a TOTP authentication for user 'john': error occurred saving the TOTP history to the storage backend", "bad stuff")
}

// TestShouldStablyIdentifyReplayedCode models the losing request when two tabs submit the same code at the same
// time: ConsumeTOTPHistory reports the step was already claimed and the request is rejected as a replay rather
// than surfacing a storage error.
func (s *HandlerSignTOTPSuite) TestShouldStablyIdentifyReplayedCode() {
	config := model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}

	gomock.InOrder(
		s.mock.StorageMock.
			EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, gomock.Any()).
			Return(&config, nil),
		s.mock.TOTPMock.
			EXPECT().
			Validate(s.mock.Ctx, gomock.Eq("123456"), gomock.Eq(&config)).
			Return(true, getStepTOTP(s.mock.Ctx, -1), nil),
		s.mock.StorageMock.
			EXPECT().
			ConsumeTOTPHistory(s.mock.Ctx, testUsername, uint64(1701295890)).
			Return(false, nil),
	)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{
		Token: "123456",
	})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert403KO(s.T(), "Authentication failed, please retry later.")

	s.AssertLastLogMessage("Error occurred validating a TOTP authentication for user 'john': error occurred satisfying security policies", "the user has already used this code recently and will not be permitted to reuse it")
}

func (s *HandlerSignTOTPSuite) TestShouldHandleAnonymous() {
	us, err := s.mock.Ctx.GetSession()

	s.Require().NoError(err)

	us.Username = ""

	s.Require().NoError(s.mock.Ctx.SaveSession(us))

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{
		Token: "abc",
	})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert403KO(s.T(), "Authentication failed, please retry later.")

	s.AssertLastLogMessage("Error occurred validating a TOTP authentication", "user is anonymous")
}

func (s *HandlerSignTOTPSuite) TestShouldHandleGETAnonymous() {
	us, err := s.mock.Ctx.GetSession()

	s.Require().NoError(err)

	us.Username = ""

	s.Require().NoError(s.mock.Ctx.SaveSession(us))

	TimeBasedOneTimePasswordGET(s.mock.Ctx)
	s.mock.Assert403KO(s.T(), "Authentication failed, please retry later.")

	s.AssertLastLogMessage("Error occurred retrieving TOTP configuration", "user is anonymous")
}

func (s *HandlerSignTOTPSuite) TestShouldHandleGETErrorLoadConfiguration() {
	gomock.InOrder(
		s.mock.StorageMock.
			EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, testUsername).
			Return(nil, fmt.Errorf("nah")),
	)

	TimeBasedOneTimePasswordGET(s.mock.Ctx)
	s.mock.Assert500KO(s.T(), "Could not find TOTP Configuration for user.")

	s.AssertLastLogMessage("Error occurred retrieving TOTP configuration for user 'john': error occurred retrieving the configuration from the storage backend", "nah")
}

func (s *HandlerSignTOTPSuite) TestShouldHandleGETErrorLoadConfigurationNotFound() {
	level := s.mock.Ctx.Logger.Level
	s.mock.SetLogLevel(logrus.DebugLevel)

	gomock.InOrder(
		s.mock.StorageMock.
			EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, testUsername).
			Return(nil, storage.ErrNoTOTPConfiguration),
	)

	TimeBasedOneTimePasswordGET(s.mock.Ctx)
	s.mock.Assert404KO(s.T(), "Could not find TOTP Configuration for user.")

	s.AssertLastLogMessage("Error occurred retrieving TOTP configuration for user 'john'", "no TOTP configuration for user")
	s.mock.SetLogLevel(level)
}

func (s *HandlerSignTOTPSuite) TestShouldReturnErrorOnInvalidValue() {
	config := model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}

	gomock.InOrder(
		s.mock.StorageMock.EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, gomock.Any()).
			Return(&config, nil),
		s.mock.TOTPMock.EXPECT().
			Validate(s.mock.Ctx, gomock.Eq("123456"), gomock.Eq(&config)).
			Return(false, uint64(0), fmt.Errorf("invalid")),
	)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{
		Token: "123456",
	})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	r := regexp.MustCompile("^authelia_session=(.*); path=")
	res := r.FindAllStringSubmatch(string(s.mock.Ctx.Response.Header.PeekCookie("authelia_session")), -1)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert403KO(s.T(), "Authentication failed, please retry later.")

	s.NotEqual(
		res[0][1],
		string(s.mock.Ctx.Request.Header.Cookie("authelia_session")))

	AssertLogEntryMessageAndError(s.T(), s.mock.Hook.LastEntry(), "Error occurred validating a TOTP authentication for user 'john': error occurred validating the user input", "invalid")
}

func (s *HandlerSignTOTPSuite) TestShouldReturnErrorOnInvalidBoolean() {
	config := model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}

	gomock.InOrder(
		s.mock.StorageMock.
			EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, gomock.Any()).
			Return(&config, nil),
		s.mock.TOTPMock.
			EXPECT().
			Validate(s.mock.Ctx, gomock.Eq("123456"), gomock.Eq(&config)).
			Return(false, uint64(0), nil),
		s.mock.StorageMock.
			EXPECT().
			AppendAuthenticationLog(s.mock.Ctx, gomock.Eq(model.AuthenticationAttempt{
				Username:   testUsername,
				Successful: false,
				Banned:     false,
				Time:       s.mock.Clock.Now(),
				Type:       regulation.AuthTypeTOTP,
				RemoteIP:   model.NewNullIPFromString("0.0.0.0"),
			})).
			Return(nil),
	)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{
		Token: "123456",
	})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	r := regexp.MustCompile("^authelia_session=(.*); path=")
	res := r.FindAllStringSubmatch(string(s.mock.Ctx.Response.Header.PeekCookie("authelia_session")), -1)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert403KO(s.T(), "Authentication failed, please retry later.")

	s.NotEqual(
		res[0][1],
		string(s.mock.Ctx.Request.Header.Cookie("authelia_session")))

	AssertLogEntryMessageAndError(s.T(), MustGetLogLastSeq(s.T(), s.mock.Hook, 1), "Error occurred validating a TOTP authentication for user 'john': error occurred validating the user input", "the user input wasn't valid")
}

func (s *HandlerSignTOTPSuite) TestShouldReturnErrorOnInvalidBooleanMarkErr() {
	config := model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}

	gomock.InOrder(
		s.mock.StorageMock.EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, gomock.Any()).
			Return(&config, nil),
		s.mock.TOTPMock.EXPECT().
			Validate(s.mock.Ctx, gomock.Eq("123456"), gomock.Eq(&config)).
			Return(false, uint64(0), nil),
		s.mock.StorageMock.
			EXPECT().
			AppendAuthenticationLog(s.mock.Ctx, gomock.Eq(model.AuthenticationAttempt{
				Username:   testUsername,
				Successful: false,
				Banned:     false,
				Time:       s.mock.Clock.Now(),
				Type:       regulation.AuthTypeTOTP,
				RemoteIP:   model.NewNullIPFromString("0.0.0.0"),
			})).Return(fmt.Errorf("failed to insert")),
	)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{
		Token: "123456",
	})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	r := regexp.MustCompile("^authelia_session=(.*); path=")
	res := r.FindAllStringSubmatch(string(s.mock.Ctx.Response.Header.PeekCookie("authelia_session")), -1)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert403KO(s.T(), "Authentication failed, please retry later.")

	s.NotEqual(
		res[0][1],
		string(s.mock.Ctx.Request.Header.Cookie("authelia_session")))

	AssertLogEntryMessageAndError(s.T(), s.mock.Hook.LastEntry(), "Unsuccessful TOTP authentication attempt by user 'john'", "")
}

func (s *HandlerSignTOTPSuite) TestShouldReturnErrorOnInvalidJSON() {
	s.mock.Ctx.Request.SetBody([]byte(`{"token:"1234"}`))

	r := regexp.MustCompile("^authelia_session=(.*); path=")
	res := r.FindAllStringSubmatch(string(s.mock.Ctx.Response.Header.PeekCookie("authelia_session")), -1)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert403KO(s.T(), "Authentication failed, please retry later.")

	s.NotEqual(
		res[0][1],
		string(s.mock.Ctx.Request.Header.Cookie("authelia_session")))

	AssertLogEntryMessageAndError(s.T(), s.mock.Hook.LastEntry(), "Error occurred validating a TOTP authentication for user 'john': error parsing the request body", "unable to parse body: invalid character '1' after object key")
}

func (s *HandlerSignTOTPSuite) TestShouldNotReturnErrorOnInvalidBooleanMarkErrSuccess() {
	config := model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}

	gomock.InOrder(
		s.mock.StorageMock.EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, gomock.Any()).
			Return(&config, nil),
		s.mock.TOTPMock.EXPECT().
			Validate(s.mock.Ctx, gomock.Eq("123456"), gomock.Eq(&config)).
			Return(true, getStepTOTP(s.mock.Ctx, -1), nil),
		s.mock.StorageMock.
			EXPECT().
			ConsumeTOTPHistory(s.mock.Ctx, testUsername, uint64(1701295890)).
			Return(true, nil),
		s.mock.StorageMock.
			EXPECT().
			UpdateTOTPConfigurationSignIn(s.mock.Ctx, gomock.Any(), gomock.Any()).
			Return(nil),
		s.mock.StorageMock.
			EXPECT().
			AppendAuthenticationLog(s.mock.Ctx, model.AuthenticationAttempt{
				Username:   testUsername,
				Successful: true,
				Banned:     false,
				Time:       s.mock.Clock.Now(),
				Type:       regulation.AuthTypeTOTP,
				RemoteIP:   model.NewNullIPFromString("0.0.0.0"),
			}).
			Return(fmt.Errorf("failed to insert")),
	)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{
		Token: "123456",
	})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	r := regexp.MustCompile("^authelia_session=(.*); path=")
	res := r.FindAllStringSubmatch(string(s.mock.Ctx.Response.Header.PeekCookie("authelia_session")), -1)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert200OK(s.T(), redirectResponse{
		Redirect: testRedirectionURLString,
	})

	s.NotEqual(
		res[0][1],
		string(s.mock.Ctx.Request.Header.Cookie("authelia_session")))

	AssertLogEntryMessageAndError(s.T(), s.mock.Hook.LastEntry(), "Failed to record TOTP authentication attempt", "failed to insert")
}

func (s *HandlerSignTOTPSuite) TestShouldReturnErrorOnInvalidConfig() {
	gomock.InOrder(
		s.mock.StorageMock.EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, gomock.Any()).
			Return(nil, fmt.Errorf("not found")),
	)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{
		Token: "123456",
	})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	r := regexp.MustCompile("^authelia_session=(.*); path=")
	res := r.FindAllStringSubmatch(string(s.mock.Ctx.Response.Header.PeekCookie("authelia_session")), -1)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert403KO(s.T(), "Authentication failed, please retry later.")

	s.NotEqual(
		res[0][1],
		string(s.mock.Ctx.Request.Header.Cookie("authelia_session")))

	AssertLogEntryMessageAndError(s.T(), s.mock.Hook.LastEntry(), "Error occurred validating a TOTP authentication for user 'john': error occurred retrieving the configuration from the storage backend", "not found")
}

func (s *HandlerSignTOTPSuite) TestShouldReturnErrorOnInvalidTokenLength() {
	bodyBytes, err := json.Marshal(bodySignTOTPRequest{
		Token: "123",
	})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	r := regexp.MustCompile("^authelia_session=(.*); path=")
	res := r.FindAllStringSubmatch(string(s.mock.Ctx.Response.Header.PeekCookie("authelia_session")), -1)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.AssertKO(s.T(), "Authentication failed, please retry later.", fasthttp.StatusBadRequest)

	s.NotEqual(
		res[0][1],
		string(s.mock.Ctx.Request.Header.Cookie("authelia_session")))

	AssertLogEntryMessageAndError(s.T(), s.mock.Hook.LastEntry(), "Error occurred validating a TOTP authentication for user 'john': expected code length is 6 or 8 but the user provided code was 3 characters in length", "")
}

func (s *HandlerSignTOTPSuite) TestShouldHandleExistsHistoryWithDisableReusePolicy() {
	config := model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}

	s.mock.Ctx.Configuration.TOTP.DisableReuseSecurityPolicy = true

	gomock.InOrder(
		s.mock.StorageMock.
			EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, gomock.Any()).
			Return(&config, nil),
		s.mock.TOTPMock.
			EXPECT().
			Validate(s.mock.Ctx, gomock.Eq("123456"), gomock.Eq(&config)).
			Return(true, getStepTOTP(s.mock.Ctx, -1), nil),
		s.mock.StorageMock.
			EXPECT().
			ConsumeTOTPHistory(s.mock.Ctx, testUsername, uint64(1701295890)).
			Return(false, nil),
		s.mock.StorageMock.
			EXPECT().
			UpdateTOTPConfigurationSignIn(s.mock.Ctx, gomock.Any(), gomock.Any()).
			Return(nil),
		s.mock.StorageMock.
			EXPECT().
			AppendAuthenticationLog(s.mock.Ctx, gomock.Eq(model.AuthenticationAttempt{
				Username:   testUsername,
				Successful: true,
				Banned:     false,
				Time:       s.mock.Clock.Now(),
				Type:       regulation.AuthTypeTOTP,
				RemoteIP:   model.NewNullIPFromString("0.0.0.0"),
			})).
			Return(nil),
	)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{Token: "123456"})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)

	s.mock.Assert200OK(s.T(), redirectResponse{Redirect: "https://www.example.com"})

	AssertLogEntryMessageAndError(s.T(), s.mock.Hook.AllEntries()[0], "User has reused a Time-based One Time Password with the given step but the policy to disable reuse is disabled", nil)
}

func (s *HandlerSignTOTPSuite) TestShouldHandleFlow() {
	config := model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}

	gomock.InOrder(
		s.mock.StorageMock.
			EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, gomock.Any()).
			Return(&config, nil),
		s.mock.TOTPMock.
			EXPECT().
			Validate(s.mock.Ctx, gomock.Eq("123456"), gomock.Eq(&config)).
			Return(true, getStepTOTP(s.mock.Ctx, -1), nil),
		s.mock.StorageMock.
			EXPECT().
			ConsumeTOTPHistory(s.mock.Ctx, testUsername, uint64(1701295890)).
			Return(true, nil),
		s.mock.StorageMock.
			EXPECT().
			UpdateTOTPConfigurationSignIn(s.mock.Ctx, gomock.Any(), gomock.Any()).
			Return(nil),
		s.mock.StorageMock.
			EXPECT().
			AppendAuthenticationLog(s.mock.Ctx, gomock.Eq(model.AuthenticationAttempt{
				Username:   testUsername,
				Successful: true,
				Banned:     false,
				Time:       s.mock.Clock.Now(),
				Type:       regulation.AuthTypeTOTP,
				RemoteIP:   model.NewNullIPFromString("0.0.0.0"),
			})).
			Return(nil),
	)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{Token: "123456", Flow: "not-a-flow"})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)

	s.mock.Assert200KO(s.T(), messageAuthenticationFailed)

	s.AssertLastLogMessage("Failed to find flow handler for the given flow parameters", "")
}

// failingTOTPSessionBackend wraps the in-memory session backend so individual session operations can fail for
// the post-claim failure tests.
type failingTOTPSessionBackend struct {
	*memory.Provider

	saveErr       error
	regenerateErr error
}

func (p *failingTOTPSessionBackend) Save(id, data []byte, expiration time.Duration) error {
	if p.saveErr != nil {
		return p.saveErr
	}

	return p.Provider.Save(id, data, expiration)
}

func (p *failingTOTPSessionBackend) Regenerate(id, newID []byte, expiration time.Duration) error {
	if p.regenerateErr != nil {
		return p.regenerateErr
	}

	return p.Provider.Regenerate(id, newID, expiration)
}

func (s *HandlerSignTOTPSuite) setFailingSessionBackend(saveErr, regenerateErr error) {
	backend, err := memory.New(memory.Config{})
	s.Require().NoError(err)

	domainSession, err := s.mock.Ctx.Providers.SessionProvider.Get("example.com")
	s.Require().NoError(err)

	failing := &failingTOTPSessionBackend{Provider: backend}
	s.Require().NoError(domainSession.SetProvider(failing))

	// Seed the one-factor session into the new backend while all operations are still healthy, then arm the
	// failures the test is interested in.
	userSession, err := s.mock.Ctx.GetSession()
	s.Require().NoError(err)

	userSession.Username = testUsername
	userSession.AuthenticationMethodRefs.UsernameAndPassword = true
	s.Require().NoError(s.mock.Ctx.SaveSession(userSession))

	failing.saveErr = saveErr
	failing.regenerateErr = regenerateErr
}

func (s *HandlerSignTOTPSuite) totpHistoryCompensationMocks(config *model.TOTPConfiguration) {
	gomock.InOrder(
		s.mock.StorageMock.
			EXPECT().
			LoadTOTPConfiguration(s.mock.Ctx, gomock.Any()).
			Return(config, nil),
		s.mock.TOTPMock.
			EXPECT().
			Validate(s.mock.Ctx, gomock.Eq("123456"), gomock.Eq(config)).
			Return(true, getStepTOTP(s.mock.Ctx, -1), nil),
		s.mock.StorageMock.
			EXPECT().
			ConsumeTOTPHistory(s.mock.Ctx, testUsername, uint64(1701295890)).
			Return(true, nil),
		s.mock.StorageMock.
			EXPECT().
			ReleaseTOTPHistory(s.mock.Ctx, testUsername, uint64(1701295890)).
			Return(nil),
	)
}

func (s *HandlerSignTOTPSuite) TestShouldReleaseHistoryWhenSessionRegenerationFails() {
	config := &model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}

	s.setFailingSessionBackend(nil, errors.New("session regenerate failed"))

	s.totpHistoryCompensationMocks(config)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{Token: "123456"})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert403KO(s.T(), "Authentication failed, please retry later.")

	s.AssertLastLogMessage("Error occurred validating a TOTP authentication for user 'john': error regenerating the user session", "session regenerate failed")
}

func (s *HandlerSignTOTPSuite) TestShouldReleaseHistoryWhenSessionSaveFails() {
	config := &model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}

	s.setFailingSessionBackend(errors.New("session save failed"), nil)

	s.totpHistoryCompensationMocks(config)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{Token: "123456"})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert403KO(s.T(), "Authentication failed, please retry later.")

	s.AssertLastLogMessage("Error occurred validating a TOTP authentication for user 'john': error occurred saving the user session data", "session save failed")
}

// TestShouldAllowRetryingSameCodeAfterElevationFailure ensures that after a session save failure the released
// code can be presented again on a new request and complete the authentication, i.e. the failure response is
// retryable instead of permanently burning the still valid code.
func (s *HandlerSignTOTPSuite) TestShouldAllowRetryingSameCodeAfterElevationFailure() {
	first := &model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}

	s.setFailingSessionBackend(errors.New("session save failed"), nil)

	s.totpHistoryCompensationMocks(first)

	bodyBytes, err := json.Marshal(bodySignTOTPRequest{Token: "123456"})
	s.Require().NoError(err)
	s.mock.Ctx.Request.SetBody(bodyBytes)

	TimeBasedOneTimePasswordPOST(s.mock.Ctx)
	s.mock.Assert403KO(s.T(), "Authentication failed, please retry later.")

	retry := mocks.NewMockAutheliaCtx(s.T())
	defer retry.Close()

	userSession, err := retry.Ctx.GetSession()
	s.Require().NoError(err)

	userSession.Username = testUsername
	userSession.AuthenticationMethodRefs.UsernameAndPassword = true
	s.Require().NoError(retry.Ctx.SaveSession(userSession))

	retry.Clock.Set(time.Unix(1701295903, 0))
	retry.Ctx.Providers.Clock = &retry.Clock
	retry.Ctx.Configuration.TOTP = schema.DefaultTOTPConfiguration

	second := model.TOTPConfiguration{ID: 1, Username: testUsername, Digits: 6, Secret: []byte("secret"), Period: 30, Algorithm: "SHA1"}

	gomock.InOrder(
		retry.StorageMock.
			EXPECT().
			LoadTOTPConfiguration(retry.Ctx, gomock.Any()).
			Return(&second, nil),
		retry.TOTPMock.
			EXPECT().
			Validate(retry.Ctx, gomock.Eq("123456"), gomock.Eq(&second)).
			Return(true, getStepTOTP(retry.Ctx, -1), nil),
		retry.StorageMock.
			EXPECT().
			ConsumeTOTPHistory(retry.Ctx, testUsername, uint64(1701295890)).
			Return(true, nil),
		retry.StorageMock.
			EXPECT().
			UpdateTOTPConfigurationSignIn(retry.Ctx, gomock.Any(), gomock.Any()).
			Return(nil),
		retry.StorageMock.
			EXPECT().
			AppendAuthenticationLog(retry.Ctx, gomock.Eq(model.AuthenticationAttempt{
				Username:   testUsername,
				Successful: true,
				Banned:     false,
				Time:       retry.Clock.Now(),
				Type:       regulation.AuthTypeTOTP,
				RemoteIP:   model.NewNullIPFromString("0.0.0.0"),
			})).
			Return(nil),
	)

	retry.Ctx.Request.SetBody(bodyBytes)

	TimeBasedOneTimePasswordPOST(retry.Ctx)
	retry.Assert200OK(s.T(), redirectResponse{Redirect: "https://www.example.com"})
}

func TestRunHandlerSignTOTPSuite(t *testing.T) {
	suite.Run(t, new(HandlerSignTOTPSuite))
}

func TestSignTOTPHandleGetSessionError(t *testing.T) {
	testCases := []struct {
		name     string
		handler  middlewares.RequestHandler
		message  string
		expected string
	}{
		{
			"ShouldHandleGET",
			TimeBasedOneTimePasswordGET,
			"Authentication failed, please retry later.",
			"Error occurred retrieving TOTP configuration: error occurred retrieving the user session data",
		},
		{
			"ShouldHandlePOST",
			TimeBasedOneTimePasswordPOST,
			"Authentication failed, please retry later.",
			"Error occurred validating a TOTP authentication: error occurred retrieving the user session data",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtx(t)
			defer mock.Close()

			mock.Clock.Set(time.Unix(1701295903, 0))
			mock.Ctx.Providers.Clock = &mock.Clock
			mock.Ctx.Configuration.TOTP = schema.DefaultTOTPConfiguration

			mock.Ctx.Request.Header.Set(fasthttp.HeaderXForwardedHost, "auth.notexample.com")

			tc.handler(mock.Ctx)

			assert.Equal(t, fasthttp.StatusForbidden, mock.Ctx.Response.StatusCode())
			assert.Equal(t, fmt.Sprintf(`{"status":"KO","message":"%s"}`, tc.message), string(mock.Ctx.Response.Body()))

			AssertLogEntryMessageAndError(t, mock.Hook.LastEntry(), tc.expected, "unable to retrieve session cookie domain provider: no configured session cookie domain matches the url 'https://auth.notexample.com/'")
		})
	}
}
