// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package regulation

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/authelia/authelia/v4/internal/clock"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/storage"
	"github.com/authelia/authelia/v4/internal/utils"
)

// NewRegulator create a regulator instance.
func NewRegulator(config schema.Regulation, store storage.RegulatorProvider, clock clock.Provider) *Regulator {
	return &Regulator{
		users:  config.MaxRetries > 0 && utils.IsStringInSlice(typeUser, config.Modes),
		ips:    config.MaxRetries > 0 && utils.IsStringInSlice(typeIP, config.Modes),
		store:  store,
		clock:  clock,
		config: config,
	}
}

// HandleAttempt records an authentication attempt and applies the relevant bans.
func (r *Regulator) HandleAttempt(ctx Context, successful bool, ban *Ban, requestURI, requestMethod, authType string) {
	if ban.Type() == BanTypeUnknown {
		// Only the ban type is filled in: the attempt keeps whatever value was provided with the ban, which may be
		// empty when the username could not be resolved.
		ban.ban, _, _, _ = r.banCheckIP(ctx)
	}

	banned := ban.IsBanned()
	username := ban.Value()

	ctx.RecordAuthn(successful, banned, strings.ToLower(authType))

	attempt := model.AuthenticationAttempt{
		Time:          r.clock.Now(),
		Successful:    successful,
		Banned:        banned,
		Username:      username,
		Type:          authType,
		RemoteIP:      model.NewNullIP(ctx.RemoteIP()),
		RequestURI:    requestURI,
		RequestMethod: requestMethod,
	}

	// We only need to perform the ban checks when; the attempt is unsuccessful, there is not an effective ban in
	// place, regulation is enabled, and the authentication type is 1FA. When IP regulation is disabled and the
	// username is empty there is also no subject to count or ban, so we can return after recording the attempt.
	if successful || banned || (!r.ips && (!r.users || username == "")) || authType != AuthType1FA {
		if err := r.store.AppendAuthenticationLog(ctx, attempt); err != nil {
			ctx.GetLogger().WithFields(map[string]any{fieldUsername: username, "successful": successful}).WithError(err).Errorf("Failed to record %s authentication attempt", authType)
		}

		return
	}

	if err := r.handleAttemptPossibleBans(ctx, attempt, username); err != nil {
		logDecisionError(ctx, username, err)
	}
}

// handleAttemptPossibleBans records the failed attempt and derives the relevant user and/or IP ban as a single
// decision: the attempt record and every ban derived from it are either all committed together, or the transaction
// is rolled back discarding all of them. Failing to record the attempt, failing to load the records, or failing to
// save any of the derived bans therefore never results in a ban based on incomplete records, and concurrent
// decisions for the same subject can only produce one effective ban.
func (r *Regulator) handleAttemptPossibleBans(ctx Context, attempt model.AuthenticationAttempt, username string) error {
	ip := model.NewIP(ctx.RemoteIP())
	since := r.clock.Now().Add(-r.config.FindTime)

	return r.store.RegulationTransaction(ctx, func(tx context.Context) error {
		if err := r.store.AppendAuthenticationLog(tx, attempt); err != nil {
			return newDecisionError("Failed to record "+attempt.Type+" authentication attempt", map[string]any{fieldUsername: username, "successful": attempt.Successful}, err)
		}

		if r.ips {
			records, err := r.store.LoadRegulationRecordsByIP(tx, ip, since, r.config.MaxRetries)
			if err != nil {
				return newDecisionError("Failed to load regulation records", map[string]any{fieldRecordType: typeIP}, err)
			}

			if banexp := r.expires(since, records); banexp != nil {
				sqlban := &model.BannedIP{
					Expires: sql.NullTime{Valid: true, Time: *banexp},
					IP:      ip,
					Source:  "regulation",
					Reason:  sql.NullString{Valid: true, String: "Exceeding Maximum Retries"},
				}

				if err = r.store.SaveBannedIP(tx, sqlban); err != nil {
					return newDecisionError("Failed to save ban", map[string]any{fieldBanType: typeIP}, err)
				}
			}
		}

		if r.users && username != "" {
			records, err := r.store.LoadRegulationRecordsByUser(tx, username, since, r.config.MaxRetries)
			if err != nil {
				return newDecisionError("Failed to load regulation records", map[string]any{fieldRecordType: typeUser, fieldUsername: username}, err)
			}

			if banexp := r.expires(since, records); banexp != nil {
				sqlban := &model.BannedUser{
					Expires:  sql.NullTime{Valid: true, Time: *banexp},
					Username: username,
					Source:   "regulation",
					Reason:   sql.NullString{Valid: true, String: "Exceeding Maximum Retries"},
				}

				if err = r.store.SaveBannedUser(tx, sqlban); err != nil {
					return newDecisionError("Failed to save ban", map[string]any{fieldBanType: typeUser, fieldUsername: username}, err)
				}
			}
		}

		return nil
	})
}

func (r *Regulator) banCheckIP(ctx Context) (ban BanType, value string, expires *time.Time, err error) {
	ip := model.NewIP(ctx.RemoteIP())

	var bansIP []model.BannedIP

	if bansIP, err = r.store.LoadBannedIP(ctx, ip); err != nil {
		return BanTypeNone, "", nil, err
	}

	if len(bansIP) != 0 {
		b := bansIP[0]

		return returnBanResult(BanTypeIP, ip.String(), b.Expires)
	}

	return BanTypeNone, "", nil, nil
}

// BanCheck returns the ban in effect for the request IP or the given username.
func (r *Regulator) BanCheck(ctx Context, username string) (ban BanType, value string, expires *time.Time, err error) {
	if ban, value, expires, err = r.banCheckIP(ctx); err != nil || ban != BanTypeNone {
		return ban, value, expires, err
	}

	var bansUser []model.BannedUser

	if bansUser, err = r.store.LoadBannedUser(ctx, username); err != nil {
		return BanTypeNone, "", nil, err
	}

	if len(bansUser) != 0 {
		b := bansUser[0]

		return returnBanResult(BanTypeUser, username, b.Expires)
	}

	return BanTypeNone, "", nil, nil
}

func (r *Regulator) expires(since time.Time, records []model.RegulationRecord) *time.Time {
	failures := make([]model.RegulationRecord, 0, len(records))

loop:
	for _, record := range records {
		switch {
		case record.Successful:
			break loop
		case len(failures) >= r.config.MaxRetries:
			continue
		case record.Time.Before(since):
			continue
		default:
			// We stop appending failed attempts once we find the first successful attempts or we reach
			// the configured number of retries, meaning the user is already banned.
			failures = append(failures, record)
		}
	}

	// If the number of failed attempts within the ban time is less than the max number of retries
	// then the user is not banned.
	if len(failures) < r.config.MaxRetries {
		return nil
	}

	expires := failures[0].Time.Add(r.config.BanTime)

	return &expires
}

// decisionError classifies a failure of a regulation decision so the failure can be logged with the relevant message
// and fields, while still allowing the underlying database error to be inspected via errors.As/Is.
type decisionError struct {
	message string
	fields  map[string]any
	err     error
}

func newDecisionError(message string, fields map[string]any, err error) *decisionError {
	return &decisionError{message: message, fields: fields, err: err}
}

func (e *decisionError) Error() string {
	return e.err.Error()
}

func (e *decisionError) Unwrap() error {
	return e.err
}

func logDecisionError(ctx Context, username string, err error) {
	var decision *decisionError

	if errors.As(err, &decision) {
		ctx.GetLogger().WithFields(decision.fields).WithError(err).Error(decision.message)

		return
	}

	ctx.GetLogger().WithField(fieldUsername, username).WithError(err).Error("Failed to apply regulation")
}
