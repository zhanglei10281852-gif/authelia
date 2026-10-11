// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/model"
)

func TestSQLProviderConcurrentTransactions(t *testing.T) {
	testCases := []struct {
		name        string
		concurrency int
		iterations  int
	}{
		{name: "ShouldRotateConcurrentlyWithSixteenWorkers", concurrency: 16, iterations: 10},
		{name: "ShouldRotateConcurrentlyWithThirtyTwoWorkers", concurrency: 32, iterations: 10},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := newTestSQLiteProviderWithEncryption(t)

			require.NoError(t, provider.StartupCheck())

			ctx := context.Background()

			for i := 0; i < tc.concurrency; i++ {
				require.NoError(t, provider.SaveOAuth2Session(ctx, OAuth2SessionTypeRefreshToken, newTestConcurrentOAuth2Session(i, 0)))
			}

			var (
				wg   sync.WaitGroup
				mu   sync.Mutex
				errs []error
			)

			record := func(err error) {
				mu.Lock()

				errs = append(errs, err)

				mu.Unlock()
			}

			for i := 0; i < tc.concurrency; i++ {
				wg.Add(1)

				go func(i int) {
					defer wg.Done()

					for j := 0; j < tc.iterations; j++ {
						if err := rotateTestConcurrentOAuth2Session(provider, i, j); err != nil {
							record(err)

							return
						}
					}
				}(i)
			}

			wg.Wait()

			assert.Empty(t, errs)

			for i := 0; i < tc.concurrency; i++ {
				session, err := provider.LoadOAuth2Session(ctx, OAuth2SessionTypeRefreshToken, newTestConcurrentOAuth2Signature(i, tc.iterations))

				require.NoError(t, err)
				assert.True(t, session.Active)
			}
		})
	}
}

func rotateTestConcurrentOAuth2Session(provider *SQLiteProvider, worker, iteration int) (err error) {
	var ctx context.Context

	for attempt := 1; ; attempt++ {
		if ctx, err = provider.BeginTX(context.Background()); err == nil {
			break
		}

		if attempt == 5 || !IsSerializationFailure(err) {
			return err
		}
	}

	if _, err = provider.LoadOAuth2Session(ctx, OAuth2SessionTypeRefreshToken, newTestConcurrentOAuth2Signature(worker, iteration)); err != nil {
		_ = provider.Rollback(ctx)

		return err
	}

	if err = provider.RevokeOAuth2Session(ctx, OAuth2SessionTypeRefreshToken, newTestConcurrentOAuth2Signature(worker, iteration)); err != nil {
		_ = provider.Rollback(ctx)

		return err
	}

	if err = provider.SaveOAuth2Session(ctx, OAuth2SessionTypeAccessToken, newTestConcurrentOAuth2Session(worker, iteration+1)); err != nil {
		_ = provider.Rollback(ctx)

		return err
	}

	if err = provider.SaveOAuth2Session(ctx, OAuth2SessionTypeRefreshToken, newTestConcurrentOAuth2Session(worker, iteration+1)); err != nil {
		_ = provider.Rollback(ctx)

		return err
	}

	return provider.Commit(ctx)
}

func newTestConcurrentOAuth2Signature(worker, iteration int) (signature string) {
	return fmt.Sprintf("concurrent-sig-%d-%d", worker, iteration)
}

func newTestConcurrentOAuth2Session(worker, iteration int) (session model.OAuth2Session) {
	return model.OAuth2Session{
		ChallengeID:     model.MustNullUUID(model.NewRandomNullUUID()),
		RequestID:       fmt.Sprintf("concurrent-req-%d-%d", worker, iteration),
		ClientID:        "test-client",
		Signature:       newTestConcurrentOAuth2Signature(worker, iteration),
		Subject:         sql.NullString{Valid: true, String: "john"},
		Active:          true,
		RequestedScopes: model.StringSlicePipeDelimited{"openid", "offline_access"},
		GrantedScopes:   model.StringSlicePipeDelimited{"openid", "offline_access"},
		Session:         []byte("{}"),
	}
}

func TestSQLProviderRegulationTransactionRecovery(t *testing.T) {
	ip := model.NewIP(net.ParseIP("127.0.0.1"))

	newAttempt := func(at time.Time) model.AuthenticationAttempt {
		return model.AuthenticationAttempt{
			Time:       at,
			Successful: false,
			Banned:     false,
			Username:   "john",
			Type:       "1FA",
			RemoteIP:   model.NewNullIP(ip.IP),
		}
	}

	t.Run("ShouldCommitAttempt", func(t *testing.T) {
		provider := newTestSQLiteProvider(t)
		require.NoError(t, provider.StartupCheck())

		ctx := context.Background()

		require.NoError(t, provider.RegulationTransaction(ctx, func(tx context.Context) error {
			return provider.AppendAuthenticationLog(tx, newAttempt(time.Now()))
		}))

		records, err := provider.LoadRegulationRecordsByUser(ctx, "john", time.Now().Add(-time.Hour), 10)
		require.NoError(t, err)
		assert.Len(t, records, 1)

		ipRecords, err := provider.LoadRegulationRecordsByIP(ctx, ip, time.Now().Add(-time.Hour), 10)
		require.NoError(t, err)
		assert.Len(t, ipRecords, 1)
	})

	t.Run("ShouldRollbackAttemptWhenDecisionFails", func(t *testing.T) {
		provider := newTestSQLiteProvider(t)
		require.NoError(t, provider.StartupCheck())

		ctx := context.Background()

		err := provider.RegulationTransaction(ctx, func(tx context.Context) error {
			require.NoError(t, provider.AppendAuthenticationLog(tx, newAttempt(time.Now())))

			return fmt.Errorf("decision failed")
		})

		require.EqualError(t, err, "decision failed")

		records, err := provider.LoadRegulationRecordsByUser(ctx, "john", time.Now().Add(-time.Hour), 10)
		require.NoError(t, err)
		assert.Empty(t, records)

		bans, err := provider.LoadBannedUser(ctx, "john")
		require.NoError(t, err)
		assert.Empty(t, bans)
	})

	t.Run("ShouldRollbackAttemptWhenBanWriteFails", func(t *testing.T) {
		provider := newTestSQLiteProvider(t)
		require.NoError(t, provider.StartupCheck())

		ctx, cancel := context.WithCancel(context.Background())

		err := provider.RegulationTransaction(ctx, func(tx context.Context) error {
			require.NoError(t, provider.AppendAuthenticationLog(tx, newAttempt(time.Now())))

			cancel()

			return provider.SaveBannedIP(tx, &model.BannedIP{
				Expires: sql.NullTime{Valid: true, Time: time.Now().Add(time.Minute)},
				IP:      ip,
				Source:  "regulation",
				Reason:  sql.NullString{Valid: true, String: "Exceeding Maximum Retries"},
			})
		})

		require.Error(t, err)

		ipRecords, err := provider.LoadRegulationRecordsByIP(context.Background(), ip, time.Now().Add(-time.Hour), 10)
		require.NoError(t, err)
		assert.Empty(t, ipRecords)

		bans, err := provider.LoadBannedIP(context.Background(), ip)
		require.NoError(t, err)
		assert.Empty(t, bans)
	})
}

func TestSQLProviderRegulationConcurrentDecisions(t *testing.T) {
	testCases := []struct {
		name    string
		workers int
	}{
		{name: "ShouldConvergeWithEightWorkers", workers: 8},
		{name: "ShouldConvergeWithSixteenWorkers", workers: 16},
		{name: "ShouldConvergeWithThirtyTwoWorkers", workers: 32},
	}

	const (
		maxRetries = 3
		banTime    = 3 * time.Minute
		findTime   = 30 * time.Second
	)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := newTestSQLiteProvider(t)
			require.NoError(t, provider.StartupCheck())

			ctx := context.Background()
			ip := model.NewIP(net.ParseIP("127.0.0.1"))
			now := time.Now()
			since := now.Add(-findTime)

			decide := func(n int) error {
				attempt := model.AuthenticationAttempt{
					Time:       now.Add(time.Duration(n) * time.Millisecond),
					Successful: false,
					Banned:     false,
					Username:   "john",
					Type:       "1FA",
					RemoteIP:   model.NewNullIP(ip.IP),
				}

				return provider.RegulationTransaction(ctx, func(tx context.Context) error {
					if err := provider.AppendAuthenticationLog(tx, attempt); err != nil {
						return err
					}

					ipRecords, err := provider.LoadRegulationRecordsByIP(tx, ip, since, maxRetries)
					if err != nil {
						return err
					}

					if banexp := testRegulationBanExpires(since, ipRecords, maxRetries, banTime); banexp != nil {
						if err = provider.SaveBannedIP(tx, &model.BannedIP{
							Expires: sql.NullTime{Valid: true, Time: *banexp},
							IP:      ip,
							Source:  "regulation",
							Reason:  sql.NullString{Valid: true, String: "Exceeding Maximum Retries"},
						}); err != nil {
							return err
						}
					}

					userRecords, err := provider.LoadRegulationRecordsByUser(tx, "john", since, maxRetries)
					if err != nil {
						return err
					}

					if banexp := testRegulationBanExpires(since, userRecords, maxRetries, banTime); banexp != nil {
						if err = provider.SaveBannedUser(tx, &model.BannedUser{
							Expires:  sql.NullTime{Valid: true, Time: *banexp},
							Username: "john",
							Source:   "regulation",
							Reason:   sql.NullString{Valid: true, String: "Exceeding Maximum Retries"},
						}); err != nil {
							return err
						}
					}

					return nil
				})
			}

			var (
				wg   sync.WaitGroup
				mu   sync.Mutex
				errs []error
			)

			record := func(err error) {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}

			for w := 0; w < tc.workers; w++ {
				wg.Add(1)

				go func(w int) {
					defer wg.Done()

					if err := decide(w); err != nil {
						record(err)
					}
				}(w)
			}

			wg.Wait()

			assert.Empty(t, errs)

			var count int

			require.NoError(t, provider.db.GetContext(ctx, &count, "SELECT COUNT(*) FROM authentication_logs"))
			assert.Equal(t, tc.workers, count)

			ipBans, err := provider.LoadBannedIP(ctx, ip)
			require.NoError(t, err)
			require.Len(t, ipBans, 1)

			userBans, err := provider.LoadBannedUser(ctx, "john")
			require.NoError(t, err)
			require.Len(t, userBans, 1)

			listedIPs, err := provider.LoadBannedIPs(ctx, 100, 0)
			require.NoError(t, err)
			assert.Len(t, listedIPs, 1)

			listedUsers, err := provider.LoadBannedUsers(ctx, 100, 0)
			require.NoError(t, err)
			assert.Len(t, listedUsers, 1)

			// A further failed login records the attempt but cannot add another effective ban while the ban holds.
			require.NoError(t, decide(tc.workers))

			require.NoError(t, provider.db.GetContext(ctx, &count, "SELECT COUNT(*) FROM authentication_logs"))
			assert.Equal(t, tc.workers+1, count)

			ipBans, err = provider.LoadBannedIP(ctx, ip)
			require.NoError(t, err)
			assert.Len(t, ipBans, 1)

			userBans, err = provider.LoadBannedUser(ctx, "john")
			require.NoError(t, err)
			assert.Len(t, userBans, 1)

			// Revoking the bans leaves no effective bans while the revoked rows stay as history.
			require.NoError(t, provider.RevokeBannedIP(ctx, ipBans[0].ID, time.Now()))
			require.NoError(t, provider.RevokeBannedUser(ctx, userBans[0].ID, time.Now()))

			ipBans, err = provider.LoadBannedIP(ctx, ip)
			require.NoError(t, err)
			assert.Empty(t, ipBans)

			userBans, err = provider.LoadBannedUser(ctx, "john")
			require.NoError(t, err)
			assert.Empty(t, userBans)
		})
	}
}

func TestSQLProviderRegulationRecordsManualBan(t *testing.T) {
	provider := newTestSQLiteProvider(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	// An effective manual ban is observed by the regulation record loader the same way a regulation ban is, so
	// decisions only start counting again once the ban window has ended.
	manual := &model.BannedUser{
		Expires:  sql.NullTime{Valid: true, Time: time.Now().Add(time.Hour)},
		Username: "john",
		Source:   "cli",
	}

	require.NoError(t, provider.SaveBannedUser(ctx, manual))

	require.NoError(t, provider.AppendAuthenticationLog(ctx, model.AuthenticationAttempt{
		Time:       time.Now(),
		Successful: false,
		Banned:     false,
		Username:   "john",
		Type:       "1FA",
	}))

	records, err := provider.LoadRegulationRecordsByUser(ctx, "john", time.Now().Add(-time.Hour), 10)
	require.NoError(t, err)
	assert.Empty(t, records)
}

// testRegulationBanExpires mirrors the regulator decision on the loaded records: the ban expires BanTime after the
// most recent counted failure once the failures in the window reach maxRetries.
func testRegulationBanExpires(since time.Time, records []model.RegulationRecord, maxRetries int, banTime time.Duration) *time.Time {
	failures := make([]time.Time, 0, len(records))

loop:
	for _, record := range records {
		switch {
		case record.Successful:
			break loop
		case record.Time.Before(since):
			continue
		default:
			failures = append(failures, record.Time)
		}
	}

	if len(failures) < maxRetries {
		return nil
	}

	expires := failures[0].Add(banTime)

	return &expires
}
