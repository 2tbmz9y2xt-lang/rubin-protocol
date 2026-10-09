//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

/*
#cgo CFLAGS: -std=c11
#include "../../../../third_party/libmdbx/mdbx.h"
#include <string.h>
#ifdef RUBIN_SELECTED_DAMAGE_FIXTURE
// Endpoint-only fixture: counts and faults bind real cursor sites in one env.
typedef struct { unsigned opens, gets, closes, queries, faults; } rubin_tip_counts;
static pthread_mutex_t rubin_tip_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t rubin_tip_cond = PTHREAD_COND_INITIALIZER;
static struct { MDBX_env *env; MDBX_dbi dbi; MDBX_cursor *cursor; unsigned mode, query, get, current_get, blocked, released, drift_active, drift_present; int code, close_code; unsigned char drift_key[78], drift_value[105]; size_t drift_key_len, drift_value_len; rubin_tip_counts counts; } rubin_tip;
int rubin_tip_arm(MDBX_env *env, MDBX_dbi dbi, unsigned mode, unsigned query, unsigned get, int code) {
	pthread_mutex_lock(&rubin_tip_mu);
	int invalid = rubin_tip.env != NULL || !env || mode < 1 || mode > 14 || query == 0 || get > 2;
	if (!invalid) { memset(&rubin_tip, 0, sizeof(rubin_tip)); rubin_tip.env = env; rubin_tip.dbi = dbi; rubin_tip.mode = mode; rubin_tip.query = query; rubin_tip.get = get; rubin_tip.code = code; }
	pthread_mutex_unlock(&rubin_tip_mu);
	return invalid ? MDBX_EINVAL : MDBX_SUCCESS;
}
void rubin_tip_disarm(rubin_tip_counts *out) {
	pthread_mutex_lock(&rubin_tip_mu); *out = rubin_tip.counts; memset(&rubin_tip, 0, sizeof(rubin_tip)); pthread_mutex_unlock(&rubin_tip_mu);
}
void rubin_tip_wait(void) {
	pthread_mutex_lock(&rubin_tip_mu); while (!rubin_tip.blocked) pthread_cond_wait(&rubin_tip_cond, &rubin_tip_mu); pthread_mutex_unlock(&rubin_tip_mu);
}
void rubin_tip_release(void) {
	pthread_mutex_lock(&rubin_tip_mu); rubin_tip.released = 1; pthread_cond_broadcast(&rubin_tip_cond); pthread_mutex_unlock(&rubin_tip_mu);
}
int rubin_tip_drift_arm(const void *key, size_t key_len, const void *value, size_t value_len, int present) {
	if (!rubin_tip.env || !key || key_len == 0 || key_len > 78 || value_len > 105 || (value_len && !value) || (present != 0 && present != 1)) return MDBX_EINVAL;
	memcpy(rubin_tip.drift_key, key, key_len); if (value_len) memcpy(rubin_tip.drift_value, value, value_len);
	rubin_tip.drift_key_len = key_len; rubin_tip.drift_value_len = value_len; rubin_tip.drift_present = (unsigned)present; rubin_tip.drift_active = 1;
	return MDBX_SUCCESS;
}
static int rubin_tip_drift(MDBX_txn *txn) {
	MDBX_val key = {rubin_tip.drift_key, rubin_tip.drift_key_len}, value = {rubin_tip.drift_value, rubin_tip.drift_value_len};
	return rubin_tip.drift_present ? mdbx_put(txn, rubin_tip.dbi, &key, &value, MDBX_UPSERT) : mdbx_del(txn, rubin_tip.dbi, &key, NULL);
}
int rubin_tip_close_fault(int code) {
	if (!rubin_tip.env || (code != 0 && code != MDBX_EIO)) return MDBX_EINVAL;
	rubin_tip.close_code = code;
	return MDBX_SUCCESS;
}
static int rubin_tip_open(MDBX_txn *txn, MDBX_dbi dbi, MDBX_cursor **cursor) {
	pthread_mutex_lock(&rubin_tip_mu);
	int owned = rubin_tip.env && mdbx_txn_env(txn) == rubin_tip.env && dbi == rubin_tip.dbi;
	unsigned mode = 0;
	if (owned) { rubin_tip.counts.opens++; rubin_tip.counts.queries++; rubin_tip.current_get = 0; if (rubin_tip.counts.queries == rubin_tip.query) mode = rubin_tip.mode; }
	if (mode >= 2 && mode <= 4) rubin_tip.counts.faults++;
	pthread_mutex_unlock(&rubin_tip_mu);
	if (mode == 2 || mode == 3) { *cursor = NULL; return mode == 2 ? MDBX_SUCCESS : MDBX_EIO; }
	int rc = mdbx_cursor_open(txn, dbi, cursor);
	if (owned && rc == MDBX_SUCCESS) { pthread_mutex_lock(&rubin_tip_mu); rubin_tip.cursor = *cursor; pthread_mutex_unlock(&rubin_tip_mu); }
	return mode == 4 && rc == MDBX_SUCCESS ? MDBX_EIO : rc;
}
static int rubin_tip_get(MDBX_cursor *cursor, MDBX_val *key, MDBX_val *value, MDBX_cursor_op op) {
	unsigned mode = 0; int code = MDBX_SUCCESS;
	pthread_mutex_lock(&rubin_tip_mu);
	if (rubin_tip.env && cursor == rubin_tip.cursor) {
		rubin_tip.counts.gets++; rubin_tip.current_get++;
		if (rubin_tip.counts.queries == rubin_tip.query && rubin_tip.current_get == rubin_tip.get) { mode = rubin_tip.mode; code = rubin_tip.code; if (mode >= 5 && mode != 13) rubin_tip.counts.faults++; }
	}
	if (mode == 13) { rubin_tip.blocked = 1; pthread_cond_broadcast(&rubin_tip_cond); while (!rubin_tip.released) pthread_cond_wait(&rubin_tip_cond, &rubin_tip_mu); }
	pthread_mutex_unlock(&rubin_tip_mu);
	if (mode == 11 || mode == 12 || mode == 14) return mode == 11 ? MDBX_EIO : (mode == 12 ? MDBX_RESULT_TRUE : code);
	int rc = mdbx_cursor_get(cursor, key, value, op);
	if (rc == MDBX_SUCCESS) {
		static unsigned char malformed[78];
		if (mode == 5) key->iov_base = NULL;
		else if (mode == 6) key->iov_len = 0;
		else if (mode == 7 || mode == 8 || mode == 9) { memset(malformed, mode == 9 && op == MDBX_SET_RANGE ? 0 : 0xff, sizeof(malformed)); key->iov_base = malformed; key->iov_len = mode == 7 ? 77 : (mode == 8 ? 78 : 16); }
		else if (mode == 10) { value->iov_base = NULL; if (value->iov_len == 0) value->iov_len = 1; }
	}
	return rc;
}
static void rubin_tip_close(MDBX_cursor *cursor) {
	pthread_mutex_lock(&rubin_tip_mu);
	if (rubin_tip.env && cursor == rubin_tip.cursor) { rubin_tip.counts.closes++; rubin_tip.cursor = NULL; }
	pthread_mutex_unlock(&rubin_tip_mu);
	mdbx_cursor_close(cursor);
}
// Large-image fixture state is isolated from the selected-side fixture. Faults
// retain or consume actual handles; physical drift is committed before readback.
typedef struct { unsigned mode, calls, gets, commits, aborts, closes, drift; MDBX_env *env; MDBX_txn *old_txn, *write_txn, *read_txn; MDBX_dbi dbi; unsigned char key[65536]; size_t key_len; } rubin_li_state;
static rubin_li_state rubin_li;
int rubin_li_arm(MDBX_env *env, MDBX_dbi dbi, unsigned mode, const void *key, size_t length) {
	if (rubin_li.mode || !env || mode < 1 || mode > 29 || length == 0 || length > sizeof(rubin_li.key) || !key) return MDBX_EINVAL;
	memset(&rubin_li, 0, sizeof(rubin_li));
	rubin_li.mode = mode; rubin_li.env = env; rubin_li.dbi = dbi; rubin_li.key_len = length;
	memcpy(rubin_li.key, key, length);
	return MDBX_SUCCESS;
}
void rubin_li_disarm(rubin_li_state *out) { *out = rubin_li; memset(&rubin_li, 0, sizeof(rubin_li)); }
unsigned rubin_li_calls(void) { return rubin_li.calls; }
static int rubin_li_drift(void) {
	MDBX_txn *txn = NULL;
	MDBX_val key = {rubin_li.key, rubin_li.key_len}, value = {NULL, 0};
	const unsigned char replacement = 0x7f;
	int rc = mdbx_txn_begin(rubin_li.env, NULL, MDBX_TXN_READWRITE, &txn);
	if (rc != MDBX_SUCCESS) return rc;
	if (rubin_tip.drift_active) rc = rubin_tip_drift(txn);
	else if (rubin_li.mode == 4) rc = mdbx_del(txn, rubin_li.dbi, &key, NULL);
	else {
		value.iov_base = (void *)&replacement; value.iov_len = 1;
		rc = mdbx_put(txn, rubin_li.dbi, &key, &value, MDBX_UPSERT);
	}
	if (rc == MDBX_SUCCESS) return mdbx_txn_commit(txn);
	mdbx_txn_abort(txn);
	return rc;
}
static int rubin_li_env_close(MDBX_env *env, bool dont_sync) {
	if (rubin_li.mode) rubin_li.calls++;
	if ((rubin_li.mode == 11 || rubin_li.mode == 24) && env == rubin_li.env) { rubin_li.closes++; return MDBX_BUSY; }
	int rc = mdbx_env_close_ex(env, dont_sync);
	return rc == MDBX_SUCCESS && env == rubin_tip.env && rubin_tip.close_code ? rubin_tip.close_code : rc;
}
static int rubin_li_prefix(const MDBX_txn *txn, MDBX_dbi dbi, MDBX_val *key, MDBX_val *value) {
	if (rubin_li.mode) rubin_li.calls++;
	if (rubin_li.mode == 29 && txn == rubin_li.read_txn && dbi != rubin_li.dbi) {
		rubin_li.gets++; key->iov_base = NULL; key->iov_len = 0; value->iov_base = NULL; value->iov_len = 0; return MDBX_EIO;
	}
	int rc = mdbx_get_equal_or_great(txn, dbi, key, value);
	int shape_mode = (rubin_li.mode >= 20 && rubin_li.mode <= 22) || rubin_li.mode == 25 || rubin_li.mode == 26 || rubin_li.mode == 27;
	if (shape_mode && txn == rubin_li.old_txn && dbi == rubin_li.dbi && (rc == MDBX_SUCCESS || rc == MDBX_RESULT_TRUE)) {
		rubin_li.gets++;
		if (rubin_li.mode == 20) key->iov_base = NULL;
		else if (rubin_li.mode == 21) key->iov_len = SIZE_MAX;
		else if (rubin_li.mode == 25) key->iov_len = 0;
		else if (rubin_li.mode == 26) key->iov_len = 31;
		else if (rubin_li.mode == 27) key->iov_len = 2023;
		else { value->iov_base = NULL; value->iov_len = 1; }
	}
	return rc;
}
// Fixture-only native boundary for the dormant selected-side operation. The fixture build defines the macro through
// its package CFLAGS; an ordinary build preprocesses this block away. One serialized invocation binds one environment,
// its OLD, write and readback transactions and one closed scenario; every interceptor forwards to libMDBX.
typedef struct { unsigned long long begin_old, begin_write, begin_read, old_gets[8], read_gets, faults, dels, commits, old_aborts, bridge_error; } rubin_sd_counts;
extern void rubinSelectedDamageProbe(uintptr_t probe);
static pthread_mutex_t rubin_sd_mu = PTHREAD_MUTEX_INITIALIZER;
static struct { unsigned scenario; int get_fired; MDBX_env *env; MDBX_txn *old_txn, *write_txn, *read_txn; MDBX_dbi dbis[8], fault_dbi; unsigned char key[78]; size_t key_len; uintptr_t probe; rubin_sd_counts counts; } rubin_sd;
int rubin_sd_arm(MDBX_env *env, unsigned scenario, const MDBX_dbi *dbis, MDBX_dbi fault_dbi, const void *key, size_t key_len, uintptr_t probe) {
	int rc = 1;
	pthread_mutex_lock(&rubin_sd_mu);
	if (rubin_sd.scenario == 0 && env != NULL && dbis != NULL && scenario >= 1 && scenario <= 13 && key_len <= sizeof(rubin_sd.key) && (key_len == 0 || key != NULL)) {
		memset(&rubin_sd, 0, sizeof(rubin_sd));
		rubin_sd.scenario = scenario;
		rubin_sd.env = env;
		rubin_sd.fault_dbi = fault_dbi;
		rubin_sd.probe = probe;
		memcpy(rubin_sd.dbis, dbis, sizeof(rubin_sd.dbis));
		if (key_len != 0) memcpy(rubin_sd.key, key, key_len);
		rubin_sd.key_len = key_len;
		rc = 0;
	}
	pthread_mutex_unlock(&rubin_sd_mu);
	return rc;
}
void rubin_sd_disarm(rubin_sd_counts *out) {
	pthread_mutex_lock(&rubin_sd_mu);
	*out = rubin_sd.counts;
	memset(&rubin_sd, 0, sizeof(rubin_sd));
	pthread_mutex_unlock(&rubin_sd_mu);
}
static int rubin_sd_txn_begin(MDBX_env *env, MDBX_txn *parent, MDBX_txn_flags_t flags, MDBX_txn **txn) {
	if (rubin_li.mode) rubin_li.calls++;
	int role = -1, fail = MDBX_SUCCESS;
	uintptr_t probe = 0;
	pthread_mutex_lock(&rubin_sd_mu);
	if (rubin_sd.scenario != 0 && env == rubin_sd.env) {
		role = (flags & MDBX_TXN_RDONLY) == 0 ? 1 : (rubin_sd.counts.begin_old == 0 ? 0 : 2);
		if (role == 0) {
			rubin_sd.counts.begin_old++;
			fail = rubin_sd.scenario == 2 ? MDBX_TXN_FULL : (rubin_sd.scenario == 3 ? MDBX_EIO : MDBX_SUCCESS);
			if (fail != MDBX_SUCCESS) rubin_sd.counts.faults++;
		} else {
			if (role == 1) rubin_sd.counts.begin_write++;
			else rubin_sd.counts.begin_read++;
			if (role == 1 && rubin_sd.scenario == 13) { fail = MDBX_TXN_FULL; rubin_sd.counts.faults++; }
			probe = rubin_sd.probe;
		}
	}
	pthread_mutex_unlock(&rubin_sd_mu);
	if (fail != MDBX_SUCCESS) {
		*txn = NULL;
		return fail;
	}
	if (rubin_li.mode == 23 && env == rubin_li.env && (flags & MDBX_TXN_RDONLY) != 0 && rubin_li.old_txn) {
		*txn = NULL;
		return MDBX_EIO;
	}
	if (probe != 0) rubinSelectedDamageProbe(probe);
	if (rubin_li.mode == 14 && env == rubin_li.env && (flags & MDBX_TXN_RDONLY) == 0 && !rubin_li.write_txn) {
		int drift_rc = rubin_li_drift();
		if (drift_rc != MDBX_SUCCESS) { *txn = NULL; return drift_rc; }
		rubin_li.drift++;
	}
	int rc = mdbx_txn_begin(env, parent, flags, txn);
	if (rubin_li.mode && env == rubin_li.env && rc == MDBX_SUCCESS) {
		if ((flags & MDBX_TXN_RDONLY) == 0) rubin_li.write_txn = *txn;
		else if (!rubin_li.old_txn) rubin_li.old_txn = *txn;
		else rubin_li.read_txn = *txn;
	}
	if (role >= 0 && rc == MDBX_SUCCESS) {
		pthread_mutex_lock(&rubin_sd_mu);
		if (role == 0) rubin_sd.old_txn = *txn;
		else if (role == 1) rubin_sd.write_txn = *txn;
		else rubin_sd.read_txn = *txn;
		pthread_mutex_unlock(&rubin_sd_mu);
	}
	return rc;
}
static int rubin_sd_get_fault(const MDBX_txn *txn, MDBX_dbi dbi, const MDBX_val *key) {
	int read = rubin_sd.read_txn != NULL && txn == rubin_sd.read_txn, want_read = rubin_sd.scenario == 9;
	int want = rubin_sd.scenario == 4 || rubin_sd.scenario == 5 || want_read;
	if (!want || rubin_sd.get_fired || read != want_read || (!read && txn != rubin_sd.old_txn)) return 0;
	return dbi == rubin_sd.fault_dbi && key->iov_len != 0 && key->iov_len == rubin_sd.key_len && memcmp(key->iov_base, rubin_sd.key, key->iov_len) == 0;
}
static int rubin_sd_get(const MDBX_txn *txn, MDBX_dbi dbi, const MDBX_val *key, MDBX_val *data) {
	if (rubin_li.mode) rubin_li.calls++;
	int li_old_fault = (rubin_li.mode == 1 || rubin_li.mode == 2 || rubin_li.mode == 24 || rubin_li.mode == 28) && txn == rubin_li.old_txn;
	int li_read_fault = rubin_li.mode == 8 && txn == rubin_li.read_txn;
	if ((li_old_fault || li_read_fault) && dbi == rubin_li.dbi && key->iov_len == rubin_li.key_len && memcmp(key->iov_base, rubin_li.key, key->iov_len) == 0) {
		rubin_li.gets++;
		if (li_old_fault && rubin_li.mode != 28 && rubin_li.gets == 1) return mdbx_get(txn, dbi, key, data);
		data->iov_base = NULL; data->iov_len = 0; return MDBX_EIO;
	}
	if ((rubin_li.mode == 17 || rubin_li.mode == 18) && txn == rubin_li.old_txn && dbi == rubin_li.dbi) {
		int rc = mdbx_get(txn, dbi, key, data);
		if (rc == MDBX_SUCCESS) {
			rubin_li.gets++;
			if (rubin_li.mode == 17) { data->iov_base = NULL; data->iov_len = 1; }
			else data->iov_len = SIZE_MAX;
		}
		return rc;
	}
	int fault = 0;
	pthread_mutex_lock(&rubin_sd_mu);
	if (rubin_sd.scenario != 0 && txn != NULL) {
		for (int i = 0; txn == rubin_sd.old_txn && i < 8; i++) if (rubin_sd.dbis[i] == dbi) rubin_sd.counts.old_gets[i]++;
		if (txn == rubin_sd.read_txn) rubin_sd.counts.read_gets++;
		fault = rubin_sd_get_fault(txn, dbi, key);
		if (fault) {
			rubin_sd.get_fired = 1;
			rubin_sd.counts.faults++;
		}
	}
	pthread_mutex_unlock(&rubin_sd_mu);
	if (fault) {
		data->iov_base = NULL;
		data->iov_len = 0;
		return MDBX_EIO;
	}
	return mdbx_get(txn, dbi, key, data);
}
static int rubin_sd_del(MDBX_txn *txn, MDBX_dbi dbi, const MDBX_val *key, const MDBX_val *data) {
	if (rubin_li.mode) rubin_li.calls++;
	int fault = 0;
	pthread_mutex_lock(&rubin_sd_mu);
	if (rubin_sd.scenario != 0 && txn != NULL && txn == rubin_sd.write_txn) {
		rubin_sd.counts.dels++;
		fault = rubin_sd.scenario == 6 && rubin_sd.counts.faults == 0;
		if (fault) rubin_sd.counts.faults++;
	}
	pthread_mutex_unlock(&rubin_sd_mu);
	return fault ? MDBX_EIO : mdbx_del(txn, dbi, key, data);
}
// rubin_sd_third is the existing physical-mismatch technique: one raw put of 0x7f to meta-v1 key 02 after the
// operation's writer committed, in a fixture-owned transaction that commits before readback begins.
static int rubin_sd_third(void) {
	MDBX_txn *txn = NULL;
	const unsigned char key = 2, value = 0x7f;
	MDBX_val k = {(void *)&key, 1}, v = {(void *)&value, 1};
	int rc = mdbx_txn_begin(rubin_sd.env, NULL, MDBX_TXN_READWRITE, &txn);
	if (rc == MDBX_SUCCESS) rc = mdbx_put(txn, rubin_sd.dbis[0], &k, &v, MDBX_UPSERT);
	if (rc == MDBX_SUCCESS) return mdbx_txn_commit(txn);
	if (txn != NULL) mdbx_txn_abort(txn);
	return rc;
}
static int rubin_sd_txn_commit(MDBX_txn *txn) {
	if (rubin_li.mode) rubin_li.calls++;
	if (rubin_li.mode >= 3 && txn == rubin_li.write_txn) {
		rubin_li.commits++;
		if (rubin_li.mode == 7 || rubin_li.mode == 19) mdbx_txn_break(txn);
		int rc = mdbx_txn_commit(txn);
		if (rc != ((rubin_li.mode == 7 || rubin_li.mode == 19) ? MDBX_RESULT_TRUE : MDBX_SUCCESS)) return rc;
		if ((rubin_li.mode >= 3 && rubin_li.mode <= 6) || rubin_li.mode == 29 || (rubin_li.mode == 7 && rubin_tip.drift_active)) {
			rc = rubin_li_drift();
			if (rc != MDBX_SUCCESS) return rc;
			rubin_li.drift++;
		}
		return ENOSPC;
	}
	unsigned scenario = 0;
	uintptr_t probe = 0;
	pthread_mutex_lock(&rubin_sd_mu);
	if (rubin_sd.scenario != 0 && txn != NULL && txn == rubin_sd.write_txn) {
		rubin_sd.counts.commits++;
		scenario = rubin_sd.scenario;
		probe = rubin_sd.probe;
	}
	pthread_mutex_unlock(&rubin_sd_mu);
	if (probe != 0) rubinSelectedDamageProbe(probe);
	if (scenario == 7) mdbx_txn_break(txn);
	int rc = mdbx_txn_commit(txn);
	if (scenario < 7 || scenario > 10) return rc;
	int bridge = rc != (scenario == 7 ? MDBX_RESULT_TRUE : MDBX_SUCCESS);
	if (!bridge && scenario == 10) bridge = rubin_sd_third() != MDBX_SUCCESS;
	pthread_mutex_lock(&rubin_sd_mu);
	rubin_sd.counts.faults++;
	rubin_sd.counts.bridge_error += (unsigned long long)bridge;
	pthread_mutex_unlock(&rubin_sd_mu);
	return ENOSPC;
}
static int rubin_sd_txn_abort(MDBX_txn *txn) {
	if (rubin_li.mode) rubin_li.calls++;
	if ((rubin_li.mode == 15 || rubin_li.mode == 16 || rubin_li.mode == 19) && txn == rubin_li.read_txn) {
		if (rubin_li.mode != 16) return MDBX_THREAD_MISMATCH;
		int rc = mdbx_txn_abort(txn);
		return rc == MDBX_SUCCESS ? MDBX_EIO : rc;
	}
	if (rubin_li.mode && txn == rubin_li.old_txn) {
		rubin_li.aborts++;
		if (rubin_li.mode == 2 || rubin_li.mode == 10) return MDBX_THREAD_MISMATCH;
		int rc = mdbx_txn_abort(txn);
		return rubin_li.mode == 9 && rc == MDBX_SUCCESS ? MDBX_EIO : rc;
	}
	int fault = 0;
	uintptr_t probe = 0;
	pthread_mutex_lock(&rubin_sd_mu);
	if (rubin_sd.scenario != 0 && txn != NULL && txn == rubin_sd.old_txn) {
		rubin_sd.counts.old_aborts++;
		probe = rubin_sd.probe;
		fault = rubin_sd.scenario == 5 || rubin_sd.scenario == 11;
	}
	pthread_mutex_unlock(&rubin_sd_mu);
	if (probe != 0) rubinSelectedDamageProbe(probe);
	int rc = mdbx_txn_abort(txn);
	if (probe != 0) rubinSelectedDamageProbe(probe);
	if (!fault) return rc;
	pthread_mutex_lock(&rubin_sd_mu);
	if (rc == MDBX_SUCCESS) rubin_sd.counts.faults++;
	else rubin_sd.counts.bridge_error++;
	pthread_mutex_unlock(&rubin_sd_mu);
	return MDBX_EIO;
}
// rubin_sd_put fails exactly one armed write-transaction put of the armed DBI and key with EIO before libMDBX sees it.
static int rubin_sd_put(MDBX_txn *txn, MDBX_dbi dbi, const MDBX_val *key, MDBX_val *data, MDBX_put_flags_t flags) {
	if (rubin_li.mode) rubin_li.calls++;
	int fault = 0;
	pthread_mutex_lock(&rubin_sd_mu);
	if (rubin_sd.scenario == 12 && txn != NULL && txn == rubin_sd.write_txn && rubin_sd.counts.faults == 0 && dbi == rubin_sd.fault_dbi && key->iov_len != 0 && key->iov_len == rubin_sd.key_len && memcmp(key->iov_base, rubin_sd.key, key->iov_len) == 0) {
		fault = 1;
		rubin_sd.counts.faults++;
	}
	pthread_mutex_unlock(&rubin_sd_mu);
	int rc = fault ? MDBX_EIO : mdbx_put(txn, dbi, key, data, flags);
	if (rc == MDBX_SUCCESS && rubin_li.mode == 13 && txn == rubin_li.write_txn && rubin_li.drift == 0) {
		const unsigned char byte = 0x7f;
		MDBX_val extra_key = {rubin_li.key, rubin_li.key_len}, extra_value = {(void *)&byte, 1};
		rc = rubin_tip.drift_active ? rubin_tip_drift(txn) : mdbx_put(txn, rubin_li.dbi, &extra_key, &extra_value, MDBX_UPSERT);
		if (rc == MDBX_SUCCESS) rubin_li.drift++;
	}
	return rc;
}
#define mdbx_txn_begin rubin_sd_txn_begin
#define mdbx_get rubin_sd_get
#define mdbx_del rubin_sd_del
#define mdbx_txn_commit rubin_sd_txn_commit
#define mdbx_txn_abort rubin_sd_txn_abort
#define mdbx_put rubin_sd_put
#define mdbx_env_close_ex rubin_li_env_close
#define mdbx_get_equal_or_great rubin_li_prefix
#define mdbx_cursor_open rubin_tip_open
#define mdbx_cursor_get rubin_tip_get
#define mdbx_cursor_close rubin_tip_close
#endif // RUBIN_SELECTED_DAMAGE_FIXTURE
typedef struct { int first; int second; } rubin_mdbx_debug_result;
static rubin_mdbx_debug_result rubin_mdbx_normalize_debug(void) {
	rubin_mdbx_debug_result result = {MDBX_PROBLEM, MDBX_PROBLEM};
	result.first = mdbx_setup_debug(MDBX_LOG_NOTICE, MDBX_DBG_NONE, NULL);
	result.second = mdbx_setup_debug(MDBX_LOG_NOTICE, MDBX_DBG_NONE, NULL);
	return result;
}
typedef struct { int rc; MDBX_env *env; } rubin_mdbx_env_result;
static rubin_mdbx_env_result rubin_mdbx_env_create(void) { rubin_mdbx_env_result result = {0, NULL}; result.rc = mdbx_env_create(&result.env); return result; }
typedef struct { int rc; MDBX_txn *txn; } rubin_mdbx_txn_result;
static rubin_mdbx_txn_result rubin_mdbx_txn_begin(MDBX_env *env, MDBX_txn_flags_t flags) { rubin_mdbx_txn_result result = {0, NULL}; result.rc = mdbx_txn_begin(env, NULL, flags, &result.txn); return result; }
static int rubin_mdbx_put_required(MDBX_txn *txn, MDBX_dbi dbi, const void *key_bytes, size_t key_len, const void *value_bytes, size_t value_len) { MDBX_val key = {(void *)key_bytes, key_len}, value = {(void *)value_bytes, value_len}; return mdbx_put(txn, dbi, &key, &value, MDBX_NOOVERWRITE); }
typedef struct { int rc; const void *bytes; size_t length; } rubin_mdbx_get_result;
static rubin_mdbx_get_result rubin_mdbx_get(const MDBX_txn *txn, MDBX_dbi dbi, const void *key_bytes, size_t key_len) { MDBX_val key = {(void *)key_bytes, key_len}, value = {0, 0}; rubin_mdbx_get_result result; result.rc = mdbx_get(txn, dbi, &key, &value); result.bytes = value.iov_base; result.length = value.iov_len; return result; }
typedef struct { int rc; const void *key_bytes; size_t key_len; const void *value_bytes; size_t value_len; } rubin_mdbx_prefix_result;
static rubin_mdbx_prefix_result rubin_mdbx_get_equal_or_great(const MDBX_txn *txn, MDBX_dbi dbi, const void *seek_bytes, size_t seek_len) {
	MDBX_val key = {(void *)seek_bytes, seek_len}, value = {NULL, 0};
	rubin_mdbx_prefix_result result = {MDBX_EINVAL, NULL, 0, NULL, 0};
	result.rc = mdbx_get_equal_or_great(txn, dbi, &key, &value);
	if (result.rc == MDBX_SUCCESS || result.rc == MDBX_RESULT_TRUE) {
		result.key_bytes = key.iov_base;
		result.key_len = key.iov_len;
		result.value_bytes = value.iov_base;
		result.value_len = value.iov_len;
	}
	return result;
}
typedef struct { int rc; MDBX_cursor *cursor; } rubin_mdbx_cursor_result;
static rubin_mdbx_cursor_result rubin_mdbx_cursor_open(MDBX_txn *txn, MDBX_dbi dbi) {
	rubin_mdbx_cursor_result result = {MDBX_EINVAL, NULL};
	result.rc = mdbx_cursor_open(txn, dbi, &result.cursor);
	return result;
}
static rubin_mdbx_prefix_result rubin_mdbx_cursor_get(MDBX_cursor *cursor, const void *seek, size_t length, MDBX_cursor_op op) {
	MDBX_val key = {(void *)seek, length}, value = {NULL, 0};
	rubin_mdbx_prefix_result result = {MDBX_EINVAL, NULL, 0, NULL, 0};
	result.rc = mdbx_cursor_get(cursor, &key, &value, op);
	if (result.rc == MDBX_SUCCESS) {
		result.key_bytes = key.iov_base; result.key_len = key.iov_len;
		result.value_bytes = value.iov_base; result.value_len = value.iov_len;
	}
	return result;
}
typedef struct { int rc; int equal; int valid; } rubin_mdbx_equal_result;
static rubin_mdbx_equal_result rubin_mdbx_get_equal(const MDBX_txn *txn, MDBX_dbi dbi, const void *key_bytes, size_t key_len, int expected_present, const void *expected_bytes, size_t expected_len) { MDBX_val key = {(void *)key_bytes, key_len}, value = {0, 0}; rubin_mdbx_equal_result result = {MDBX_EINVAL, 0, 0}; if ((expected_present != 0 && expected_present != 1) || (expected_len != 0 && expected_bytes == NULL)) return result; result.rc = mdbx_get(txn, dbi, &key, &value); if (result.rc == MDBX_SUCCESS) { result.valid = value.iov_len == 0 || value.iov_base != NULL; if (expected_present && result.valid && value.iov_len == expected_len && (expected_len == 0 || memcmp(value.iov_base, expected_bytes, expected_len) == 0)) result.equal = 1; } else if (result.rc == MDBX_NOTFOUND) { result.valid = value.iov_base == NULL && value.iov_len == 0; if (!expected_present && result.valid) result.equal = 1; } return result; }
static int rubin_mdbx_del_exact(MDBX_txn *txn, MDBX_dbi dbi, const void *key_bytes, size_t key_len) { MDBX_val key = {(void *)key_bytes, key_len}; return mdbx_del(txn, dbi, &key, NULL); }
static int rubin_mdbx_put_nooverwrite(MDBX_txn *txn, MDBX_dbi dbi, const void *key_bytes, size_t key_len, const void *value_bytes, size_t value_len) { MDBX_val key = {(void *)key_bytes, key_len}, value = {(void *)value_bytes, value_len}; return mdbx_put(txn, dbi, &key, &value, MDBX_NOOVERWRITE); }
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

var (
	fixtureCreateExtraDBI   func(string) bool
	fixtureBeforeInitCensus func(*C.MDBX_txn, C.MDBX_dbi) error
)

type engineOperation string

const (
	operationCreate     engineOperation = "create"
	operationOpen       engineOperation = "open"
	operationInit       engineOperation = "init"
	operationAbort      engineOperation = "abort"
	operationClose      engineOperation = "close"
	operationView       engineOperation = "view"
	operationGet        engineOperation = "get"
	operationPrefixPage engineOperation = "prefix-page"
	operationInspect    engineOperation = "inspect"
	operationUpdate     engineOperation = "update"
)

func validEngineOperation(operation engineOperation) bool {
	switch operation {
	case operationCreate, operationOpen, operationInit, operationAbort, operationClose, operationView, operationGet, operationPrefixPage, operationInspect, operationUpdate:
		return true
	}
	return false
}

type EngineClass string

const (
	EngineInvalidInput   EngineClass = "InvalidInput"
	EngineIntegrity      EngineClass = "Integrity"
	EngineCapacity       EngineClass = "Capacity"
	EngineConcurrency    EngineClass = "Concurrency"
	EngineTransaction    EngineClass = "Transaction"
	EngineIO             EngineClass = "IO"
	EngineStateMismatch  EngineClass = "StateMismatch"
	EngineLocalInvariant EngineClass = "LocalInvariant"
)

type EngineError struct {
	Class          EngineClass
	Operation      string
	Code           int
	Diagnostic     string
	Cause          error
	ReopenRequired bool
}

func (e *EngineError) Error() string {
	if e == nil {
		return "<nil>"
	}
	message := fmt.Sprintf("%s: %s: code %d: %s", e.Operation, e.Class, e.Code, e.Diagnostic)
	if e.Cause != nil {
		message += ": " + e.Cause.Error()
	}
	return message
}

func (e *EngineError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

const (
	codeSuccess, codeResultTrue                                                          = int(C.MDBX_SUCCESS), int(C.MDBX_RESULT_TRUE)
	codePageNotFound, codeCorrupted, codePanic, codeVersionMismatch, codeInvalid         = int(C.MDBX_PAGE_NOTFOUND), int(C.MDBX_CORRUPTED), int(C.MDBX_PANIC), int(C.MDBX_VERSION_MISMATCH), int(C.MDBX_INVALID)
	codeMapFull, codeDBsFull, codeReadersFull, codeTxnFull, codeCursorFull, codePageFull = int(C.MDBX_MAP_FULL), int(C.MDBX_DBS_FULL), int(C.MDBX_READERS_FULL), int(C.MDBX_TXN_FULL), int(C.MDBX_CURSOR_FULL), int(C.MDBX_PAGE_FULL)
	codeUnableExtendMapsize, codeBadRSlot, codeBadTxn, codeBadValSize, codeBadDBI        = int(C.MDBX_UNABLE_EXTEND_MAPSIZE), int(C.MDBX_BAD_RSLOT), int(C.MDBX_BAD_TXN), int(C.MDBX_BAD_VALSIZE), int(C.MDBX_BAD_DBI)
	codeProblem, codeBadSignature, codeWannaRecovery, codeKeyMismatch                    = int(C.MDBX_PROBLEM), int(C.MDBX_EBADSIGN), int(C.MDBX_WANNA_RECOVERY), int(C.MDBX_EKEYMISMATCH)
	codeTooLarge, codeThreadMismatch, codeMultiValue, codeTxnOverlapping                 = int(C.MDBX_TOO_LARGE), int(C.MDBX_THREAD_MISMATCH), int(C.MDBX_EMULTIVAL), int(C.MDBX_TXN_OVERLAPPING)
	codeBacklogDepleted, codeDuplicatedLock, codeDanglingDBI, codeOusted                 = int(C.MDBX_BACKLOG_DEPLETED), int(C.MDBX_DUPLICATED_LCK), int(C.MDBX_DANGLING_DBI), int(C.MDBX_OUSTED)
	codeMVCCRetarded, codeLaggardReader, codeBusy, codeEINVAL, codeEIO                   = int(C.MDBX_MVCC_RETARDED), int(C.MDBX_LAGGARD_READER), int(C.MDBX_BUSY), int(C.MDBX_EINVAL), int(C.MDBX_EIO)
	codeEROFS, codeEREMOTE, codeEAccess, codeEPerm, codeEIntr, codeEDeadlock             = int(C.MDBX_EROFS), int(C.MDBX_EREMOTE), int(C.MDBX_EACCESS), int(C.MDBX_EPERM), int(C.MDBX_EINTR), int(C.MDBX_EDEADLK)
	codeENOMEM, codeEExist, codeENOFile, codeIncompatible                                = int(C.MDBX_ENOMEM), int(C.MDBX_EEXIST), int(C.MDBX_ENOFILE), int(C.MDBX_INCOMPATIBLE)
	codeKeyExist, codeNotFound                                                           = int(C.MDBX_KEYEXIST), int(C.MDBX_NOTFOUND)
	codeENODEV, codeESTALE, codeENOSPC, codeEDQUOT                                       = int(syscall.ENODEV), int(syscall.ESTALE), int(syscall.ENOSPC), int(syscall.EDQUOT)
)

func fixedNativeClass(code int) (EngineClass, bool) {
	switch code {
	case codeBadValSize, codeEINVAL:
		return EngineInvalidInput, true
	case codePageNotFound, codeCorrupted, codePanic, codeVersionMismatch, codeInvalid,
		codeWannaRecovery, codeDuplicatedLock, codeCursorFull:
		return EngineIntegrity, true
	case codeMapFull, codeUnableExtendMapsize, codeENOMEM, codeENOSPC, codeEDQUOT:
		return EngineCapacity, true
	case codeReadersFull, codeBusy, codeLaggardReader, codeEDeadlock:
		return EngineConcurrency, true
	case codeTxnFull, codeResultTrue:
		return EngineTransaction, true
	case codeBadRSlot, codePageFull, codeBadDBI, codeDBsFull, codeMultiValue,
		codeKeyMismatch, codeBadTxn, codeThreadMismatch, codeTxnOverlapping,
		codeOusted, codeMVCCRetarded, codeProblem, codeBacklogDepleted,
		codeDanglingDBI, codeBadSignature:
		return EngineLocalInvariant, true
	case codeENOFile, codeEIO, codeEROFS, codeENODEV, codeESTALE, codeEREMOTE,
		codeEAccess, codeEPerm, codeEIntr:
		return EngineIO, true
	default:
		return "", false
	}
}

func chooseClass(condition bool, yes, no EngineClass) EngineClass {
	if condition {
		return yes
	}
	return no
}

func classifyNative(operation engineOperation, code int) EngineClass {
	if class, ok := fixedNativeClass(code); ok {
		return class
	}
	switch code {
	case codeIncompatible:
		if operation == operationCreate {
			return EngineInvalidInput
		}
		if operation == operationOpen {
			return EngineIntegrity
		}
		return EngineLocalInvariant
	case codeTooLarge:
		return chooseClass(operation == operationCreate, EngineInvalidInput, EngineCapacity)
	case codeEExist:
		return chooseClass(operation == operationCreate, EngineInvalidInput, EngineIO)
	default:
		return chooseClass(code < 0, EngineLocalInvariant, EngineIO)
	}
}

func reopenRequired(code int) bool {
	switch code {
	case codePageNotFound, codeCorrupted, codePanic, codeVersionMismatch, codeInvalid,
		codeCursorFull, codeUnableExtendMapsize, codeBadSignature, codeWannaRecovery,
		codeDuplicatedLock, codeThreadMismatch:
		return true
	default:
		return false
	}
}

func validEngineClass(operation engineOperation, class EngineClass) bool {
	if class == EngineStateMismatch {
		return operation == operationUpdate
	}
	return class == EngineInvalidInput || class == EngineIntegrity || class == EngineCapacity || class == EngineConcurrency || class == EngineTransaction || class == EngineIO || class == EngineLocalInvariant
}

func engineError(operation engineOperation, class EngineClass, code int, diagnostic string, cause error) *EngineError {
	if !validEngineOperation(operation) {
		return &EngineError{EngineLocalInvariant, string(operationInit), codeProblem, "unsupported engine operation", cause, false}
	}
	if !validEngineClass(operation, class) {
		return &EngineError{EngineLocalInvariant, string(operation), codeProblem, "unsupported engine class", cause, false}
	}
	return &EngineError{class, string(operation), code, diagnostic, cause, reopenRequired(code)}
}

func nativeDiagnostic(code int) string {
	cCode := C.int(code)
	if int(cCode) != code {
		return fmt.Sprintf("error code %d outside C int range", code)
	}
	if code >= 0 {
		return fmt.Sprintf("error %d", code)
	}
	if diagnostic := C.mdbx_liberr2str(cCode); diagnostic != nil {
		return C.GoString(diagnostic)
	}
	return fmt.Sprintf("error %d", code)
}

func nativeError(operation engineOperation, code int) *EngineError {
	if !validEngineOperation(operation) {
		return engineError(operation, EngineLocalInvariant, code, "", nil)
	}
	if code == codeSuccess {
		return nil
	}
	return engineError(operation, classifyNative(operation, code), code, nativeDiagnostic(code), nil)
}

func metadataError(operation engineOperation, code, ownershipCode int) *EngineError {
	err := nativeError(operation, code)
	if err == nil {
		return nil
	}
	if err.Code == code && code == ownershipCode && (code == codeKeyExist || code == codeNotFound) {
		return engineError(operation, EngineIntegrity, err.Code, err.Diagnostic, err.Cause)
	}
	return err
}

func adapterError(operation engineOperation, class EngineClass, code int, diagnostic string, cause error) *EngineError {
	return engineError(operation, class, code, diagnostic, cause)
}

func integrityError(operation engineOperation, diagnostic string, cause error) *EngineError {
	return adapterError(operation, EngineIntegrity, codeInvalid, diagnostic, cause)
}

func ioError(operation engineOperation, diagnostic string, cause error) *EngineError {
	code := codeEIO
	var errno syscall.Errno
	if errors.As(cause, &errno) {
		code = int(errno)
	}
	return adapterError(operation, classifyNative(operation, code), code, diagnostic, cause)
}

func writerLockError(operation engineOperation, result filelock.Result, cause error) *EngineError {
	switch result {
	case filelock.ResultContended:
		return adapterError(operation, EngineConcurrency, codeBusy, "Rubin writer lock is already held", cause)
	case filelock.ResultInvalidOrUnopenable:
		err := ioError(operation, "acquire Rubin writer lock", cause)
		return engineError(operation, EngineIO, err.Code, err.Diagnostic, err.Cause)
	default:
		return adapterError(operation, EngineLocalInvariant, codeProblem, "unsupported writer-lock result", cause)
	}
}

type storeState string

const (
	storeOPEN           storeState = "OPEN"
	storeCLOSEBLOCKED   storeState = "CLOSE_BLOCKED"
	storeCLOSED         storeState = "CLOSED"
	storePOISONEDTHREAD storeState = "POISONED_THREAD"
)

type errorOrder uint8

const (
	orderNone errorOrder = iota
	orderPrimary
	orderResult
	orderPrimaryResult
	orderResultCausesPrimary
)

type nativeTransition struct {
	consumed bool
	next     storeState
	order    errorOrder
}

func commitTransition(code int) nativeTransition {
	switch code {
	case codeSuccess:
		return nativeTransition{true, storeOPEN, orderNone}
	case codeThreadMismatch:
		return nativeTransition{false, storePOISONEDTHREAD, orderResult}
	default:
		return nativeTransition{true, storeCLOSED, orderResult}
	}
}

func abortTransition(code int, hasPrimary bool) nativeTransition {
	switch code {
	case codeThreadMismatch:
		return nativeTransition{false, storePOISONEDTHREAD, chooseOrder(hasPrimary, orderResultCausesPrimary, orderResult)}
	case codeSuccess:
		return nativeTransition{true, chooseState(hasPrimary, storeCLOSED, storeOPEN), chooseOrder(hasPrimary, orderPrimary, orderNone)}
	default:
		return nativeTransition{true, storeCLOSED, chooseOrder(hasPrimary, orderPrimaryResult, orderResult)}
	}
}

func closeTransition(code int, hasPrimary bool) nativeTransition {
	switch code {
	case codeBusy:
		return nativeTransition{false, storeCLOSEBLOCKED, chooseOrder(hasPrimary, orderResultCausesPrimary, orderResult)}
	case codeSuccess:
		return nativeTransition{true, storeCLOSED, chooseOrder(hasPrimary, orderPrimary, orderNone)}
	default:
		return nativeTransition{true, storeCLOSED, chooseOrder(hasPrimary, orderPrimaryResult, orderResult)}
	}
}

func chooseOrder(condition bool, yes, no errorOrder) errorOrder {
	if condition {
		return yes
	}
	return no
}

func chooseState(condition bool, yes, no storeState) storeState {
	if condition {
		return yes
	}
	return no
}

//nolint:errorlint // Native cleanup results must be direct EngineError pointers.
func directNativeResult(operation engineOperation, result error) (*EngineError, bool) {
	engine, ok := result.(*EngineError)
	return engine, ok && engine != nil && engine.Operation == string(operation) && validEngineClass(operation, engine.Class) && engine.Code != codeSuccess && engine.Class == classifyNative(operation, engine.Code) && engine.ReopenRequired == reopenRequired(engine.Code)
}

func errorOrderShape(order errorOrder) (bool, bool, bool) {
	switch order {
	case orderNone:
		return false, false, true
	case orderPrimary:
		return true, false, true
	case orderResult:
		return false, true, true
	case orderPrimaryResult, orderResultCausesPrimary:
		return true, true, true
	default:
		return false, false, false
	}
}

func orderedErrors(operation engineOperation, order errorOrder, primary, result error) error {
	if !validEngineOperation(operation) {
		return adapterError(operation, EngineLocalInvariant, codeProblem, "unsupported engine operation", joinErrors(primary, result))
	}
	needsPrimary, needsResult, knownOrder := errorOrderShape(order)
	if !knownOrder {
		return composeOrderedErrors(operation, order, primary, result, nil)
	}
	hasPrimary, hasResult := primary != nil, result != nil
	if hasPrimary != needsPrimary || hasResult != needsResult {
		return adapterError(operation, EngineLocalInvariant, codeProblem, "native errors do not match ordering", joinErrors(primary, result))
	}
	engine, validResult := directNativeResult(operation, result)
	if needsResult && !validResult {
		return adapterError(operation, EngineLocalInvariant, codeProblem, "native result is not an EngineError", joinErrors(primary, result))
	}
	return composeOrderedErrors(operation, order, primary, result, engine)
}

func composeOrderedErrors(operation engineOperation, order errorOrder, primary, result error, engine *EngineError) error {
	switch order {
	case orderNone:
		return nil
	case orderPrimary:
		return joinErrors(primary)
	case orderResult:
		return result
	case orderPrimaryResult:
		return joinErrors(primary, result)
	case orderResultCausesPrimary:
		copy := *engine
		copy.Cause = joinErrors(primary, engine.Cause)
		return &copy
	default:
		return adapterError(operation, EngineLocalInvariant, codeProblem, "invalid native result ordering", joinErrors(primary, result))
	}
}

func requiredValueResult(operation engineOperation, rc int, length uint64, present bool, expected uint64) error {
	if !validEngineOperation(operation) {
		return adapterError(operation, EngineLocalInvariant, codeProblem, "unsupported engine operation", nil)
	}
	if rc != codeSuccess {
		return metadataError(operation, rc, codeNotFound)
	}
	if length != expected || !present {
		return integrityError(operation, "required metadata width mismatch", nil)
	}
	return nil
}

func joinErrors(errs ...error) error {
	nonNil := make([]error, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			nonNil = append(nonNil, err)
		}
	}
	switch len(nonNil) {
	case 0:
		return nil
	case 1:
		return nonNil[0]
	default:
		return errors.Join(nonNil...)
	}
}

type Store struct {
	operations    sync.RWMutex
	self          *Store
	env           *C.MDBX_env
	writer        *filelock.Handle
	txn           *C.MDBX_txn
	config        ConfigV1
	dbis          [8]C.MDBX_dbi
	state         storeState
	terminal      error
	terminalTruth CommitTruth

	// canonicalOwnerVerified is this handle's canonical-owner verification (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.6):
	// only the Create publication and bootstrapBatch after its exact-empty census set it, Open never does, and every
	// non-OPEN state refuses before a Reader exists, so nothing clears it.
	canonicalOwnerVerified bool
}

type Reader struct {
	self       *Reader
	txn        *C.MDBX_txn
	dbis       [8]C.MDBX_dbi
	getMu      sync.Mutex
	active     atomic.Bool
	failure    error
	largeVisit atomic.Bool
	maxKey     uint64
	updateOld  bool
	tip        *canonicalTipCell

	// ownerVerified is the Store's canonical-owner verification copied when Update or View created this Reader.
	ownerVerified bool
}

const (
	// MaxPrefixPageRows bounds copied rows and permits one native lookahead.
	MaxPrefixPageRows uint32 = 1_440
	// MaxPrefixPageBytes bounds the sum of copied key and value bytes.
	MaxPrefixPageBytes uint64 = MaxOperationDataBytes
)

// PrefixPageStop identifies the exact reason a successful page ended.
type PrefixPageStop uint8

const (
	// PrefixPageExhausted means no greater in-prefix row exists.
	PrefixPageExhausted PrefixPageStop = iota + 1
	// PrefixPageRowLimit means another valid row exists beyond the row cap.
	PrefixPageRowLimit
	// PrefixPageByteLimit means another valid row exceeds the byte cap.
	PrefixPageByteLimit
)

// PrefixRow owns independent Go copies of one native key and value.
type PrefixRow struct {
	Key   []byte
	Value []byte
}

// PrefixPage is an ordered finite page from one Reader snapshot. Successful
// pages have a nonzero Stop; an error returns the zero PrefixPage.
type PrefixPage struct {
	Rows []PrefixRow
	Stop PrefixPageStop
}

type DBIInspection struct {
	DBI           DBI
	Entries       uint64
	Depth         uint32
	BranchPages   uint64
	LeafPages     uint64
	OverflowPages uint64
	PageSize      uint32
}

type Inspection struct {
	Config            ConfigV1
	MapSize           uint64
	FileSize          uint64
	AllocatedSize     uint64
	MaxReaders        uint32
	ReaderTableLength uint32
	RecentTxnID       uint64
	LatterReaderTxnID uint64
	UnsyncBytes       uint64
	DBIs              [8]DBIInspection
}

type getResult uint8

const (
	getResultAbsent getResult = iota
	getResultEmpty
	getResultCopy
	getResultInvalidShape
	getResultInvalidBound
	getResultNative
)

type AfterKind uint8

const (
	AfterAbsent AfterKind = iota + 1
	AfterLiteral
	// AfterOldValueRef installs into the absent Key the exact bytes the OLD snapshot holds at RefDBI/RefKey; those source bytes
	// are read from OLD and are neither validated nor consumed. Two directions are admitted by the common grammar: an undo-v1
	// entry referencing a utxo-v1 row (Key[41:77] == RefKey[8:44]) and a utxo-v1 row referencing an undo-v1 entry (Key[8:44] ==
	// RefKey[41:77]); Batch.Reverse refuses the forward one (the undo-v1 destination). Only those outpoint bytes are bound; the
	// image ID and the undo block hash, transaction index and input index are used as supplied. A reference carries Literal
	// nil and BeforePresent false.
	AfterOldValueRef
)

type Mutation struct {
	DBI           DBI
	Key           []byte
	BeforePresent bool
	AfterKind     AfterKind
	Literal       []byte
	RefDBI        DBI
	RefKey        []byte
}

// ConsultedRow names one exact-key row the callback read and requires unchanged through commit; it carries no value
// and no expected bytes (RUBIN_MEMPOOL_POLICY.md Section 6.4.1).
type ConsultedRow struct {
	DBI DBI
	Key []byte
}

type Batch struct {
	// Mutations is the admitted plan. Canonical-v1 (rank 2) and canonical-owner-v1 (rank 7) targets must keep both paths
	// bijective (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.3). N1: a forward literal (g,h)->x needs an owner literal target
	// (g,x) holding h. N2: an owner literal (g,x)->h needs a forward literal target (g,h) naming x. O1: a forward target
	// whose OLD value is exactly 104 bytes naming x, and whose NEW value is absent or names another hash, needs an owner
	// target (g,x) whenever the OLD owner (g,x) is exactly 8 bytes holding h. O2: an owner target whose OLD value is
	// exactly 8 bytes holding h, and whose NEW value is absent or holds another height, needs a forward target (g,h)
	// whenever the OLD forward (g,h) is exactly 104 bytes naming x. An OLD value of another width or an unpaired OLD
	// partner creates no obligation. The rules run after every OLD image is captured and before the OLD/write
	// comparison, in the order N1, N2, O1, O2 over targets in plan order; the first violation returns the direct
	// EngineInvalidInput refusal "unpaired canonical owner mutation" (operation update, code EINVAL, no cause), and a
	// failed OLD read of a non-target partner returns its native error unchanged. Either result is CommitTruthOld at
	// UpdateStagePrewrite with nothing written; the Store is consumed when the write/OLD aborts and the environment close
	// succeed, and a retained abort or close keeps the existing POISONED_THREAD or CLOSE_BLOCKED lifecycle.
	Mutations []Mutation
	// Reverse selects the reverse-block admission envelope. True refuses a rank-1 literal, a rank-5 literal and a rank-5
	// reference with the same direct InvalidInput refusal ("invalid Update Batch") as a malformed row, decided before ordering,
	// literal validation and every charge, so only an admitted row can exhaust a family or a ceiling into Capacity; it counts
	// rank-1 deletions up to maxUpdateOutputs, rank-1 references up to maxUpdateInputs, 77-byte tag-1 rank-5 deletions up to
	// maxUpdateInputs, every other admitted row up to maxUpdateAux, and key bytes up to maxReverseKeyBytes; the mutation
	// count and literal bytes keep maxUpdateMutations and maxUpdateLiterals in both modes. False, the zero value, keeps the
	// default domain and ceilings. Only admission reads it: the owned plan and the native path carry no mode.
	Reverse bool
	// Consulted lists rows compared unchanged against OLD, the write snapshot, the final image and any possible-crossed readback,
	// with no delete and no put. Admitted after every mutation: exact SchemaV2 DBI/key shape, strict (DBI.Rank, key) increase and
	// the 16,384-row count are decided per row in declared order, then disjointness from every target and OLD_VALUE_REF source
	// over that set, so an over-cap overlapping set refuses as Capacity; at most MaxOperationDataBytes present-value bytes,
	// qualified once from OLD before any write transaction. Values are not retained: each comparison rereads the same protected
	// ORIGINAL OLD transaction. Those refusals return the direct EngineError, truth OLD and, when the
	// OLD abort succeeds, an open reusable Store; an abort failure keeps the existing terminal or retained lifecycle, and a
	// native qualification read failure keeps its error and the existing infrastructure lifecycle. A later OLD read failure before
	// commit returns its native error with truth OLD; during possible-crossed readback it returns truth UNKNOWN and a CommitError
	// retaining the original commit cause and the read failure in ReadbackCause. These failures consume the Store when aborts and
	// environment close succeed; retained abort or close keeps the existing POISONED_THREAD or CLOSE_BLOCKED lifecycle.
	// A row differing from that OLD image
	// at the write snapshot or the final image returns EngineStateMismatch, truth OLD and no reusable Store. A possible-crossed
	// readback mismatch fails both predicates: Update returns CommitTruthUnknown with the original CommitError. Nil and empty
	// behave alike; the caller leaves rows and key bytes unchanged until Update returns.
	Consulted []ConsultedRow
	// ContextConsulted names one finite unchanged OLD canonical index/header window; nil adds no domain.
	// The descriptor is copied by value; the caller leaves Batch unchanged until Update returns.
	ContextConsulted *CanonicalContextWindowV1
	// LargeConsulted proves complete physical body/family residuals alongside the exact mutation and reference predicates.
	LargeConsulted []LargeImageSelectorV1
	// ObsoleteDeletes removes same-OLD observed present rows; every row needs a covering witness.
	ObsoleteDeletes []ObsoleteRowV1
	// ObsoleteConsulted retains observed physical intervals and own-projection proof points.
	ObsoleteConsulted []ObsoletePageWitnessV1
}

const (
	maxUpdateInputs    uint64 = 414_634
	maxUpdateOutputs   uint64 = 1_545_454
	maxUpdateAux       uint64 = 16_384
	maxUpdateMutations uint64 = 2_391_106
	maxUpdateKeyBytes  uint64 = 137_676_154
	maxUpdateLiterals  uint64 = 155_659_727
	maxReverseKeyBytes uint64 = 151_359_076 // 1545454*44 + 414634*121 + 414634*77 + 16384*77 (conservative: reverse auxiliary keys are at most 33 bytes)
	maxUpdateConsulted uint64 = 16_384
)

type ownedMutation struct {
	dbi           DBI
	key           []byte
	beforePresent bool
	after         AfterKind
	literal       []byte
	refDBI        DBI
	refKey        []byte
}

type updateBudget struct {
	mutations, keyBytes, literals uint64
	utxoDeletes, undoRefs         uint64
	utxoLiterals, aux             uint64
	undoEntryDeletes              uint64
	reverse                       bool
}

func updateInvalidBatch() error {
	return adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "invalid Update Batch", nil)
}

func updateBoundError() error {
	return adapterError(operationUpdate, EngineCapacity, codeTooLarge, "Update Batch exceeds bound", nil)
}

func updateAdd(total, add, limit uint64) (uint64, bool) {
	if total > limit || add > limit-total {
		return 0, false
	}
	return total + add, true
}

func updateClone(bytes []byte) []byte {
	if bytes == nil {
		return nil
	}
	out := make([]byte, len(bytes))
	copy(out, bytes)
	return out
}

func updateOrdered(previous, next Mutation) bool {
	return updateKeyOrdered(previous.DBI.Rank, previous.Key, next.DBI.Rank, next.Key)
}

// updateKeyOrdered reports (previousRank, previousKey) strictly before (rank, key): by rank, then by bytes.Compare.
func updateKeyOrdered(previousRank uint8, previousKey []byte, rank uint8, key []byte) bool {
	if previousRank != rank {
		return previousRank < rank
	}
	return bytes.Compare(previousKey, key) < 0
}

func updateMutableMeta(key []byte, absent bool) bool {
	if key[0] == 0 || key[0] == 1 {
		return false
	}
	return !absent || key[0] != 2
}

func updateLiteralAllowed(m Mutation) bool {
	switch m.DBI.Rank {
	case 0:
		return updateMutableMeta(m.Key, false)
	case 1, 2, 6, 7:
		return true
	case 3, 4:
		return !m.BeforePresent
	case 5:
		return m.Key[32] == 0 && !m.BeforePresent
	default:
		return false
	}
}

func updateAbsentAllowed(m Mutation) bool {
	if m.DBI.Rank != 0 {
		return true
	}
	return updateMutableMeta(m.Key, true)
}

func updateLiteralPayload(m Mutation) bool {
	return m.Literal != nil && m.RefDBI == (DBI{}) && m.RefKey == nil && updateLiteralAllowed(m)
}

func updateAbsentPayload(m Mutation) bool {
	return m.BeforePresent && m.Literal == nil && m.RefDBI == (DBI{}) && m.RefKey == nil && updateAbsentAllowed(m)
}

// updateUndoEntryKey is strictly narrower than validKey for rank 5, which also admits the 33-byte manifest.
func updateUndoEntryKey(key []byte) bool {
	return len(key) == 77 && key[32] == 1
}

func updateForwardRef(m Mutation, dbis [8]DBI) bool {
	return m.DBI == dbis[5] && updateUndoEntryKey(m.Key) && m.RefDBI == dbis[1] && validKey(m.RefDBI.Rank, m.RefKey) && bytes.Equal(m.Key[41:77], m.RefKey[8:44])
}

func updateReverseRef(m Mutation, dbis [8]DBI) bool {
	return m.DBI == dbis[1] && validKey(m.DBI.Rank, m.Key) && m.RefDBI == dbis[5] && updateUndoEntryKey(m.RefKey) && bytes.Equal(m.Key[8:44], m.RefKey[41:77])
}

func updateRefPayload(m Mutation) bool {
	dbis := SchemaV2DBIs()
	return !m.BeforePresent && m.Literal == nil && (updateForwardRef(m, dbis) || updateReverseRef(m, dbis))
}

func updateValidMutation(m Mutation) bool {
	if ValidateDBI(m.DBI) != nil || !validKey(m.DBI.Rank, m.Key) {
		return false
	}
	switch m.AfterKind {
	case AfterAbsent:
		return updateAbsentPayload(m)
	case AfterLiteral:
		return updateLiteralPayload(m)
	case AfterOldValueRef:
		return updateRefPayload(m)
	default:
		return false
	}
}

func updateKeyCharge(m Mutation) uint64 {
	charge := uint64(len(m.Key))
	if m.AfterKind == AfterOldValueRef {
		charge += uint64(len(m.RefKey))
	}
	return charge
}

// updateRefFamily holds for the forward (rank-5) and reverse (rank-1) reference destinations.
func updateRefFamily(m Mutation) bool {
	return m.AfterKind == AfterOldValueRef && (m.DBI.Rank == 1 || m.DBI.Rank == 5)
}

func updateUndoEntryDelete(m Mutation) bool {
	return m.DBI.Rank == 5 && m.AfterKind == AfterAbsent && updateUndoEntryKey(m.Key)
}

func (budget *updateBudget) addTotals(m Mutation) bool {
	var ok bool
	if budget.mutations, ok = updateAdd(budget.mutations, 1, maxUpdateMutations); !ok {
		return false
	}
	keyLimit := maxUpdateKeyBytes
	if budget.reverse {
		keyLimit = maxReverseKeyBytes
	}
	if budget.keyBytes, ok = updateAdd(budget.keyBytes, updateKeyCharge(m), keyLimit); !ok {
		return false
	}
	if budget.literals, ok = updateAdd(budget.literals, uint64(len(m.Literal)), maxUpdateLiterals); !ok {
		return false
	}
	return true
}

func (budget *updateBudget) addMutation(m Mutation) bool {
	if !budget.addTotals(m) {
		return false
	}
	if budget.reverse {
		return budget.addReverseFamily(m)
	}
	var ok bool
	switch {
	case m.DBI.Rank == 1 && m.AfterKind == AfterAbsent:
		budget.utxoDeletes, ok = updateAdd(budget.utxoDeletes, 1, maxUpdateInputs)
	case updateRefFamily(m):
		budget.undoRefs, ok = updateAdd(budget.undoRefs, 1, maxUpdateInputs)
	case m.DBI.Rank == 1 && m.AfterKind == AfterLiteral:
		budget.utxoLiterals, ok = updateAdd(budget.utxoLiterals, 1, maxUpdateOutputs)
	default:
		budget.aux, ok = updateAdd(budget.aux, 1, maxUpdateAux)
	}
	return ok
}

// addReverseFamily charges exactly one true-mode family of an admitted mutation; false reports that family exhausted.
func (budget *updateBudget) addReverseFamily(m Mutation) bool {
	var ok bool
	switch {
	case m.DBI.Rank == 1 && m.AfterKind == AfterAbsent:
		budget.utxoDeletes, ok = updateAdd(budget.utxoDeletes, 1, maxUpdateOutputs)
	case m.DBI.Rank == 1 && m.AfterKind == AfterOldValueRef:
		budget.undoRefs, ok = updateAdd(budget.undoRefs, 1, maxUpdateInputs)
	case updateUndoEntryDelete(m):
		budget.undoEntryDeletes, ok = updateAdd(budget.undoEntryDeletes, 1, maxUpdateInputs)
	default:
		budget.aux, ok = updateAdd(budget.aux, 1, maxUpdateAux)
	}
	return ok
}

// admits reports whether the budget's mode admits a common-valid mutation: false admits every one; true refuses a
// rank-1 literal and every rank-5 row other than a deletion, admits ranks 0, 2, 3, 4, 6 and 7 unchanged, and admits
// no other rank.
func (budget *updateBudget) admits(m Mutation) bool {
	if !budget.reverse {
		return true
	}
	switch m.DBI.Rank {
	case 1:
		return m.AfterKind == AfterAbsent || m.AfterKind == AfterOldValueRef
	case 5:
		return m.AfterKind == AfterAbsent
	case 0, 2, 3, 4, 6, 7:
		return true
	default:
		return false
	}
}

func updateScanMutation(first bool, previous, mutation Mutation, budget *updateBudget) error {
	if !updateValidMutation(mutation) {
		return updateInvalidBatch()
	}
	if !budget.admits(mutation) {
		return updateInvalidBatch()
	}
	if !first && !updateOrdered(previous, mutation) {
		return updateInvalidBatch()
	}
	if mutation.AfterKind == AfterLiteral && ValidateRow(mutation.DBI, mutation.Key, mutation.Literal) != nil {
		return updateInvalidBatch()
	}
	if !budget.addMutation(mutation) {
		return updateBoundError()
	}
	return nil
}

func updateOwnedBatch(batch Batch, readers ...*Reader) ([]ownedMutation, error) {
	if len(batch.Mutations) == 0 && len(batch.ObsoleteDeletes) == 0 {
		return nil, updateInvalidBatch()
	}
	budget, previous := updateBudget{reverse: batch.Reverse}, Mutation{}
	for i, mutation := range batch.Mutations {
		scanErr := updateScanMutation(i == 0, previous, mutation, &budget)
		if scanErr != nil {
			return nil, scanErr
		}
		previous = mutation
	}
	owned := make([]ownedMutation, len(batch.Mutations))
	for i, mutation := range batch.Mutations {
		owned[i] = ownedMutation{mutation.DBI, updateClone(mutation.Key), mutation.BeforePresent, mutation.AfterKind, updateClone(mutation.Literal), mutation.RefDBI, mutation.RefKey}
	}
	if len(readers) != 0 {
		var err error
		owned, err = updateOwnedObsolete(batch, readers[0], owned)
		if err != nil {
			return nil, err
		}
	}
	updateOwnReferences(owned)
	return owned, nil
}

// Resolve references only after all targets, including obsolete additions, own their keys.
func updateOwnReferences(plan []ownedMutation) {
	for i, mutation := range plan {
		if mutation.after != AfterOldValueRef {
			continue
		}
		target := canonicalTargetIndex(plan, mutation.refDBI.Rank, mutation.refKey)
		if target >= 0 {
			plan[i].refKey = plan[target].key
			continue
		}
		plan[i].refKey = updateClone(mutation.refKey)
	}
}

// ownedConsulted retains only the admitted identity; every proof queries the protected OLD again.
type ownedConsulted struct {
	dbi DBI
	key []byte
}

// updateScanConsulted admits one row: exact DBI/key shape and strict order before its charge against maxUpdateConsulted.
func updateScanConsulted(first bool, previous, row ConsultedRow, count *uint64) error {
	if ValidateDBI(row.DBI) != nil || !validKey(row.DBI.Rank, row.Key) {
		return updateInvalidBatch()
	}
	if !first && !updateKeyOrdered(previous.DBI.Rank, previous.Key, row.DBI.Rank, row.Key) {
		return updateInvalidBatch()
	}
	var ok bool
	if *count, ok = updateAdd(*count, 1, maxUpdateConsulted); !ok {
		return updateBoundError()
	}
	return nil
}

// updateConsultedContains reports whether the strictly ordered consulted rows hold exactly (dbi, key).
func updateConsultedContains(consulted []ConsultedRow, dbi DBI, key []byte) bool {
	index := sort.Search(len(consulted), func(i int) bool {
		return !updateKeyOrdered(consulted[i].DBI.Rank, consulted[i].Key, dbi.Rank, key)
	})
	return index < len(consulted) && consulted[index].DBI == dbi && bytes.Equal(consulted[index].Key, key)
}

// updateConsultedDisjoint reports whether no mutation target and no OLD_VALUE_REF source is a consulted row.
func updateConsultedDisjoint(consulted []ConsultedRow, plan []ownedMutation) bool {
	for _, mutation := range plan {
		if updateConsultedContains(consulted, mutation.dbi, mutation.key) {
			return false
		}
		if mutation.after == AfterOldValueRef && updateConsultedContains(consulted, mutation.refDBI, mutation.refKey) {
			return false
		}
	}
	return true
}

// updateOwnedConsulted admits batch.Consulted after plan was admitted: nil for an empty set; otherwise rows are validated
// and charged in declared order, the whole set is checked disjoint from plan, and keys are cloned only after all of that.
func updateOwnedConsulted(batch Batch, plan []ownedMutation) ([]ownedConsulted, error) {
	if len(batch.Consulted) == 0 {
		return nil, nil
	}
	var count uint64
	previous := ConsultedRow{}
	for i, row := range batch.Consulted {
		scanErr := updateScanConsulted(i == 0, previous, row, &count)
		if scanErr != nil {
			return nil, scanErr
		}
		previous = row
	}
	if !updateConsultedDisjoint(batch.Consulted, plan) {
		return nil, updateInvalidBatch()
	}
	owned := make([]ownedConsulted, len(batch.Consulted))
	for i, row := range batch.Consulted {
		owned[i] = ownedConsulted{dbi: row.DBI, key: updateClone(row.Key)}
	}
	return owned, nil
}

type CommitTruth uint8

const (
	CommitTruthOld CommitTruth = iota + 1
	CommitTruthNew
	CommitTruthUnknown
)

func (truth CommitTruth) String() string {
	if truth > CommitTruthUnknown {
		return ""
	}
	return [...]string{"", "OLD", "NEW", "UNKNOWN"}[truth]
}

type CommitError struct {
	Cause         error
	Truth         CommitTruth
	ReadbackCause error
}

func (e *CommitError) Error() string {
	if e == nil {
		return "<nil>"
	}
	message := fmt.Sprintf("mdbx update %s: %v", e.Truth, e.Cause)
	if e.ReadbackCause != nil {
		message += "; readback/cleanup: " + e.ReadbackCause.Error()
	}
	return message
}

func (e *CommitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

type UpdateStage uint8

const (
	UpdateStageInvalid                         UpdateStage = 0
	UpdateStagePrewrite                        UpdateStage = 1
	UpdateStageWriteStartedDefinitelyPrecommit UpdateStage = 2
	UpdateStageCommitMayHaveCrossed            UpdateStage = 3
)

type updateNativeOutcome struct {
	truth                       CommitTruth
	stage                       UpdateStage
	commitAttempted             bool
	primary, secondary          error
	retainedWrite, retainedRead *C.MDBX_txn
}

func updateNativeInvariant(diagnostic string) error {
	return adapterError(operationUpdate, EngineLocalInvariant, codeProblem, diagnostic, nil)
}

func (outcome updateNativeOutcome) valid() error {
	if outcome.truth < CommitTruthOld || outcome.truth > CommitTruthUnknown || outcome.stage < UpdateStagePrewrite || outcome.stage > UpdateStageCommitMayHaveCrossed {
		return updateNativeInvariant("invalid update native outcome shape")
	}
	shape := outcome.validConsumed
	switch {
	case outcome.retainedWrite != nil:
		shape = outcome.validRetainedWrite
	case outcome.retainedRead != nil:
		shape = outcome.validRetainedRead
	}
	if shape() {
		return nil
	}
	return updateNativeInvariant("invalid update native outcome shape")
}

func (outcome updateNativeOutcome) validRetainedWrite() bool {
	return outcome.stage != UpdateStageCommitMayHaveCrossed && outcome.retainedRead == nil && outcome.truth == CommitTruthOld && outcome.primary != nil && (!outcome.commitAttempted || outcome.secondary == nil)
}

func (outcome updateNativeOutcome) validRetainedRead() bool {
	return outcome.stage == UpdateStageCommitMayHaveCrossed && outcome.retainedWrite == nil && outcome.commitAttempted && outcome.primary != nil && outcome.secondary != nil
}

func (outcome updateNativeOutcome) validConsumed() bool {
	if outcome.stage != UpdateStageCommitMayHaveCrossed {
		return outcome.truth == CommitTruthOld && outcome.primary != nil
	}
	return outcome.commitAttempted && (outcome.truth == CommitTruthNew || outcome.primary != nil) && (outcome.secondary == nil || outcome.primary != nil)
}

func updateNativeConsumed(truth CommitTruth, commitAttempted bool, primary, secondary error, stage UpdateStage) updateNativeOutcome {
	return updateNativeOutcome{truth: truth, stage: stage, commitAttempted: commitAttempted, primary: primary, secondary: secondary}
}

func updateNativeRetainedWrite(commitAttempted bool, primary, secondary error, txn *C.MDBX_txn, stage UpdateStage) updateNativeOutcome {
	return updateNativeOutcome{truth: CommitTruthOld, stage: stage, commitAttempted: commitAttempted, primary: primary, secondary: secondary, retainedWrite: txn}
}

func updateNativeRetainedRead(primary, secondary error, txn *C.MDBX_txn) updateNativeOutcome {
	return updateNativeOutcome{truth: CommitTruthUnknown, stage: UpdateStageCommitMayHaveCrossed, commitAttempted: true, primary: primary, secondary: secondary, retainedRead: txn}
}

func (outcome updateNativeOutcome) lockedOutcome() transactionOutcome {
	return transactionOutcome{poisoned: outcome.retainedWrite != nil || outcome.retainedRead != nil}
}

type updateImage struct {
	present bool
	bytes   unsafe.Pointer
	length  C.size_t
}

func validUpdateImage(image updateImage) bool {
	return image.present && (image.length == 0 || image.bytes != nil) || !image.present && image.length == 0 && image.bytes == nil
}

type updateReference struct {
	index, target int
}

func updateOwnedImage(value []byte) (updateImage, error) {
	if uint64(len(value)) > uint64(^C.size_t(0)) {
		return updateImage{}, updateNativeInvariant("Go length is not representable as C size_t")
	}
	image := updateImage{present: true, length: C.size_t(len(value))}
	if len(value) != 0 {
		image.bytes = unsafe.Pointer(&value[0])
	}
	return image, nil
}

func updateNativeImage(txn *C.MDBX_txn, dbi C.MDBX_dbi, key []byte) (updateImage, error) {
	keyImage, err := updateOwnedImage(key)
	if err != nil {
		return updateImage{}, err
	}
	value := C.rubin_mdbx_get(txn, dbi, keyImage.bytes, keyImage.length)
	runtime.KeepAlive(key)
	switch rc := int(value.rc); rc {
	case codeSuccess:
		image := updateImage{present: true, bytes: unsafe.Pointer(value.bytes), length: value.length}
		if !validUpdateImage(image) {
			return updateImage{}, updateNativeInvariant("mdbx_get returned invalid result shape")
		}
		return image, nil
	case codeNotFound:
		if value.bytes != nil || value.length != 0 {
			return updateImage{}, updateNativeInvariant("mdbx_get returned invalid result shape")
		}
		return updateImage{}, nil
	default:
		return updateImage{}, nativeError(operationUpdate, rc)
	}
}

// libMDBX borrows all bytes only for this synchronous point operation.
func updateNativeEqual(txn *C.MDBX_txn, dbi C.MDBX_dbi, key []byte, expected updateImage) (bool, error) {
	if !validUpdateImage(expected) {
		return false, updateNativeInvariant("invalid update image shape")
	}
	keyImage, err := updateOwnedImage(key)
	if err != nil {
		return false, err
	}
	expectedPresent := C.int(0)
	if expected.present {
		expectedPresent = 1
	}
	value := C.rubin_mdbx_get_equal(txn, dbi, keyImage.bytes, keyImage.length, expectedPresent, expected.bytes, expected.length)
	runtime.KeepAlive(key)
	if rc := int(value.rc); rc != codeSuccess && rc != codeNotFound {
		return false, nativeError(operationUpdate, rc)
	}
	if value.valid == 0 {
		return false, updateNativeInvariant("mdbx_get returned invalid result shape")
	}
	return value.equal != 0, nil
}

// largePoint borrows a checked physical value; callers hold getMu and keep txn alive.
func (r *Reader) largePoint(rank uint8, key []byte) (updateImage, error) {
	value := C.rubin_mdbx_get(r.txn, r.dbis[rank], unsafe.Pointer(&key[0]), C.size_t(len(key)))
	runtime.KeepAlive(key)
	if rc := int(value.rc); rc != codeSuccess && rc != codeNotFound {
		return updateImage{}, nativeError(operationGet, rc)
	}
	image := updateImage{present: int(value.rc) == codeSuccess, bytes: unsafe.Pointer(value.bytes), length: value.length}
	if !validUpdateImage(image) || !largeNativeShape(image.bytes, uint64(image.length)) {
		return updateImage{}, largeImageShapeError()
	}
	return image, nil
}

func (r *Reader) largeFetch(selector LargeImageSelectorV1, seek []byte) (largeNativeRow, error) {
	if selector.Kind == LargeImageBlockBodyV1 {
		image, err := r.largePoint(4, selector.Hash[:])
		return largeNativeRow{key: bytes.Clone(selector.Hash[:]), image: image}, err
	}
	value := C.rubin_mdbx_get_equal_or_great(r.txn, r.dbis[5], unsafe.Pointer(&seek[0]), C.size_t(len(seek)))
	runtime.KeepAlive(seek)
	if int(value.rc) == codeNotFound {
		return largeNativeRow{done: true}, nil
	}
	if !prefixPageFoundCode(int(value.rc)) {
		return largeNativeRow{}, nativeError(operationGet, int(value.rc))
	}
	if !largeNativeShape(unsafe.Pointer(value.value_bytes), uint64(value.value_len)) {
		return largeNativeRow{}, largeImageShapeError()
	}
	key, err := largeNativeKey(unsafe.Pointer(value.key_bytes), uint64(value.key_len), r.maxKey, seek)
	if err != nil {
		return largeNativeRow{}, err
	}
	if !bytes.HasPrefix(key, selector.Hash[:]) {
		return largeNativeRow{done: true}, nil
	}
	return largeNativeRow{key: key, image: updateImage{present: true, bytes: unsafe.Pointer(value.value_bytes), length: value.value_len}}, nil
}

// obsoletePoint retains no pointer beyond the already owned Reader transaction.
func (r *Reader) obsoletePoint(rank uint8, key []byte, op engineOperation) (updateImage, error) {
	value := C.rubin_mdbx_get(r.txn, r.dbis[rank], unsafe.Pointer(&key[0]), C.size_t(len(key)))
	runtime.KeepAlive(key)
	if rc := int(value.rc); rc != codeSuccess && rc != codeNotFound {
		return updateImage{}, nativeError(op, rc)
	}
	image := updateImage{present: int(value.rc) == codeSuccess, bytes: unsafe.Pointer(value.bytes), length: value.length}
	if !validUpdateImage(image) || !largeNativeShape(image.bytes, uint64(image.length)) {
		return updateImage{}, obsoleteShape(op)
	}
	return image, nil
}

func (r *Reader) obsoleteFetch(domain obsoleteDomain, seek []byte, op engineOperation) (largeNativeRow, error) {
	if seek == nil {
		return largeNativeRow{done: true}, nil
	}
	value := C.rubin_mdbx_get_equal_or_great(r.txn, r.dbis[domain.rank], unsafe.Pointer(&seek[0]), C.size_t(len(seek)))
	runtime.KeepAlive(seek)
	if int(value.rc) == codeNotFound {
		return largeNativeRow{done: true}, nil
	}
	if !prefixPageFoundCode(int(value.rc)) {
		return largeNativeRow{}, nativeError(op, int(value.rc))
	}
	if !largeNativeShape(unsafe.Pointer(value.value_bytes), uint64(value.value_len)) {
		return largeNativeRow{}, obsoleteShape(op)
	}
	key, err := largeNativeKey(unsafe.Pointer(value.key_bytes), uint64(value.key_len), r.maxKey, seek)
	if err != nil {
		return largeNativeRow{}, obsoleteShape(op)
	}
	if !bytes.HasPrefix(key, domain.prefix) {
		return largeNativeRow{done: true}, nil
	}
	return largeNativeRow{key: key, image: updateImage{present: true, bytes: unsafe.Pointer(value.value_bytes), length: value.value_len}}, nil
}

func updateNativeLargeEqual(old, candidate *C.MDBX_txn, dbis [8]C.MDBX_dbi, plan []ownedMutation, scopes ...largeImageScope) (bool, error) {
	if len(scopes) == 0 {
		return true, nil
	}
	before, after := newReader(old, dbis), newReader(candidate, dbis)
	before.maxKey, after.maxKey = scopes[0].maxKey, scopes[0].maxKey
	before.active.Store(true)
	after.active.Store(true)
	defer before.expire()
	defer after.expire()
	return largeResidualEqual(before, after, scopes[0], plan)
}

func updateNativeLargeMatch(old, candidate *C.MDBX_txn, dbis [8]C.MDBX_dbi, plan []ownedMutation, diagnostic string, scopes ...largeImageScope) error {
	equal, err := updateNativeLargeEqual(old, candidate, dbis, plan, scopes...)
	if err == nil && !equal {
		return adapterError(operationUpdate, EngineStateMismatch, codeProblem, diagnostic, nil)
	}
	return err
}

// Qualify all targets before any reference, without retaining a queried value.
func updateNativeImages(old *C.MDBX_txn, dbis [8]C.MDBX_dbi, plan []ownedMutation) ([]updateReference, error) {
	for _, mutation := range plan {
		_, err := updateNativeImage(old, dbis[mutation.dbi.Rank], mutation.key)
		if err != nil {
			return nil, err
		}
	}
	references := make([]updateReference, 0)
	for i, mutation := range plan {
		if mutation.after != AfterOldValueRef {
			continue
		}
		_, err := updateNativeReferenceImage(old, dbis, mutation)
		if err != nil {
			return nil, err
		}
		references = append(references, updateReference{index: i, target: canonicalTargetIndex(plan, mutation.refDBI.Rank, mutation.refKey)})
	}
	return references, nil
}

// The source is always ORIGINAL OLD, even when its write target was deleted or replaced.
func updateNativeReferenceImage(old *C.MDBX_txn, dbis [8]C.MDBX_dbi, mutation ownedMutation) (updateImage, error) {
	image, err := updateNativeImage(old, dbis[mutation.refDBI.Rank], mutation.refKey)
	if err == nil && !image.present {
		return updateImage{}, adapterError(operationUpdate, EngineStateMismatch, codeProblem, "OLD_VALUE_REF is absent from OLD", nil)
	}
	return image, err
}

// Consume one OLD span synchronously; no image escapes this point comparison.
func updateNativeOldEqual(old, candidate *C.MDBX_txn, dbi C.MDBX_dbi, key []byte) (bool, error) {
	image, err := updateNativeImage(old, dbi, key)
	if err != nil {
		return false, err
	}
	return updateNativeEqual(candidate, dbi, key, image)
}

func updateNativeOldMatch(old, candidate *C.MDBX_txn, dbi C.MDBX_dbi, key []byte, diagnostic string) error {
	equal, err := updateNativeOldEqual(old, candidate, dbi, key)
	if err == nil && !equal {
		return adapterError(operationUpdate, EngineStateMismatch, codeProblem, diagnostic, nil)
	}
	return err
}

func updateNativeMatch(txn *C.MDBX_txn, dbi C.MDBX_dbi, key []byte, expected updateImage, diagnostic string) error {
	equal, err := updateNativeEqual(txn, dbi, key, expected)
	if err == nil && !equal {
		return adapterError(operationUpdate, EngineStateMismatch, codeProblem, diagnostic, nil)
	}
	return err
}

// updateNativeConsultedImages qualifies each consulted row's OLD image in declared order, charging only present value
// lengths against MaxOperationDataBytes (absent and present-empty charge zero and stay distinct). It returns (false, nil),
// (false, updateBoundError()) only for its own byte charge, or (true, err) with the unchanged first updateNativeImage
// error; the flag is never derived from err.
func updateNativeConsultedImages(old *C.MDBX_txn, dbis [8]C.MDBX_dbi, consulted []ownedConsulted) (infrastructure bool, err error) {
	var total uint64
	for _, row := range consulted {
		image, readErr := updateNativeImage(old, dbis[row.dbi.Rank], row.key)
		if readErr != nil {
			return true, readErr
		}
		if image.present {
			var ok bool
			if total, ok = updateAdd(total, uint64(image.length), MaxOperationDataBytes); !ok {
				return false, updateBoundError()
			}
		}
	}
	return false, nil
}

// updateNativeConsultedMatch returns the first comparison error, or the StateMismatch diagnostic for the first consulted
// row whose candidate image differs from its current ORIGINAL OLD image.
func updateNativeConsultedMatch(old, txn *C.MDBX_txn, dbis [8]C.MDBX_dbi, consulted []ownedConsulted, diagnostic string) error {
	for _, row := range consulted {
		matchErr := updateNativeOldMatch(old, txn, dbis[row.dbi.Rank], row.key, diagnostic)
		if matchErr != nil {
			return matchErr
		}
	}
	return nil
}

// Legacy and large consulted domains are checked in order against the same OLD.
func updateNativeScopedMatch(old, candidate *C.MDBX_txn, dbis [8]C.MDBX_dbi, plan []ownedMutation, consulted []ownedConsulted, diagnostic string, scopes ...largeImageScope) error {
	err := updateNativeConsultedMatch(old, candidate, dbis, consulted, diagnostic)
	if err != nil {
		return err
	}
	err = updateNativeLargeMatch(old, candidate, dbis, plan, diagnostic, scopes...)
	if err != nil {
		return err
	}
	equal, err := canonicalTipEqual(candidate, dbis[2], scopes...)
	if err == nil && !equal {
		return adapterError(operationUpdate, EngineStateMismatch, codeProblem, diagnostic, nil)
	}
	return err
}

func updateNativePreflight(old, write *C.MDBX_txn, dbis [8]C.MDBX_dbi, plan []ownedMutation, consulted []ownedConsulted, scopes ...largeImageScope) ([]updateReference, error) {
	references, err := updateNativePairedImages(old, dbis, plan)
	if err != nil {
		return nil, err
	}
	for _, mutation := range plan {
		err = updateNativeOldMatch(old, write, dbis[mutation.dbi.Rank], mutation.key, "OLD/write snapshot mismatch")
		if err != nil {
			return nil, err
		}
	}
	for _, reference := range references {
		if reference.target >= 0 {
			continue
		}
		mutation := plan[reference.index]
		err = updateNativeOldMatch(old, write, dbis[mutation.refDBI.Rank], mutation.refKey, "OLD/write snapshot mismatch")
		if err != nil {
			return nil, err
		}
	}
	err = updateNativeScopedMatch(old, write, dbis, plan, consulted, "OLD/write snapshot mismatch", scopes...)
	if err != nil {
		return nil, err
	}
	return references, nil
}

// libMDBX does not retain either Go-owned literal or OLD-borrowed bytes.
func updateNativePut(txn *C.MDBX_txn, dbi C.MDBX_dbi, key []byte, value updateImage, keep []byte, stage *UpdateStage) error {
	if !value.present || !validUpdateImage(value) {
		return updateNativeInvariant("invalid update value shape")
	}
	keyImage, err := updateOwnedImage(key)
	if err != nil {
		return err
	}
	*stage = UpdateStageWriteStartedDefinitelyPrecommit
	rc := int(C.rubin_mdbx_put_nooverwrite(txn, dbi, keyImage.bytes, keyImage.length, value.bytes, value.length))
	runtime.KeepAlive(key)
	runtime.KeepAlive(keep)
	if rc == codeKeyExist {
		return adapterError(operationUpdate, EngineStateMismatch, rc, nativeDiagnostic(rc), nil)
	}
	if rc != codeSuccess {
		return nativeError(operationUpdate, rc)
	}
	return nil
}

func updateNativeDeletes(txn *C.MDBX_txn, dbis [8]C.MDBX_dbi, plan []ownedMutation, stage *UpdateStage) error {
	for _, mutation := range plan {
		if mutation.beforePresent {
			keyImage, keyErr := updateOwnedImage(mutation.key)
			if keyErr != nil {
				return keyErr
			}
			*stage = UpdateStageWriteStartedDefinitelyPrecommit
			rc := int(C.rubin_mdbx_del_exact(txn, dbis[mutation.dbi.Rank], keyImage.bytes, keyImage.length))
			runtime.KeepAlive(mutation.key)
			if rc == codeNotFound {
				return adapterError(operationUpdate, EngineStateMismatch, rc, nativeDiagnostic(rc), nil)
			}
			if rc != codeSuccess {
				return nativeError(operationUpdate, rc)
			}
		}
	}
	return nil
}

func updateNativeFinalImage(old *C.MDBX_txn, dbis [8]C.MDBX_dbi, mutation ownedMutation, references []updateReference, at *int, index int) (updateImage, error) {
	switch mutation.after {
	case AfterAbsent:
		return updateImage{}, nil
	case AfterLiteral:
		return updateOwnedImage(mutation.literal)
	case AfterOldValueRef:
		if *at >= len(references) || references[*at].index != index {
			return updateImage{}, updateNativeInvariant("invalid update reference shape")
		}
		*at++
		return updateNativeReferenceImage(old, dbis, mutation)
	default:
		return updateImage{}, updateNativeInvariant("invalid update final image")
	}
}

func updateNativePuts(old, txn *C.MDBX_txn, dbis [8]C.MDBX_dbi, plan []ownedMutation, references []updateReference, stage *UpdateStage) error {
	refAt := 0
	for i, mutation := range plan {
		image, err := updateNativeFinalImage(old, dbis, mutation, references, &refAt, i)
		if err != nil {
			return err
		}
		if mutation.after == AfterAbsent {
			continue
		}
		putErr := updateNativePut(txn, dbis[mutation.dbi.Rank], mutation.key, image, mutation.literal, stage)
		if putErr != nil {
			return putErr
		}
	}
	if refAt != len(references) {
		return updateNativeInvariant("invalid update reference shape")
	}
	return nil
}

func updateNativeVerify(old, txn *C.MDBX_txn, dbis [8]C.MDBX_dbi, plan []ownedMutation, references []updateReference) error {
	refAt := 0
	for i, mutation := range plan {
		image, err := updateNativeFinalImage(old, dbis, mutation, references, &refAt, i)
		if err != nil {
			return err
		}
		err = updateNativeMatch(txn, dbis[mutation.dbi.Rank], mutation.key, image, "final update image mismatch")
		runtime.KeepAlive(mutation.literal)
		if err != nil {
			return err
		}
	}
	if refAt != len(references) {
		return updateNativeInvariant("invalid update reference shape")
	}
	return updateNativeVerifyReferences(old, txn, dbis, plan, references)
}

func updateNativeVerifyReferences(old, txn *C.MDBX_txn, dbis [8]C.MDBX_dbi, plan []ownedMutation, references []updateReference) error {
	for _, reference := range references {
		if reference.target >= 0 {
			continue
		}
		mutation := plan[reference.index]
		matchErr := updateNativeOldMatch(old, txn, dbis[mutation.refDBI.Rank], mutation.refKey, "final update image mismatch")
		if matchErr != nil {
			return matchErr
		}
	}
	return nil
}

func updateNativeAbort(txn *C.MDBX_txn, primary error, stage UpdateStage) updateNativeOutcome {
	rc := int(C.mdbx_txn_abort(txn))
	if rc == codeThreadMismatch {
		return updateNativeRetainedWrite(false, primary, nativeError(operationAbort, rc), txn, stage)
	}
	var secondary error
	if rc != codeSuccess {
		secondary = nativeError(operationAbort, rc)
	}
	return updateNativeConsumed(CommitTruthOld, false, primary, secondary, stage)
}

func updateNativeReadbackTruth(old, read *C.MDBX_txn, dbis [8]C.MDBX_dbi, plan []ownedMutation, consulted []ownedConsulted, scopes ...largeImageScope) (CommitTruth, error) {
	references, err := updateNativeImages(old, dbis, plan)
	if err != nil {
		return CommitTruthUnknown, err
	}
	oldImage, newImage, err := updateNativeReadbackTargets(old, read, dbis, plan, references)
	if err != nil {
		return CommitTruthUnknown, err
	}
	oldImage, newImage, err = updateNativeReadbackReferences(old, read, dbis, plan, references, oldImage, newImage)
	if err != nil {
		return CommitTruthUnknown, err
	}
	oldImage, newImage, err = updateNativeReadbackScoped(old, read, dbis, plan, consulted, oldImage, newImage, scopes...)
	if err != nil {
		return CommitTruthUnknown, err
	}
	if oldImage {
		return CommitTruthOld, nil
	}
	if newImage {
		return CommitTruthNew, nil
	}
	return CommitTruthUnknown, nil
}

// Finish every consulted domain before selecting OLD first or planned NEW.
func updateNativeReadbackScoped(old, read *C.MDBX_txn, dbis [8]C.MDBX_dbi, plan []ownedMutation, consulted []ownedConsulted, oldImage, newImage bool, scopes ...largeImageScope) (bool, bool, error) {
	oldImage, newImage, err := updateNativeReadbackConsulted(old, read, dbis, consulted, oldImage, newImage)
	if err != nil {
		return false, false, err
	}
	residual, err := updateNativeLargeEqual(old, read, dbis, plan, scopes...)
	if err != nil {
		return false, false, err
	}
	endpoint, err := canonicalTipEqual(read, dbis[2], scopes...)
	if err != nil {
		return false, false, err
	}
	return oldImage && residual && endpoint, newImage && residual && endpoint, nil
}

func updateNativeReadbackTargets(old, read *C.MDBX_txn, dbis [8]C.MDBX_dbi, plan []ownedMutation, references []updateReference) (bool, bool, error) {
	oldImage, newImage, refAt := true, true, 0
	for i, mutation := range plan {
		oldEqual, oldErr := updateNativeOldEqual(old, read, dbis[mutation.dbi.Rank], mutation.key)
		if oldErr != nil {
			return false, false, oldErr
		}
		oldImage = oldImage && oldEqual
		final, finalErr := updateNativeFinalImage(old, dbis, mutation, references, &refAt, i)
		if finalErr != nil {
			return false, false, finalErr
		}
		newEqual, newErr := updateNativeEqual(read, dbis[mutation.dbi.Rank], mutation.key, final)
		runtime.KeepAlive(mutation.literal)
		if newErr != nil {
			return false, false, newErr
		}
		newImage = newImage && newEqual
	}
	if refAt != len(references) {
		return false, false, updateNativeInvariant("invalid update reference shape")
	}
	return oldImage, newImage, nil
}

func updateNativeReadbackReferences(old, read *C.MDBX_txn, dbis [8]C.MDBX_dbi, plan []ownedMutation, references []updateReference, oldImage, newImage bool) (bool, bool, error) {
	for _, reference := range references {
		if reference.target >= 0 {
			continue
		}
		mutation := plan[reference.index]
		equal, compareErr := updateNativeOldEqual(old, read, dbis[mutation.refDBI.Rank], mutation.refKey)
		if compareErr != nil {
			return false, false, compareErr
		}
		oldImage, newImage = oldImage && equal, newImage && equal
	}
	return oldImage, newImage, nil
}

// Requery and fold every consulted identity into both predicates, even after both are false.
func updateNativeReadbackConsulted(old, read *C.MDBX_txn, dbis [8]C.MDBX_dbi, consulted []ownedConsulted, oldImage, newImage bool) (bool, bool, error) {
	for _, row := range consulted {
		equal, compareErr := updateNativeOldEqual(old, read, dbis[row.dbi.Rank], row.key)
		if compareErr != nil {
			return false, false, compareErr
		}
		oldImage, newImage = oldImage && equal, newImage && equal
	}
	return oldImage, newImage, nil
}

func updateNativeReadback(env *C.MDBX_env, dbis [8]C.MDBX_dbi, plan []ownedMutation, consulted []ownedConsulted, old *C.MDBX_txn, primary error, scopes ...largeImageScope) updateNativeOutcome {
	begun := C.rubin_mdbx_txn_begin(env, C.MDBX_TXN_RDONLY)
	beginErr := nativePointerResultError(operationUpdate, "mdbx_txn_begin returned invalid result shape", int(begun.rc), begun.txn != nil)
	if beginErr != nil {
		if begun.txn != nil {
			return updateNativeRetainedRead(primary, beginErr, begun.txn)
		}
		return updateNativeConsumed(CommitTruthUnknown, true, primary, beginErr, UpdateStageCommitMayHaveCrossed)
	}
	truth, readErr := updateNativeReadbackTruth(old, begun.txn, dbis, plan, consulted, scopes...)
	rc := int(C.mdbx_txn_abort(begun.txn))
	if rc == codeThreadMismatch {
		retained := updateNativeRetainedRead(primary, joinErrors(readErr, nativeError(operationAbort, rc)), begun.txn)
		retained.truth = truth
		return retained
	}
	var abortErr error
	if rc != codeSuccess {
		abortErr = nativeError(operationAbort, rc)
	}
	if readErr != nil {
		truth = CommitTruthUnknown
	}
	return updateNativeConsumed(truth, true, primary, joinErrors(readErr, abortErr), UpdateStageCommitMayHaveCrossed)
}

func updateNativeCommit(env *C.MDBX_env, dbis [8]C.MDBX_dbi, plan []ownedMutation, consulted []ownedConsulted, old, write *C.MDBX_txn, stage UpdateStage, scopes ...largeImageScope) updateNativeOutcome {
	rc := int(C.mdbx_txn_commit(write))
	commitErr := nativeError(operationUpdate, rc)
	switch rc {
	case codeSuccess:
		return updateNativeConsumed(CommitTruthNew, true, nil, nil, UpdateStageCommitMayHaveCrossed)
	case codeResultTrue:
		return updateNativeConsumed(CommitTruthOld, true, commitErr, nil, stage)
	case codeThreadMismatch:
		return updateNativeRetainedWrite(true, commitErr, nil, write, stage)
	case codePanic, codeEPerm, codeBadSignature, codeEINVAL, codeBadTxn, codeProblem:
		return updateNativeConsumed(CommitTruthOld, true, commitErr, nil, stage)
	}
	return updateNativeReadback(env, dbis, plan, consulted, old, commitErr, scopes...)
}

func updateNativeExecute(env *C.MDBX_env, dbis [8]C.MDBX_dbi, plan []ownedMutation, consulted []ownedConsulted, old *C.MDBX_txn, scopes ...largeImageScope) updateNativeOutcome {
	stage := UpdateStagePrewrite
	begun := C.rubin_mdbx_txn_begin(env, C.MDBX_TXN_READWRITE)
	beginErr := nativePointerResultError(operationUpdate, "mdbx_txn_begin returned invalid result shape", int(begun.rc), begun.txn != nil)
	if beginErr != nil {
		if begun.txn != nil {
			return updateNativeRetainedWrite(false, beginErr, nil, begun.txn, stage)
		}
		return updateNativeConsumed(CommitTruthOld, false, beginErr, nil, stage)
	}
	references, preflightErr := updateNativePreflight(old, begun.txn, dbis, plan, consulted, scopes...)
	if preflightErr != nil {
		return updateNativeAbort(begun.txn, preflightErr, stage)
	}
	deleteErr := updateNativeDeletes(begun.txn, dbis, plan, &stage)
	if deleteErr != nil {
		return updateNativeAbort(begun.txn, deleteErr, stage)
	}
	putErr := updateNativePuts(old, begun.txn, dbis, plan, references, &stage)
	if putErr != nil {
		return updateNativeAbort(begun.txn, putErr, stage)
	}
	verifyErr := updateNativeVerify(old, begun.txn, dbis, plan, references)
	if verifyErr != nil {
		return updateNativeAbort(begun.txn, verifyErr, stage)
	}
	consultedErr := updateNativeScopedMatch(old, begun.txn, dbis, plan, consulted, "final update image mismatch", scopes...)
	if consultedErr != nil {
		return updateNativeAbort(begun.txn, consultedErr, stage)
	}
	return updateNativeCommit(env, dbis, plan, consulted, old, begun.txn, stage, scopes...)
}

func (s *Store) updateNative(plan []ownedMutation, consulted []ownedConsulted, old *C.MDBX_txn, scopes ...largeImageScope) updateNativeOutcome {
	if s == nil || s.env == nil || old == nil || len(plan) == 0 || !validRetainedDBIs(s.dbis) {
		return updateNativeConsumed(CommitTruthOld, false, updateNativeInvariant("invalid native update input"), nil, UpdateStagePrewrite)
	}
	var outcome updateNativeOutcome
	runLocked(func() transactionOutcome {
		outcome = updateNativeExecute(s.env, s.dbis, plan, consulted, old, scopes...)
		return outcome.lockedOutcome()
	})
	return outcome
}

func invokeUpdate(callback func(*Reader) (Batch, error), reader *Reader) (batch Batch, panicValue any, panicked bool, err error) {
	panicked = true
	func() {
		defer func() { panicValue = recover() }()
		batch, err = callback(reader)
		panicked = false
	}()
	return batch, panicValue, panicked, err
}

func (s *Store) updatePlan(callback func(*Reader) (Batch, error), reader *Reader, old *C.MDBX_txn) ([]ownedMutation, []ownedConsulted, largeImageScope, error) {
	returned := false
	defer func() {
		if returned {
			return
		}
		reader.expire().retire()
		primary, infrastructure := readPrimary(nil, reader.failure)
		_ = s.abortReadLocked(old, primary, infrastructure)
	}()
	batch, panicValue, panicked, callbackErr := invokeUpdate(callback, reader)
	returned = true
	tip := reader.expire()
	primary, infrastructure := readPrimary(callbackErr, reader.failure)
	if panicked {
		tip.retire()
		_ = s.abortReadLocked(old, primary, infrastructure)
		panic(panicValue) //nolint:forbidigo // OLD cleanup and Store projection complete before resuming the original callback panic.
	}
	if primary != nil {
		tip.retire()
		return nil, nil, largeImageScope{}, s.abortReadLocked(old, primary, infrastructure)
	}
	plan, planErr := updateOwnedBatch(batch, reader)
	if planErr != nil {
		tip.retire()
		return nil, nil, largeImageScope{}, s.abortReadLocked(old, planErr, false)
	}
	return s.updateImagePlan(batch, plan, reader, old, tip)
}

// Post-callback image admission preserves the legacy, Large/Obsolete, context order.
func (s *Store) updateImagePlan(batch Batch, plan []ownedMutation, reader *Reader, old *C.MDBX_txn, tip *canonicalTipCell) ([]ownedMutation, []ownedConsulted, largeImageScope, error) {
	consulted, consultedErr := updateOwnedConsulted(batch, plan)
	if consultedErr != nil {
		tip.retire()
		return nil, nil, largeImageScope{}, s.abortReadLocked(old, consultedErr, false)
	}
	infrastructure, captureErr := updateNativeConsultedImages(old, s.dbis, consulted)
	if captureErr != nil {
		tip.retire()
		return nil, nil, largeImageScope{}, s.abortReadLocked(old, captureErr, infrastructure)
	}
	large, largeErr := updateOwnedLarge(batch, consulted, reader.maxKey)
	if largeErr != nil {
		tip.retire()
		return nil, nil, largeImageScope{}, s.abortReadLocked(old, largeErr, false)
	}
	large, contextErr := updateOwnedContext(batch.ContextConsulted, plan, large)
	if contextErr != nil {
		tip.retire()
		return nil, nil, largeImageScope{}, s.abortReadLocked(old, contextErr, false)
	}
	infrastructure, contextErr = contextQualify(reader, plan, large)
	if contextErr != nil {
		tip.retire()
		return nil, nil, largeImageScope{}, s.abortReadLocked(old, contextErr, infrastructure)
	}
	tipErr := canonicalTipAdmit(plan, tip)
	if tipErr != nil {
		tip.retire()
		return nil, nil, largeImageScope{}, s.abortReadLocked(old, tipErr, false)
	}
	large.tip = tip
	return plan, consulted, large, nil
}

func updateResult(outcome updateNativeOutcome, cleanup error) (CommitTruth, UpdateStage, error) {
	shapeErr := outcome.valid()
	if shapeErr != nil {
		return CommitTruthOld, UpdateStageInvalid, joinErrors(shapeErr, cleanup)
	}
	if !outcome.commitAttempted {
		return CommitTruthOld, outcome.stage, joinErrors(outcome.primary, outcome.secondary, cleanup)
	}
	if outcome.primary == nil && cleanup == nil {
		return outcome.truth, outcome.stage, nil
	}
	cause, remaining := outcome.primary, joinErrors(outcome.secondary, cleanup)
	if cause == nil {
		cause, remaining = cleanup, nil
	}
	return outcome.truth, outcome.stage, &CommitError{Cause: cause, Truth: outcome.truth, ReadbackCause: remaining}
}

func updateRetained(outcome updateNativeOutcome) *C.MDBX_txn {
	if outcome.retainedWrite != nil {
		return outcome.retainedWrite
	}
	return outcome.retainedRead
}

func updateAbortOld(txn *C.MDBX_txn) (error, bool) {
	return updateAbortOldResult(int(C.mdbx_txn_abort(txn)))
}

func updateAbortOldResult(rc int) (error, bool) {
	if rc == codeSuccess {
		return nil, false
	}
	return nativeError(operationAbort, rc), rc == codeThreadMismatch
}

func (s *Store) applyUpdateOutcome(outcome updateNativeOutcome, old *C.MDBX_txn, cleanup error, oldRetained bool) (CommitTruth, UpdateStage, error) {
	if shapeErr := outcome.valid(); shapeErr != nil && (outcome.retainedWrite != nil || outcome.retainedRead != nil) {
		return CommitTruthOld, UpdateStageInvalid, joinErrors(shapeErr, cleanup)
	}
	truth, stage, terminal := updateResult(outcome, cleanup)
	retained := updateRetained(outcome)
	if retained == nil && oldRetained {
		retained = old
	}
	if retained != nil {
		s.terminalTruth = truth
		return truth, stage, s.poison(retained, terminal).err
	}
	if terminal == nil {
		return truth, stage, nil
	}
	s.terminalTruth = truth
	_, terminal = s.consume(terminal)
	return truth, stage, terminal
}

func (s *Store) latchUpdateTerminalTruth() {
	if s.state != storeOPEN && s.terminalTruth == 0 {
		s.terminalTruth = CommitTruthOld
	}
}

func (s *Store) Update(callback func(*Reader) (Batch, error)) (CommitTruth, UpdateStage, error) {
	if s == nil {
		return CommitTruthOld, UpdateStagePrewrite, adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "nil Store", nil)
	}
	if callback == nil {
		return CommitTruthOld, UpdateStagePrewrite, adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "nil Update callback", nil)
	}
	if !s.operations.TryLock() {
		return CommitTruthOld, UpdateStagePrewrite, adapterError(operationUpdate, EngineConcurrency, codeBusy, "store operation in progress", nil)
	}
	defer s.operations.Unlock()
	stateErr := s.observationStateError(operationUpdate)
	if stateErr != nil {
		truth := s.terminalTruth
		if truth-CommitTruthOld > CommitTruthUnknown-CommitTruthOld {
			truth = CommitTruthOld
		}
		return truth, UpdateStagePrewrite, stateErr
	}
	defer s.latchUpdateTerminalTruth()
	begun := C.rubin_mdbx_txn_begin(s.env, C.MDBX_TXN_RDONLY)
	beginErr := nativePointerResultError(operationUpdate, "mdbx_txn_begin returned invalid result shape", int(begun.rc), begun.txn != nil)
	if beginErr != nil {
		return CommitTruthOld, UpdateStagePrewrite, s.failedReadBegin(begun.txn, beginErr)
	}
	reader := newReader(begun.txn, s.dbis)
	reader.updateOld = true
	reader.ownerVerified = s.canonicalOwnerVerified
	reader.maxKey = uint64(limitsForPage(s.config.PageSize).maxKey)
	reader.active.Store(true)
	plan, consulted, large, planErr := s.updatePlan(callback, reader, begun.txn)
	if planErr != nil {
		return CommitTruthOld, UpdateStagePrewrite, planErr
	}
	// Idempotently clear the Go cell on this goroutine's unwinding after registration.
	defer large.tip.retire()
	outcome := s.updateNative(plan, consulted, begun.txn, large)
	// Clear the borrowed source cell before OLD cleanup.
	large.tip.retire()
	cleanupErr, oldRetained := updateAbortOld(begun.txn)
	return s.applyUpdateOutcome(outcome, begun.txn, cleanupErr, oldRetained)
}

func (s *Store) View(callback func(*Reader) error) (err error) {
	if s == nil {
		return adapterError(operationView, EngineInvalidInput, codeEINVAL, "nil Store", nil)
	}
	if callback == nil {
		return adapterError(operationView, EngineInvalidInput, codeEINVAL, "nil View callback", nil)
	}
	if !s.operations.TryLock() {
		return adapterError(operationView, EngineConcurrency, codeBusy, "store operation in progress", nil)
	}
	defer s.operations.Unlock()
	stateErr := s.observationStateError(operationView)
	if stateErr != nil {
		return stateErr
	}
	begun := C.rubin_mdbx_txn_begin(s.env, C.MDBX_TXN_RDONLY)
	beginErr := nativePointerResultError(operationView, "mdbx_txn_begin returned invalid result shape", int(begun.rc), begun.txn != nil)
	if beginErr != nil {
		return s.failedReadBegin(begun.txn, beginErr)
	}
	reader := newReader(begun.txn, s.dbis)
	reader.ownerVerified = s.canonicalOwnerVerified
	reader.maxKey = uint64(limitsForPage(s.config.PageSize).maxKey)
	reader.active.Store(true)
	defer func() {
		reader.expire().retire()
		primary, infrastructure := readPrimary(err, reader.failure)
		err = s.abortReadLocked(begun.txn, primary, infrastructure)
	}()
	return callback(reader)
}

func (r *Reader) Get(dbi DBI, key []byte) ([]byte, bool, error) {
	if !r.usable() {
		return nil, false, adapterError(operationGet, EngineInvalidInput, codeEINVAL, "Reader is not active", nil)
	}
	dbiErr := ValidateDBI(dbi)
	if dbiErr != nil {
		return nil, false, adapterError(operationGet, EngineInvalidInput, codeEINVAL, "invalid SchemaV2 DBI", dbiErr)
	}
	if !validKey(dbi.Rank, key) {
		return nil, false, adapterError(operationGet, EngineInvalidInput, codeEINVAL, "invalid SchemaV2 key", nil)
	}
	r.getMu.Lock()
	defer r.getMu.Unlock()
	if !r.usable() {
		return nil, false, adapterError(operationGet, EngineInvalidInput, codeEINVAL, "Reader is not active", nil)
	}
	value := C.rubin_mdbx_get(r.txn, r.dbis[dbi.Rank], unsafe.Pointer(&key[0]), C.size_t(len(key)))
	runtime.KeepAlive(key)
	result, present, err := copiedGetResult(dbi, key, int(value.rc), unsafe.Pointer(value.bytes), value.length)
	if err != nil {
		r.failure = err
		r.active.Store(false)
	}
	return result, present, err
}

// canonicalTipCell owns no copied source or scalar. The two spans remain
// database-owned under the original OLD transaction, including after cursor close.
type canonicalTipCell struct {
	generation uint64
	key, value unsafe.Pointer
}

func (tip *canonicalTipCell) retire() {
	if tip != nil {
		*tip = canonicalTipCell{}
	}
}

type canonicalTipRow struct {
	key   []byte
	image updateImage
}

func canonicalTipShape(op engineOperation) error {
	return adapterError(op, EngineLocalInvariant, codeProblem, "mdbx_cursor_get returned invalid result shape", nil)
}

func canonicalTipResultShape(result C.rubin_mdbx_prefix_result) bool {
	return result.key_bytes != nil && result.key_len != 0 && result.key_len <= 77 && (result.value_len == 0 || result.value_bytes != nil)
}

// Check every found boundary, including the successor, before reading key bytes.
// The foreign value's payload is never dereferenced.
func canonicalTipFound(result C.rubin_mdbx_prefix_result, seek []byte, direction int, op engineOperation) (canonicalTipRow, error) {
	if rc := int(result.rc); rc != codeSuccess {
		if rc == codeNotFound {
			return canonicalTipRow{}, nil
		}
		return canonicalTipRow{}, nativeError(op, rc)
	}
	if !canonicalTipResultShape(result) {
		return canonicalTipRow{}, canonicalTipShape(op)
	}
	key := unsafe.Slice((*byte)(unsafe.Pointer(result.key_bytes)), int(result.key_len))
	if len(seek) != 0 && (bytes.Compare(key, seek) >= 0) != (direction > 0) {
		return canonicalTipRow{}, canonicalTipShape(op)
	}
	return canonicalTipRow{key: key, image: updateImage{present: true, bytes: unsafe.Pointer(result.value_bytes), length: result.value_len}}, nil
}

func canonicalTipLast(cursor *C.MDBX_cursor, generation uint64, op engineOperation) (canonicalTipRow, error) {
	if generation == ^uint64(0) {
		return canonicalTipFound(C.rubin_mdbx_cursor_get(cursor, nil, 0, C.MDBX_LAST), nil, 0, op)
	}
	var seek [8]byte
	binary.BigEndian.PutUint64(seek[:], generation+1)
	seekPointer := unsafe.Pointer(&seek)
	result := C.rubin_mdbx_cursor_get(cursor, seekPointer, 8, C.MDBX_SET_RANGE)
	runtime.KeepAlive(seek)
	row, err := canonicalTipFound(result, seek[:], 1, op)
	if err != nil {
		return canonicalTipRow{}, err
	}
	if row.key == nil {
		return canonicalTipFound(C.rubin_mdbx_cursor_get(cursor, nil, 0, C.MDBX_LAST), nil, 0, op)
	}
	return canonicalTipFound(C.rubin_mdbx_cursor_get(cursor, nil, 0, C.MDBX_PREV), seek[:], -1, op)
}

func canonicalTipEndpoint(txn *C.MDBX_txn, dbi C.MDBX_dbi, generation uint64, op engineOperation) (canonicalTipRow, error) {
	opened := C.rubin_mdbx_cursor_open(txn, dbi)
	if opened.cursor != nil {
		defer C.mdbx_cursor_close(opened.cursor)
	}
	err := nativePointerResultError(op, "mdbx_cursor_open returned invalid result shape", int(opened.rc), opened.cursor != nil)
	if err != nil {
		return canonicalTipRow{}, err
	}
	row, err := canonicalTipLast(opened.cursor, generation, op)
	if err != nil {
		return canonicalTipRow{}, err
	}
	if len(row.key) < 8 {
		var lower [8]byte
		binary.BigEndian.PutUint64(lower[:], generation)
		if bytes.Compare(row.key, lower[:]) < 0 {
			return canonicalTipRow{}, nil
		}
		return row, nil
	}
	if binary.BigEndian.Uint64(row.key[:8]) != generation {
		return canonicalTipRow{}, nil
	}
	return row, nil
}

func canonicalTipPoint(row canonicalTipRow) (*AuthorityPointV1, error) {
	if len(row.key) != 16 {
		return nil, integrityError(operationPrefixPage, "stored key outside SchemaV2 prefix-page domain", nil)
	}
	height := binary.BigEndian.Uint64(row.key[8:])
	if height > 0xffffffff {
		return nil, integrityError(operationPrefixPage, "canonical tip height outside domain", nil)
	}
	if row.image.length != 104 {
		return nil, integrityError(operationPrefixPage, "stored value width outside SchemaV2 bound", nil)
	}
	value := unsafe.Slice((*byte)(row.image.bytes), 104)
	if !validWork([40]byte(value[64:104])) {
		return nil, integrityError(operationPrefixPage, "canonical tip work outside domain", nil)
	}
	point := &AuthorityPointV1{Height: height}
	copy(point.BlockHash[:], value[:32])
	return point, nil
}

// CanonicalTipV1 acquires once the greatest physical canonical-v1 key in a
// nonzero generation of this Reader. A nil point with nil error proves empty;
// a source failure returns nil and disarms the Reader. This does not certify
// history, headers, linkage or the authority's choice of generation.
// The returned scalar is independent and remains safe after the callback ends.
func (r *Reader) CanonicalTipV1(generation uint64) (*AuthorityPointV1, error) {
	if !r.usable() {
		return nil, prefixPageInputError("Reader is not active", nil)
	}
	r.getMu.Lock()
	defer r.getMu.Unlock()
	if !r.usable() {
		return nil, prefixPageInputError("Reader is not active", nil)
	}
	if generation == 0 {
		return nil, prefixPageInputError("invalid prefix-page prefix", nil)
	}
	if r.tip != nil {
		return nil, prefixPageInputError("canonical tip already acquired", nil)
	}
	point, err := r.canonicalTipAcquire(generation)
	return point, err
}

func (r *Reader) canonicalTipAcquire(generation uint64) (*AuthorityPointV1, error) {
	row, err := canonicalTipEndpoint(r.txn, r.dbis[2], generation, operationPrefixPage)
	var point *AuthorityPointV1
	if err == nil && row.key != nil {
		point, err = canonicalTipPoint(row)
	}
	if err != nil {
		r.failure = err
		r.active.Store(false)
		return nil, err
	}
	r.tip = &canonicalTipCell{generation: generation}
	if row.key != nil {
		r.tip.key, r.tip.value = unsafe.Pointer(&row.key[0]), row.image.bytes
	}
	return point, nil
}

func canonicalTipAdmit(plan []ownedMutation, tip *canonicalTipCell) error {
	if tip == nil {
		return nil
	}
	for _, target := range plan {
		if target.dbi.Rank == 2 && binary.BigEndian.Uint64(target.key[:8]) == tip.generation {
			return updateInvalidBatch()
		}
	}
	return nil
}

// Candidate bytes are compared with the qualified original source, never
// requalified as source. Unequal readable widths require no payload access.
func canonicalTipEqual(txn *C.MDBX_txn, dbi C.MDBX_dbi, scopes ...largeImageScope) (bool, error) {
	if len(scopes) == 0 || scopes[0].tip == nil {
		return true, nil
	}
	tip := scopes[0].tip
	row, err := canonicalTipEndpoint(txn, dbi, tip.generation, operationUpdate)
	if err != nil {
		return false, err
	}
	if tip.key == nil {
		return row.key == nil, nil
	}
	if len(row.key) != 16 || row.image.length != 104 {
		return false, nil
	}
	key := unsafe.Slice((*byte)(tip.key), 16)
	value := unsafe.Slice((*byte)(tip.value), 104)
	return bytes.Equal(key, row.key) && bytes.Equal(value, unsafe.Slice((*byte)(row.image.bytes), 104)), nil
}

// OptionalSideValueV1 is one GetOptionalSide observation. Present false is verified absence. For a present row Length
// is the actual native value length. InvalidWidth reports a proved stored width outside the SchemaV2 bound without
// copying the value; otherwise Value is one owned Go copy of a legal-width value.
type OptionalSideValueV1 struct {
	Value        []byte
	Length       uint64
	Present      bool
	InvalidWidth bool
}

// GetOptionalSide reads one exact headers-v1 or blocks-v1 row keyed by a 32-byte hash (RUBIN_MEMPOOL_POLICY.md
// 6.4.1.6 positive evidence). Postconditions: another DBI or key width is a direct InvalidInput refusal that records
// nothing; NOTFOUND is Present false and leaves the Reader usable; native SUCCESS whose width lies outside 116 (headers)
// or 116..68000125 (blocks) is Present and InvalidWidth with its native Length, no Go copy and a usable Reader; a legal
// width returns one owned copy. An impossible pointer/length shape or a native failure is recorded as this Reader's
// failure, disarms it and follows the existing View/Update disposition, exactly as Get does.
func (r *Reader) GetOptionalSide(dbi DBI, key []byte) (OptionalSideValueV1, error) {
	if !r.usable() {
		return OptionalSideValueV1{}, adapterError(operationGet, EngineInvalidInput, codeEINVAL, "Reader is not active", nil)
	}
	if (dbi != schemaDBIs[3] && dbi != schemaDBIs[4]) || len(key) != 32 {
		return OptionalSideValueV1{}, adapterError(operationGet, EngineInvalidInput, codeEINVAL, "invalid optional-side DBI or key", nil)
	}
	r.getMu.Lock()
	defer r.getMu.Unlock()
	if !r.usable() {
		return OptionalSideValueV1{}, adapterError(operationGet, EngineInvalidInput, codeEINVAL, "Reader is not active", nil)
	}
	value := C.rubin_mdbx_get(r.txn, r.dbis[dbi.Rank], unsafe.Pointer(&key[0]), C.size_t(len(key)))
	runtime.KeepAlive(key)
	result, err := optionalSideResult(dbi, key, int(value.rc), unsafe.Pointer(value.bytes), value.length)
	if err != nil {
		r.failure = err
		r.active.Store(false)
	}
	return result, err
}

// optionalSideResult decides the native shape and width before any copy; both admitted DBIs have a 116-byte minimum,
// so a zero-length SUCCESS is a proved invalid width and getResultEmpty cannot arise. C.size_t is 64-bit on every
// supported target, so the length conversion is exact and a legal width fits C.int for C.GoBytes.
func optionalSideResult(dbi DBI, key []byte, rc int, bytes unsafe.Pointer, length C.size_t) (OptionalSideValueV1, error) {
	minimum, maximum := rawValueBounds(dbi, key)
	switch getResultDecision(rc, bytes != nil, uint64(length), minimum, maximum) {
	case getResultAbsent:
		return OptionalSideValueV1{}, nil
	case getResultInvalidBound:
		return OptionalSideValueV1{Length: uint64(length), Present: true, InvalidWidth: true}, nil
	case getResultCopy:
		return OptionalSideValueV1{Value: C.GoBytes(bytes, C.int(length)), Length: uint64(length), Present: true}, nil
	case getResultInvalidShape:
		return OptionalSideValueV1{}, adapterError(operationGet, EngineLocalInvariant, codeProblem, "mdbx_get returned invalid result shape", nil)
	default:
		return OptionalSideValueV1{}, nativeError(operationGet, rc)
	}
}

// ReadRequiredSideLink returns the owned 104-byte staged-v1 SideLink (generation, height): hash, parent hash and
// chainwork. Postconditions: generation zero is a direct InvalidInput refusal that records nothing; a width, shape or
// native failure is the error Get already recorded; a positively absent row or one whose chainwork is outside
// 0 < work <= 2^288 is recorded as this Reader's Integrity failure and that same object is returned.
func (r *Reader) ReadRequiredSideLink(generation, height uint64) ([]byte, error) {
	key, err := HeightKey(generation, height)
	if err != nil {
		return nil, adapterError(operationGet, EngineInvalidInput, codeEINVAL, "invalid SchemaV2 key", nil)
	}
	value, present, err := r.Get(schemaDBIs[6], key)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, bootstrapFailure(r, integrityError(operationGet, "selected side link is absent", nil))
	}
	if !validWork([40]byte(value[64:104])) {
		return nil, bootstrapFailure(r, integrityError(operationGet, "selected side link identity is undecodable", nil))
	}
	return value, nil
}

// ReadStorageAuthorityV1 reads and validates meta-v1 key 02. Postconditions: a width, shape or native failure is the
// error Get already recorded; an absent, undecodable or structurally illegal authority is recorded as this Reader's
// Integrity failure "invalid storage authority" and that same object is returned.
func (r *Reader) ReadStorageAuthorityV1() (StorageAuthorityV1, error) {
	value, present, err := r.Get(schemaDBIs[0], []byte{2})
	if err != nil {
		return StorageAuthorityV1{}, err
	}
	a, err := DecodeStorageAuthorityV1(value)
	if !present || err != nil {
		return StorageAuthorityV1{}, bootstrapFailure(r, integrityError(operationGet, "invalid storage authority", err))
	}
	return a, nil
}

type prefixPageScan struct {
	dbi        DBI
	prefix     []byte
	seek       [78]byte
	seekLength int
	maxRows    uint32
	maxBytes   uint64
}

type prefixPageNative struct {
	key         []byte
	value       unsafe.Pointer
	valueLength int
	charge      uint64
	outside     bool
}

func prefixPageInputError(diagnostic string, cause error) *EngineError {
	return adapterError(operationPrefixPage, EngineInvalidInput, codeEINVAL, diagnostic, cause)
}

func supportedPrefixPageDBI(dbi DBI) bool {
	switch dbi.Rank {
	case 1, 2, 5, 6, 7:
		return true
	default:
		return false
	}
}

func validPrefixPagePrefix(dbi DBI, prefix []byte) bool {
	if dbi.Rank == 5 {
		return len(prefix) == 32
	}
	return validImageKey(prefix, 8)
}

func validPrefixPageContinuation(dbi DBI, prefix, afterExclusive []byte) bool {
	if afterExclusive == nil {
		return true
	}
	return validKey(dbi.Rank, afterExclusive) && bytes.HasPrefix(afterExclusive, prefix)
}

func prefixPageMinimumBytes(dbi DBI) uint64 {
	switch dbi.Rank {
	case 1:
		return 65_604
	case 2, 6:
		return 120
	case 7:
		return 48
	default:
		return 65_637
	}
}

func validatePrefixPageRequest(dbi DBI, prefix, afterExclusive []byte, maxRows uint32, maxBytes uint64) error {
	dbiErr := ValidateDBI(dbi)
	if dbiErr != nil {
		return prefixPageInputError("invalid SchemaV2 DBI", dbiErr)
	}
	if !supportedPrefixPageDBI(dbi) {
		return prefixPageInputError("unsupported prefix-page DBI", nil)
	}
	if !validPrefixPagePrefix(dbi, prefix) {
		return prefixPageInputError("invalid prefix-page prefix", nil)
	}
	if !validPrefixPageContinuation(dbi, prefix, afterExclusive) {
		return prefixPageInputError("invalid prefix-page continuation", nil)
	}
	return validatePrefixPageLimits(dbi, maxRows, maxBytes)
}

func validatePrefixPageLimits(dbi DBI, maxRows uint32, maxBytes uint64) error {
	if maxRows == 0 || maxRows > MaxPrefixPageRows {
		return prefixPageInputError("invalid prefix-page row limit", nil)
	}
	if maxBytes < prefixPageMinimumBytes(dbi) || maxBytes > MaxPrefixPageBytes {
		return prefixPageInputError("invalid prefix-page byte limit", nil)
	}
	return nil
}

func newPrefixPageScan(dbi DBI, prefix, afterExclusive []byte, maxRows uint32, maxBytes uint64) prefixPageScan {
	scan := prefixPageScan{dbi: dbi, prefix: prefix, maxRows: maxRows, maxBytes: maxBytes}
	if afterExclusive == nil {
		scan.seekLength = copy(scan.seek[:], prefix)
		return scan
	}
	scan.seekLength = copy(scan.seek[:], afterExclusive)
	scan.seek[scan.seekLength] = 0
	scan.seekLength++
	return scan
}

// PrefixPage returns rows after afterExclusive from the Reader's current
// snapshot. UTXO, canonical, staged and canonical-owner prefixes are exact 8-byte
// nonzero big-endian image or generation IDs; undo prefixes are any exact 32-byte
// hash. A non-nil continuation is an exact same-prefix SchemaV2 key. Rows are
// limited to 1..1440; bytes are limited to 65604 for UTXO, 120 for canonical/staged,
// 48 for canonical-owner or 65637 for undo through 154611151. A nil continuation
// starts at prefix.
// Inputs are borrowed only synchronously; results are independent copies and no
// native cursor escapes. Native or stored-row failure returns a zero page,
// invalidates the Reader, and follows the existing View/Update disposition.
func (r *Reader) PrefixPage(dbi DBI, prefix, afterExclusive []byte, maxRows uint32, maxBytes uint64) (PrefixPage, error) {
	if !r.usable() {
		return PrefixPage{}, prefixPageInputError("Reader is not active", nil)
	}
	requestErr := validatePrefixPageRequest(dbi, prefix, afterExclusive, maxRows, maxBytes)
	if requestErr != nil {
		return PrefixPage{}, requestErr
	}
	scan := newPrefixPageScan(dbi, prefix, afterExclusive, maxRows, maxBytes)
	r.getMu.Lock()
	defer r.getMu.Unlock()
	if !r.usable() {
		return PrefixPage{}, prefixPageInputError("Reader is not active", nil)
	}
	page, err := r.prefixPageRead(scan)
	if err != nil {
		r.failure = err
		r.active.Store(false)
	}
	return page, err
}

func prefixPageShapeError() *EngineError {
	return adapterError(operationPrefixPage, EngineLocalInvariant, codeProblem, "mdbx_get_equal_or_great returned invalid result shape", nil)
}

func prefixPageNativeKey(seek []byte, keyBytes unsafe.Pointer, keyLength C.size_t) ([]byte, error) {
	if keyBytes == nil || keyLength == 0 || keyLength > C.size_t(77) {
		return nil, prefixPageShapeError()
	}
	// The 77-byte envelope makes both the int conversion and borrowed view safe.
	key := unsafe.Slice((*byte)(keyBytes), int(keyLength))
	if bytes.Compare(key, seek) < 0 {
		return nil, prefixPageShapeError()
	}
	return key, nil
}

func prefixPageFoundCode(rc int) bool {
	return rc == codeSuccess || rc == codeResultTrue
}

func prefixPageValueShape(valueBytes unsafe.Pointer, valueLength C.size_t) error {
	if valueLength != 0 && valueBytes == nil {
		return prefixPageShapeError()
	}
	return nil
}

func prefixPageNativeRow(dbi DBI, prefix, seek []byte, rc int, keyBytes unsafe.Pointer, keyLength C.size_t, valueBytes unsafe.Pointer, valueLength C.size_t) (prefixPageNative, error) {
	if !prefixPageFoundCode(rc) {
		return prefixPageNative{}, nativeError(operationPrefixPage, rc)
	}
	valueShapeErr := prefixPageValueShape(valueBytes, valueLength)
	if valueShapeErr != nil {
		return prefixPageNative{}, valueShapeErr
	}
	key, err := prefixPageNativeKey(seek, keyBytes, keyLength)
	if err != nil {
		return prefixPageNative{}, err
	}
	return prefixPageStoredRow(dbi, prefix, key, valueBytes, valueLength)
}

func prefixPageStoredRow(dbi DBI, prefix, key []byte, valueBytes unsafe.Pointer, valueLength C.size_t) (prefixPageNative, error) {
	if !bytes.HasPrefix(key, prefix) {
		return prefixPageNative{outside: true}, nil
	}
	if !validKey(dbi.Rank, key) {
		return prefixPageNative{}, integrityError(operationPrefixPage, "stored key outside SchemaV2 prefix-page domain", nil)
	}
	length, valid := prefixPageValueLength(dbi, key, valueLength)
	if !valid {
		return prefixPageNative{}, integrityError(operationPrefixPage, "stored value width outside SchemaV2 bound", nil)
	}
	return prefixPageNative{key: key, value: valueBytes, valueLength: length, charge: uint64(len(key)) + uint64(length)}, nil
}

func prefixPageValueLength(dbi DBI, key []byte, valueLength C.size_t) (int, bool) {
	minimum, maximum := rawValueBounds(dbi, key)
	if valueLength < C.size_t(minimum) || valueLength > C.size_t(maximum) {
		return 0, false
	}
	return int(valueLength), true
}

func prefixPageNativeResult(dbi DBI, prefix, seek []byte, rc int, keyBytes unsafe.Pointer, keyLength C.size_t, valueBytes unsafe.Pointer, valueLength C.size_t) (prefixPageNative, bool, error) {
	if rc == codeNotFound {
		return prefixPageNative{}, true, nil
	}
	row, err := prefixPageNativeRow(dbi, prefix, seek, rc, keyBytes, keyLength, valueBytes, valueLength)
	return row, false, err
}

func prefixPageStop(rowCount int, used, charge, maxBytes uint64, maxRows uint32) PrefixPageStop {
	if uint32(rowCount) == maxRows {
		return PrefixPageRowLimit
	}
	if charge > maxBytes-used {
		return PrefixPageByteLimit
	}
	return 0
}

func copyPrefixPageRow(row prefixPageNative) PrefixRow {
	// C.GoBytes copies both borrowed MDBX buffers before the next native seek.
	key := C.GoBytes(unsafe.Pointer(&row.key[0]), C.int(len(row.key)))
	value := C.GoBytes(row.value, C.int(row.valueLength))
	return PrefixRow{Key: key, Value: value}
}

func advancePrefixPageSeek(scan *prefixPageScan, key []byte) {
	scan.seekLength = copy(scan.seek[:], key)
	scan.seek[scan.seekLength] = 0
	scan.seekLength++
}

func (r *Reader) prefixPageRead(scan prefixPageScan) (PrefixPage, error) {
	var rows []PrefixRow
	var used uint64
	for {
		seek := scan.seek[:scan.seekLength]
		result := C.rubin_mdbx_get_equal_or_great(r.txn, r.dbis[scan.dbi.Rank], unsafe.Pointer(&seek[0]), C.size_t(len(seek)))
		runtime.KeepAlive(scan)
		row, exhausted, err := prefixPageNativeResult(scan.dbi, scan.prefix, seek, int(result.rc), unsafe.Pointer(result.key_bytes), result.key_len, unsafe.Pointer(result.value_bytes), result.value_len)
		if err != nil {
			return PrefixPage{}, err
		}
		if exhausted || row.outside {
			return PrefixPage{Rows: rows, Stop: PrefixPageExhausted}, nil
		}
		if stop := prefixPageStop(len(rows), used, row.charge, scan.maxBytes, scan.maxRows); stop != 0 {
			return PrefixPage{Rows: rows, Stop: stop}, nil
		}
		rows = append(rows, copyPrefixPageRow(row))
		used += row.charge
		advancePrefixPageSeek(&scan, row.key)
	}
}

func (s *Store) Inspect() (Inspection, error) {
	if s == nil {
		return Inspection{}, adapterError(operationInspect, EngineInvalidInput, codeEINVAL, "nil Store", nil)
	}
	if !s.operations.TryLock() {
		return Inspection{}, adapterError(operationInspect, EngineConcurrency, codeBusy, "store operation in progress", nil)
	}
	defer s.operations.Unlock()
	stateErr := s.observationStateError(operationInspect)
	if stateErr != nil {
		return Inspection{}, stateErr
	}
	begun := C.rubin_mdbx_txn_begin(s.env, C.MDBX_TXN_RDONLY)
	beginErr := nativePointerResultError(operationInspect, "mdbx_txn_begin returned invalid result shape", int(begun.rc), begun.txn != nil)
	if beginErr != nil {
		return Inspection{}, s.failedReadBegin(begun.txn, beginErr)
	}
	inspection, primary := s.inspectReadLocked(begun.txn)
	cleanupErr := s.abortReadLocked(begun.txn, primary, primary != nil)
	if cleanupErr != nil {
		return Inspection{}, cleanupErr
	}
	return inspection, nil
}

func (s *Store) failedReadBegin(txn *C.MDBX_txn, primary error) error {
	if txn != nil {
		return s.poison(txn, primary).err
	}
	_, err := s.consume(primary)
	return err
}

//nolint:errorlint // Only the exact recorded EngineError is de-duplicated.
func readPrimary(application, infrastructure error) (error, bool) {
	if infrastructure == nil {
		return application, false
	}
	if recorded, ok := infrastructure.(*EngineError); ok {
		if returned, exact := application.(*EngineError); exact && returned == recorded {
			return infrastructure, true
		}
	}
	return joinErrors(application, infrastructure), true
}

func (s *Store) abortReadLocked(txn *C.MDBX_txn, primary error, infrastructure bool) error {
	return s.applyReadAbort(txn, primary, infrastructure, int(C.mdbx_txn_abort(txn)))
}

func (s *Store) applyReadAbort(txn *C.MDBX_txn, primary error, infrastructure bool, rc int) error {
	decision := abortTransition(rc, primary != nil)
	var abortErr error
	if rc != codeSuccess {
		abortErr = nativeError(operationAbort, rc)
	}
	result := orderedErrors(operationAbort, decision.order, primary, abortErr)
	if !decision.consumed {
		return s.poison(txn, result).err
	}
	if rc == codeSuccess && !infrastructure {
		return result
	}
	_, result = s.consume(result)
	return result
}

func (s *Store) observationStateError(operation engineOperation) error {
	if !validStoreState(s.state) {
		return adapterError(operation, EngineLocalInvariant, codeProblem, "invalid Store state", nil)
	}
	if !validStoreShape(s) {
		return adapterError(operation, EngineLocalInvariant, codeProblem, "invalid Store resource shape", nil)
	}
	if s.state == storeOPEN {
		return nil
	}
	if s.terminal != nil {
		return s.terminal
	}
	return adapterError(operation, EngineInvalidInput, codeEINVAL, "Store is closed", nil)
}

func newReader(txn *C.MDBX_txn, dbis [8]C.MDBX_dbi) *Reader {
	reader := &Reader{txn: txn, dbis: dbis}
	reader.self = reader
	return reader
}

func (r *Reader) usable() bool {
	return r != nil && r.self == r && r.txn != nil && validRetainedDBIs(r.dbis) && r.active.Load()
}

func (r *Reader) expire() *canonicalTipCell {
	r.active.Store(false)
	r.getMu.Lock()
	tip := r.tip
	r.tip = nil
	r.getMu.Unlock()
	return tip
}

func copiedGetResult(dbi DBI, key []byte, rc int, bytes unsafe.Pointer, length C.size_t) ([]byte, bool, error) {
	minimum, maximum := rawValueBounds(dbi, key)
	decision := getResultDecision(rc, bytes != nil, uint64(length), minimum, maximum)
	switch decision {
	case getResultAbsent:
		return nil, false, nil
	case getResultEmpty:
		return []byte{}, true, nil
	case getResultCopy:
		return C.GoBytes(bytes, C.int(length)), true, nil
	case getResultInvalidShape:
		return nil, false, adapterError(operationGet, EngineLocalInvariant, codeProblem, "mdbx_get returned invalid result shape", nil)
	case getResultInvalidBound:
		return nil, false, integrityError(operationGet, "stored value width outside SchemaV2 bound", nil)
	default:
		return nil, false, nativeError(operationGet, rc)
	}
}

func getResultDecision(rc int, present bool, length, minimum, maximum uint64) getResult {
	if rc == codeNotFound {
		if !present && length == 0 {
			return getResultAbsent
		}
		return getResultInvalidShape
	}
	if rc != codeSuccess {
		return getResultNative
	}
	if length == 0 {
		return zeroLengthGetResult(minimum)
	}
	if !present {
		return getResultInvalidShape
	}
	if !validRawValueLength(length, minimum, maximum) {
		return getResultInvalidBound
	}
	return getResultCopy
}

func zeroLengthGetResult(minimum uint64) getResult {
	if minimum == 0 {
		return getResultEmpty
	}
	return getResultInvalidBound
}

func validRawValueLength(length, minimum, maximum uint64) bool {
	return length >= minimum && length <= maximum
}

func rawValueBounds(dbi DBI, key []byte) (uint64, uint64) {
	if dbi.Rank == 0 {
		return metaRawValueBounds(key[0])
	}
	if dbi.Rank == 5 {
		return undoRawValueBounds(key[32])
	}
	return rankedRawValueBounds(dbi.Rank)
}

func metaRawValueBounds(kind byte) (uint64, uint64) {
	switch kind {
	case 0x00:
		return 4, 4
	case 0x01:
		return 48, 48
	case 0x02:
		return 0, MaxMetadataBytes
	default:
		return 16, 16
	}
}

func undoRawValueBounds(kind byte) (uint64, uint64) {
	if kind == 0 {
		return 33, 33
	}
	return 20, 65_560
}

func rankedRawValueBounds(rank uint8) (uint64, uint64) {
	switch rank {
	case 1:
		return 20, 65_560
	case 2, 6:
		return 104, 104
	case 3:
		return 116, 116
	case 7:
		return 8, 8
	default:
		return 116, MaxBlockBytes
	}
}

func (s *Store) inspectReadLocked(txn *C.MDBX_txn) (Inspection, error) {
	var info C.MDBX_envinfo
	if rc := int(C.mdbx_env_info_ex(s.env, txn, &info, C.size_t(unsafe.Sizeof(info)))); rc != codeSuccess {
		return Inspection{}, nativeError(operationInspect, rc)
	}
	current := uint64(info.mi_geo.current)
	if !validEffectiveCurrent(s.config, current) {
		return Inspection{}, integrityError(operationInspect, "effective ConfigV1 Now is invalid", nil)
	}
	inspection := Inspection{Config: s.config, MapSize: uint64(info.mi_mapsize), FileSize: uint64(info.mi_dxb_fsize), AllocatedSize: uint64(info.mi_dxb_fallocated), MaxReaders: uint32(info.mi_maxreaders), ReaderTableLength: uint32(info.mi_numreaders), RecentTxnID: uint64(info.mi_recent_txnid), LatterReaderTxnID: uint64(info.mi_latter_reader_txnid), UnsyncBytes: uint64(info.mi_unsync_volume)}
	inspection.Config.Now = current
	for i, dbi := range SchemaV2DBIs() {
		var stat C.MDBX_stat
		if rc := int(C.mdbx_dbi_stat(txn, s.dbis[i], &stat, C.size_t(unsafe.Sizeof(stat)))); rc != codeSuccess {
			return Inspection{}, nativeError(operationInspect, rc)
		}
		inspection.DBIs[i] = DBIInspection{DBI: dbi, Entries: uint64(stat.ms_entries), Depth: uint32(stat.ms_depth), BranchPages: uint64(stat.ms_branch_pages), LeafPages: uint64(stat.ms_leaf_pages), OverflowPages: uint64(stat.ms_overflow_pages), PageSize: uint32(stat.ms_psize)}
	}
	return inspection, nil
}

func Create(path string, cfg ConfigV1) (*Store, error) {
	encoded, err := validateCreateStatic(path, cfg)
	if err != nil {
		return nil, err
	}
	err = normalizeMDBXModule()
	if err != nil {
		return nil, err
	}
	err = validateLimits(cfg, limitsForPage(cfg.PageSize))
	if err != nil {
		return nil, adapterError(operationCreate, EngineInvalidInput, codeTooLarge, "ConfigV1 exceeds pinned native limits", err)
	}
	store := &Store{}
	store.self = store
	err = store.configureCreateEnvironment(path, cfg)
	if err != nil {
		return store.consumeFailure(err)
	}
	err = createDirectory(path)
	if err != nil {
		return store.consumeFailure(err)
	}
	writer, err := acquireWriter(path, operationCreate, true)
	if err != nil {
		return store.consumeFailure(err)
	}
	store.writer = writer
	err = store.createEnvironment(path, cfg)
	if err != nil {
		return store.consumeFailure(err)
	}
	return finishConstruction(store, runLocked(func() transactionOutcome { return store.initializeLocked(cfg, encoded) }))
}

func Open(path string, cfg ConfigV1) (*Store, error) {
	err := validatePath(operationOpen, path)
	if err != nil {
		return nil, err
	}
	_, err = validateOpenArtifacts(path)
	if err != nil {
		return nil, err
	}
	err = validateOpenStatic(cfg)
	if err != nil {
		return nil, err
	}
	err = validateOpenNativePreconditions(path, cfg)
	if err != nil {
		return nil, err
	}
	writer, err := acquireWriter(path, operationOpen, false)
	if err != nil {
		return nil, err
	}
	store := &Store{writer: writer}
	store.self = store
	err = store.openEnvironment(path, cfg)
	if err != nil {
		return store.consumeFailure(err)
	}
	return finishConstruction(store, runLocked(func() transactionOutcome { return store.inspectOpenLocked(cfg) }))
}

func validateOpenNativePreconditions(path string, cfg ConfigV1) error {
	err := normalizeMDBXModule()
	if err != nil {
		return err
	}
	err = validatePreopenSnapshot(path)
	if err != nil {
		return err
	}
	err = validateLimits(cfg, limitsForPage(cfg.PageSize))
	if err != nil {
		return adapterError(operationOpen, EngineInvalidInput, codeTooLarge, "ConfigV1 exceeds pinned native limits", err)
	}
	return nil
}

func validateCreateStatic(path string, cfg ConfigV1) ([]byte, error) {
	err := validatePath(operationCreate, path)
	if err != nil {
		return nil, err
	}
	err = requireCreateTargetAbsent(path)
	if err != nil {
		return nil, err
	}
	encoded, err := cfg.Encode()
	if err != nil {
		return nil, adapterError(operationCreate, EngineInvalidInput, codeEINVAL, "invalid ConfigV1", err)
	}
	return encoded, nil
}

func finishConstruction(store *Store, outcome transactionOutcome) (*Store, error) {
	if outcome.poisoned {
		return store, outcome.err
	}
	if outcome.err != nil {
		return store.consumeFailure(outcome.err)
	}
	return store, nil
}

func (s *Store) Close() error {
	if s == nil {
		return adapterError(operationClose, EngineInvalidInput, codeEINVAL, "nil Store", nil)
	}
	if !s.operations.TryLock() {
		return adapterError(operationClose, EngineConcurrency, codeBusy, "store operation in progress", nil)
	}
	defer s.operations.Unlock()
	if !validStoreState(s.state) {
		return adapterError(operationClose, EngineLocalInvariant, codeProblem, "invalid Store state", nil)
	}
	if !validStoreShape(s) {
		return adapterError(operationClose, EngineLocalInvariant, codeProblem, "invalid Store resource shape", nil)
	}
	if s.state == storeCLOSED || s.state == storePOISONEDTHREAD {
		return s.terminal
	}
	var primary error
	if s.terminalTruth != 0 {
		primary = s.terminal
	}
	_, err := s.consume(primary)
	return err
}

func validStoreState(state storeState) bool {
	return state == storeOPEN || state == storeCLOSEBLOCKED || state == storeCLOSED || state == storePOISONEDTHREAD
}

func validStoreShape(s *Store) bool {
	if s.self != s || !validStoreTerminalTruth(s) {
		return false
	}
	switch s.state {
	case storeOPEN:
		return validOpenStoreShape(s)
	case storeCLOSEBLOCKED:
		return validCloseBlockedStoreShape(s)
	case storeCLOSED:
		return validClosedStoreShape(s)
	case storePOISONEDTHREAD:
		return validPoisonedStoreShape(s)
	default:
		return false
	}
}

func validStoreTerminalTruth(s *Store) bool {
	if s.terminalTruth == 0 {
		return true
	}
	return s.state != storeOPEN && s.terminalTruth >= CommitTruthOld && s.terminalTruth <= CommitTruthUnknown
}

func validOpenStoreShape(s *Store) bool {
	return s.env != nil && s.writer != nil && s.txn == nil && s.terminal == nil && s.config.valid() && validRetainedDBIs(s.dbis)
}

func validCloseBlockedStoreShape(s *Store) bool {
	if s.terminalTruth != 0 {
		return validUpdateCloseBlockedStoreShape(s)
	}
	engine, terminalOK := directNativeResult(operationClose, s.terminal)
	resourcesOK := validPublishedStoreResources(s) || validConstructionStoreResources(s, engine, terminalOK)
	return s.env != nil && s.writer != nil && s.txn == nil && terminalOK && engine.Code == codeBusy && resourcesOK
}

func validUpdateCloseBlockedStoreShape(s *Store) bool {
	return s.env != nil && s.writer != nil && s.txn == nil && s.terminal != nil && validPublishedStoreResources(s)
}

func validPublishedStoreResources(s *Store) bool {
	return s.config.valid() && validRetainedDBIs(s.dbis)
}

func validConstructionStoreResources(s *Store, engine *EngineError, terminalOK bool) bool {
	return s.config == (ConfigV1{}) && s.dbis == ([8]C.MDBX_dbi{}) && terminalOK && engine.Cause != nil
}

func validClosedStoreShape(s *Store) bool {
	resources := s.env == nil && s.writer == nil && s.txn == nil && s.config == (ConfigV1{}) && s.dbis == ([8]C.MDBX_dbi{})
	if !resources {
		return false
	}
	if s.terminalTruth != 0 {
		return s.terminal != nil
	}
	return validClosedTerminal(s.terminal)
}

func validPoisonedStoreShape(s *Store) bool {
	resources := s.env != nil && s.writer != nil && s.txn != nil && s.config == (ConfigV1{}) && s.dbis == ([8]C.MDBX_dbi{})
	if !resources {
		return false
	}
	if s.terminalTruth != 0 {
		return s.terminal != nil
	}
	return validPoisonTerminal(s.terminal)
}

func validRetainedDBIs(dbis [8]C.MDBX_dbi) bool {
	seen := make(map[C.MDBX_dbi]bool, len(dbis))
	for _, dbi := range dbis {
		if dbi == 0 || seen[dbi] {
			return false
		}
		seen[dbi] = true
	}
	return true
}

func validPoisonTerminal(err error) bool {
	engine, ok := directEngineError(err)
	if !ok {
		return false
	}
	operation := engineOperation(engine.Operation)
	if engine.Code == codeThreadMismatch && (operation == operationInit || operation == operationAbort) {
		_, ok := directNativeResult(operation, err)
		return ok
	}
	if !validPointerShapePoison(engine, operation) {
		return false
	}
	_, ok = directNativeResult(operation, engine.Cause)
	return ok
}

func validPointerShapePoison(engine *EngineError, operation engineOperation) bool {
	return engine.Class == EngineLocalInvariant && engine.Code == codeProblem && engine.Diagnostic == "mdbx_txn_begin returned invalid result shape" && (operation == operationInit || operation == operationOpen || operation == operationView || operation == operationInspect)
}

func validClosedTerminal(err error) bool {
	if validDirectClosedTerminal(err) {
		return true
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return false
	}
	parts := joined.Unwrap()
	return len(parts) == 2 && validConsumedCloseTerminal(parts[0]) && validReleaseTerminal(parts[1])
}

func validDirectClosedTerminal(err error) bool {
	return err == nil || validReleaseTerminal(err) || validConsumedCloseTerminal(err) || validConsumedReadTerminal(err)
}

func validConsumedReadTerminal(err error) bool {
	if valid, direct := validDirectConsumedReadTerminal(err); direct {
		return valid
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return false
	}
	parts := joined.Unwrap()
	if len(parts) != 2 {
		return false
	}
	if validConsumedReadTerminal(parts[1]) {
		return parts[0] != nil
	}
	if validConsumedCleanupTerminal(parts[1]) {
		return validConsumedReadTerminal(parts[0])
	}
	return false
}

func validDirectConsumedReadTerminal(err error) (bool, bool) {
	engine, direct := directEngineError(err)
	if !direct {
		return false, false
	}
	operation := engineOperation(engine.Operation)
	switch operation {
	case operationAbort:
		_, valid := directNativeResult(operationAbort, err)
		return valid && engine.Code != codeThreadMismatch, true
	case operationView, operationGet, operationPrefixPage, operationInspect:
		_, valid := directNativeResult(operation, err)
		return valid, true
	default:
		return false, true
	}
}

func validConsumedCleanupTerminal(err error) bool {
	return validConsumedCloseTerminal(err) || validReleaseTerminal(err)
}

func validConsumedCloseTerminal(e error) bool {
	v, ok := directNativeResult(operationClose, e)
	return ok && v.Code != codeBusy
}

func validReleaseTerminal(err error) bool {
	engine, ok := directEngineError(err)
	return ok && engine.Operation == string(operationClose) && engine.Diagnostic == "release Rubin writer lock" && engine.Cause != nil && engine.Class == classifyNative(operationClose, engine.Code) && engine.ReopenRequired == reopenRequired(engine.Code)
}

func directEngineError(err error) (*EngineError, bool) {
	value := reflect.ValueOf(err)
	if !value.IsValid() || value.Type() != reflect.TypeFor[*EngineError]() || value.Kind() != reflect.Pointer || value.IsNil() {
		return nil, false
	}
	engine, ok := value.Interface().(*EngineError)
	return engine, ok
}

func validatePath(operation engineOperation, path string) error {
	if path == "" || strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return adapterError(operation, EngineInvalidInput, codeEINVAL, "path must be nonempty, NUL-free, absolute and clean", nil)
	}
	return nil
}

func requireCreateTargetAbsent(path string) error {
	_, err := os.Lstat(path)
	if err == nil {
		return adapterError(operationCreate, EngineInvalidInput, codeEExist, "Create path already exists", nil)
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return ioError(operationCreate, "inspect Create path", err)
}

func createDirectory(path string) error {
	err := os.Mkdir(path, 0o700)
	if err != nil {
		return ioError(operationCreate, "create environment directory", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return ioError(operationCreate, "read back environment directory", err)
	}
	if !validDirectoryInfo(info, false) {
		return integrityError(operationCreate, "environment directory is unsafe", nil)
	}
	err = os.Chmod(path, 0o700)
	if err != nil {
		return ioError(operationCreate, "normalize environment directory mode", err)
	}
	info, err = os.Lstat(path)
	if err != nil {
		return ioError(operationCreate, "read back environment directory", err)
	}
	if !validDirectoryInfo(info, true) {
		return integrityError(operationCreate, "environment directory is unsafe", nil)
	}
	return nil
}

func validateOpenArtifacts(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, adapterError(operationOpen, EngineInvalidInput, codeENOFile, "Open path is absent", nil)
	}
	if err != nil {
		return false, ioError(operationOpen, "inspect environment directory", err)
	}
	if !validDirectoryInfo(info, true) {
		return false, integrityError(operationOpen, "environment directory is unsafe", nil)
	}
	for _, name := range [...]string{"mdbx.dat", "mdbx.lck"} {
		_, err = inspectOpenFile(path, name, false, false)
		if err != nil {
			return false, err
		}
	}
	return inspectOpenFile(path, "rubin-writer.lock", true, false)
}

func validateOpenStatic(cfg ConfigV1) error {
	_, err := cfg.Encode()
	if err != nil {
		return adapterError(operationOpen, EngineInvalidInput, codeEINVAL, "invalid ConfigV1", err)
	}
	return nil
}

func validatePreopenSnapshot(path string) error {
	pathBytes := append([]byte(path), 0)
	var info C.MDBX_envinfo
	rc := int(C.mdbx_preopen_snapinfo((*C.char)(unsafe.Pointer(&pathBytes[0])), &info, C.size_t(unsafe.Sizeof(info))))
	runtime.KeepAlive(pathBytes)
	if rc == codeSuccess {
		return nil
	}
	if rc == int(C.MDBX_ENODATA) {
		return integrityError(operationOpen, "mdbx.dat is undersized", nil)
	}
	return nativeError(operationOpen, rc)
}

func inspectOpenFile(path, name string, empty, missingAllowed bool) (bool, error) {
	info, err := os.Lstat(filepath.Join(path, name))
	if errors.Is(err, os.ErrNotExist) {
		if missingAllowed {
			return true, nil
		}
		return false, adapterError(operationOpen, EngineInvalidInput, codeENOFile, name+" is absent", nil)
	}
	if err != nil {
		return false, ioError(operationOpen, "inspect "+name, err)
	}
	if !validFileInfo(info, empty, true) {
		return false, integrityError(operationOpen, name+" is unsafe", nil)
	}
	return false, nil
}

func validDirectoryInfo(info os.FileInfo, exactMode bool) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0 && (!exactMode || exactPermissionBits(info.Mode()) == 0o700)
}

func validFileInfo(info os.FileInfo, empty, exactMode bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return info.Mode().IsRegular() && ok && uint64(stat.Nlink) == 1 && (!empty || info.Size() == 0) && (!exactMode || exactPermissionBits(info.Mode()) == 0o600)
}

func exactPermissionBits(mode os.FileMode) os.FileMode {
	return mode & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
}

var normalizeMDBXModule = sync.OnceValue(func() error {
	result := C.rubin_mdbx_normalize_debug()
	return debugNormalizationError(int(result.first), int(result.second))
})

func debugNormalizationError(first, second int) error {
	if first < 0 {
		return adapterError(operationInit, EngineLocalInvariant, codeProblem, "MDBX debug normalization failed", nil)
	}
	if second != 0x00030000 {
		return adapterError(operationInit, EngineLocalInvariant, codeProblem, "MDBX debug normalization did not stabilize", nil)
	}
	return nil
}

func acquireWriter(path string, operation engineOperation, create bool) (*filelock.Handle, error) {
	lockPath := filepath.Join(path, "rubin-writer.lock")
	handle, result, err := filelock.AcquireDirectory(path)
	if err != nil {
		return nil, writerLockError(operation, result, err)
	}
	if create {
		err = createWriterMarker(lockPath, operation)
		if err == nil {
			err = normalizeOwnedFile(lockPath, "rubin-writer.lock", true, operation, "normalize Rubin writer lock mode", "read back Rubin writer lock")
		}
	} else {
		err = readOwnedFile(lockPath, "rubin-writer.lock", true, operation, "read back Rubin writer lock")
	}
	if err != nil {
		return nil, joinErrors(err, releaseError(handle))
	}
	return handle, nil
}

func createWriterMarker(lockPath string, operation engineOperation) error {
	marker, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return writerLockError(operation, filelock.ResultInvalidOrUnopenable, err)
	}
	closeErr := marker.Close()
	if closeErr != nil {
		return writerLockError(operation, filelock.ResultInvalidOrUnopenable, closeErr)
	}
	return nil
}

func normalizeOwnedFile(path, name string, empty bool, operation engineOperation, normalizeDiagnostic, readDiagnostic string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return ioError(operation, readDiagnostic, err)
	}
	if !validFileInfo(info, empty, false) {
		return integrityError(operation, name+" is unsafe", nil)
	}
	err = os.Chmod(path, 0o600)
	if err != nil {
		return ioError(operation, normalizeDiagnostic, err)
	}
	return readOwnedFile(path, name, empty, operation, readDiagnostic)
}

func readOwnedFile(path, name string, empty bool, operation engineOperation, diagnostic string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return ioError(operation, diagnostic, err)
	}
	if !validFileInfo(info, empty, true) {
		return integrityError(operation, name+" is unsafe", nil)
	}
	return nil
}

type nativeLimits struct{ minDB, maxDB, maxKey, maxValue int64 }

func limitsForPage(pageSize uint32) nativeLimits {
	page := C.intptr_t(pageSize)
	return nativeLimits{minDB: int64(C.mdbx_limits_dbsize_min(page)), maxDB: int64(C.mdbx_limits_dbsize_max(page)), maxKey: int64(C.mdbx_limits_keysize_max(page, C.MDBX_DB_DEFAULTS)), maxValue: int64(C.mdbx_limits_valsize_max(page, C.MDBX_DB_DEFAULTS))}
}

func validateLimits(cfg ConfigV1, limits nativeLimits) error {
	if limits.minDB < 0 || limits.maxDB < limits.minDB || limits.maxKey < 77 || limits.maxValue < 68_000_125 {
		return fmt.Errorf("native limits min=%d max=%d key=%d value=%d", limits.minDB, limits.maxDB, limits.maxKey, limits.maxValue)
	}
	if cfg.Lower < uint64(limits.minDB) || cfg.Now < uint64(limits.minDB) || cfg.Upper > uint64(limits.maxDB) {
		return fmt.Errorf("geometry [%d,%d,%d] outside [%d,%d]", cfg.Lower, cfg.Now, cfg.Upper, limits.minDB, limits.maxDB)
	}
	return nil
}

func (s *Store) createEnvironment(path string, cfg ConfigV1) error {
	err := openNativeEnvironment(s.env, path, C.MDBX_NOSTICKYTHREADS, 0o600, operationCreate)
	if err != nil {
		return err
	}
	for _, name := range [...]string{"mdbx.dat", "mdbx.lck"} {
		err = normalizeOwnedFile(filepath.Join(path, name), name, false, operationCreate, "normalize "+name+" mode", "read back "+name)
		if err != nil {
			return err
		}
	}
	effective, err := readEffective(s.env, nil, operationCreate)
	if err != nil {
		return err
	}
	err = validateEffective(cfg, effective)
	if err != nil {
		return integrityError(operationCreate, "effective environment mismatch", err)
	}
	return nil
}

func (s *Store) configureCreateEnvironment(path string, cfg ConfigV1) error {
	err := s.allocateEnvironment(operationCreate)
	if err != nil {
		return err
	}
	maxDBs := C.MDBX_dbi(8)
	if fixtureCreateExtraDBI != nil && fixtureCreateExtraDBI(path) {
		maxDBs = 9
	}
	if rc := int(C.mdbx_env_set_maxdbs(s.env, maxDBs)); rc != codeSuccess {
		return nativeError(operationCreate, rc)
	}
	if rc := int(C.mdbx_env_set_maxreaders(s.env, C.uint(cfg.MaxReaders))); rc != codeSuccess {
		return nativeError(operationCreate, rc)
	}
	if rc := int(C.mdbx_env_set_geometry(s.env, C.intptr_t(cfg.Lower), C.intptr_t(cfg.Now), C.intptr_t(cfg.Upper), C.intptr_t(cfg.Growth), C.intptr_t(cfg.Shrink), C.intptr_t(cfg.PageSize))); rc != codeSuccess {
		return nativeError(operationCreate, rc)
	}
	return validateCreateGeometry(s.env, cfg)
}

func validateCreateGeometry(env *C.MDBX_env, cfg ConfigV1) error {
	var info C.MDBX_envinfo
	if rc := int(C.mdbx_env_info_ex(env, nil, &info, C.size_t(unsafe.Sizeof(info)))); rc != codeSuccess {
		return nativeError(operationCreate, rc)
	}
	for _, field := range []struct {
		name      string
		got, want uint64
	}{{"PageSize", uint64(info.mi_dxb_pagesize), uint64(cfg.PageSize)}, {"Lower", uint64(info.mi_geo.lower), cfg.Lower}, {"Now", uint64(info.mi_geo.current), cfg.Now}, {"Upper", uint64(info.mi_geo.upper), cfg.Upper}, {"Growth", uint64(info.mi_geo.grow), cfg.Growth}, {"Shrink", uint64(info.mi_geo.shrink), cfg.Shrink}} {
		if field.got != field.want {
			err := fmt.Errorf("%s: got %d, want %d", field.name, field.got, field.want)
			return adapterError(operationCreate, EngineInvalidInput, codeEINVAL, "ConfigV1 geometry is not natively representable", err)
		}
	}
	return nil
}

func (s *Store) openEnvironment(path string, cfg ConfigV1) error {
	err := s.allocateEnvironment(operationOpen)
	if err != nil {
		return err
	}
	if rc := int(C.mdbx_env_set_maxdbs(s.env, 8)); rc != codeSuccess {
		return nativeError(operationOpen, rc)
	}
	if rc := int(C.mdbx_env_set_maxreaders(s.env, C.uint(cfg.MaxReaders))); rc != codeSuccess {
		return nativeError(operationOpen, rc)
	}
	err = openNativeEnvironment(s.env, path, C.MDBX_NOSTICKYTHREADS, 0, operationOpen)
	if err != nil {
		return err
	}
	for _, name := range []string{"mdbx.dat", "mdbx.lck"} {
		err = readOwnedFile(filepath.Join(path, name), name, false, operationOpen, "read back "+name)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) allocateEnvironment(operation engineOperation) error {
	created := C.rubin_mdbx_env_create()
	err := nativePointerResultError(operation, "mdbx_env_create returned invalid result shape", int(created.rc), created.env != nil)
	if err != nil {
		return err
	}
	s.env = created.env
	return nil
}

func nativePointerResultError(operation engineOperation, diagnostic string, rc int, present bool) error {
	if !validEngineOperation(operation) {
		return adapterError(operation, EngineLocalInvariant, codeProblem, diagnostic, nil)
	}
	if rc == codeSuccess && present {
		return nil
	}
	if rc == codeSuccess {
		return adapterError(operation, EngineLocalInvariant, codeProblem, diagnostic, nil)
	}
	native := nativeError(operation, rc)
	if !present {
		return native
	}
	return adapterError(operation, EngineLocalInvariant, codeProblem, diagnostic, native)
}

func openNativeEnvironment(env *C.MDBX_env, path string, flags C.MDBX_env_flags_t, mode C.mdbx_mode_t, operation engineOperation) error {
	pathBytes := append([]byte(path), 0)
	rc := int(C.mdbx_env_open(env, (*C.char)(unsafe.Pointer(&pathBytes[0])), flags, mode))
	runtime.KeepAlive(pathBytes)
	if rc != codeSuccess {
		return nativeError(operation, rc)
	}
	return nil
}

type effectiveConfig struct {
	flags, mode, pageSize, systemPageSize uint32
	maxReaders                            uint32
	lower, current, upper, growth, shrink uint64
	maxKey, maxValue                      int64
	limits                                nativeLimits
}

func readEffective(env *C.MDBX_env, txn *C.MDBX_txn, operation engineOperation) (effectiveConfig, error) {
	var flags C.uint
	if rc := int(C.mdbx_env_get_flags(env, &flags)); rc != codeSuccess {
		return effectiveConfig{}, nativeError(operation, rc)
	}
	var info C.MDBX_envinfo
	if rc := int(C.mdbx_env_info_ex(env, txn, &info, C.size_t(unsafe.Sizeof(info)))); rc != codeSuccess {
		return effectiveConfig{}, nativeError(operation, rc)
	}
	pageSize := uint32(info.mi_dxb_pagesize)
	return effectiveConfig{flags: uint32(flags), mode: uint32(info.mi_mode), pageSize: pageSize, systemPageSize: uint32(info.mi_sys_pagesize), maxReaders: uint32(info.mi_maxreaders), lower: uint64(info.mi_geo.lower), current: uint64(info.mi_geo.current), upper: uint64(info.mi_geo.upper), growth: uint64(info.mi_geo.grow), shrink: uint64(info.mi_geo.shrink), maxKey: int64(C.mdbx_env_get_maxkeysize_ex(env, C.MDBX_DB_DEFAULTS)), maxValue: int64(C.mdbx_env_get_maxvalsize_ex(env, C.MDBX_DB_DEFAULTS)), limits: limitsForPage(pageSize)}, nil
}

func validateEffective(cfg ConfigV1, got effectiveConfig) error {
	err := validateEffectiveHeader(cfg, got)
	if err != nil {
		return err
	}
	for _, field := range []struct {
		name      string
		got, want uint64
	}{
		{"Lower", got.lower, cfg.Lower},
		{"Upper", got.upper, cfg.Upper},
		{"Growth", got.growth, cfg.Growth},
		{"Shrink", got.shrink, cfg.Shrink},
	} {
		if field.got != field.want {
			return fmt.Errorf("%s: got %d, want %d", field.name, field.got, field.want)
		}
	}
	if !validEffectiveCurrent(cfg, got.current) {
		return fmt.Errorf("%s: got %d outside aligned [%d,%d]", "Current", got.current, cfg.Lower, cfg.Upper)
	}
	if got.maxKey < 77 {
		return fmt.Errorf("MaxKey: got %d, want at least 77", got.maxKey)
	}
	if got.maxValue < 68_000_125 {
		return fmt.Errorf("MaxValue: got %d, want at least 68000125", got.maxValue)
	}
	return validateLimits(cfg, got.limits)
}

func validateEffectiveHeader(cfg ConfigV1, got effectiveConfig) error {
	if got.flags != 0x02200000 {
		return fmt.Errorf("flags: got %#x, want 0x2200000", got.flags)
	}
	if got.mode != 0 {
		return fmt.Errorf("mode: got %#x, want 0", got.mode)
	}
	if got.pageSize != cfg.PageSize {
		return fmt.Errorf("PageSize: got %d, want %d", got.pageSize, cfg.PageSize)
	}
	return validateEffectiveMaxReaders(cfg.MaxReaders, got.maxReaders, got.systemPageSize)
}

func validateEffectiveMaxReaders(requested, effective, systemPageSize uint32) error {
	if systemPageSize < 256 || systemPageSize > 16*1024*1024 || systemPageSize&(systemPageSize-1) != 0 {
		return fmt.Errorf("%s: got %d outside supported power-of-two [256,16777216]", "SystemPageSize", systemPageSize)
	}
	upper := uint64(requested) + uint64(systemPageSize)/32 - 1
	if upper > 32767 {
		upper = 32767
	}
	if effective < requested || effective > 32767 || uint64(effective) > upper {
		return fmt.Errorf("%s: got %d outside native rounding [%d,%d] for system page %d", "MaxReaders", effective, requested, upper, systemPageSize)
	}
	return nil
}

func validEffectiveCurrent(cfg ConfigV1, current uint64) bool {
	return current >= cfg.Lower && current <= cfg.Upper && current%uint64(cfg.PageSize) == 0
}

type transactionOutcome struct {
	err      error
	poisoned bool
}

func runLocked(operation func() transactionOutcome) transactionOutcome {
	result := make(chan transactionOutcome, 1)
	go func() {
		runtime.LockOSThread()
		outcome := operation()
		if !outcome.poisoned {
			runtime.UnlockOSThread()
		}
		result <- outcome
		if outcome.poisoned {
			select {}
		}
	}()
	return <-result
}

func (s *Store) initializeLocked(cfg ConfigV1, encodedConfig []byte) transactionOutcome {
	begun := C.rubin_mdbx_txn_begin(s.env, C.MDBX_TXN_READWRITE)
	err := nativePointerResultError(operationInit, "mdbx_txn_begin returned invalid result shape", int(begun.rc), begun.txn != nil)
	if err != nil {
		if begun.txn != nil {
			return s.poison(begun.txn, err)
		}
		return transactionOutcome{err: err}
	}
	dbis, err := initializeSchema(begun.txn, encodedConfig)
	if err != nil {
		return s.abortLocked(begun.txn, err)
	}
	rc := int(C.mdbx_txn_commit(begun.txn))
	decision := commitTransition(rc)
	var commitErr error
	if rc != codeSuccess {
		commitErr = nativeError(operationInit, rc)
	}
	result := orderedErrors(operationInit, decision.order, nil, commitErr)
	if !decision.consumed {
		return s.poison(begun.txn, result)
	}
	if result != nil {
		return transactionOutcome{err: result}
	}
	s.state, s.config, s.dbis, s.canonicalOwnerVerified = storeOPEN, cfg, dbis, true
	return transactionOutcome{}
}

func initializeSchema(txn *C.MDBX_txn, encodedConfig []byte) ([8]C.MDBX_dbi, error) {
	dbis, err := openSchemaDBIs(txn, true, operationInit)
	if err != nil {
		return dbis, err
	}
	err = putRequiredMeta(txn, dbis[0], encodedConfig)
	if err != nil {
		return dbis, err
	}
	if fixtureBeforeInitCensus != nil {
		err = fixtureBeforeInitCensus(txn, dbis[0])
		if err != nil {
			return dbis, err
		}
	}
	err = verifyMainCardinality(txn, operationInit)
	if err != nil {
		return dbis, err
	}
	return dbis, verifyCreatedMeta(txn, dbis[0], encodedConfig)
}

func (s *Store) inspectOpenLocked(cfg ConfigV1) transactionOutcome {
	begun := C.rubin_mdbx_txn_begin(s.env, C.MDBX_TXN_RDONLY)
	err := nativePointerResultError(operationOpen, "mdbx_txn_begin returned invalid result shape", int(begun.rc), begun.txn != nil)
	if err != nil {
		if begun.txn != nil {
			return s.poison(begun.txn, err)
		}
		return transactionOutcome{err: err}
	}
	dbis, primary := inspectSchema(s.env, begun.txn, cfg)
	outcome := s.abortLocked(begun.txn, primary)
	if outcome.err == nil && !outcome.poisoned {
		s.state, s.config, s.dbis = storeOPEN, cfg, dbis
	}
	return outcome
}

func inspectSchema(env *C.MDBX_env, txn *C.MDBX_txn, cfg ConfigV1) ([8]C.MDBX_dbi, error) {
	err := verifyMainCardinality(txn, operationOpen)
	if err != nil {
		return [8]C.MDBX_dbi{}, err
	}
	dbis, err := openSchemaDBIs(txn, false, operationOpen)
	if err != nil {
		return dbis, err
	}
	stored, err := readRequiredMeta(txn, dbis[0])
	if err != nil {
		return dbis, err
	}
	err = validateStoredConfig(stored, cfg)
	if err != nil {
		return dbis, integrityError(operationOpen, "effective environment mismatch", err)
	}
	effective, err := readEffective(env, txn, operationOpen)
	if err != nil {
		return dbis, err
	}
	if err = validateEffective(cfg, effective); err != nil {
		return dbis, integrityError(operationOpen, "effective environment mismatch", err)
	}
	return dbis, nil
}

func validateStoredConfig(stored, caller ConfigV1) error {
	for _, field := range []struct {
		name        string
		got, wanted uint64
	}{
		{"Lower", stored.Lower, caller.Lower},
		{"Now", stored.Now, caller.Now},
		{"Upper", stored.Upper, caller.Upper},
		{"Growth", stored.Growth, caller.Growth},
		{"Shrink", stored.Shrink, caller.Shrink},
		{"PageSize", uint64(stored.PageSize), uint64(caller.PageSize)},
		{"MaxReaders", uint64(stored.MaxReaders), uint64(caller.MaxReaders)},
	} {
		if field.got != field.wanted {
			return fmt.Errorf("%s: got %d, want %d", field.name, field.got, field.wanted)
		}
	}
	return nil
}

func (s *Store) abortLocked(txn *C.MDBX_txn, primary error) transactionOutcome {
	rc := int(C.mdbx_txn_abort(txn))
	decision := abortTransition(rc, primary != nil)
	var abortErr error
	if rc != codeSuccess {
		abortErr = nativeError(operationAbort, rc)
	}
	result := orderedErrors(operationAbort, decision.order, primary, abortErr)
	if !decision.consumed {
		return s.poison(txn, result)
	}
	return transactionOutcome{err: result}
}

func (s *Store) poison(txn *C.MDBX_txn, err error) transactionOutcome {
	s.state, s.txn, s.config, s.dbis, s.terminal = storePOISONEDTHREAD, txn, ConfigV1{}, [8]C.MDBX_dbi{}, err
	return transactionOutcome{err: err, poisoned: true}
}

func openSchemaDBIs(txn *C.MDBX_txn, create bool, operation engineOperation) ([8]C.MDBX_dbi, error) {
	var opened [8]C.MDBX_dbi
	flags := C.MDBX_db_flags_t(C.MDBX_DB_ACCEDE)
	if create {
		flags = C.MDBX_DB_DEFAULTS | C.MDBX_CREATE
	}
	for i, dbi := range SchemaV2DBIs() {
		name := append([]byte(dbi.Name), 0)
		rc := int(C.mdbx_dbi_open(txn, (*C.char)(unsafe.Pointer(&name[0])), flags, &opened[i]))
		runtime.KeepAlive(name)
		if rc != codeSuccess {
			if !create {
				return opened, metadataError(operation, rc, codeNotFound)
			}
			return opened, nativeError(operation, rc)
		}
		var persistent, state C.uint
		if rc = int(C.mdbx_dbi_flags_ex(txn, opened[i], &persistent, &state)); rc != codeSuccess {
			return opened, nativeError(operation, rc)
		}
		if persistent != 0 {
			return opened, integrityError(operation, "SchemaV2 DBI flags mismatch", nil)
		}
	}
	return opened, nil
}

func putRequiredMeta(txn *C.MDBX_txn, meta C.MDBX_dbi, encodedConfig []byte) error {
	for _, row := range []struct{ key, value []byte }{{[]byte{0}, []byte{0, 0, 0, 2}}, {[]byte{1}, encodedConfig}} {
		rc := int(C.rubin_mdbx_put_required(txn, meta, unsafe.Pointer(&row.key[0]), C.size_t(len(row.key)), unsafe.Pointer(&row.value[0]), C.size_t(len(row.value))))
		runtime.KeepAlive(row)
		if rc != codeSuccess {
			return metadataError(operationInit, rc, codeKeyExist)
		}
	}
	return nil
}

func verifyMainCardinality(txn *C.MDBX_txn, operation engineOperation) error {
	var main C.MDBX_dbi
	if rc := int(C.mdbx_dbi_open(txn, nil, C.MDBX_DB_DEFAULTS, &main)); rc != codeSuccess {
		return nativeError(operation, rc)
	}
	var stat C.MDBX_stat
	if rc := int(C.mdbx_dbi_stat(txn, main, &stat, C.size_t(unsafe.Sizeof(stat)))); rc != codeSuccess {
		return nativeError(operation, rc)
	}
	if uint64(stat.ms_entries) != 8 {
		return integrityError(operation, "SchemaV2 main cardinality mismatch", nil)
	}
	return nil
}

func verifyCreatedMeta(txn *C.MDBX_txn, meta C.MDBX_dbi, encodedConfig []byte) error {
	var stat C.MDBX_stat
	if rc := int(C.mdbx_dbi_stat(txn, meta, &stat, C.size_t(unsafe.Sizeof(stat)))); rc != codeSuccess {
		return nativeError(operationInit, rc)
	}
	if uint64(stat.ms_entries) != 2 {
		return integrityError(operationInit, "SchemaV2 metadata cardinality mismatch", nil)
	}
	if err := verifyExactValue(txn, meta, []byte{0}, []byte{0, 0, 0, 2}, operationInit); err != nil {
		return err
	}
	return verifyExactValue(txn, meta, []byte{1}, encodedConfig, operationInit)
}

func readRequiredMeta(txn *C.MDBX_txn, meta C.MDBX_dbi) (ConfigV1, error) {
	version, err := getSizedValue(txn, meta, []byte{0}, 4, operationOpen)
	if err != nil {
		return ConfigV1{}, err
	}
	if err = DecodeSchemaVersionValue(version); err != nil {
		return ConfigV1{}, integrityError(operationOpen, "invalid SchemaV2 version row", err)
	}
	encoded, err := getSizedValue(txn, meta, []byte{1}, 48, operationOpen)
	if err != nil {
		return ConfigV1{}, err
	}
	cfg, err := DecodeConfigV1(encoded)
	if err != nil {
		return ConfigV1{}, integrityError(operationOpen, "invalid ConfigV1 row", err)
	}
	return cfg, nil
}

func verifyExactValue(txn *C.MDBX_txn, dbi C.MDBX_dbi, key, expected []byte, operation engineOperation) error {
	value, err := getSizedValue(txn, dbi, key, len(expected), operation)
	if err != nil {
		return err
	}
	if !bytes.Equal(value, expected) {
		return integrityError(operation, "required metadata value mismatch", nil)
	}
	return nil
}

func getSizedValue(txn *C.MDBX_txn, dbi C.MDBX_dbi, key []byte, size int, operation engineOperation) ([]byte, error) {
	value := C.rubin_mdbx_get(txn, dbi, unsafe.Pointer(&key[0]), C.size_t(len(key)))
	runtime.KeepAlive(key)
	if err := requiredValueResult(operation, int(value.rc), uint64(value.length), value.bytes != nil, uint64(size)); err != nil {
		return nil, err
	}
	return C.GoBytes(unsafe.Pointer(value.bytes), C.int(size)), nil
}

func (s *Store) consumeFailure(primary error) (*Store, error) {
	retained, err := s.consume(primary)
	if retained {
		return s, err
	}
	return nil, err
}

func (s *Store) consume(primary error) (bool, error) {
	nativeOutcome := primary
	if s.env != nil {
		rc := int(C.mdbx_env_close_ex(s.env, false))
		decision := closeTransition(rc, primary != nil)
		var closeErr error
		if rc != codeSuccess {
			closeErr = nativeError(operationClose, rc)
		}
		nativeOutcome = orderedErrors(operationClose, decision.order, primary, closeErr)
		if !decision.consumed {
			if s.state != storeCLOSEBLOCKED {
				s.state, s.terminal = decision.next, nativeOutcome
			}
			return true, s.terminal
		}
		s.env = nil
	}
	releaseErr := releaseError(s.writer)
	s.writer, s.txn = nil, nil
	s.config, s.dbis = ConfigV1{}, [8]C.MDBX_dbi{}
	s.state = storeCLOSED
	s.terminal = joinErrors(nativeOutcome, releaseErr)
	return false, s.terminal
}

func releaseError(handle *filelock.Handle) error {
	return releaseResult(handle.Release())
}

func releaseResult(err error) error {
	if err == nil {
		return nil
	}
	return ioError(operationClose, "release Rubin writer lock", err)
}
