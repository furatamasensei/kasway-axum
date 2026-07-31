# Admin connection used to drop the integration-test databases. Points at the
# `postgres` maintenance DB, mirroring what the test harness connects to.
ADMIN_URL ?= postgres://postgres:postgres@localhost:5432/postgres

# Force-drop of every disposable database, including ones a live run is still
# connected to. `Db::connect_fresh` already sweeps last run's leftovers on its
# own, so this is the impatient version: use it to reclaim the current run's
# databases now instead of waiting for the next run.
# Matches only the two disposable shapes — `kasway_test_<pid>_<millis>_<counter>`
# and `kasway_smoke_<millis>` — so real databases (kasway, kasway_e2e) are
# never touched.
.PHONY: test-db-clean
test-db-clean:
	@psql "$(ADMIN_URL)" -tAc "select 'DROP DATABASE IF EXISTS \"'||datname||'\" WITH (FORCE);' \
	    from pg_database where datname ~ '^kasway_test_[0-9]+_[0-9]+_[0-9]+$$' \
	                        or datname ~ '^kasway_smoke_[0-9]+$$'" \
	  | psql "$(ADMIN_URL)" -q -v ON_ERROR_STOP=0
	@psql "$(ADMIN_URL)" -tAc "select 'remaining disposable databases: '||count(*) \
	    from pg_database where datname like 'kasway\_test\_%' or datname like 'kasway\_smoke\_%'"
