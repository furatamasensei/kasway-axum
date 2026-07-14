# Admin connection used to drop the integration-test databases. Points at the
# `postgres` maintenance DB, mirroring what the test harness connects to.
ADMIN_URL ?= postgres://postgres:postgres@localhost:5432/postgres

# The integration-test harness (Db::connect_memory) creates a database per test
# and never drops it, so a full run leaks ~130. Sweep them.
# Matches only the harness's `kasway_test_<pid>_<millis>_<counter>` shape, so
# real databases (kasway, kasway_e2e) are never touched.
.PHONY: test-db-clean
test-db-clean:
	@psql "$(ADMIN_URL)" -tAc "select 'DROP DATABASE IF EXISTS \"'||datname||'\" WITH (FORCE);' \
	    from pg_database where datname ~ '^kasway_test_[0-9]+_[0-9]+_[0-9]+$$'" \
	  | psql "$(ADMIN_URL)" -q -v ON_ERROR_STOP=0
	@psql "$(ADMIN_URL)" -tAc "select 'remaining test databases: '||count(*) \
	    from pg_database where datname like 'kasway_test_%'"
