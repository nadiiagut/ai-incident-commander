CREATE DATABASE IF NOT EXISTS incident_demo;

CREATE TABLE IF NOT EXISTS incident_demo.checkout_logs
(
    timestamp          DateTime64(3, 'UTC'),
    request_id         String,
    client_ip          String,
    endpoint           LowCardinality(String),
    method             LowCardinality(String),
    status_code        UInt16,
    error              Nullable(String),
    deployment_version LowCardinality(String),
    response_time_ms   UInt32
)
ENGINE = MergeTree
ORDER BY (timestamp, endpoint, status_code);
