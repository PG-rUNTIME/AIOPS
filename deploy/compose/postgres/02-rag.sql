\connect rag
CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE IF NOT EXISTS rag_runbooks (
  id text PRIMARY KEY, title text NOT NULL, failure_types text[] NOT NULL, body text NOT NULL,
  embedding vector(1024)
);
CREATE TABLE IF NOT EXISTS rag_incidents (
  ref text PRIMARY KEY, tenant_id text NOT NULL DEFAULT '*', failure_type text NOT NULL,
  summary text NOT NULL, root_cause text NOT NULL, fix text NOT NULL, embedding vector(1024)
);
CREATE INDEX IF NOT EXISTS rag_runbooks_hnsw ON rag_runbooks USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS rag_incidents_hnsw ON rag_incidents USING hnsw (embedding vector_cosine_ops);
