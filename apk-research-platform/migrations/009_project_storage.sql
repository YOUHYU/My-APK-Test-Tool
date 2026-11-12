-- Per-project storage location.
--
-- ``storage_root`` holds the absolute directory that owns one project's files
-- (inputs/, artifacts/, indexes/, evidence/, logs/, reports/). When NULL the
-- project lives under <APKPLAT_STORAGE>/projects/<project_id> like before, so
-- every existing row keeps working without a backfill.

ALTER TABLE projects ADD COLUMN storage_root TEXT;
