-- database_schema.sql
-- PostgreSQL 14+ Schema for CVE/CWE Integration

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm"; -- For text search

-- ==================== CWE Table ====================
CREATE TABLE IF NOT EXISTS cwe (
    cwe_id VARCHAR(20) PRIMARY KEY,
    name VARCHAR(500),
    description TEXT,
    extended_description TEXT,
    likelihood_of_exploit VARCHAR(50),
    typical_severity VARCHAR(50),
    related_weaknesses TEXT[],
    applicable_platforms TEXT[],
    common_consequences JSONB,
    detection_methods JSONB,
    potential_mitigations JSONB,
    observed_examples JSONB,
    references JSONB,
    content_history JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_cwe_name ON cwe USING gin(name gin_trgm_ops);
CREATE INDEX idx_cwe_severity ON cwe(typical_severity);

-- ==================== CVE Table ====================
CREATE TABLE IF NOT EXISTS cve (
    cve_id VARCHAR(30) PRIMARY KEY,
    source_identifier VARCHAR(255),
    published_date TIMESTAMP,
    last_modified_date TIMESTAMP,
    vuln_status VARCHAR(50),
    description TEXT,

    -- CVSS v3.1 Metrics
    cvss_version VARCHAR(10),
    cvss_vector_string VARCHAR(100),
    cvss_base_score DECIMAL(3,1),
    cvss_base_severity VARCHAR(20),
    cvss_exploitability_score DECIMAL(3,1),
    cvss_impact_score DECIMAL(3,1),

    -- Attack Complexity
    attack_vector VARCHAR(20),
    attack_complexity VARCHAR(20),
    privileges_required VARCHAR(20),
    user_interaction VARCHAR(20),
    scope VARCHAR(20),
    confidentiality_impact VARCHAR(20),
    integrity_impact VARCHAR(20),
    availability_impact VARCHAR(20),

    -- CWE References
    cwe_ids TEXT[],

    -- CPE (Affected Products)
    affected_products JSONB,

    -- References
    references JSONB,

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_cve_published ON cve(published_date DESC);
CREATE INDEX idx_cve_severity ON cve(cvss_base_severity);
CREATE INDEX idx_cve_score ON cve(cvss_base_score DESC);
CREATE INDEX idx_cve_cwe ON cve USING gin(cwe_ids);
CREATE INDEX idx_cve_description ON cve USING gin(description gin_trgm_ops);

-- ==================== CPE (Common Platform Enumeration) ====================
CREATE TABLE IF NOT EXISTS cpe (
    cpe_id SERIAL PRIMARY KEY,
    cpe23_uri VARCHAR(500) UNIQUE,
    cpe_name VARCHAR(500),
    part VARCHAR(1), -- a=application, o=operating system, h=hardware
    vendor VARCHAR(255),
    product VARCHAR(255),
    version VARCHAR(100),
    update_version VARCHAR(100),
    edition VARCHAR(100),
    language VARCHAR(50),
    sw_edition VARCHAR(100),
    target_sw VARCHAR(100),
    target_hw VARCHAR(100),
    other VARCHAR(100),
    deprecated BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_cpe_vendor ON cpe(vendor);
CREATE INDEX idx_cpe_product ON cpe(product);
CREATE INDEX idx_cpe_version ON cpe(version);
CREATE INDEX idx_cpe_uri ON cpe USING gin(cpe23_uri gin_trgm_ops);

-- ==================== CVE-CPE Mapping ====================
CREATE TABLE IF NOT EXISTS cve_cpe_mapping (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(30) REFERENCES cve(cve_id) ON DELETE CASCADE,
    cpe_id INTEGER REFERENCES cpe(cpe_id) ON DELETE CASCADE,
    vulnerable BOOLEAN DEFAULT TRUE,
    version_start_including VARCHAR(100),
    version_start_excluding VARCHAR(100),
    version_end_including VARCHAR(100),
    version_end_excluding VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(cve_id, cpe_id)
);

CREATE INDEX idx_cve_cpe_cve ON cve_cpe_mapping(cve_id);
CREATE INDEX idx_cve_cpe_cpe ON cve_cpe_mapping(cpe_id);

-- ==================== Scan Results Table ====================
CREATE TABLE IF NOT EXISTS scan_results (
    id SERIAL PRIMARY KEY,
    scan_id UUID DEFAULT uuid_generate_v4(),
    repository_url VARCHAR(500),
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    detection_score JSONB,
    scan_duration_seconds INTEGER,
    completed BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_scan_date ON scan_results(scan_date DESC);
CREATE INDEX idx_scan_repo ON scan_results(repository_url);

-- ==================== Findings Table ====================
CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    scan_id UUID REFERENCES scan_results(scan_id) ON DELETE CASCADE,
    source VARCHAR(100), -- Semgrep, Tree-sitter, AI
    file_path VARCHAR(1000),
    line_number VARCHAR(20),
    vulnerability_description TEXT,
    severity VARCHAR(20),
    cwe_id VARCHAR(20) REFERENCES cwe(cwe_id),
    cve_id VARCHAR(30) REFERENCES cve(cve_id),
    zero_day_risk VARCHAR(20),
    ast_analysis JSONB,
    mitigation TEXT,
    false_positive BOOLEAN DEFAULT FALSE,
    resolved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_cwe ON findings(cwe_id);
CREATE INDEX idx_findings_resolved ON findings(resolved);

-- ==================== Statistics Views ====================

CREATE OR REPLACE VIEW vulnerability_statistics AS
SELECT 
    cwe_id,
    cwe.name as cwe_name,
    COUNT(*) as occurrence_count,
    AVG(CASE 
        WHEN severity = 'CRITICAL' THEN 4
        WHEN severity = 'HIGH' THEN 3
        WHEN severity = 'MEDIUM' THEN 2
        WHEN severity = 'LOW' THEN 1
        ELSE 0
    END) as avg_severity_score,
    COUNT(DISTINCT scan_id) as affected_scans
FROM findings
LEFT JOIN cwe USING (cwe_id)
WHERE resolved = FALSE
GROUP BY cwe_id, cwe.name
ORDER BY occurrence_count DESC;

CREATE OR REPLACE VIEW scan_summary AS
SELECT 
    s.scan_id,
    s.repository_url,
    s.scan_date,
    s.total_findings,
    COUNT(f.id) FILTER (WHERE f.severity = 'CRITICAL') as critical,
    COUNT(f.id) FILTER (WHERE f.severity = 'HIGH') as high,
    COUNT(f.id) FILTER (WHERE f.severity = 'MEDIUM') as medium,
    COUNT(f.id) FILTER (WHERE f.severity = 'LOW') as low,
    COUNT(f.id) FILTER (WHERE f.resolved = TRUE) as resolved,
    COUNT(f.id) FILTER (WHERE f.false_positive = TRUE) as false_positives
FROM scan_results s
LEFT JOIN findings f ON s.scan_id = f.scan_id
GROUP BY s.scan_id, s.repository_url, s.scan_date, s.total_findings
ORDER BY s.scan_date DESC;

-- ==================== Functions ====================

-- Function to get CWE details
CREATE OR REPLACE FUNCTION get_cwe_details(p_cwe_id VARCHAR)
RETURNS TABLE (
    cwe_id VARCHAR,
    name VARCHAR,
    description TEXT,
    severity VARCHAR,
    mitigations JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        c.cwe_id,
        c.name,
        c.description,
        c.typical_severity,
        c.potential_mitigations
    FROM cwe c
    WHERE c.cwe_id = p_cwe_id;
END;
$$ LANGUAGE plpgsql;

-- Function to search CVEs by CWE
CREATE OR REPLACE FUNCTION search_cves_by_cwe(p_cwe_id VARCHAR)
RETURNS TABLE (
    cve_id VARCHAR,
    description TEXT,
    cvss_score DECIMAL,
    severity VARCHAR,
    published_date TIMESTAMP
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        c.cve_id,
        c.description,
        c.cvss_base_score,
        c.cvss_base_severity,
        c.published_date
    FROM cve c
    WHERE p_cwe_id = ANY(c.cwe_ids)
    ORDER BY c.cvss_base_score DESC, c.published_date DESC
    LIMIT 100;
END;
$$ LANGUAGE plpgsql;

-- Update timestamp trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_cve_updated_at BEFORE UPDATE ON cve
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_cwe_updated_at BEFORE UPDATE ON cwe
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ==================== Sample Queries ====================

-- Get top 10 most common CWEs in findings
-- SELECT * FROM vulnerability_statistics LIMIT 10;

-- Get all CVEs for a specific CWE
-- SELECT * FROM search_cves_by_cwe('CWE-89');

-- Get recent scans with summary
-- SELECT * FROM scan_summary LIMIT 20;

-- Find findings with known CVEs
-- SELECT f.*, c.cvss_base_score, c.cvss_base_severity
-- FROM findings f
-- JOIN cve c ON f.cve_id = c.cve_id
-- WHERE f.resolved = FALSE
-- ORDER BY c.cvss_base_score DESC;
