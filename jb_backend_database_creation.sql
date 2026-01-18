-- Create extension for UUID generation (if not exists)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- Users Table
-- =============================================================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'job_seeker',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for users
CREATE INDEX IF NOT EXISTS ix_users_email ON users(email);
CREATE INDEX IF NOT EXISTS ix_users_role ON users(role);
CREATE INDEX IF NOT EXISTS ix_users_is_active ON users(is_active);

-- =============================================================================
-- Jobs Table
-- =============================================================================
CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    employer_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    company_name VARCHAR(255) NOT NULL,
    location VARCHAR(255) NOT NULL,
    job_type VARCHAR(50) NOT NULL DEFAULT 'full_time',
    salary_min INTEGER,
    salary_max INTEGER,
    status VARCHAR(50) NOT NULL DEFAULT 'draft',
    search_vector TSVECTOR,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE
);

-- Indexes for jobs
CREATE INDEX IF NOT EXISTS ix_jobs_employer ON jobs(employer_id);
CREATE INDEX IF NOT EXISTS ix_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS ix_jobs_location ON jobs(location);
CREATE INDEX IF NOT EXISTS ix_jobs_job_type ON jobs(job_type);
CREATE INDEX IF NOT EXISTS ix_jobs_created_at ON jobs(created_at DESC);

-- GIN index for full-text search (very important for performance!)
CREATE INDEX IF NOT EXISTS ix_jobs_search_vector ON jobs USING GIN(search_vector);

-- =============================================================================
-- Full-Text Search Trigger
-- =============================================================================
-- This trigger automatically updates the search_vector column
-- whenever a job is inserted or updated.

-- Function to update search vector
CREATE OR REPLACE FUNCTION jobs_search_vector_update() RETURNS trigger AS $$
BEGIN
    NEW.search_vector := 
        setweight(to_tsvector('english', COALESCE(NEW.title, '')), 'A') ||
        setweight(to_tsvector('english', COALESCE(NEW.company_name, '')), 'B') ||
        setweight(to_tsvector('english', COALESCE(NEW.description, '')), 'C') ||
        setweight(to_tsvector('english', COALESCE(NEW.location, '')), 'D');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger
DROP TRIGGER IF EXISTS jobs_search_vector_trigger ON jobs;
CREATE TRIGGER jobs_search_vector_trigger
    BEFORE INSERT OR UPDATE ON jobs
    FOR EACH ROW
    EXECUTE FUNCTION jobs_search_vector_update();

-- =============================================================================
-- Applications Table
-- =============================================================================
CREATE TABLE IF NOT EXISTS applications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    applicant_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    cover_letter TEXT,
    resume_url VARCHAR(500),
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Unique constraint: one application per job per user
    CONSTRAINT uq_application_job_applicant UNIQUE(job_id, applicant_id)
);

-- Indexes for applications
CREATE INDEX IF NOT EXISTS ix_applications_job_id ON applications(job_id);
CREATE INDEX IF NOT EXISTS ix_applications_applicant_id ON applications(applicant_id);
CREATE INDEX IF NOT EXISTS ix_applications_status ON applications(status);
CREATE INDEX IF NOT EXISTS ix_applications_created_at ON applications(created_at DESC);

-- =============================================================================
-- Updated_at Trigger
-- =============================================================================
-- Automatically update the updated_at timestamp when a row is modified

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to all tables
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_jobs_updated_at
    BEFORE UPDATE ON jobs
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_applications_updated_at
    BEFORE UPDATE ON applications
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Sample Data (for testing)
-- =============================================================================

-- Insert sample employer
INSERT INTO users (id, email, hashed_password, full_name, role) VALUES
    ('00000000-0000-0000-0000-000000000001', 'employer@example.com', 
     '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.AFcLH1JxjRdMGS', -- password: Test1234
     'John Employer', 'employer')
ON CONFLICT (email) DO NOTHING;

-- Insert sample job seeker
INSERT INTO users (id, email, hashed_password, full_name, role) VALUES
    ('00000000-0000-0000-0000-000000000002', 'jobseeker@example.com',
     '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.AFcLH1JxjRdMGS', -- password: Test1234
     'Jane Seeker', 'job_seeker')
ON CONFLICT (email) DO NOTHING;

-- Insert sample jobs
INSERT INTO jobs (employer_id, title, description, company_name, location, job_type, salary_min, salary_max, status) VALUES
    ('00000000-0000-0000-0000-000000000001',
     'Senior Software Engineer',
     'We are looking for an experienced software engineer to join our team. You will work on distributed systems and help scale our infrastructure to handle millions of users. Requirements: 5+ years experience with Python, experience with PostgreSQL, familiarity with Docker and Kubernetes.',
     'TechCorp Inc',
     'San Francisco, CA',
     'full_time',
     150000,
     200000,
     'active'),
    ('00000000-0000-0000-0000-000000000001',
     'Backend Developer',
     'Join our backend team to build RESTful APIs and microservices. You will work with Python, FastAPI, and PostgreSQL. Great opportunity for someone who wants to learn distributed systems. Requirements: 2+ years experience with Python, SQL knowledge.',
     'TechCorp Inc',
     'Remote',
     'full_time',
     100000,
     130000,
     'active'),
    ('00000000-0000-0000-0000-000000000001',
     'Junior Developer',
     'Entry-level position for recent graduates. You will learn from experienced engineers and work on real projects. We provide mentorship and training. Requirements: Bachelor degree in CS or related field, basic programming knowledge.',
     'TechCorp Inc',
     'New York, NY',
     'full_time',
     70000,
     90000,
     'active')
ON CONFLICT DO NOTHING;

COMMENT ON DATABASE jobboard IS 'Job Board Application Database';
