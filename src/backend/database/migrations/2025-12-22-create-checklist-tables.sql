-- Migration: Create Checklist Tables
-- Version: 1.0
-- Date: 2025-12-22
-- Work Stream: 26 - Action Item Checklist Backend

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Table: checklist_items
-- Stores action items that can be tracked and completed by consultants and clients
CREATE TABLE checklist_items (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,

  -- Item content
  title VARCHAR(500) NOT NULL,
  description TEXT,
  phase VARCHAR(50) NOT NULL, -- 'Stabilize', 'Organize', 'Build', 'Grow', 'Systemic'
  priority INT DEFAULT 0, -- 0=none, 1=low, 2=medium, 3=high
  sort_order INT NOT NULL DEFAULT 0,

  -- Completion tracking
  is_completed BOOLEAN DEFAULT FALSE,
  completed_at TIMESTAMPTZ,
  completed_by UUID REFERENCES users(id), -- consultant or client who marked it complete

  -- Client notes
  client_notes TEXT,
  client_notes_updated_at TIMESTAMPTZ,

  -- Auto-generation metadata
  auto_generated BOOLEAN DEFAULT FALSE,
  source_recommendation_id VARCHAR(100), -- Reference to report recommendation section

  -- Audit fields
  created_at TIMESTAMPTZ DEFAULT NOW(),
  created_by UUID NOT NULL REFERENCES users(id),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  updated_by UUID REFERENCES users(id),
  deleted_at TIMESTAMPTZ, -- Soft delete

  CONSTRAINT checklist_items_phase_check CHECK (
    phase IN ('Stabilize', 'Organize', 'Build', 'Grow', 'Systemic')
  ),
  CONSTRAINT checklist_items_priority_check CHECK (
    priority BETWEEN 0 AND 3
  )
);

-- Indexes for checklist_items
CREATE INDEX idx_checklist_items_assessment_id ON checklist_items(assessment_id);
CREATE INDEX idx_checklist_items_phase ON checklist_items(phase);
CREATE INDEX idx_checklist_items_completed ON checklist_items(is_completed);
CREATE INDEX idx_checklist_items_sort_order ON checklist_items(assessment_id, sort_order);
CREATE INDEX idx_checklist_items_deleted_at ON checklist_items(deleted_at);

-- Table: checklist_edit_history
-- Tracks all changes made to checklist items for audit purposes
CREATE TABLE checklist_edit_history (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  checklist_item_id UUID NOT NULL REFERENCES checklist_items(id) ON DELETE CASCADE,

  -- Change tracking
  action VARCHAR(50) NOT NULL, -- 'created', 'updated', 'completed', 'uncompleted', 'deleted'
  field_name VARCHAR(100), -- Which field was changed
  old_value TEXT,
  new_value TEXT,

  -- Audit
  changed_by UUID NOT NULL REFERENCES users(id),
  changed_at TIMESTAMPTZ DEFAULT NOW(),
  ip_address INET,
  user_agent TEXT
);

-- Index for checklist_edit_history
CREATE INDEX idx_checklist_history_item_id ON checklist_edit_history(checklist_item_id);
CREATE INDEX idx_checklist_history_changed_at ON checklist_edit_history(changed_at);

-- Comments
COMMENT ON TABLE checklist_items IS 'Action items that consultants and clients can track and complete';
COMMENT ON TABLE checklist_edit_history IS 'Audit trail of all changes to checklist items';

COMMENT ON COLUMN checklist_items.phase IS 'Financial phase: Stabilize, Organize, Build, Grow, or Systemic';
COMMENT ON COLUMN checklist_items.priority IS '0=none, 1=low, 2=medium, 3=high';
COMMENT ON COLUMN checklist_items.auto_generated IS 'True if item was auto-generated from report recommendations';
COMMENT ON COLUMN checklist_items.source_recommendation_id IS 'Reference to the recommendation in the report that generated this item';
COMMENT ON COLUMN checklist_items.deleted_at IS 'Soft delete timestamp - item is hidden but not removed';
