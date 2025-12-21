/**
 * Test fixtures for algorithm integration tests
 */

/**
 * Sample DISC question responses for testing
 * These represent a client with high D (Dominance) scores
 */
export const highDominanceResponses = [
  { question_id: 'disc-001', response_value: 'decide_quickly' },
  { question_id: 'disc-002', response_value: 'lead_direct' },
  { question_id: 'disc-003', response_value: 'bottom_line' },
  { question_id: 'disc-004', response_value: 'quick_action' },
  { question_id: 'disc-005', response_value: 'competitive' },
  { question_id: 'disc-006', response_value: 'direct_approach' },
  { question_id: 'disc-007', response_value: 'results_focused' },
  { question_id: 'disc-008', response_value: 'fast_paced' },
  { question_id: 'disc-009', response_value: 'challenge_status' },
  { question_id: 'disc-010', response_value: 'independent' },
  { question_id: 'disc-011', response_value: 'decisive' },
  { question_id: 'disc-012', response_value: 'goal_oriented' },
  { question_id: 'disc-013', response_value: 'assertive' },
  { question_id: 'disc-014', response_value: 'efficient' },
  { question_id: 'disc-015', response_value: 'bold' },
];

/**
 * Sample DISC responses for high Influence (I) type
 */
export const highInfluenceResponses = [
  { question_id: 'disc-001', response_value: 'consult_others' },
  { question_id: 'disc-002', response_value: 'brainstorm' },
  { question_id: 'disc-003', response_value: 'big_picture' },
  { question_id: 'disc-004', response_value: 'collaborate' },
  { question_id: 'disc-005', response_value: 'enthusiastic' },
  { question_id: 'disc-006', response_value: 'friendly_approach' },
  { question_id: 'disc-007', response_value: 'relationship_focused' },
  { question_id: 'disc-008', response_value: 'energetic' },
  { question_id: 'disc-009', response_value: 'inspire_others' },
  { question_id: 'disc-010', response_value: 'team_player' },
  { question_id: 'disc-011', response_value: 'optimistic' },
  { question_id: 'disc-012', response_value: 'people_oriented' },
  { question_id: 'disc-013', response_value: 'persuasive' },
  { question_id: 'disc-014', response_value: 'creative' },
  { question_id: 'disc-015', response_value: 'expressive' },
];

/**
 * Sample DISC responses for high Steadiness (S) type
 */
export const highSteadinessResponses = [
  { question_id: 'disc-001', response_value: 'take_time' },
  { question_id: 'disc-002', response_value: 'listen_support' },
  { question_id: 'disc-003', response_value: 'step_by_step' },
  { question_id: 'disc-004', response_value: 'patient_approach' },
  { question_id: 'disc-005', response_value: 'cooperative' },
  { question_id: 'disc-006', response_value: 'gentle_approach' },
  { question_id: 'disc-007', response_value: 'stability_focused' },
  { question_id: 'disc-008', response_value: 'steady_paced' },
  { question_id: 'disc-009', response_value: 'support_others' },
  { question_id: 'disc-010', response_value: 'team_harmony' },
  { question_id: 'disc-011', response_value: 'considerate' },
  { question_id: 'disc-012', response_value: 'reliable' },
  { question_id: 'disc-013', response_value: 'calm' },
  { question_id: 'disc-014', response_value: 'consistent' },
  { question_id: 'disc-015', response_value: 'loyal' },
];

/**
 * Sample DISC responses for high Compliance (C) type
 */
export const highComplianceResponses = [
  { question_id: 'disc-001', response_value: 'research_thoroughly' },
  { question_id: 'disc-002', response_value: 'present_data' },
  { question_id: 'disc-003', response_value: 'detailed_analysis' },
  { question_id: 'disc-004', response_value: 'systematic_approach' },
  { question_id: 'disc-005', response_value: 'analytical' },
  { question_id: 'disc-006', response_value: 'precise_approach' },
  { question_id: 'disc-007', response_value: 'quality_focused' },
  { question_id: 'disc-008', response_value: 'methodical' },
  { question_id: 'disc-009', response_value: 'ensure_accuracy' },
  { question_id: 'disc-010', response_value: 'follow_procedures' },
  { question_id: 'disc-011', response_value: 'logical' },
  { question_id: 'disc-012', response_value: 'detail_oriented' },
  { question_id: 'disc-013', response_value: 'careful' },
  { question_id: 'disc-014', response_value: 'thorough' },
  { question_id: 'disc-015', response_value: 'accurate' },
];

/**
 * Sample phase question responses for Stabilize phase (poor financial organization)
 */
export const stabilizePhaseResponses = [
  { question_id: 'stab-001', response_value: 'very_behind' }, // Bookkeeping very behind
  { question_id: 'stab-002', response_value: 'not_separated' }, // Business/personal not separated
  { question_id: 'stab-003', response_value: 'no_reconciliation' }, // No bank reconciliation
  { question_id: 'stab-004', response_value: 'missing_records' }, // Missing financial records
  { question_id: 'stab-005', response_value: 'no_tracking' }, // No expense tracking
  { question_id: 'stab-006', response_value: 'tax_issues' }, // Tax compliance issues
  { question_id: 'stab-007', response_value: 'debt_problems' }, // Debt management problems
  { question_id: 'stab-008', response_value: 'no_system' }, // No accounting system
  { question_id: 'org-001', response_value: 'no_coa' }, // No chart of accounts
  { question_id: 'org-002', response_value: 'no_integration' }, // No system integration
];

/**
 * Sample phase responses for Organize phase (good stabilization, needs organization)
 */
export const organizePhaseResponses = [
  { question_id: 'stab-001', response_value: 'current' }, // Bookkeeping current
  { question_id: 'stab-002', response_value: 'fully_separated' }, // Business/personal separated
  { question_id: 'stab-003', response_value: 'monthly_reconciliation' }, // Regular reconciliation
  { question_id: 'stab-004', response_value: 'organized_records' }, // Organized records
  { question_id: 'org-001', response_value: 'basic_coa' }, // Basic chart of accounts
  { question_id: 'org-002', response_value: 'needs_integration' }, // Needs better integration
  { question_id: 'org-003', response_value: 'manual_processes' }, // Manual processes
  { question_id: 'org-004', response_value: 'no_automation' }, // No automation
  { question_id: 'build-001', response_value: 'no_sops' }, // No SOPs yet
  { question_id: 'build-002', response_value: 'no_workflows' }, // No documented workflows
];

/**
 * Sample phase responses for Build phase (good foundation, building systems)
 */
export const buildPhaseResponses = [
  { question_id: 'stab-001', response_value: 'current' },
  { question_id: 'stab-002', response_value: 'fully_separated' },
  { question_id: 'org-001', response_value: 'detailed_coa' }, // Detailed chart of accounts
  { question_id: 'org-002', response_value: 'integrated_systems' }, // Integrated systems
  { question_id: 'org-003', response_value: 'automated_processes' }, // Automated processes
  { question_id: 'build-001', response_value: 'basic_sops' }, // Basic SOPs
  { question_id: 'build-002', response_value: 'developing_workflows' }, // Developing workflows
  { question_id: 'build-003', response_value: 'building_tools' }, // Building custom tools
  { question_id: 'grow-001', response_value: 'no_forecasting' }, // Not forecasting yet
  { question_id: 'grow-002', response_value: 'reactive_planning' }, // Reactive planning
];

/**
 * Sample phase responses for Grow phase (strong systems, ready for growth)
 */
export const growPhaseResponses = [
  { question_id: 'stab-001', response_value: 'current' },
  { question_id: 'stab-002', response_value: 'fully_separated' },
  { question_id: 'org-001', response_value: 'detailed_coa' },
  { question_id: 'org-002', response_value: 'integrated_systems' },
  { question_id: 'build-001', response_value: 'comprehensive_sops' }, // Comprehensive SOPs
  { question_id: 'build-002', response_value: 'documented_workflows' }, // Documented workflows
  { question_id: 'build-003', response_value: 'custom_tools' }, // Custom tools built
  { question_id: 'grow-001', response_value: 'basic_forecasting' }, // Basic forecasting
  { question_id: 'grow-002', response_value: 'strategic_planning' }, // Strategic planning
  { question_id: 'grow-003', response_value: 'cash_flow_planning' }, // Cash flow planning
];

/**
 * Insufficient DISC responses (less than 12) for edge case testing
 */
export const insufficientDISCResponses = [
  { question_id: 'disc-001', response_value: 'decide_quickly' },
  { question_id: 'disc-002', response_value: 'lead_direct' },
  { question_id: 'disc-003', response_value: 'bottom_line' },
  { question_id: 'disc-004', response_value: 'quick_action' },
  { question_id: 'disc-005', response_value: 'competitive' },
  { question_id: 'disc-006', response_value: 'direct_approach' },
  { question_id: 'disc-007', response_value: 'results_focused' },
  { question_id: 'disc-008', response_value: 'fast_paced' },
  // Only 8 responses - below minimum of 12
];

/**
 * Mixed DISC responses for testing secondary traits
 */
export const mixedDISCResponses = [
  // High D responses
  { question_id: 'disc-001', response_value: 'decide_quickly' },
  { question_id: 'disc-002', response_value: 'lead_direct' },
  { question_id: 'disc-003', response_value: 'bottom_line' },
  { question_id: 'disc-004', response_value: 'quick_action' },
  { question_id: 'disc-005', response_value: 'competitive' },
  // High I responses
  { question_id: 'disc-006', response_value: 'friendly_approach' },
  { question_id: 'disc-007', response_value: 'relationship_focused' },
  { question_id: 'disc-008', response_value: 'energetic' },
  { question_id: 'disc-009', response_value: 'inspire_others' },
  { question_id: 'disc-010', response_value: 'team_player' },
  // Mix
  { question_id: 'disc-011', response_value: 'decisive' },
  { question_id: 'disc-012', response_value: 'people_oriented' },
  { question_id: 'disc-013', response_value: 'assertive' },
  { question_id: 'disc-014', response_value: 'creative' },
  { question_id: 'disc-015', response_value: 'bold' },
];

/**
 * Combined responses for full test scenarios
 */
export const fullAssessmentResponses = {
  highDStabilize: [...highDominanceResponses, ...stabilizePhaseResponses],
  highIOrganize: [...highInfluenceResponses, ...organizePhaseResponses],
  highSBuild: [...highSteadinessResponses, ...buildPhaseResponses],
  highCGrow: [...highComplianceResponses, ...growPhaseResponses],
  mixedDIStabilize: [...mixedDISCResponses, ...stabilizePhaseResponses],
};
