/**
 * Recommendation Extractor
 *
 * Extracts action items from report recommendations for auto-generating checklists.
 * Handles DISC-specific formatting and priority determination.
 *
 * @module services/recommendationExtractor
 * @version 1.0
 * @date 2025-12-22
 */

/**
 * Recommendation item structure
 */
export interface RecommendationItem {
  title: string;
  description?: string;
  phase: string;
  priority: number;
  sourceSection: string;
}

/**
 * Report data structure (from report generation system)
 */
export interface ReportData {
  recommendations: {
    [phase: string]: Array<{
      title: string;
      description?: string;
      details?: string;
      priority?: number;
      id?: string;
    }>;
  };
  primaryPhase: string;
  discProfile?: string;
}

/**
 * Extract recommendations from report data
 *
 * Parses the report recommendations and converts them into
 * checklist-ready items with proper prioritization.
 *
 * @param reportData - Report data from client report
 * @returns Array of recommendation items ready for checklist
 */
export async function extractRecommendations(
  reportData: ReportData
): Promise<RecommendationItem[]> {
  const recommendations: RecommendationItem[] = [];

  // Extract from each phase section in the report
  const phases = ['Stabilize', 'Organize', 'Build', 'Grow', 'Systemic'];

  for (const phase of phases) {
    const phaseRecommendations = reportData.recommendations[phase];

    if (!phaseRecommendations || phaseRecommendations.length === 0) {
      continue;
    }

    for (const rec of phaseRecommendations) {
      recommendations.push({
        title: rec.title,
        description: rec.description || rec.details,
        phase: phase,
        priority: rec.priority || determinePriority(phase, reportData.primaryPhase),
        sourceSection: `${phase}-${rec.id || Math.random().toString(36).substr(2, 9)}`
      });
    }
  }

  return recommendations;
}

/**
 * Determine priority based on phase distance from primary phase
 *
 * Priority logic:
 * - 3 (High): Primary phase recommendations - focus here first
 * - 2 (Medium): Adjacent phase recommendations - important but not urgent
 * - 1 (Low): Future phase recommendations - plan for later
 * - 0 (None): General recommendations - optional
 *
 * @param recommendationPhase - Phase of the recommendation
 * @param primaryPhase - Client's primary financial phase
 * @returns Priority level (0-3)
 */
export function determinePriority(
  recommendationPhase: string,
  primaryPhase: string
): number {
  if (recommendationPhase === primaryPhase) {
    return 3; // High priority - primary phase
  }

  const phaseOrder = ['Stabilize', 'Organize', 'Build', 'Grow', 'Systemic'];
  const primaryIndex = phaseOrder.indexOf(primaryPhase);
  const recIndex = phaseOrder.indexOf(recommendationPhase);

  if (primaryIndex === -1 || recIndex === -1) {
    return 0; // Unknown phase
  }

  const distance = Math.abs(primaryIndex - recIndex);

  if (distance === 1) {
    return 2; // Medium priority - adjacent phase
  }

  if (distance >= 2) {
    return 1; // Low priority - future phase
  }

  return 0; // Fallback
}

/**
 * Parse DISC-formatted recommendations
 *
 * Different DISC profiles format recommendations differently:
 * - D-Profile: Bullet points with ROI metrics
 * - I-Profile: Numbered steps with collaborative language
 * - S-Profile: Week-by-week timeline
 * - C-Profile: Detailed numbered actions with impact/effort analysis
 *
 * This function normalizes these different formats into standard items.
 *
 * @param text - Raw recommendation text
 * @param discProfile - Client's DISC profile
 * @returns Parsed recommendation items
 */
export function parseDiscFormattedRecommendations(
  text: string,
  discProfile: string
): Array<{ title: string; description?: string }> {
  const items: Array<{ title: string; description?: string }> = [];

  // Split by common patterns
  const lines = text.split('\n').filter(line => line.trim().length > 0);

  for (const line of lines) {
    // Match bullet points, numbered lists, or timeline entries
    const bulletMatch = line.match(/^[\-\*•]\s*(.+)$/);
    const numberedMatch = line.match(/^\d+\.\s*(.+)$/);
    const weekMatch = line.match(/^Week\s+\d+:\s*(.+)$/i);

    if (bulletMatch) {
      items.push({ title: bulletMatch[1].trim() });
    } else if (numberedMatch) {
      items.push({ title: numberedMatch[1].trim() });
    } else if (weekMatch) {
      items.push({ title: weekMatch[1].trim() });
    } else if (line.trim().length > 0 && !line.includes(':')) {
      // Standalone line that's not a header
      items.push({ title: line.trim() });
    }
  }

  return items;
}

export default {
  extractRecommendations,
  determinePriority,
  parseDiscFormattedRecommendations
};
