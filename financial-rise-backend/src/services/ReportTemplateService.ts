import { DISCType, FinancialPhase } from '../types';

interface ClientInfo {
  name: string;
  businessName: string;
  email?: string;
}

interface DISCProfile {
  primaryType: DISCType;
  scores: {
    D: number;
    I: number;
    S: number;
    C: number;
  };
  secondaryTraits: string[];
  confidence: string;
}

interface PhaseResults {
  primaryPhase: FinancialPhase;
  scores: {
    [key in FinancialPhase]: number;
  };
  secondaryPhases: FinancialPhase[];
}

interface AssessmentResponse {
  questionId: string;
  questionText: string;
  answer: string;
  phase: FinancialPhase;
  notes?: string;
}

interface AssessmentInfo {
  id: string;
  completedAt: Date;
}

interface ConsultantReportData {
  client: ClientInfo;
  assessment: AssessmentInfo;
  discProfile: DISCProfile;
  phaseResults: PhaseResults;
  responses: AssessmentResponse[];
  consultantNotes: string;
}

interface QuickWin {
  action: string;
  why: string;
  benefit: string;
}

interface Roadmap {
  phases: FinancialPhase[];
  milestones: string[];
}

interface Branding {
  consultantName: string;
  logo: string | null;
  brandColor: string;
}

interface ClientReportData {
  client: ClientInfo;
  discProfile: DISCProfile;
  phaseResults: PhaseResults;
  quickWins: string[] | QuickWin[];
  roadmap: Roadmap;
  branding: Branding;
}

interface CommunicationStrategy {
  dos: string[];
  donts: string[];
  meetingApproach: string;
}

export class ReportTemplateService {
  private readonly brandColors = {
    primary: '#4B006E',
    gold: '#D4AF37',
    black: '#000000',
    white: '#FFFFFF',
    gray: '#666666',
    lightGray: '#F5F5F5'
  };

  private readonly fontFamily = 'Calibri, Candara, "Segoe UI", Arial, sans-serif';
  private readonly baseFontSize = '14px';

  /**
   * Renders the complete consultant report as HTML
   */
  public renderConsultantReport(data: ConsultantReportData): string {
    const { client, assessment, discProfile, phaseResults, responses, consultantNotes } = data;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Consultant Report - ${client.name}</title>
  ${this.getConsultantReportStyles()}
</head>
<body>
  <div class="report-container">
    ${this.renderConsultantHeader(client, assessment)}
    ${this.renderExecutiveSummary(client, discProfile, phaseResults)}
    ${this.renderDISCAnalysis(discProfile)}
    ${this.renderFinancialReadinessResults(phaseResults)}
    ${this.renderActionPlan(phaseResults, discProfile)}
    ${this.renderResponseSummary(responses)}
    ${this.renderCommunicationStrategy(discProfile.primaryType)}
    ${consultantNotes ? this.renderConsultantNotes(consultantNotes) : ''}
    ${this.renderConsultantFooter()}
  </div>
</body>
</html>`;
  }

  /**
   * Renders the complete client report as HTML
   */
  public renderClientReport(data: ClientReportData): string {
    const { client, discProfile, phaseResults, quickWins, roadmap, branding } = data;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Financial RISE Report - ${client.name}</title>
  ${this.getClientReportStyles(branding.brandColor)}
</head>
<body>
  <div class="report-container">
    ${this.renderClientHeader(client, branding)}
    ${this.renderWelcomeSection(client, discProfile.primaryType)}
    ${this.renderFinancialJourney(phaseResults, discProfile.primaryType)}
    ${this.renderQuickWins(quickWins, discProfile.primaryType)}
    ${this.renderPersonalizedRoadmap(roadmap, phaseResults, discProfile.primaryType)}
    ${this.renderNextSteps(phaseResults, discProfile.primaryType)}
    ${this.renderConfidenceBuilding(discProfile.primaryType, branding)}
    ${this.renderClientFooter(branding)}
  </div>
</body>
</html>`;
  }

  /**
   * Gets DISC-adapted content variation for a specific section
   */
  public getDISCContentVariation(section: string, discType: DISCType): string {
    const variations: Record<string, Record<DISCType, string>> = {
      quickWinIntro: {
        D: 'Here are your immediate action items that will deliver the fastest ROI and move you toward your goals efficiently.',
        I: 'We\'re excited to share these opportunities for growth! These collaborative actions will create positive momentum for your business.',
        S: 'Let\'s take this step-by-step. These comfortable, manageable actions will help you build financial confidence gradually.',
        C: 'Based on detailed analysis of your assessment data, here are the most accurate and methodical actions to improve your financial systems.'
      },
      roadmapIntro: {
        D: 'Your strategic pathway to financial excellence focuses on results-driven milestones that maximize efficiency.',
        I: 'Your exciting financial journey includes collaborative milestones that create opportunities for growth and success together.',
        S: 'Your gradual roadmap provides a safe, supportive timeline for building financial strength at a comfortable pace.',
        C: 'Your detailed, analytical roadmap is based on accurate metrics and standards for systematic financial improvement.'
      },
      closingMessage: {
        D: 'Take action on these priorities to achieve measurable results quickly. Your bottom line will improve through focused execution.',
        I: 'Together, we\'ll make this vision a reality! The opportunities ahead are exciting, and you have the support to succeed.',
        S: 'You\'re making steady progress. Take your time with each step, and remember we\'re here to support you throughout this comfortable journey.',
        C: 'Follow this data-driven plan with precision. Each detailed action is backed by thorough analysis and will lead to accurate improvements.'
      }
    };

    return variations[section]?.[discType] || '';
  }

  /**
   * Gets communication strategy for a DISC type
   */
  public getCommunicationStrategy(discType: DISCType): CommunicationStrategy {
    const strategies: Record<DISCType, CommunicationStrategy> = {
      D: {
        dos: [
          'Be direct and results-focused',
          'Highlight ROI and bottom-line impact',
          'Present options for quick wins',
          'Focus on efficiency and action',
          'Keep meetings brief and on-point'
        ],
        donts: [
          'Don\'t over-explain or provide excessive detail',
          'Avoid lengthy discussions without clear outcomes',
          'Don\'t focus on feelings or relationship-building',
          'Avoid slow, methodical approaches'
        ],
        meetingApproach: 'Start with the bottom line. Present 2-3 action items with clear ROI. Let them make quick decisions. Focus on results and efficiency.'
      },
      I: {
        dos: [
          'Build rapport and collaborative relationships',
          'Focus on the big picture and vision',
          'Use storytelling and examples',
          'Highlight opportunities for growth',
          'Make it interactive and engaging'
        ],
        donts: [
          'Don\'t be overly formal or rigid',
          'Avoid focusing solely on data and details',
          'Don\'t rush through discussions',
          'Avoid negative or critical language'
        ],
        meetingApproach: 'Start with relationship-building. Discuss the exciting vision and opportunities. Make it collaborative and engaging. Use stories and examples.'
      },
      S: {
        dos: [
          'Provide reassurance and support',
          'Take a step-by-step approach',
          'Allow time for questions and concerns',
          'Build trust through consistency',
          'Offer a gentle, comfortable pace'
        ],
        donts: [
          'Don\'t rush or pressure them',
          'Avoid sudden changes or surprises',
          'Don\'t be overly aggressive',
          'Avoid conflict or confrontation'
        ],
        meetingApproach: 'Build trust first. Present a clear timeline with manageable steps. Allow plenty of time for questions. Be supportive and reassuring.'
      },
      C: {
        dos: [
          'Provide detailed data and analysis',
          'Be thorough and accurate',
          'Support recommendations with evidence',
          'Allow time for analysis and questions',
          'Focus on quality and standards'
        ],
        donts: [
          'Don\'t make assumptions without data',
          'Avoid vague or imprecise language',
          'Don\'t rush the decision-making process',
          'Avoid emotional appeals'
        ],
        meetingApproach: 'Provide comprehensive documentation in advance. Present data-driven recommendations. Allow time for detailed analysis. Answer all questions thoroughly.'
      }
    };

    return strategies[discType];
  }

  /**
   * Generates SVG phase diagram
   */
  public getPhaseDiagramSVG(primaryPhase: string, secondaryPhases: string[]): string {
    const phases = ['Stabilize', 'Organize', 'Build', 'Grow', 'Systemic'];
    const phaseWidth = 150;
    const phaseHeight = 100;
    const spacing = 20;
    const totalWidth = (phaseWidth * phases.length) + (spacing * (phases.length - 1));
    const totalHeight = phaseHeight + 100;

    let svg = `<svg width="${totalWidth}" height="${totalHeight}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Financial Readiness Phase Diagram showing current position">
  <defs>
    <style>
      .phase-box { stroke: #666; stroke-width: 2; }
      .phase-box-inactive { fill: #f0f0f0; }
      .phase-box-secondary { fill: #e6d5f0; }
      .phase-box-primary { fill: #4B006E; }
      .phase-label { font-family: ${this.fontFamily}; font-size: 14px; font-weight: bold; text-anchor: middle; }
      .phase-label-inactive { fill: #666; }
      .phase-label-active { fill: white; }
      .arrow { stroke: #666; stroke-width: 2; fill: none; marker-end: url(#arrowhead); }
    </style>
    <marker id="arrowhead" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
      <polygon points="0 0, 10 3, 0 6" fill="#666" />
    </marker>
  </defs>

  <g id="phase-diagram">`;

    // Draw arrows between phases
    for (let i = 0; i < phases.length - 1; i++) {
      const x1 = (i * (phaseWidth + spacing)) + phaseWidth;
      const x2 = ((i + 1) * (phaseWidth + spacing));
      const y = phaseHeight / 2 + 20;
      svg += `
    <line class="arrow" x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" />`;
    }

    // Draw phase boxes
    phases.forEach((phase, index) => {
      const x = index * (phaseWidth + spacing);
      const y = 20;

      let boxClass = 'phase-box phase-box-inactive';
      let labelClass = 'phase-label phase-label-inactive';

      if (phase === primaryPhase) {
        boxClass = 'phase-box phase-box-primary';
        labelClass = 'phase-label phase-label-active';
      } else if (secondaryPhases.includes(phase)) {
        boxClass = 'phase-box phase-box-secondary';
        labelClass = 'phase-label phase-label-inactive';
      }

      svg += `
    <rect class="${boxClass}" x="${x}" y="${y}" width="${phaseWidth}" height="${phaseHeight}" rx="8" />
    <text class="${labelClass}" x="${x + phaseWidth / 2}" y="${y + phaseHeight / 2 + 5}">${phase}</text>`;
    });

    svg += `
  </g>

  <g id="legend" transform="translate(0, ${phaseHeight + 50})">
    <rect class="phase-box phase-box-primary" x="0" y="0" width="20" height="20" rx="4" />
    <text x="30" y="15" style="font-family: ${this.fontFamily}; font-size: 12px; fill: #666;">Your Current Focus</text>

    <rect class="phase-box phase-box-secondary" x="200" y="0" width="20" height="20" rx="4" />
    <text x="230" y="15" style="font-family: ${this.fontFamily}; font-size: 12px; fill: #666;">Secondary Areas</text>
  </g>
</svg>`;

    return svg;
  }

  /**
   * Gets phase icon SVG
   */
  public getPhaseIcon(phase: string): string {
    const icons: Record<string, string> = {
      Stabilize: `<svg width="40" height="40" xmlns="http://www.w3.org/2000/svg" aria-label="Stabilize phase icon">
        <circle cx="20" cy="20" r="18" fill="#4B006E" stroke="#666" stroke-width="2"/>
        <path d="M 10,20 L 20,10 L 30,20" stroke="white" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
        <line x1="10" y1="25" x2="30" y2="25" stroke="white" stroke-width="3" stroke-linecap="round"/>
      </svg>`,

      Organize: `<svg width="40" height="40" xmlns="http://www.w3.org/2000/svg" aria-label="Organize phase icon">
        <circle cx="20" cy="20" r="18" fill="#4B006E" stroke="#666" stroke-width="2"/>
        <rect x="10" y="10" width="8" height="8" fill="white" rx="1"/>
        <rect x="22" y="10" width="8" height="8" fill="white" rx="1"/>
        <rect x="10" y="22" width="8" height="8" fill="white" rx="1"/>
        <rect x="22" y="22" width="8" height="8" fill="white" rx="1"/>
      </svg>`,

      Build: `<svg width="40" height="40" xmlns="http://www.w3.org/2000/svg" aria-label="Build phase icon">
        <circle cx="20" cy="20" r="18" fill="#4B006E" stroke="#666" stroke-width="2"/>
        <rect x="12" y="18" width="6" height="12" fill="white"/>
        <rect x="22" y="12" width="6" height="18" fill="white"/>
      </svg>`,

      Grow: `<svg width="40" height="40" xmlns="http://www.w3.org/2000/svg" aria-label="Grow phase icon">
        <circle cx="20" cy="20" r="18" fill="#4B006E" stroke="#666" stroke-width="2"/>
        <path d="M 12,28 L 16,20 L 20,24 L 24,16 L 28,22" stroke="white" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
        <polyline points="24,16 28,16 28,22" fill="white"/>
      </svg>`,

      Systemic: `<svg width="40" height="40" xmlns="http://www.w3.org/2000/svg" aria-label="Systemic phase icon">
        <circle cx="20" cy="20" r="18" fill="#4B006E" stroke="#666" stroke-width="2"/>
        <circle cx="20" cy="14" r="3" fill="white"/>
        <circle cx="12" cy="24" r="3" fill="white"/>
        <circle cx="28" cy="24" r="3" fill="white"/>
        <line x1="20" y1="17" x2="14" y2="22" stroke="white" stroke-width="2"/>
        <line x1="20" y1="17" x2="26" y2="22" stroke="white" stroke-width="2"/>
        <line x1="15" y1="24" x2="25" y2="24" stroke="white" stroke-width="2"/>
      </svg>`
    };

    return icons[phase] || '';
  }

  // Private helper methods for consultant report sections

  private getConsultantReportStyles(): string {
    return `<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: ${this.fontFamily};
      font-size: ${this.baseFontSize};
      line-height: 1.6;
      color: ${this.brandColors.black};
      background: ${this.brandColors.white};
    }

    .report-container {
      max-width: 8.5in;
      margin: 0 auto;
      padding: 0.5in;
    }

    .header {
      border-bottom: 3px solid ${this.brandColors.primary};
      padding-bottom: 20px;
      margin-bottom: 30px;
    }

    .header h1 {
      color: ${this.brandColors.primary};
      font-size: 28px;
      margin-bottom: 10px;
    }

    .header .meta {
      color: ${this.brandColors.gray};
      font-size: 12px;
    }

    section {
      margin-bottom: 40px;
      page-break-inside: avoid;
    }

    h2 {
      color: ${this.brandColors.primary};
      font-size: 20px;
      margin-bottom: 15px;
      padding-bottom: 5px;
      border-bottom: 2px solid ${this.brandColors.lightGray};
    }

    h3 {
      color: ${this.brandColors.black};
      font-size: 16px;
      margin-bottom: 10px;
      margin-top: 15px;
    }

    .disc-profile {
      background: ${this.brandColors.lightGray};
      padding: 20px;
      border-radius: 8px;
      margin-bottom: 20px;
    }

    .disc-scores {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 15px;
      margin-top: 15px;
    }

    .disc-score-item {
      text-align: center;
    }

    .disc-score-bar {
      background: ${this.brandColors.white};
      height: 100px;
      border: 1px solid ${this.brandColors.gray};
      border-radius: 4px;
      position: relative;
      overflow: hidden;
    }

    .disc-score-fill {
      position: absolute;
      bottom: 0;
      left: 0;
      right: 0;
      background: ${this.brandColors.primary};
      transition: height 0.3s;
    }

    .disc-score-label {
      font-weight: bold;
      margin-bottom: 5px;
    }

    .action-plan-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 15px;
    }

    .action-plan-table th,
    .action-plan-table td {
      padding: 12px;
      text-align: left;
      border: 1px solid ${this.brandColors.lightGray};
    }

    .action-plan-table th {
      background: ${this.brandColors.primary};
      color: ${this.brandColors.white};
      font-weight: bold;
    }

    .action-plan-table tr:nth-child(even) {
      background: ${this.brandColors.lightGray};
    }

    .priority-high {
      color: #c41e3a;
      font-weight: bold;
    }

    .priority-medium {
      color: #f39c12;
      font-weight: bold;
    }

    .priority-low {
      color: #27ae60;
      font-weight: bold;
    }

    .warning-flag {
      background: #fff3cd;
      border-left: 4px solid #ffc107;
      padding: 15px;
      margin: 15px 0;
    }

    .communication-strategy {
      background: ${this.brandColors.lightGray};
      padding: 20px;
      border-radius: 8px;
    }

    .strategy-list {
      margin: 15px 0;
    }

    .strategy-list h4 {
      color: ${this.brandColors.primary};
      margin-bottom: 8px;
    }

    .strategy-list ul {
      margin-left: 20px;
    }

    .strategy-list li {
      margin-bottom: 5px;
    }

    .consultant-notes {
      background: #e8f4f8;
      border-left: 4px solid #17a2b8;
      padding: 15px;
      margin: 15px 0;
      font-style: italic;
    }

    .footer {
      margin-top: 50px;
      padding-top: 20px;
      border-top: 2px solid ${this.brandColors.lightGray};
      text-align: center;
      color: ${this.brandColors.gray};
      font-size: 12px;
    }

    @media print {
      body { background: white; }
      .report-container { padding: 0; }
      section { page-break-inside: avoid; }
    }

    @page {
      size: letter;
      margin: 0.5in;
    }
  </style>`;
  }

  private renderConsultantHeader(client: ClientInfo, assessment: AssessmentInfo): string {
    const date = new Date(assessment.completedAt).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });

    return `<header class="header">
    <h1>Consultant Report</h1>
    <div class="meta">
      <p><strong>Client:</strong> ${client.name}</p>
      <p><strong>Business:</strong> ${client.businessName}</p>
      <p><strong>Assessment Date:</strong> ${date}</p>
      <p><strong>Assessment ID:</strong> ${assessment.id}</p>
    </div>
  </header>`;
  }

  private renderExecutiveSummary(client: ClientInfo, discProfile: DISCProfile, phaseResults: PhaseResults): string {
    return `<section id="executive-summary">
    <h2>Executive Summary</h2>
    <p><strong>Client Overview:</strong> ${client.name} of ${client.businessName} has completed the Financial RISE assessment.</p>
    <p><strong>Primary DISC Profile:</strong> ${discProfile.primaryType}-type (${this.getDISCTypeName(discProfile.primaryType)})</p>
    <p><strong>Current Financial Readiness Phase:</strong> ${phaseResults.primaryPhase}</p>
    <p><strong>Recommended Starting Point:</strong> Focus on ${phaseResults.primaryPhase} phase actions with attention to ${phaseResults.secondaryPhases.length > 0 ? phaseResults.secondaryPhases.join(', ') : 'foundational elements'}.</p>
  </section>`;
  }

  private renderDISCAnalysis(discProfile: DISCProfile): string {
    const typeName = this.getDISCTypeName(discProfile.primaryType);
    const secondaryText = discProfile.secondaryTraits.length > 0
      ? `<p><strong>Secondary Traits:</strong> ${discProfile.secondaryTraits.join(', ')}</p>`
      : '<p><strong>Secondary Traits:</strong> None identified</p>';

    return `<section id="disc-analysis">
    <h2>DISC Personality Analysis</h2>
    <div class="disc-profile">
      <p><strong>Primary Type: ${discProfile.primaryType}</strong> - ${typeName}</p>
      ${secondaryText}
      <p><strong>Confidence Level:</strong> ${discProfile.confidence}</p>

      <div class="disc-scores">
        ${Object.entries(discProfile.scores).map(([type, score]) => `
          <div class="disc-score-item">
            <div class="disc-score-label">${type}</div>
            <div class="disc-score-bar">
              <div class="disc-score-fill" style="height: ${score}%;"></div>
            </div>
            <div>${score}</div>
          </div>
        `).join('')}
      </div>

      <h3>Communication Preferences</h3>
      <p>${this.getDISCCommunicationPreference(discProfile.primaryType)}</p>

      <h3>Approach Recommendations</h3>
      <p>${this.getDISCApproachRecommendation(discProfile.primaryType)}</p>
    </div>
  </section>`;
  }

  private renderFinancialReadinessResults(phaseResults: PhaseResults): string {
    const criticalPhases = Object.entries(phaseResults.scores)
      .filter(([_, score]) => score < 40)
      .map(([phase]) => phase);

    return `<section id="financial-results">
    <h2>Financial Readiness Assessment Results</h2>

    <h3>Phase-by-Phase Scoring</h3>
    <table class="action-plan-table">
      <thead>
        <tr>
          <th>Phase</th>
          <th>Score</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${Object.entries(phaseResults.scores).map(([phase, score]) => `
          <tr>
            <td><strong>${phase}</strong></td>
            <td>${score}%</td>
            <td>${score >= 70 ? '✓ Strong' : score >= 40 ? '⚠ Needs Attention' : '❗ Critical'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <h3>Strengths Identified</h3>
    <ul>
      ${Object.entries(phaseResults.scores)
        .filter(([_, score]) => score >= 70)
        .map(([phase]) => `<li>${phase}: Strong foundation in place</li>`)
        .join('')}
    </ul>

    <h3>Areas Requiring Attention</h3>
    <ul>
      ${Object.entries(phaseResults.scores)
        .filter(([_, score]) => score < 70)
        .map(([phase, score]) => `<li>${phase}: ${score < 40 ? 'Critical priority' : 'Improvement needed'} (${score}%)</li>`)
        .join('')}
    </ul>

    ${criticalPhases.length > 0 ? `
      <div class="warning-flag">
        <h4>⚠ Urgency Indicators</h4>
        <p>The following areas require immediate attention: <strong>${criticalPhases.join(', ')}</strong></p>
      </div>
    ` : ''}
  </section>`;
  }

  private renderActionPlan(phaseResults: PhaseResults, discProfile: DISCProfile): string {
    return `<section id="action-plan">
    <h2>Recommended Action Plan</h2>

    <h3>Priority 1 Actions (Start Immediately)</h3>
    <ul>
      <li>Address ${phaseResults.primaryPhase} phase foundational elements</li>
      <li>Review critical areas scoring below 40%</li>
      <li>Establish baseline metrics and tracking systems</li>
    </ul>

    <h3>Priority 2 Actions (Next 30 Days)</h3>
    <ul>
      <li>Implement quick wins identified in assessment</li>
      <li>Build systems for ${phaseResults.primaryPhase} phase</li>
      <li>Schedule regular check-ins and progress reviews</li>
    </ul>

    <h3>Priority 3 Actions (Next 90 Days)</h3>
    <ul>
      <li>Strengthen secondary focus areas</li>
      <li>Develop long-term financial systems</li>
      <li>Build financial literacy and confidence</li>
    </ul>

    <h3>Long-term Recommendations</h3>
    <p>Continue progressing through the Financial RISE framework, adapting communication and pacing to the client's ${discProfile.primaryType}-type preferences.</p>
  </section>`;
  }

  private renderResponseSummary(responses: AssessmentResponse[]): string {
    const byPhase = responses.reduce((acc, response) => {
      if (!acc[response.phase]) {
        acc[response.phase] = [];
      }
      acc[response.phase].push(response);
      return acc;
    }, {} as Record<string, AssessmentResponse[]>);

    const warningFlags = responses.filter(r =>
      r.notes?.toLowerCase().includes('critical') ||
      r.notes?.toLowerCase().includes('warning') ||
      r.answer?.toLowerCase().includes('no')
    );

    return `<section id="response-summary">
    <h2>Detailed Response Summary</h2>

    ${warningFlags.length > 0 ? `
      <div class="warning-flag">
        <h3>⚠ Red Flags Identified</h3>
        <ul>
          ${warningFlags.map(r => `
            <li>
              <strong>${r.questionText}</strong><br>
              Answer: ${r.answer}<br>
              ${r.notes ? `Notes: ${r.notes}` : ''}
            </li>
          `).join('')}
        </ul>
      </div>
    ` : ''}

    ${Object.entries(byPhase).map(([phase, phaseResponses]) => `
      <h3>${phase} Phase Responses</h3>
      <table class="action-plan-table">
        <thead>
          <tr>
            <th>Question</th>
            <th>Answer</th>
            <th>Notes</th>
          </tr>
        </thead>
        <tbody>
          ${phaseResponses.map(r => `
            <tr>
              <td>${r.questionText}</td>
              <td>${r.answer}</td>
              <td>${r.notes || '-'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `).join('')}
  </section>`;
  }

  private renderCommunicationStrategy(discType: DISCType): string {
    const strategy = this.getCommunicationStrategy(discType);

    return `<section id="communication-strategy">
    <h2>Communication Strategy</h2>
    <div class="communication-strategy">
      <p><strong>Based on ${discType}-type profile</strong></p>

      <div class="strategy-list">
        <h4>Do's:</h4>
        <ul>
          ${strategy.dos.map(item => `<li>${item}</li>`).join('')}
        </ul>
      </div>

      <div class="strategy-list">
        <h4>Don'ts:</h4>
        <ul>
          ${strategy.donts.map(item => `<li>${item}</li>`).join('')}
        </ul>
      </div>

      <div class="strategy-list">
        <h4>Recommended Meeting Approach:</h4>
        <p>${strategy.meetingApproach}</p>
      </div>
    </div>
  </section>`;
  }

  private renderConsultantNotes(notes: string): string {
    return `<section id="consultant-notes">
    <h2>Consultant Notes</h2>
    <div class="consultant-notes">
      <p>${notes}</p>
    </div>
  </section>`;
  }

  private renderConsultantFooter(): string {
    return `<footer class="footer">
    <p>Financial RISE Report - Readiness Insights for Sustainable Entrepreneurship</p>
    <p>This consultant report is confidential and intended for professional use only.</p>
  </footer>`;
  }

  // Private helper methods for client report sections

  private getClientReportStyles(brandColor: string): string {
    return `<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: ${this.fontFamily};
      font-size: ${this.baseFontSize};
      line-height: 1.6;
      color: ${this.brandColors.black};
      background: ${this.brandColors.white};
    }

    .report-container {
      max-width: 8.5in;
      margin: 0 auto;
      padding: 0.5in;
    }

    .header {
      text-align: center;
      border-bottom: 3px solid ${brandColor};
      padding-bottom: 30px;
      margin-bottom: 40px;
    }

    .header h1 {
      color: ${brandColor};
      font-size: 32px;
      margin-bottom: 10px;
    }

    .header .subtitle {
      color: ${this.brandColors.gray};
      font-size: 18px;
      margin-bottom: 20px;
    }

    .logo {
      max-width: 200px;
      margin-bottom: 20px;
    }

    section {
      margin-bottom: 40px;
      page-break-inside: avoid;
    }

    h2 {
      color: ${brandColor};
      font-size: 24px;
      margin-bottom: 20px;
      padding-bottom: 10px;
      border-bottom: 2px solid ${this.brandColors.lightGray};
    }

    h3 {
      color: ${this.brandColors.black};
      font-size: 18px;
      margin-bottom: 15px;
      margin-top: 20px;
    }

    .welcome {
      background: ${this.brandColors.lightGray};
      padding: 25px;
      border-radius: 8px;
      margin-bottom: 30px;
    }

    .phase-diagram-container {
      margin: 30px 0;
      text-align: center;
    }

    .quick-wins {
      background: #f0f8ff;
      padding: 25px;
      border-radius: 8px;
      border-left: 5px solid ${brandColor};
    }

    .quick-win-item {
      margin: 20px 0;
      padding: 15px;
      background: white;
      border-radius: 6px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .quick-win-item h4 {
      color: ${brandColor};
      margin-bottom: 10px;
    }

    .roadmap {
      background: ${this.brandColors.lightGray};
      padding: 25px;
      border-radius: 8px;
    }

    .milestone {
      margin: 15px 0;
      padding-left: 30px;
      position: relative;
    }

    .milestone::before {
      content: "✓";
      position: absolute;
      left: 0;
      color: ${brandColor};
      font-weight: bold;
      font-size: 20px;
    }

    .confidence-building {
      background: linear-gradient(135deg, ${brandColor} 0%, #6a1b9a 100%);
      color: white;
      padding: 30px;
      border-radius: 8px;
      text-align: center;
    }

    .confidence-building h2 {
      color: white;
      border-bottom: 2px solid rgba(255,255,255,0.3);
    }

    .footer {
      margin-top: 50px;
      padding-top: 20px;
      border-top: 2px solid ${this.brandColors.lightGray};
      text-align: center;
      color: ${this.brandColors.gray};
      font-size: 12px;
    }

    @media print {
      body { background: white; }
      .report-container { padding: 0; }
      section { page-break-inside: avoid; }
    }

    @page {
      size: letter;
      margin: 0.5in;
    }
  </style>`;
  }

  private renderClientHeader(client: ClientInfo, branding: Branding): string {
    return `<header class="header">
    ${branding.logo ? `<img src="${branding.logo}" alt="${branding.consultantName} logo" class="logo">` : ''}
    <h1>Your Financial RISE Report</h1>
    <div class="subtitle">Readiness Insights for Sustainable Entrepreneurship</div>
    <p>Prepared for <strong>${client.name}</strong></p>
    <p>${client.businessName}</p>
    <p style="margin-top: 20px; font-size: 12px;">Prepared by ${branding.consultantName}</p>
  </header>`;
  }

  private renderWelcomeSection(client: ClientInfo, discType: DISCType): string {
    const welcomeMessages: Record<DISCType, string> = {
      D: `${client.name}, this report provides actionable insights to drive your business forward efficiently. Let's focus on the key priorities that will deliver results.`,
      I: `Welcome, ${client.name}! We're excited to share this journey with you. This report highlights exciting opportunities to grow and strengthen your business together.`,
      S: `Welcome, ${client.name}. This report provides a comfortable, step-by-step guide to help you build financial confidence at your own pace. We're here to support you every step of the way.`,
      C: `Welcome, ${client.name}. This report provides detailed, data-driven insights based on your thorough assessment. Each recommendation is supported by accurate analysis.`
    };

    return `<section id="welcome">
    <div class="welcome">
      <h2>Welcome and Overview</h2>
      <p>${welcomeMessages[discType]}</p>
      <h3>Purpose of This Assessment</h3>
      <p>The Financial RISE assessment evaluates your business across five key phases of financial readiness, helping you understand where you are now and where to focus next.</p>
      <h3>How to Use This Report</h3>
      <p>Review each section carefully. Start with your Quick Wins for immediate improvements, then explore your Personalized Roadmap for long-term growth.</p>
    </div>
  </section>`;
  }

  private renderFinancialJourney(phaseResults: PhaseResults, discType: DISCType): string {
    const explanations: Record<DISCType, string> = {
      D: `You're currently focused on the ${phaseResults.primaryPhase} phase. This means prioritizing actions that deliver measurable improvements in efficiency and results.`,
      I: `Your exciting position in the ${phaseResults.primaryPhase} phase offers great opportunities for collaborative growth and positive momentum.`,
      S: `You're currently in the ${phaseResults.primaryPhase} phase. This comfortable position allows you to take steady, gradual steps toward financial strength.`,
      C: `Your current position in the ${phaseResults.primaryPhase} phase indicates specific, data-driven areas for systematic improvement.`
    };

    return `<section id="financial-journey">
    <h2>Your Financial Readiness Journey</h2>

    <div class="phase-diagram-container">
      ${this.getPhaseDiagramSVG(phaseResults.primaryPhase, phaseResults.secondaryPhases)}
    </div>

    <h3>Your Current Position</h3>
    <p>${explanations[discType]}</p>

    <h3>What This Means for Your Business</h3>
    <p>The ${phaseResults.primaryPhase} phase focuses on building the right foundations for sustainable growth. By addressing these areas, you'll create lasting improvements in your financial systems.</p>
  </section>`;
  }

  private renderQuickWins(quickWins: string[] | QuickWin[], discType: DISCType): string {
    const intro = this.getDISCContentVariation('quickWinIntro', discType);

    return `<section id="quick-wins">
    <h2>Your Quick Wins</h2>
    <div class="quick-wins">
      <p>${intro}</p>
      ${quickWins.map((win, index) => {
        const action = typeof win === 'string' ? win : win.action;
        const why = typeof win === 'string' ? '' : win.why;
        const benefit = typeof win === 'string' ? '' : win.benefit;

        return `
        <div class="quick-win-item">
          <h4>${index + 1}. ${action}</h4>
          ${why ? `<p><strong>Why this matters:</strong> ${why}</p>` : ''}
          ${benefit ? `<p><strong>Expected benefit:</strong> ${benefit}</p>` : ''}
        </div>
        `;
      }).join('')}
    </div>
  </section>`;
  }

  private renderPersonalizedRoadmap(roadmap: Roadmap, _phaseResults: PhaseResults, discType: DISCType): string {
    const intro = this.getDISCContentVariation('roadmapIntro', discType);

    return `<section id="roadmap">
    <h2>Your Personalized Roadmap</h2>
    <div class="roadmap">
      <p>${intro}</p>

      <h3>Phase-by-Phase Pathway</h3>
      ${roadmap.phases.map(phase => `
        <div class="milestone">
          <strong>${phase} Phase</strong> - ${this.getPhaseDescription(phase)}
        </div>
      `).join('')}

      <h3>Milestones and Goals</h3>
      ${roadmap.milestones.map(milestone => `
        <div class="milestone">${milestone}</div>
      `).join('')}

      <h3>Timeline (Flexible)</h3>
      <p>Progress through these phases at your own comfortable pace. Each milestone builds on the previous one, creating lasting financial strength.</p>
    </div>
  </section>`;
  }

  private renderNextSteps(phaseResults: PhaseResults, _discType: DISCType): string {
    return `<section id="next-steps">
    <h2>Understanding Your Next Steps</h2>

    <h3>Detailed Explanation of Recommended Actions</h3>
    <p>Your ${phaseResults.primaryPhase} phase focus involves specific systems and processes that will strengthen your financial foundation.</p>

    <h3>Resources and Support Available</h3>
    <p>Your financial consultant is here to guide you through each step, providing expertise and support tailored to your needs and preferences.</p>

    <h3>What to Expect</h3>
    <p>As you progress, you'll notice improvements in financial clarity, organization, and confidence. Each action builds on the last, creating sustainable growth.</p>
  </section>`;
  }

  private renderConfidenceBuilding(discType: DISCType, branding: Branding): string {
    const closingMessage = this.getDISCContentVariation('closingMessage', discType);

    return `<section id="confidence-building">
    <div class="confidence-building">
      <h2>Building Your Financial Confidence</h2>
      <p style="font-size: 16px; margin: 20px 0;">${closingMessage}</p>

      <h3 style="color: white; border-bottom: none; margin-top: 30px;">Long-term Vision</h3>
      <p>By following this roadmap, you'll develop the financial systems, knowledge, and confidence to drive sustainable business growth.</p>

      <h3 style="color: white; border-bottom: none; margin-top: 30px;">Next Meeting Planning</h3>
      <p>Schedule your next meeting with ${branding.consultantName} to begin implementing these recommendations and track your progress.</p>
    </div>
  </section>`;
  }

  private renderClientFooter(branding: Branding): string {
    return `<footer class="footer">
    <p>Financial RISE Report - Readiness Insights for Sustainable Entrepreneurship</p>
    <p>Prepared by ${branding.consultantName}</p>
    <p style="margin-top: 10px; font-size: 11px;">This report is personalized for your business and confidential.</p>
  </footer>`;
  }

  // Utility helper methods

  private getDISCTypeName(type: DISCType): string {
    const names: Record<DISCType, string> = {
      D: 'Dominance',
      I: 'Influence',
      S: 'Steadiness',
      C: 'Compliance'
    };
    return names[type];
  }

  private getDISCCommunicationPreference(type: DISCType): string {
    const preferences: Record<DISCType, string> = {
      D: 'Direct, results-focused communication. Values efficiency and quick decisions.',
      I: 'Collaborative, enthusiastic communication. Values relationships and big-picture vision.',
      S: 'Steady, supportive communication. Values reassurance and step-by-step guidance.',
      C: 'Detailed, analytical communication. Values accuracy and thorough documentation.'
    };
    return preferences[type];
  }

  private getDISCApproachRecommendation(type: DISCType): string {
    const recommendations: Record<DISCType, string> = {
      D: 'Present clear action items with ROI. Be brief and results-oriented. Allow them to make quick decisions.',
      I: 'Build rapport first. Make it collaborative and engaging. Focus on opportunities and the bigger vision.',
      S: 'Provide reassurance and support. Take a gentle pace. Build trust through consistency.',
      C: 'Provide detailed data and analysis. Be thorough and accurate. Allow time for questions.'
    };
    return recommendations[type];
  }

  private getPhaseDescription(phase: string): string {
    const descriptions: Record<string, string> = {
      Stabilize: 'Establish basic financial order and compliance',
      Organize: 'Build foundational systems and processes',
      Build: 'Create robust operational systems and workflows',
      Grow: 'Develop strategic financial planning capabilities',
      Systemic: 'Master financial literacy and report interpretation'
    };
    return descriptions[phase] || 'Financial readiness development';
  }
}
