import { ReportTemplateService } from '../ReportTemplateService';
import { DISCType } from '../../types';

describe('ReportTemplateService', () => {
  let service: ReportTemplateService;

  beforeEach(() => {
    service = new ReportTemplateService();
  });

  describe('Consultant Report Generation', () => {
    describe('renderConsultantReport', () => {
      it('should generate complete HTML consultant report with all sections', () => {
        const mockData = {
          client: {
            name: 'John Doe',
            businessName: 'Acme Corp',
            email: 'john@acme.com'
          },
          assessment: {
            id: 'assessment-123',
            completedAt: new Date('2025-12-22T10:00:00Z')
          },
          discProfile: {
            primaryType: 'D' as DISCType,
            scores: { D: 85, I: 60, S: 45, C: 55 },
            secondaryTraits: ['I'],
            confidence: 'high'
          },
          phaseResults: {
            primaryPhase: 'Organize',
            scores: {
              Stabilize: 75,
              Organize: 45,
              Build: 30,
              Grow: 20,
              Systemic: 50
            },
            secondaryPhases: ['Stabilize']
          },
          responses: [
            {
              questionId: 'q1',
              questionText: 'Do you have a Chart of Accounts?',
              answer: 'No',
              phase: 'Organize',
              notes: 'Client needs COA setup'
            }
          ],
          consultantNotes: 'Client is motivated and ready to improve'
        };

        const html = service.renderConsultantReport(mockData);

        // Verify HTML structure
        expect(html).toContain('<!DOCTYPE html>');
        expect(html).toContain('<html');
        expect(html).toContain('</html>');

        // Verify executive summary section
        expect(html).toContain('Executive Summary');
        expect(html).toContain('John Doe');
        expect(html).toContain('Acme Corp');

        // Verify DISC section
        expect(html).toContain('DISC Personality Analysis');
        expect(html).toContain('Primary Type: D');

        // Verify phase results section
        expect(html).toContain('Financial Readiness Assessment Results');
        expect(html).toContain('Organize');

        // Verify action plan section
        expect(html).toContain('Recommended Action Plan');

        // Verify response summary section
        expect(html).toContain('Detailed Response Summary');

        // Verify communication strategy section
        expect(html).toContain('Communication Strategy');
      });

      it('should include DISC communication recommendations based on primary type', () => {
        const mockData = {
          client: { name: 'Jane Smith', businessName: 'Tech LLC', email: 'jane@tech.com' },
          assessment: { id: 'assessment-456', completedAt: new Date() },
          discProfile: {
            primaryType: 'S' as DISCType,
            scores: { D: 30, I: 45, S: 85, C: 50 },
            secondaryTraits: [],
            confidence: 'high'
          },
          phaseResults: {
            primaryPhase: 'Stabilize',
            scores: { Stabilize: 40, Organize: 60, Build: 50, Grow: 30, Systemic: 45 },
            secondaryPhases: []
          },
          responses: [],
          consultantNotes: ''
        };

        const html = service.renderConsultantReport(mockData);

        // S-type specific recommendations
        expect(html).toContain('step-by-step');
        expect(html).toContain('reassuring');
        expect(html).toContain('gentle pace');
      });

      it('should display consultant notes when provided', () => {
        const mockData = {
          client: { name: 'Bob Johnson', businessName: 'Services Inc', email: 'bob@services.com' },
          assessment: { id: 'assessment-789', completedAt: new Date() },
          discProfile: {
            primaryType: 'C' as DISCType,
            scores: { D: 40, I: 35, S: 50, C: 90 },
            secondaryTraits: [],
            confidence: 'high'
          },
          phaseResults: {
            primaryPhase: 'Build',
            scores: { Stabilize: 80, Organize: 75, Build: 45, Grow: 25, Systemic: 60 },
            secondaryPhases: []
          },
          responses: [],
          consultantNotes: 'Client is detail-oriented and analytical. Prefers data-driven decisions.'
        };

        const html = service.renderConsultantReport(mockData);

        expect(html).toContain('Client is detail-oriented and analytical');
      });

      it('should highlight warning flags from responses', () => {
        const mockData = {
          client: { name: 'Alice Williams', businessName: 'Retail Co', email: 'alice@retail.com' },
          assessment: { id: 'assessment-101', completedAt: new Date() },
          discProfile: {
            primaryType: 'I' as DISCType,
            scores: { D: 50, I: 80, S: 55, C: 45 },
            secondaryTraits: [],
            confidence: 'moderate'
          },
          phaseResults: {
            primaryPhase: 'Stabilize',
            scores: { Stabilize: 25, Organize: 35, Build: 20, Grow: 15, Systemic: 30 },
            secondaryPhases: []
          },
          responses: [
            {
              questionId: 'q-debt',
              questionText: 'Are you current on all debt payments?',
              answer: 'No',
              phase: 'Stabilize',
              notes: 'Critical: 90 days behind on loan'
            }
          ],
          consultantNotes: ''
        };

        const html = service.renderConsultantReport(mockData);

        expect(html).toContain('Critical');
        expect(html).toContain('90 days behind on loan');
      });
    });

    describe('renderClientReport', () => {
      it('should generate complete HTML client report with all sections', () => {
        const mockData = {
          client: {
            name: 'Sarah Connor',
            businessName: 'Cyberdyne Systems'
          },
          discProfile: {
            primaryType: 'D' as DISCType,
            scores: { D: 90, I: 50, S: 40, C: 60 },
            secondaryTraits: [],
            confidence: 'high'
          },
          phaseResults: {
            primaryPhase: 'Grow',
            scores: { Stabilize: 85, Organize: 80, Build: 75, Grow: 50, Systemic: 70 },
            secondaryPhases: []
          },
          quickWins: [
            'Set up weekly cash flow review',
            'Create 13-week cash flow projection',
            'Implement revenue forecasting'
          ],
          roadmap: {
            phases: ['Grow', 'Systemic'],
            milestones: ['Complete cash flow planning', 'Master financial reporting']
          },
          branding: {
            consultantName: 'Financial Advisor LLC',
            logo: null,
            brandColor: '#4B006E'
          }
        };

        const html = service.renderClientReport(mockData);

        // Verify HTML structure
        expect(html).toContain('<!DOCTYPE html>');
        expect(html).toContain('<html');
        expect(html).toContain('</html>');

        // Verify welcome section
        expect(html).toContain('Welcome');
        expect(html).toContain('Sarah Connor');

        // Verify financial journey section
        expect(html).toContain('Your Financial Readiness Journey');
        expect(html).toContain('Grow');

        // Verify quick wins section
        expect(html).toContain('Your Quick Wins');
        expect(html).toContain('Set up weekly cash flow review');

        // Verify roadmap section
        expect(html).toContain('Your Personalized Roadmap');

        // Verify next steps section
        expect(html).toContain('Understanding Your Next Steps');

        // Verify confidence-building closing
        expect(html).toContain('Building Your Financial Confidence');
      });

      it('should adapt language for D-type personalities (brief, results-oriented)', () => {
        const mockData = {
          client: { name: 'David Leader', businessName: 'Executive Solutions' },
          discProfile: {
            primaryType: 'D' as DISCType,
            scores: { D: 95, I: 40, S: 30, C: 50 },
            secondaryTraits: [],
            confidence: 'high'
          },
          phaseResults: {
            primaryPhase: 'Build',
            scores: { Stabilize: 90, Organize: 85, Build: 55, Grow: 40, Systemic: 65 },
            secondaryPhases: []
          },
          quickWins: ['Implement SOPs', 'Create financial dashboard'],
          roadmap: { phases: ['Build'], milestones: ['Systems operational'] },
          branding: { consultantName: 'Advisor', logo: null, brandColor: '#4B006E' }
        };

        const html = service.renderClientReport(mockData);

        // D-type language patterns
        expect(html).toMatch(/ROI|results|efficiency|bottom line|action/i);
      });

      it('should adapt language for I-type personalities (collaborative, big-picture)', () => {
        const mockData = {
          client: { name: 'Irene Networker', businessName: 'Social Ventures' },
          discProfile: {
            primaryType: 'I' as DISCType,
            scores: { D: 45, I: 88, S: 60, C: 35 },
            secondaryTraits: ['S'],
            confidence: 'high'
          },
          phaseResults: {
            primaryPhase: 'Organize',
            scores: { Stabilize: 70, Organize: 50, Build: 40, Grow: 30, Systemic: 55 },
            secondaryPhases: []
          },
          quickWins: ['Set up COA', 'Integrate accounting software'],
          roadmap: { phases: ['Organize', 'Build'], milestones: ['Foundation complete'] },
          branding: { consultantName: 'Advisor', logo: null, brandColor: '#4B006E' }
        };

        const html = service.renderClientReport(mockData);

        // I-type language patterns
        expect(html).toMatch(/vision|opportunity|together|growth|exciting/i);
      });

      it('should adapt language for S-type personalities (step-by-step, reassuring)', () => {
        const mockData = {
          client: { name: 'Steve Steady', businessName: 'Reliable Services' },
          discProfile: {
            primaryType: 'S' as DISCType,
            scores: { D: 30, I: 50, S: 92, C: 45 },
            secondaryTraits: [],
            confidence: 'high'
          },
          phaseResults: {
            primaryPhase: 'Stabilize',
            scores: { Stabilize: 35, Organize: 45, Build: 25, Grow: 20, Systemic: 40 },
            secondaryPhases: []
          },
          quickWins: ['Organize receipts', 'Review bank reconciliation'],
          roadmap: { phases: ['Stabilize'], milestones: ['Financial stability achieved'] },
          branding: { consultantName: 'Advisor', logo: null, brandColor: '#4B006E' }
        };

        const html = service.renderClientReport(mockData);

        // S-type language patterns
        expect(html).toMatch(/step|gradual|support|safe|comfortable|timeline/i);
      });

      it('should adapt language for C-type personalities (detailed, analytical)', () => {
        const mockData = {
          client: { name: 'Carol Analyst', businessName: 'Data Consulting' },
          discProfile: {
            primaryType: 'C' as DISCType,
            scores: { D: 40, I: 30, S: 50, C: 95 },
            secondaryTraits: [],
            confidence: 'high'
          },
          phaseResults: {
            primaryPhase: 'Systemic',
            scores: { Stabilize: 90, Organize: 88, Build: 85, Grow: 80, Systemic: 45 },
            secondaryPhases: []
          },
          quickWins: ['Master variance analysis', 'Learn KPI interpretation'],
          roadmap: { phases: ['Systemic'], milestones: ['Financial literacy mastery'] },
          branding: { consultantName: 'Advisor', logo: null, brandColor: '#4B006E' }
        };

        const html = service.renderClientReport(mockData);

        // C-type language patterns
        expect(html).toMatch(/data|analysis|accurate|detailed|metrics|standards/i);
      });

      it('should include phase diagram visual asset', () => {
        const mockData = {
          client: { name: 'Test Client', businessName: 'Test Business' },
          discProfile: {
            primaryType: 'D' as DISCType,
            scores: { D: 80, I: 60, S: 50, C: 55 },
            secondaryTraits: [],
            confidence: 'high'
          },
          phaseResults: {
            primaryPhase: 'Organize',
            scores: { Stabilize: 75, Organize: 45, Build: 30, Grow: 20, Systemic: 50 },
            secondaryPhases: []
          },
          quickWins: ['Action 1', 'Action 2'],
          roadmap: { phases: ['Organize'], milestones: ['Milestone 1'] },
          branding: { consultantName: 'Advisor', logo: null, brandColor: '#4B006E' }
        };

        const html = service.renderClientReport(mockData);

        // Should include SVG or reference to phase diagram
        expect(html).toMatch(/<svg|phase-diagram/i);
      });

      it('should apply consultant branding when provided', () => {
        const mockData = {
          client: { name: 'Branded Client', businessName: 'Branded Business' },
          discProfile: {
            primaryType: 'D' as DISCType,
            scores: { D: 80, I: 60, S: 50, C: 55 },
            secondaryTraits: [],
            confidence: 'high'
          },
          phaseResults: {
            primaryPhase: 'Build',
            scores: { Stabilize: 85, Organize: 80, Build: 55, Grow: 40, Systemic: 65 },
            secondaryPhases: []
          },
          quickWins: ['Action 1'],
          roadmap: { phases: ['Build'], milestones: ['Milestone 1'] },
          branding: {
            consultantName: 'Elite Financial Advisors',
            logo: 'https://example.com/logo.png',
            brandColor: '#FF5733'
          }
        };

        const html = service.renderClientReport(mockData);

        expect(html).toContain('Elite Financial Advisors');
        expect(html).toContain('https://example.com/logo.png');
        expect(html).toContain('#FF5733');
      });

      it('should use non-judgmental, encouraging language throughout', () => {
        const mockData = {
          client: { name: 'Struggling Client', businessName: 'Challenged Business' },
          discProfile: {
            primaryType: 'S' as DISCType,
            scores: { D: 30, I: 40, S: 85, C: 45 },
            secondaryTraits: [],
            confidence: 'moderate'
          },
          phaseResults: {
            primaryPhase: 'Stabilize',
            scores: { Stabilize: 20, Organize: 25, Build: 15, Grow: 10, Systemic: 25 },
            secondaryPhases: []
          },
          quickWins: ['Organize receipts', 'Set up basic bookkeeping'],
          roadmap: { phases: ['Stabilize'], milestones: ['Basic order achieved'] },
          branding: { consultantName: 'Advisor', logo: null, brandColor: '#4B006E' }
        };

        const html = service.renderClientReport(mockData);

        // Should NOT contain judgmental language
        expect(html).not.toMatch(/poor|bad|wrong|failed|inadequate|behind/i);

        // SHOULD contain encouraging language
        expect(html).toMatch(/opportunity|improve|progress|growth|develop|strengthen/i);
      });
    });
  });

  describe('DISC Content Adaptation', () => {
    describe('getDISCContentVariation', () => {
      it('should return D-type content variations', () => {
        const content = service.getDISCContentVariation('quickWinIntro', 'D');

        expect(content).toBeDefined();
        expect(content).toMatch(/action|results|efficiency/i);
      });

      it('should return I-type content variations', () => {
        const content = service.getDISCContentVariation('quickWinIntro', 'I');

        expect(content).toBeDefined();
        expect(content).toMatch(/excited|opportunity|collaborative/i);
      });

      it('should return S-type content variations', () => {
        const content = service.getDISCContentVariation('quickWinIntro', 'S');

        expect(content).toBeDefined();
        expect(content).toMatch(/step|gradual|comfortable/i);
      });

      it('should return C-type content variations', () => {
        const content = service.getDISCContentVariation('quickWinIntro', 'C');

        expect(content).toBeDefined();
        expect(content).toMatch(/data|detailed|accurate/i);
      });

      it('should handle multiple content sections for each DISC type', () => {
        const sections = ['quickWinIntro', 'roadmapIntro', 'closingMessage'];
        const types: DISCType[] = ['D', 'I', 'S', 'C'];

        sections.forEach(section => {
          types.forEach(type => {
            const content = service.getDISCContentVariation(section, type);
            expect(content).toBeDefined();
            expect(content.length).toBeGreaterThan(0);
          });
        });
      });
    });

    describe('getCommunicationStrategy', () => {
      it('should return communication strategy for D-type', () => {
        const strategy = service.getCommunicationStrategy('D');

        expect(strategy).toHaveProperty('dos');
        expect(strategy).toHaveProperty('donts');
        expect(strategy).toHaveProperty('meetingApproach');
        expect(strategy.dos).toContain('Be direct and results-focused');
      });

      it('should return communication strategy for I-type', () => {
        const strategy = service.getCommunicationStrategy('I');

        expect(strategy).toHaveProperty('dos');
        expect(strategy).toHaveProperty('donts');
        expect(strategy.meetingApproach).toMatch(/collaborative|discussion/i);
      });

      it('should return communication strategy for S-type', () => {
        const strategy = service.getCommunicationStrategy('S');

        expect(strategy.dos).toContain('Provide reassurance and support');
      });

      it('should return communication strategy for C-type', () => {
        const strategy = service.getCommunicationStrategy('C');

        expect(strategy.dos).toContain('Provide detailed data and analysis');
      });
    });
  });

  describe('Visual Assets', () => {
    describe('getPhaseDiagramSVG', () => {
      it('should generate SVG phase diagram with current position highlighted', () => {
        const svg = service.getPhaseDiagramSVG('Organize', ['Stabilize']);

        expect(svg).toContain('<svg');
        expect(svg).toContain('</svg>');
        expect(svg).toContain('Stabilize');
        expect(svg).toContain('Organize');
        expect(svg).toContain('Build');
        expect(svg).toContain('Grow');
        expect(svg).toContain('Systemic');
      });

      it('should highlight the primary phase', () => {
        const svg = service.getPhaseDiagramSVG('Build', []);

        // Primary phase should have different styling (phase-box-primary class)
        expect(svg).toContain('phase-box-primary');
        expect(svg).toContain('Build');
      });

      it('should show secondary phases when provided', () => {
        const svg = service.getPhaseDiagramSVG('Grow', ['Build', 'Systemic']);

        // Secondary phases should have the 'phase-box-secondary' CSS class
        expect(svg).toContain('phase-box-secondary');

        // Verify the SVG contains all expected phases
        expect(svg).toContain('Build');
        expect(svg).toContain('Systemic');
        expect(svg).toContain('Grow');
      });

      it('should be accessible with proper ARIA labels', () => {
        const svg = service.getPhaseDiagramSVG('Stabilize', []);

        expect(svg).toMatch(/aria-label|role="img"/i);
      });
    });

    describe('getPhaseIcon', () => {
      it('should return SVG icon for Stabilize phase', () => {
        const icon = service.getPhaseIcon('Stabilize');

        expect(icon).toContain('<svg');
        expect(icon).toContain('</svg>');
      });

      it('should return SVG icon for Organize phase', () => {
        const icon = service.getPhaseIcon('Organize');

        expect(icon).toContain('<svg');
      });

      it('should return SVG icon for Build phase', () => {
        const icon = service.getPhaseIcon('Build');

        expect(icon).toContain('<svg');
      });

      it('should return SVG icon for Grow phase', () => {
        const icon = service.getPhaseIcon('Grow');

        expect(icon).toContain('<svg');
      });

      it('should return SVG icon for Systemic phase', () => {
        const icon = service.getPhaseIcon('Systemic');

        expect(icon).toContain('<svg');
      });
    });
  });

  describe('Template Styling', () => {
    it('should include brand colors in consultant report CSS', () => {
      const mockData = {
        client: { name: 'Test', businessName: 'Test Co', email: 'test@test.com' },
        assessment: { id: 'test-123', completedAt: new Date() },
        discProfile: {
          primaryType: 'D' as DISCType,
          scores: { D: 80, I: 60, S: 50, C: 55 },
          secondaryTraits: [],
          confidence: 'high'
        },
        phaseResults: {
          primaryPhase: 'Build',
          scores: { Stabilize: 85, Organize: 80, Build: 55, Grow: 40, Systemic: 65 },
          secondaryPhases: []
        },
        responses: [],
        consultantNotes: ''
      };

      const html = service.renderConsultantReport(mockData);

      expect(html).toContain('#4B006E'); // Primary purple
    });

    it('should use Calibri font family with 14px minimum', () => {
      const mockData = {
        client: { name: 'Test', businessName: 'Test Co' },
        discProfile: {
          primaryType: 'D' as DISCType,
          scores: { D: 80, I: 60, S: 50, C: 55 },
          secondaryTraits: [],
          confidence: 'high'
        },
        phaseResults: {
          primaryPhase: 'Build',
          scores: { Stabilize: 85, Organize: 80, Build: 55, Grow: 40, Systemic: 65 },
          secondaryPhases: []
        },
        quickWins: ['Test action'],
        roadmap: { phases: ['Build'], milestones: ['Test'] },
        branding: { consultantName: 'Advisor', logo: null, brandColor: '#4B006E' }
      };

      const html = service.renderClientReport(mockData);

      expect(html).toMatch(/font-family:.*Calibri/i);
      expect(html).toMatch(/font-size:.*14px/i);
    });

    it('should be print-optimized for PDF generation', () => {
      const mockData = {
        client: { name: 'Test', businessName: 'Test Co', email: 'test@test.com' },
        assessment: { id: 'test-123', completedAt: new Date() },
        discProfile: {
          primaryType: 'D' as DISCType,
          scores: { D: 80, I: 60, S: 50, C: 55 },
          secondaryTraits: [],
          confidence: 'high'
        },
        phaseResults: {
          primaryPhase: 'Build',
          scores: { Stabilize: 85, Organize: 80, Build: 55, Grow: 40, Systemic: 65 },
          secondaryPhases: []
        },
        responses: [],
        consultantNotes: ''
      };

      const html = service.renderConsultantReport(mockData);

      // Should include print media styles
      expect(html).toMatch(/@media print|@page/i);
    });
  });

  describe('Error Handling', () => {
    it('should handle missing optional fields gracefully in consultant report', () => {
      const mockData = {
        client: { name: 'Test', businessName: 'Test Co', email: 'test@test.com' },
        assessment: { id: 'test-123', completedAt: new Date() },
        discProfile: {
          primaryType: 'D' as DISCType,
          scores: { D: 80, I: 60, S: 50, C: 55 },
          secondaryTraits: [],
          confidence: 'high'
        },
        phaseResults: {
          primaryPhase: 'Build',
          scores: { Stabilize: 85, Organize: 80, Build: 55, Grow: 40, Systemic: 65 },
          secondaryPhases: []
        },
        responses: [],
        consultantNotes: '' // Empty notes
      };

      expect(() => service.renderConsultantReport(mockData)).not.toThrow();
    });

    it('should handle missing optional fields gracefully in client report', () => {
      const mockData = {
        client: { name: 'Test', businessName: 'Test Co' },
        discProfile: {
          primaryType: 'D' as DISCType,
          scores: { D: 80, I: 60, S: 50, C: 55 },
          secondaryTraits: [],
          confidence: 'high'
        },
        phaseResults: {
          primaryPhase: 'Build',
          scores: { Stabilize: 85, Organize: 80, Build: 55, Grow: 40, Systemic: 65 },
          secondaryPhases: []
        },
        quickWins: [],
        roadmap: { phases: [], milestones: [] },
        branding: { consultantName: 'Advisor', logo: null, brandColor: '#4B006E' }
      };

      expect(() => service.renderClientReport(mockData)).not.toThrow();
    });
  });
});
