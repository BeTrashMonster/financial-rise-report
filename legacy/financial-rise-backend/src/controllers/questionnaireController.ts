import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../types';
import questionnaireService from '../services/questionnaireService';

/**
 * Questionnaire Controller
 * Provides questionnaire structure to frontend
 */
class QuestionnaireController {
  /**
   * GET /api/v1/questionnaire
   * Get the complete questionnaire structure
   * REQ-QUEST-001 through REQ-QUEST-010
   */
  async getQuestionnaire(_req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const questionnaire = await questionnaireService.getQuestionnaire();
      res.status(200).json(questionnaire);
    } catch (error) {
      next(error);
    }
  }
}

export default new QuestionnaireController();
