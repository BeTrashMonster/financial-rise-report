import { Router } from 'express';
import questionnaireController from '../controllers/questionnaireController';
import { authenticate } from '../middleware/auth';

const router = Router();

/**
 * Questionnaire API Routes
 */

// Get questionnaire structure
router.get('/', authenticate, questionnaireController.getQuestionnaire.bind(questionnaireController));

export default router;
