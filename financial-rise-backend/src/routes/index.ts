import { Router } from 'express';
import assessmentRoutes from './assessmentRoutes';
import questionnaireRoutes from './questionnaireRoutes';

const router = Router();

// API v1 routes
router.use('/assessments', assessmentRoutes);
router.use('/questionnaire', questionnaireRoutes);

export default router;
