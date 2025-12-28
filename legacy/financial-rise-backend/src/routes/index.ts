import { Router } from 'express';
import assessmentRoutes from './assessmentRoutes';
import questionnaireRoutes from './questionnaireRoutes';
import reportRoutes from './reportRoutes';

const router = Router();

// API v1 routes
router.use('/assessments', assessmentRoutes);
router.use('/questionnaire', questionnaireRoutes);
router.use('/', reportRoutes);

export default router;
