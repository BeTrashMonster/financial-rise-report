import { Router } from 'express';
import reportController from '../controllers/reportController';
import { authenticate } from '../middleware/auth';

const router = Router();

/**
 * @swagger
 * /api/v1/assessments/{id}/reports/consultant:
 *   post:
 *     summary: Generate consultant report for an assessment
 *     tags: [Reports]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Assessment ID
 *     responses:
 *       201:
 *         description: Consultant report generated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *                   properties:
 *                     reportId:
 *                       type: string
 *                       format: uuid
 *                     reportType:
 *                       type: string
 *                       enum: [consultant]
 *                     assessmentId:
 *                       type: string
 *                       format: uuid
 *                     pdfUrl:
 *                       type: string
 *                       format: uri
 *                     generatedAt:
 *                       type: string
 *                       format: date-time
 *       400:
 *         description: Assessment not completed
 *       404:
 *         description: Assessment not found
 *       500:
 *         description: Report generation failed
 */
router.post('/assessments/:id/reports/consultant', authenticate, reportController.generateConsultantReport);

/**
 * @swagger
 * /api/v1/assessments/{id}/reports/client:
 *   post:
 *     summary: Generate client report for an assessment
 *     tags: [Reports]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Assessment ID
 *     responses:
 *       201:
 *         description: Client report generated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *                   properties:
 *                     reportId:
 *                       type: string
 *                       format: uuid
 *                     reportType:
 *                       type: string
 *                       enum: [client]
 *                     assessmentId:
 *                       type: string
 *                       format: uuid
 *                     pdfUrl:
 *                       type: string
 *                       format: uri
 *                     generatedAt:
 *                       type: string
 *                       format: date-time
 *       400:
 *         description: Assessment not completed
 *       404:
 *         description: Assessment not found
 *       500:
 *         description: Report generation failed
 */
router.post('/assessments/:id/reports/client', authenticate, reportController.generateClientReport);

/**
 * @swagger
 * /api/v1/assessments/{id}/reports:
 *   post:
 *     summary: Generate both consultant and client reports
 *     tags: [Reports]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Assessment ID
 *     responses:
 *       201:
 *         description: Both reports generated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *                   properties:
 *                     consultantReport:
 *                       type: object
 *                       properties:
 *                         reportId:
 *                           type: string
 *                           format: uuid
 *                         reportType:
 *                           type: string
 *                           enum: [consultant]
 *                         assessmentId:
 *                           type: string
 *                           format: uuid
 *                         pdfUrl:
 *                           type: string
 *                           format: uri
 *                         generatedAt:
 *                           type: string
 *                           format: date-time
 *                     clientReport:
 *                       type: object
 *                       properties:
 *                         reportId:
 *                           type: string
 *                           format: uuid
 *                         reportType:
 *                           type: string
 *                           enum: [client]
 *                         assessmentId:
 *                           type: string
 *                           format: uuid
 *                         pdfUrl:
 *                           type: string
 *                           format: uri
 *                         generatedAt:
 *                           type: string
 *                           format: date-time
 *       400:
 *         description: Assessment not completed
 *       404:
 *         description: Assessment not found
 *       500:
 *         description: Report generation failed
 */
router.post('/assessments/:id/reports', authenticate, reportController.generateBothReports);

/**
 * @swagger
 * /api/v1/reports/{reportId}/download:
 *   get:
 *     summary: Download a generated report
 *     tags: [Reports]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: reportId
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Report ID
 *     responses:
 *       200:
 *         description: Report download URL
 *       404:
 *         description: Report not found
 *       500:
 *         description: Download failed
 */
router.get('/reports/:reportId/download', authenticate, reportController.downloadReport);

export default router;
