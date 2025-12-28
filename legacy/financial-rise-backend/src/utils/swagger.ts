import swaggerJsdoc from 'swagger-jsdoc';

const options: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Financial RISE Report API',
      version: '1.0.0',
      description: 'Backend API for Financial RISE Report - Assessment Management System',
      contact: {
        name: 'Financial RISE Team',
      },
      license: {
        name: 'MIT',
      },
    },
    servers: [
      {
        url: 'http://localhost:3000/api/v1',
        description: 'Development server',
      },
      {
        url: 'https://api.financial-rise.com/api/v1',
        description: 'Production server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'JWT authorization header using the Bearer scheme',
        },
      },
      schemas: {
        Assessment: {
          type: 'object',
          properties: {
            assessmentId: {
              type: 'string',
              format: 'uuid',
              description: 'Unique assessment identifier',
            },
            clientName: {
              type: 'string',
              maxLength: 100,
              description: 'Client full name',
            },
            businessName: {
              type: 'string',
              maxLength: 100,
              description: 'Client business name',
            },
            clientEmail: {
              type: 'string',
              format: 'email',
              description: 'Client email address',
            },
            status: {
              type: 'string',
              enum: ['draft', 'in_progress', 'completed'],
              description: 'Assessment status',
            },
            progress: {
              type: 'number',
              minimum: 0,
              maximum: 100,
              description: 'Completion progress percentage',
            },
            createdAt: {
              type: 'string',
              format: 'date-time',
              description: 'Assessment creation timestamp',
            },
            updatedAt: {
              type: 'string',
              format: 'date-time',
              description: 'Last modification timestamp',
            },
            startedAt: {
              type: 'string',
              format: 'date-time',
              nullable: true,
              description: 'When first response was recorded',
            },
            completedAt: {
              type: 'string',
              format: 'date-time',
              nullable: true,
              description: 'When assessment was completed',
            },
          },
        },
        AssessmentResponse: {
          type: 'object',
          properties: {
            questionId: {
              type: 'string',
              format: 'uuid',
              description: 'Question identifier',
            },
            answer: {
              description: 'Answer value (type varies by question)',
            },
            notApplicable: {
              type: 'boolean',
              default: false,
              description: 'Marked as not applicable',
            },
            consultantNotes: {
              type: 'string',
              maxLength: 1000,
              nullable: true,
              description: 'Consultant notes for this question',
            },
            answeredAt: {
              type: 'string',
              format: 'date-time',
              nullable: true,
              description: 'When answer was provided',
            },
          },
        },
        CreateAssessmentRequest: {
          type: 'object',
          required: ['clientName', 'businessName', 'clientEmail'],
          properties: {
            clientName: {
              type: 'string',
              minLength: 1,
              maxLength: 100,
            },
            businessName: {
              type: 'string',
              minLength: 1,
              maxLength: 100,
            },
            clientEmail: {
              type: 'string',
              format: 'email',
            },
            notes: {
              type: 'string',
              maxLength: 1000,
            },
          },
        },
        UpdateAssessmentRequest: {
          type: 'object',
          properties: {
            responses: {
              type: 'array',
              items: {
                type: 'object',
                required: ['questionId'],
                properties: {
                  questionId: {
                    type: 'string',
                    format: 'uuid',
                  },
                  answer: {},
                  notApplicable: {
                    type: 'boolean',
                  },
                  consultantNotes: {
                    type: 'string',
                    maxLength: 1000,
                  },
                },
              },
            },
            status: {
              type: 'string',
              enum: ['draft', 'in_progress', 'completed'],
            },
          },
        },
        Error: {
          type: 'object',
          properties: {
            error: {
              type: 'object',
              properties: {
                code: {
                  type: 'string',
                  description: 'Error code',
                },
                message: {
                  type: 'string',
                  description: 'Human-readable error message',
                },
                details: {
                  type: 'object',
                  description: 'Additional error details',
                },
              },
            },
          },
        },
      },
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
    tags: [
      {
        name: 'Assessments',
        description: 'Assessment management operations',
      },
      {
        name: 'Questionnaire',
        description: 'Questionnaire retrieval operations',
      },
    ],
  },
  apis: ['./src/routes/*.ts'],
};

export const swaggerSpec = swaggerJsdoc(options);

export default swaggerSpec;
