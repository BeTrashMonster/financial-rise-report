import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { QuestionsService } from './questions.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@ApiTags('questionnaire')
@ApiBearerAuth()
@Controller('api/v1/questionnaire')
@UseGuards(JwtAuthGuard)
export class QuestionsController {
  constructor(private readonly questionsService: QuestionsService) {}

  @Get('questions')
  @ApiOperation({
    summary: 'Get all questions',
    description: 'Returns all assessment questions in display order',
  })
  @ApiQuery({
    name: 'assessmentId',
    required: false,
    type: String,
    description: 'Optional assessment ID to include user responses',
  })
  @ApiResponse({
    status: 200,
    description: 'List of all questions',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getQuestions(@Query('assessmentId') assessmentId?: string) {
    const questions = await this.questionsService.findAll();
    const total = questions.length;
    const required = questions.filter(q => q.required).length;
    const optional = total - required;

    return {
      questions,
      meta: {
        totalQuestions: total,
        requiredQuestions: required,
        optionalQuestions: optional,
      },
    };
  }
}
