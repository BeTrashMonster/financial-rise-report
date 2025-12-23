import { Controller, Get, Query, Param, UseGuards, ParseUUIDPipe, ParseBoolPipe } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery,
  ApiParam,
} from '@nestjs/swagger';
import { QuestionsService } from './questions.service';
import { QuestionnaireResponseDto, QuestionResponseDto } from './dto/question-response.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '../../../../../database/entities/User'
import { QuestionSection } from '../../../../../database/entities/Question'

@ApiTags('questions')
@ApiBearerAuth()
@Controller('api/v1/questionnaire')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.CONSULTANT, UserRole.ADMIN)
export class QuestionsController {
  constructor(private readonly questionsService: QuestionsService) {}

  @Get()
  @ApiOperation({
    summary: 'Get complete questionnaire',
    description:
      'Returns all assessment questions in order. ' +
      'By default includes DISC questions (consultant view). ' +
      'Set includeDisc=false for client-facing view (hides DISC questions per REQ-QUEST-003).',
  })
  @ApiQuery({
    name: 'includeDisc',
    required: false,
    type: Boolean,
    description: 'Include DISC personality questions (default: true for consultant view)',
  })
  @ApiResponse({
    status: 200,
    description: 'Complete questionnaire with all questions',
    type: QuestionnaireResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getQuestionnaire(
    @Query('includeDisc', new ParseBoolPipe({ optional: true })) includeDisc: boolean = true,
  ): Promise<QuestionnaireResponseDto> {
    return this.questionsService.getQuestionnaire(includeDisc);
  }

  @Get('sections/:section')
  @ApiOperation({
    summary: 'Get questions by section',
    description: 'Returns questions filtered by financial readiness phase/section',
  })
  @ApiParam({
    name: 'section',
    enum: QuestionSection,
    description: 'Question section/phase',
  })
  @ApiResponse({
    status: 200,
    description: 'Questions for the specified section',
    type: [QuestionResponseDto],
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getQuestionsBySection(@Param('section') section: QuestionSection) {
    return this.questionsService.findBySection(section);
  }

  @Get('conditional/:parentId')
  @ApiOperation({
    summary: 'Get conditional questions',
    description:
      'Returns conditional questions that depend on a parent question. ' +
      'Used for Phase 3 conditional logic feature (e.g., S-Corp payroll question).',
  })
  @ApiParam({
    name: 'parentId',
    description: 'Parent question ID',
    type: String,
  })
  @ApiResponse({
    status: 200,
    description: 'Conditional questions for the parent',
    type: [QuestionResponseDto],
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getConditionalQuestions(@Param('parentId', ParseUUIDPipe) parentId: string) {
    return this.questionsService.findConditionalQuestions(parentId);
  }
}
