import {
  Controller,
  Post,
  Patch,
  Body,
  Param,
  UseGuards,
  ParseUUIDPipe,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
} from '@nestjs/swagger';
import { QuestionnaireService } from './questionnaire.service';
import { SubmitResponseDto } from './dto/submit-response.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';

@ApiTags('questionnaire')
@ApiBearerAuth()
@Controller('api/v1/questionnaire')
@UseGuards(JwtAuthGuard)
export class QuestionnaireController {
  constructor(private readonly questionnaireService: QuestionnaireService) {}

  @Post('responses')
  @ApiOperation({
    summary: 'Submit response to question',
    description: 'Saves or updates a response to a question. Updates progress automatically.',
  })
  @ApiResponse({
    status: 201,
    description: 'Response saved successfully',
  })
  @ApiResponse({ status: 404, description: 'Assessment or question not found' })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  submitResponse(@Body() submitResponseDto: SubmitResponseDto, @GetUser() user: any) {
    return this.questionnaireService.submitResponse(submitResponseDto, user.id);
  }

  @Patch('responses/:id')
  @ApiOperation({
    summary: 'Update response',
    description: 'Updates an existing response to a question',
  })
  @ApiParam({ name: 'id', description: 'Response ID', type: String })
  @ApiResponse({
    status: 200,
    description: 'Response updated successfully',
  })
  @ApiResponse({ status: 404, description: 'Response not found' })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  updateResponse(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() updateDto: Partial<SubmitResponseDto>,
    @GetUser() user: any,
  ) {
    return this.questionnaireService.updateResponse(id, updateDto, user.id);
  }
}
