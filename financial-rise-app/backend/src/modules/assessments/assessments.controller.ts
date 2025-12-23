import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  Query,
  ParseUUIDPipe,
  ParseBoolPipe,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';
import { AssessmentsService } from './assessments.service';
import { CreateAssessmentDto } from './dto/create-assessment.dto';
import { UpdateAssessmentDto } from './dto/update-assessment.dto';
import { SaveResponseDto } from './dto/save-response.dto';
import { AssessmentResponseDto } from './dto/assessment-response.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '../../../../../database/entities/User'
import { GetUser } from '../auth/decorators/get-user.decorator';

@ApiTags('assessments')
@ApiBearerAuth()
@Controller('api/v1/assessments')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.CONSULTANT, UserRole.ADMIN)
export class AssessmentsController {
  constructor(private readonly assessmentsService: AssessmentsService) {}

  @Post()
  @ApiOperation({
    summary: 'Create a new assessment',
    description: 'Creates a new financial readiness assessment for a client',
  })
  @ApiResponse({
    status: 201,
    description: 'Assessment created successfully',
    type: AssessmentResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  create(@Body() createAssessmentDto: CreateAssessmentDto, @GetUser() user: any) {
    return this.assessmentsService.create(createAssessmentDto, user.id);
  }

  @Get()
  @ApiOperation({
    summary: 'Get all assessments',
    description: 'Retrieves all assessments for the authenticated consultant',
  })
  @ApiQuery({
    name: 'archived',
    required: false,
    type: Boolean,
    description: 'Filter archived assessments (false = active only, true = archived only)',
  })
  @ApiResponse({
    status: 200,
    description: 'List of assessments',
    type: [AssessmentResponseDto],
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  findAll(@GetUser() user: any, @Query('archived', new ParseBoolPipe({ optional: true })) archived: boolean = false) {
    return this.assessmentsService.findAll(user.id, archived);
  }

  @Get(':id')
  @ApiOperation({
    summary: 'Get assessment by ID',
    description: 'Retrieves a specific assessment with all responses',
  })
  @ApiParam({ name: 'id', description: 'Assessment ID', type: String })
  @ApiResponse({
    status: 200,
    description: 'Assessment details',
    type: AssessmentResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Assessment not found' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  findOne(@Param('id', ParseUUIDPipe) id: string, @GetUser() user: any) {
    return this.assessmentsService.findOne(id, user.id);
  }

  @Patch(':id')
  @ApiOperation({
    summary: 'Update assessment',
    description: 'Updates assessment fields. Supports auto-save functionality.',
  })
  @ApiParam({ name: 'id', description: 'Assessment ID', type: String })
  @ApiResponse({
    status: 200,
    description: 'Assessment updated successfully',
    type: AssessmentResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Assessment not found' })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() updateAssessmentDto: UpdateAssessmentDto,
    @GetUser() user: any,
  ) {
    return this.assessmentsService.update(id, updateAssessmentDto, user.id);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete assessment',
    description: 'Soft deletes an assessment. Only DRAFT assessments can be deleted.',
  })
  @ApiParam({ name: 'id', description: 'Assessment ID', type: String })
  @ApiResponse({ status: 204, description: 'Assessment deleted successfully' })
  @ApiResponse({
    status: 400,
    description: 'Cannot delete non-draft assessment',
  })
  @ApiResponse({ status: 404, description: 'Assessment not found' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  remove(@Param('id', ParseUUIDPipe) id: string, @GetUser() user: any) {
    return this.assessmentsService.remove(id, user.id);
  }

  @Patch(':id/archive')
  @ApiOperation({
    summary: 'Archive assessment',
    description: 'Archives a completed assessment to keep dashboard clean',
  })
  @ApiParam({ name: 'id', description: 'Assessment ID', type: String })
  @ApiResponse({
    status: 200,
    description: 'Assessment archived successfully',
    type: AssessmentResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Assessment not found' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  archive(@Param('id', ParseUUIDPipe) id: string, @GetUser() user: any) {
    return this.assessmentsService.archive(id, user.id);
  }

  @Patch(':id/restore')
  @ApiOperation({
    summary: 'Restore archived assessment',
    description: 'Restores an archived assessment back to active list',
  })
  @ApiParam({ name: 'id', description: 'Assessment ID', type: String })
  @ApiResponse({
    status: 200,
    description: 'Assessment restored successfully',
    type: AssessmentResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Assessment not found' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  restore(@Param('id', ParseUUIDPipe) id: string, @GetUser() user: any) {
    return this.assessmentsService.restore(id, user.id);
  }

  @Post(':id/responses')
  @ApiOperation({
    summary: 'Save response to question',
    description:
      'Saves or updates a response to a question. Supports auto-save. Updates progress automatically.',
  })
  @ApiParam({ name: 'id', description: 'Assessment ID', type: String })
  @ApiResponse({ status: 201, description: 'Response saved successfully' })
  @ApiResponse({ status: 404, description: 'Assessment or question not found' })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  saveResponse(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() saveResponseDto: SaveResponseDto,
    @GetUser() user: any,
  ) {
    return this.assessmentsService.saveResponse(id, saveResponseDto, user.id);
  }

  @Get(':id/responses')
  @ApiOperation({
    summary: 'Get all responses',
    description: 'Retrieves all responses for an assessment',
  })
  @ApiParam({ name: 'id', description: 'Assessment ID', type: String })
  @ApiResponse({ status: 200, description: 'List of responses' })
  @ApiResponse({ status: 404, description: 'Assessment not found' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getResponses(@Param('id', ParseUUIDPipe) id: string, @GetUser() user: any) {
    return this.assessmentsService.getResponses(id, user.id);
  }
}
