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
  ParseIntPipe,
  HttpCode,
  HttpStatus,
  ParseEnumPipe,
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
import { AssessmentResponseDto, PaginatedAssessmentsResponseDto } from './dto/assessment-response.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AssessmentOwnershipGuard } from '../../common/guards/assessment-ownership.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { AssessmentStatus } from './entities/assessment.entity';

@ApiTags('assessments')
@ApiBearerAuth()
@Controller('assessments')
@UseGuards(JwtAuthGuard)
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
    summary: 'List assessments',
    description: 'Retrieves all assessments for the authenticated consultant with pagination and filtering',
  })
  @ApiQuery({ name: 'page', required: false, type: Number, description: 'Page number (default: 1)' })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Items per page (default: 10, max: 100)' })
  @ApiQuery({ name: 'status', required: false, enum: AssessmentStatus, description: 'Filter by status' })
  @ApiQuery({ name: 'search', required: false, type: String, description: 'Search by client name, business name, or email' })
  @ApiQuery({ name: 'sortBy', required: false, type: String, description: 'Sort field (default: updatedAt)' })
  @ApiQuery({ name: 'sortOrder', required: false, enum: ['asc', 'desc'], description: 'Sort order (default: desc)' })
  @ApiResponse({
    status: 200,
    description: 'Paginated list of assessments',
    type: PaginatedAssessmentsResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  findAll(
    @GetUser() user: any,
    @Query('page', new ParseIntPipe({ optional: true })) page?: number,
    @Query('limit', new ParseIntPipe({ optional: true })) limit?: number,
    @Query('status') status?: AssessmentStatus,
    @Query('search') search?: string,
    @Query('sortBy') sortBy?: string,
    @Query('sortOrder') sortOrder?: 'ASC' | 'DESC',
  ) {
    return this.assessmentsService.findAll(user.id, {
      page,
      limit,
      status,
      search,
      sortBy,
      sortOrder,
    });
  }

  @Get(':id')
  @UseGuards(AssessmentOwnershipGuard)
  @ApiOperation({
    summary: 'Get assessment by ID',
    description: 'Retrieves a specific assessment with all responses. IDOR protected - users can only access their own assessments.',
  })
  @ApiParam({ name: 'id', description: 'Assessment ID', type: String })
  @ApiResponse({
    status: 200,
    description: 'Assessment details',
    type: AssessmentResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Assessment not found' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden - assessment belongs to another user' })
  findOne(@Param('id', ParseUUIDPipe) id: string, @GetUser() user: any) {
    return this.assessmentsService.findOne(id, user.id);
  }

  @Patch(':id')
  @UseGuards(AssessmentOwnershipGuard)
  @ApiOperation({
    summary: 'Update assessment',
    description: 'Updates assessment fields. Supports auto-save functionality. IDOR protected - users can only update their own assessments.',
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
  @ApiResponse({ status: 403, description: 'Forbidden - assessment belongs to another user' })
  update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() updateAssessmentDto: UpdateAssessmentDto,
    @GetUser() user: any,
  ) {
    return this.assessmentsService.update(id, updateAssessmentDto, user.id);
  }

  @Delete(':id')
  @UseGuards(AssessmentOwnershipGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete assessment',
    description: 'Soft deletes an assessment. IDOR protected - users can only delete their own assessments.',
  })
  @ApiParam({ name: 'id', description: 'Assessment ID', type: String })
  @ApiResponse({ status: 204, description: 'Assessment deleted successfully' })
  @ApiResponse({ status: 404, description: 'Assessment not found' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden - assessment belongs to another user' })
  remove(@Param('id', ParseUUIDPipe) id: string, @GetUser() user: any) {
    return this.assessmentsService.remove(id, user.id);
  }
}
