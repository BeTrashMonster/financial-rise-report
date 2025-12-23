import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Question, QuestionSection } from '../../../../../database/entities/Question'
import { QuestionnaireResponseDto } from './dto/question-response.dto';

@Injectable()
export class QuestionsService {
  constructor(
    @InjectRepository(Question)
    private questionRepository: Repository<Question>,
  ) {}

  /**
   * Find all non-conditional questions
   * Used for initial questionnaire display
   */
  async findAll(): Promise<Question[]> {
    return this.questionRepository.find({
      where: {
        deletedAt: null as any,
        isConditional: false,
      },
      order: { orderIndex: 'ASC' },
    });
  }

  /**
   * Find a single question by ID
   */
  async findOne(id: string): Promise<Question | null> {
    return this.questionRepository.findOne({
      where: { id, deletedAt: null as any },
    });
  }

  /**
   * Find questions by section/phase
   */
  async findBySection(section: QuestionSection): Promise<Question[]> {
    return this.questionRepository.find({
      where: {
        section,
        deletedAt: null as any,
      },
      order: { orderIndex: 'ASC' },
    });
  }

  /**
   * Count total number of non-conditional questions
   * Used for progress calculation
   */
  async countTotal(): Promise<number> {
    return this.questionRepository.count({
      where: {
        deletedAt: null as any,
        isConditional: false,
      },
    });
  }

  /**
   * Find conditional questions that depend on a parent question
   * Used for Phase 3 conditional logic feature
   */
  async findConditionalQuestions(parentQuestionId: string): Promise<Question[]> {
    return this.questionRepository.find({
      where: {
        conditionalParentId: parentQuestionId,
        deletedAt: null as any,
      },
      order: { orderIndex: 'ASC' },
    });
  }

  /**
   * Get complete questionnaire
   * @param includeDisc - Whether to include DISC questions (consultant view) or hide them (client view)
   *
   * REQ-QUEST-003: DISC questions must be hidden from clients
   */
  async getQuestionnaire(includeDisc: boolean = true): Promise<QuestionnaireResponseDto> {
    let questions: Question[];

    if (includeDisc) {
      // Consultant view: include all questions including DISC
      questions = await this.findAll();
    } else {
      // Client view: exclude DISC questions per REQ-QUEST-003
      questions = await this.questionRepository.find({
        where: {
          deletedAt: null as any,
          isConditional: false,
        },
        order: { orderIndex: 'ASC' },
      });

      // Filter out DISC questions
      questions = questions.filter((q) => q.section !== QuestionSection.DISC);
    }

    return {
      questions,
      total: questions.length,
    };
  }

  /**
   * Get questions with their conditional children
   * Used for Phase 3 conditional logic display
   */
  async getQuestionsWithConditionals(): Promise<Question[]> {
    return this.questionRepository.find({
      where: { deletedAt: null as any },
      relations: ['conditionalChildren'],
      order: { orderIndex: 'ASC' },
    });
  }
}
