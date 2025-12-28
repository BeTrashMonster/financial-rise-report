import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Question } from './entities/question.entity';

@Injectable()
export class QuestionsService {
  constructor(
    @InjectRepository(Question)
    private questionRepository: Repository<Question>,
  ) {}

  /**
   * Find all questions ordered by displayOrder
   */
  async findAll(): Promise<Question[]> {
    return this.questionRepository.find({
      order: { display_order: 'ASC' },
    });
  }

  /**
   * Find a single question by ID
   */
  async findOne(id: string): Promise<Question | null> {
    return this.questionRepository.findOne({
      where: { id },
    });
  }

  /**
   * Count total questions
   */
  async countTotal(): Promise<number> {
    return this.questionRepository.count();
  }
}
