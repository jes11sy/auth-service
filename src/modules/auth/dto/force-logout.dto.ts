import { IsNumber, IsPositive, IsIn, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

/**
 * DTO для принудительной деавторизации пользователя
 * ✅ FIX: Добавлена валидация для защиты от некорректных данных
 */
export class ForceLogoutDto {
  @ApiProperty({
    description: 'ID пользователя для деавторизации',
    example: 123,
  })
  @IsNumber()
  @IsPositive()
  @IsNotEmpty()
  userId: number;

  @ApiProperty({
    description: 'Роль пользователя',
    enum: ['admin', 'operator', 'director', 'master'],
    example: 'operator',
  })
  @IsIn(['admin', 'operator', 'director', 'master'])
  @IsNotEmpty()
  role: 'admin' | 'operator' | 'director' | 'master';
}
