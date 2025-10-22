import { IsString, IsNotEmpty, IsIn } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({
    description: 'User login',
    example: 'admin',
  })
  @IsString()
  @IsNotEmpty()
  login: string;

  @ApiProperty({
    description: 'User password',
    example: 'password123',
  })
  @IsString()
  @IsNotEmpty()
  password: string;

  @ApiProperty({
    description: 'User role',
    enum: ['admin', 'operator', 'director', 'master'],
    example: 'admin',
  })
  @IsIn(['admin', 'operator', 'director', 'master'])
  @IsNotEmpty()
  role: 'admin' | 'operator' | 'director' | 'master';
}

