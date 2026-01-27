import { IsString, IsNotEmpty, IsIn, MinLength, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { SecurityConfig } from '../../../config/security.config';

export class LoginDto {
  @ApiProperty({
    description: 'User login',
    example: 'admin',
    minLength: SecurityConfig.MIN_LOGIN_LENGTH,
    maxLength: SecurityConfig.MAX_LOGIN_LENGTH,
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(SecurityConfig.MIN_LOGIN_LENGTH, { message: `Login must be at least ${SecurityConfig.MIN_LOGIN_LENGTH} characters` })
  @MaxLength(SecurityConfig.MAX_LOGIN_LENGTH, { message: `Login must not exceed ${SecurityConfig.MAX_LOGIN_LENGTH} characters` })
  login: string;

  @ApiProperty({
    description: 'User password',
    example: 'password123',
    minLength: SecurityConfig.MIN_PASSWORD_LENGTH,
    maxLength: SecurityConfig.MAX_PASSWORD_LENGTH,
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(SecurityConfig.MIN_PASSWORD_LENGTH, { message: `Password must be at least ${SecurityConfig.MIN_PASSWORD_LENGTH} characters` })
  @MaxLength(SecurityConfig.MAX_PASSWORD_LENGTH, { message: `Password must not exceed ${SecurityConfig.MAX_PASSWORD_LENGTH} characters` })
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

