import { IsString, IsNotEmpty, IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum UserRole {
  CALLCENTRE_ADMIN = 'CALLCENTRE_ADMIN',
  CALLCENTRE_OPERATOR = 'CALLCENTRE_OPERATOR',
  DIRECTOR = 'DIRECTOR',
  MASTER = 'MASTER',
}

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
    enum: UserRole,
    example: UserRole.CALLCENTRE_ADMIN,
  })
  @IsEnum(UserRole)
  @IsNotEmpty()
  role: UserRole;
}

