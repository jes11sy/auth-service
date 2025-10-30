/**
 * Перечисление ролей пользователей
 */
export enum UserRole {
  ADMIN = 'admin',
  OPERATOR = 'operator',
  DIRECTOR = 'director',
  MASTER = 'master',
}

/**
 * Базовая информация о пользователе
 */
export interface BaseUser {
  id: number;
  login: string;
  name?: string;
  role: UserRole;
}

/**
 * Пользователь после успешной аутентификации
 */
export interface AuthUser extends BaseUser {
  cities?: string[];
  city?: string;
  status?: string;
  statusWork?: string;
  tgId?: string;
  chatId?: string;
  sipAddress?: string;
}

/**
 * JWT Payload структура
 */
export interface JwtPayload {
  sub: number;
  login: string;
  role: UserRole;
  name?: string;
  cities?: string[];
  iat?: number;
  exp?: number;
}

/**
 * Полная информация профиля пользователя
 */
export interface UserProfile extends BaseUser {
  createdAt: Date;
  updatedAt: Date;
  note?: string;
  dateCreate?: Date;
  
  // Специфичные поля для разных ролей
  cities?: string[];      // для director, master
  city?: string;          // для operator
  status?: string;        // для operator
  statusWork?: string;    // для operator, master
  tgId?: string;          // для director, master
  chatId?: string;        // для master
  sipAddress?: string;    // для operator
}

/**
 * Ответ успешного логина
 */
export interface LoginResponse {
  success: boolean;
  message: string;
  data: {
    user: {
      id: number;
      login: string;
      name?: string;
      role: UserRole;
      cities?: string[];
      city?: string;
    };
    accessToken: string;
    refreshToken: string;
  };
}

/**
 * Ответ с профилем пользователя
 */
export interface ProfileResponse {
  success: boolean;
  data: UserProfile;
}

/**
 * Ответ с обновленными токенами
 */
export interface RefreshTokenResponse {
  success: boolean;
  data: {
    accessToken: string;
    refreshToken: string;
  };
}

/**
 * Стандартный успешный ответ
 */
export interface SuccessResponse {
  success: boolean;
  message: string;
}

