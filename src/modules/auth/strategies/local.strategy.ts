import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      usernameField: 'login',
      passwordField: 'password',
      passReqToCallback: true,
    });
  }

  async validate(req: any, login: string, password: string): Promise<any> {
    const { role } = req.body;
    
    if (!role) {
      throw new UnauthorizedException('Role is required');
    }

    const user = await this.authService.validateUser(login, password, role);
    
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    
    return user;
  }
}

