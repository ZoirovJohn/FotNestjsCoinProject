import {
  Body,
  Controller,
  Get,
  Headers,
  Ip,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from '../common/jwt.guard';

@Controller('auth')
export class AuthController {
  constructor(private auth: AuthService) {}

  @Post('signup')
  signup(@Body() dto: SignupDto) {
    return this.auth.signup(dto.email, dto.password, dto.name);
  }

  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Headers('user-agent') ua: string,
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.auth.login(dto.email, dto.password, ua, ip);
    const secure = String(process.env.COOKIE_SECURE) === 'true';
    const domain = process.env.COOKIE_DOMAIN || 'localhost';
    res.cookie('rt', result.refreshToken, {
      httpOnly: true,
      secure,
      sameSite: 'lax',
      maxAge: Number(process.env.JWT_REFRESH_TTL || 2592000) * 1000,
      domain,
      path: '/',
    });
    return { accessToken: result.accessToken, user: result.user };
  }

  @Post('refresh')
  async refresh(
    @Req() req: Request,
    @Headers('user-agent') ua: string,
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    const old = (req.cookies && (req.cookies as any).rt) || '';
    const result = await this.auth.refresh(old, ua, ip);
    const secure = String(process.env.COOKIE_SECURE) === 'true';
    const domain = process.env.COOKIE_DOMAIN || 'localhost';
    res.cookie('rt', result.refreshToken, {
      httpOnly: true,
      secure,
      sameSite: 'lax',
      maxAge: Number(process.env.JWT_REFRESH_TTL || 2592000) * 1000,
      domain,
      path: '/',
    });
    return { accessToken: result.accessToken };
  }

  @Post('logout')
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const rt = (req.cookies && (req.cookies as any).rt) || '';
    await this.auth.logout(rt);
    res.clearCookie('rt', { path: '/' });
    return { ok: true };
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  me(@Req() req: Request) {
    return { user: (req as any).user };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout-all')
  logoutAll(@Req() req: any) {
    return this.auth.logoutAll(req.user.sub);
  }
}
