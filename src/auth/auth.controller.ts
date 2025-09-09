// src/auth/auth.controller.ts
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
import { log } from 'console';

// ---- cookie helper (no domain on localhost) ----
function setRtCookie(res: Response, token: string) {
  const secure = String(process.env.COOKIE_SECURE) === 'true'; // false in local dev (HTTP)
  const base = {
    httpOnly: true,
    secure,
    sameSite: 'lax' as const,
    maxAge: Number(process.env.JWT_REFRESH_TTL || 2592000) * 1000, // 30d default
    path: '/',
  };
  const domain = process.env.COOKIE_DOMAIN; // e.g. "example.com" (prod only)

  if (process.env.NODE_ENV === 'production' && domain) {
    res.cookie('rt', token, { ...base, domain });
  } else {
    res.cookie('rt', token, base); // no domain on localhost
  }
}

@Controller('auth')
export class AuthController {
  constructor(private auth: AuthService) {}

  @Post('signup')
  async signup(
    @Body() dto: SignupDto,
    @Headers('user-agent') ua: string,
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    console.log('AuthController signup called with:', dto);
    const result = await this.auth.signup(
      dto.email,
      dto.password,
      dto.name,
      ua,
      ip,
    );
    setRtCookie(res, result.refreshToken);
    return { accessToken: result.accessToken, user: result.user };
  }

  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Headers('user-agent') ua: string,
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    console.log('AuthController login called with:', { dto, ua, ip });
    const result = await this.auth.login(dto.email, dto.password, ua, ip);
    setRtCookie(res, result.refreshToken);
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
    setRtCookie(res, result.refreshToken);
    return { accessToken: result.accessToken };
  }

  @Post('logout')
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const rt = (req.cookies && (req.cookies as any).rt) || '';
    await this.auth.logout(rt);

    // Clear cookie (match how it was set)
    if (process.env.NODE_ENV === 'production' && process.env.COOKIE_DOMAIN) {
      res.clearCookie('rt', { path: '/', domain: process.env.COOKIE_DOMAIN });
    } else {
      res.clearCookie('rt', { path: '/' });
    }
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
